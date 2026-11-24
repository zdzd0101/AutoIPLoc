#import <Foundation/Foundation.h>
#import <CoreLocation/CoreLocation.h>
#import <SystemConfiguration/CaptiveNetwork.h>
#import <objc/runtime.h>
#import <mach/mach.h>
#import <mach/vm_map.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <dlfcn.h>
#import <string.h>

static NSString *const kGeoPrefPath = @"/var/mobile/Library/Preferences/com.autoiploc.geo.plist";
static NSString *const kWifiPrefPath = @"/var/mobile/Library/Preferences/com.autoiploc.wifi.plist";

// 安全 Mach-O GOT/LAZY 符号重绑定（带 vm_protect 写权限申请，绝不引发内存保护闪退）
static void safe_rebind_symbol_in_image(const struct mach_header *header, intptr_t slide, const char *target_name, void *replacement, void **replaced) {
    if (!header || header->magic != MH_MAGIC_64) return;

    struct segment_command_64 *cur_seg_cmd;
    struct segment_command_64 *linkedit_segment = NULL;
    struct symtab_command *symtab_cmd = NULL;
    struct dysymtab_command *dysymtab_cmd = NULL;

    uintptr_t cur = (uintptr_t)header + sizeof(struct mach_header_64);
    for (uint i = 0; i < header->ncmds; i++, cur += cur_seg_cmd->cmdsize) {
        cur_seg_cmd = (struct segment_command_64 *)cur;
        if (cur_seg_cmd->cmd == LC_SEGMENT_64) {
            if (strcmp(cur_seg_cmd->segname, "__LINKEDIT") == 0) {
                linkedit_segment = cur_seg_cmd;
            }
        } else if (cur_seg_cmd->cmd == LC_SYMTAB) {
            symtab_cmd = (struct symtab_command *)cur_seg_cmd;
        } else if (cur_seg_cmd->cmd == LC_DYSYMTAB) {
            dysymtab_cmd = (struct dysymtab_command *)cur_seg_cmd;
        }
    }

    if (!symtab_cmd || !dysymtab_cmd || !linkedit_segment || !dysymtab_cmd->nindirectsyms) return;

    uintptr_t linkedit_base = (uintptr_t)slide + linkedit_segment->vmaddr - linkedit_segment->fileoff;
    struct nlist_64 *symtab = (struct nlist_64 *)(linkedit_base + symtab_cmd->symoff);
    char *strtab = (char *)(linkedit_base + symtab_cmd->stroff);
    uint32_t *indirect_symtab = (uint32_t *)(linkedit_base + dysymtab_cmd->indirectsymoff);

    cur = (uintptr_t)header + sizeof(struct mach_header_64);
    for (uint i = 0; i < header->ncmds; i++, cur += cur_seg_cmd->cmdsize) {
        cur_seg_cmd = (struct segment_command_64 *)cur;
        if (cur_seg_cmd->cmd == LC_SEGMENT_64) {
            if (strcmp(cur_seg_cmd->segname, "__DATA") != 0 &&
                strcmp(cur_seg_cmd->segname, "__DATA_CONST") != 0) continue;

            for (uint j = 0; j < cur_seg_cmd->nsects; j++) {
                struct section_64 *sect = (struct section_64 *)(cur + sizeof(struct segment_command_64)) + j;
                uint32_t flags = sect->flags & SECTION_TYPE;
                if (flags != S_LAZY_SYMBOL_POINTERS && flags != S_NON_LAZY_SYMBOL_POINTERS) continue;

                uint32_t *indirect_symbol_indices = indirect_symtab + sect->reserved1;
                void **indirect_symbol_bindings = (void **)((uintptr_t)slide + sect->addr);
                size_t count = sect->size / sizeof(void *);

                for (size_t k = 0; k < count; k++) {
                    uint32_t symtab_index = indirect_symbol_indices[k];
                    if (symtab_index == INDIRECT_SYMBOL_ABS || symtab_index == INDIRECT_SYMBOL_LOCAL ||
                        symtab_index == (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS)) continue;

                    uint32_t strtab_offset = symtab[symtab_index].n_un.n_strx;
                    char *symbol_name = strtab + strtab_offset;
                    if (strlen(symbol_name) > 1 && strcmp(&symbol_name[1], target_name) == 0) {
                        kern_return_t kr = vm_protect(
                            mach_task_self(),
                            (vm_address_t)&indirect_symbol_bindings[k],
                            sizeof(void *),
                            false,
                            VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY
                        );
                        if (kr == KERN_SUCCESS) {
                            if (replaced && *replaced == NULL) {
                                *replaced = indirect_symbol_bindings[k];
                            }
                            indirect_symbol_bindings[k] = replacement;
                        }
                    }
                }
            }
        }
    }
}

// 1. 抹除软件模拟定位标记 (isSimulatedBySoftware = NO, isProducedByAccessory = NO)
static BOOL hook_returnNO(id self, SEL _cmd) {
    return NO;
}

// 2. 强制 GEOCountryConfiguration 返回当前 IP 国家码（彻底去除高德地图）
static NSString *(*orig_countryCode)(id self, SEL _cmd);
static NSString *hook_countryCode(id self, SEL _cmd) {
    NSDictionary *cfg = [NSDictionary dictionaryWithContentsOfFile:kGeoPrefPath];
    NSString *cc = cfg[@"countryCode"];
    if (cc && cc.length == 2 && ![cc isEqualToString:@"--"]) {
        return cc;
    }
    return orig_countryCode ? orig_countryCode(self, _cmd) : @"US";
}

// 3. 接管系统 CNCopyCurrentNetworkInfo 与 NEHotspotNetwork 返回模拟美国 Wi-Fi
static NSDictionary *GetActiveMockWiFi(void) {
    NSDictionary *wifiCfg = [NSDictionary dictionaryWithContentsOfFile:kWifiPrefPath];
    if ([wifiCfg[@"enabled"] boolValue]) {
        NSArray *nets = wifiCfg[@"networks"];
        if ([nets isKindOfClass:[NSArray class]] && nets.count > 0) {
            return nets[0];
        }
    }
    return nil;
}

static CFArrayRef (*orig_CNCopySupportedInterfaces)(void);
static CFArrayRef hook_CNCopySupportedInterfaces(void) {
    if (GetActiveMockWiFi() != nil) {
        return (__bridge_retained CFArrayRef)@[@"en0"];
    }
    return orig_CNCopySupportedInterfaces ? orig_CNCopySupportedInterfaces() : (__bridge_retained CFArrayRef)@[@"en0"];
}

static CFDictionaryRef (*orig_CNCopyCurrentNetworkInfo)(CFStringRef interfaceName);
static CFDictionaryRef hook_CNCopyCurrentNetworkInfo(CFStringRef interfaceName) {
    NSDictionary *topAP = GetActiveMockWiFi();
    if (topAP != nil) {
        NSString *ssid = topAP[@"SSID"] ?: @"CenturyLink3825-5G";
        NSString *bssid = topAP[@"BSSID"] ?: @"20:4E:7F:FB:40:31";
        NSDictionary *result = @{
            (__bridge NSString *)kCNNetworkInfoKeySSID: ssid,
            (__bridge NSString *)kCNNetworkInfoKeyBSSID: bssid,
            (__bridge NSString *)kCNNetworkInfoKeySSIDData: [ssid dataUsingEncoding:NSUTF8StringEncoding]
        };
        return (__bridge_retained CFDictionaryRef)result;
    }
    return orig_CNCopyCurrentNetworkInfo ? orig_CNCopyCurrentNetworkInfo(interfaceName) : NULL;
}

static NSString *(*orig_hotspotSSID)(id self, SEL _cmd);
static NSString *hook_hotspotSSID(id self, SEL _cmd) {
    NSDictionary *topAP = GetActiveMockWiFi();
    if (topAP[@"SSID"]) return topAP[@"SSID"];
    return orig_hotspotSSID ? orig_hotspotSSID(self, _cmd) : nil;
}

static NSString *(*orig_hotspotBSSID)(id self, SEL _cmd);
static NSString *hook_hotspotBSSID(id self, SEL _cmd) {
    NSDictionary *topAP = GetActiveMockWiFi();
    if (topAP[@"BSSID"]) return topAP[@"BSSID"];
    return orig_hotspotBSSID ? orig_hotspotBSSID(self, _cmd) : nil;
}

__attribute__((constructor))
static void AutoIPLocHookEntry(void) {
    @autoreleasepool {
        // A. 抹除所有 App 读取到的模拟定位标记
        Class srcInfoCls = objc_getClass("CLLocationSourceInformation");
        if (srcInfoCls) {
            Method mSim = class_getInstanceMethod(srcInfoCls, NSSelectorFromString(@"isSimulatedBySoftware"));
            if (mSim) method_setImplementation(mSim, (IMP)hook_returnNO);
            Method mAcc = class_getInstanceMethod(srcInfoCls, NSSelectorFromString(@"isProducedByAccessory"));
            if (mAcc) method_setImplementation(mAcc, (IMP)hook_returnNO);
        }
        Class locCls = objc_getClass("CLLocation");
        if (locCls) {
            Method mLocSim = class_getInstanceMethod(locCls, NSSelectorFromString(@"isSimulatedBySoftware"));
            if (mLocSim) method_setImplementation(mLocSim, (IMP)hook_returnNO);
            Method mLocPriv = class_getInstanceMethod(locCls, NSSelectorFromString(@"_isSimulated"));
            if (mLocPriv) method_setImplementation(mLocPriv, (IMP)hook_returnNO);
        }

        // B. 强制苹果国际原生地图国家码
        Class geoCls = objc_getClass("GEOCountryConfiguration");
        if (geoCls) {
            Method m1 = class_getInstanceMethod(geoCls, NSSelectorFromString(@"countryCode"));
            if (m1) {
                orig_countryCode = (void *)method_getImplementation(m1);
                method_setImplementation(m1, (IMP)hook_countryCode);
            }
            Method m1b = class_getInstanceMethod(geoCls, NSSelectorFromString(@"_countryCode"));
            if (m1b) method_setImplementation(m1b, (IMP)hook_countryCode);
        }
        Class platformCls = objc_getClass("GEOPlatform");
        if (platformCls) {
            Method mChina = class_getInstanceMethod(platformCls, NSSelectorFromString(@"isChina"));
            if (mChina) method_setImplementation(mChina, (IMP)hook_returnNO);
        }

        // C. 接管 NEHotspotNetwork Wi-Fi 属性
        Class hotspotCls = objc_getClass("NEHotspotNetwork");
        if (hotspotCls) {
            Method mSSID = class_getInstanceMethod(hotspotCls, NSSelectorFromString(@"SSID"));
            if (mSSID) {
                orig_hotspotSSID = (void *)method_getImplementation(mSSID);
                method_setImplementation(mSSID, (IMP)hook_hotspotSSID);
            }
            Method mBSSID = class_getInstanceMethod(hotspotCls, NSSelectorFromString(@"BSSID"));
            if (mBSSID) {
                orig_hotspotBSSID = (void *)method_getImplementation(mBSSID);
                method_setImplementation(mBSSID, (IMP)hook_hotspotBSSID);
            }
        }

        // D. 安全重绑定当前主程序及 SystemConfiguration 符号（跳过系统动态库缓存只读段避免崩溃）
        const struct mach_header *mainHdr = _dyld_get_image_header(0);
        intptr_t mainSlide = _dyld_get_image_vmaddr_slide(0);
        safe_rebind_symbol_in_image(mainHdr, mainSlide, "CNCopyCurrentNetworkInfo", (void *)hook_CNCopyCurrentNetworkInfo, (void **)&orig_CNCopyCurrentNetworkInfo);
        safe_rebind_symbol_in_image(mainHdr, mainSlide, "CNCopySupportedInterfaces", (void *)hook_CNCopySupportedInterfaces, (void **)&orig_CNCopySupportedInterfaces);
    }
}
