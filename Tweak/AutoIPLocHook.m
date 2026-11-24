#import <Foundation/Foundation.h>
#import <SystemConfiguration/CaptiveNetwork.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <dlfcn.h>
#import <string.h>

static NSString *const kGeoPrefPath = @"/var/mobile/Library/Preferences/com.autoiploc.geo.plist";
static NSString *const kWifiPrefPath = @"/var/mobile/Library/Preferences/com.autoiploc.wifi.plist";

// 轻量级 Mach-O GOT/LAZY 符号重绑定（无需外部 substrate C 符号依赖）
static void rebind_symbol_in_image(const struct mach_header *header, intptr_t slide, const char *target_name, void *replacement, void **replaced) {
    Dl_info info;
    if (dladdr(header, &info) == 0) return;

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
                strcmp(cur_seg_cmd->segname, "__DATA_CONST") != 0 &&
                strcmp(cur_seg_cmd->segname, "__AUTH_CONST") != 0) continue;

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

// 1. 强制 GEOCountryConfiguration 返回当前 IP 国家码
static NSString *(*orig_countryCode)(id self, SEL _cmd);
static NSString *hook_countryCode(id self, SEL _cmd) {
    NSDictionary *cfg = [NSDictionary dictionaryWithContentsOfFile:kGeoPrefPath];
    NSString *cc = cfg[@"countryCode"];
    if (cc && cc.length == 2 && ![cc isEqualToString:@"--"]) {
        return cc;
    }
    return orig_countryCode ? orig_countryCode(self, _cmd) : @"US";
}

// 2. 屏蔽国行硬件强制跳转高德中国瓦片清单
static BOOL (*orig_isChina)(id self, SEL _cmd);
static BOOL hook_isChina(id self, SEL _cmd) {
    NSDictionary *cfg = [NSDictionary dictionaryWithContentsOfFile:kGeoPrefPath];
    if ([cfg[@"forceAppleMaps"] boolValue]) {
        return NO;
    }
    return orig_isChina ? orig_isChina(self, _cmd) : NO;
}

// 3. 接管系统 CNCopyCurrentNetworkInfo 与 CNCopySupportedInterfaces
static CFArrayRef (*orig_CNCopySupportedInterfaces)(void);
static CFArrayRef hook_CNCopySupportedInterfaces(void) {
    NSDictionary *wifiCfg = [NSDictionary dictionaryWithContentsOfFile:kWifiPrefPath];
    if ([wifiCfg[@"enabled"] boolValue]) {
        return (__bridge_retained CFArrayRef)@[@"en0"];
    }
    return orig_CNCopySupportedInterfaces ? orig_CNCopySupportedInterfaces() : (__bridge_retained CFArrayRef)@[@"en0"];
}

static CFDictionaryRef (*orig_CNCopyCurrentNetworkInfo)(CFStringRef interfaceName);
static CFDictionaryRef hook_CNCopyCurrentNetworkInfo(CFStringRef interfaceName) {
    NSDictionary *wifiCfg = [NSDictionary dictionaryWithContentsOfFile:kWifiPrefPath];
    if ([wifiCfg[@"enabled"] boolValue]) {
        NSArray *nets = wifiCfg[@"networks"];
        if ([nets isKindOfClass:[NSArray class]] && nets.count > 0) {
            NSDictionary *topAP = nets[0];
            NSString *ssid = topAP[@"SSID"] ?: @"Xfinity-Home-5G";
            NSString *bssid = topAP[@"BSSID"] ?: @"20:4E:7F:8A:12:4C";
            NSDictionary *result = @{
                (__bridge NSString *)kCNNetworkInfoKeySSID: ssid,
                (__bridge NSString *)kCNNetworkInfoKeyBSSID: bssid,
                (__bridge NSString *)kCNNetworkInfoKeySSIDData: [ssid dataUsingEncoding:NSUTF8StringEncoding]
            };
            return (__bridge_retained CFDictionaryRef)result;
        }
    }
    return orig_CNCopyCurrentNetworkInfo ? orig_CNCopyCurrentNetworkInfo(interfaceName) : NULL;
}

__attribute__((constructor))
static void AutoIPLocHookEntry(void) {
    @autoreleasepool {
        Class geoCls = objc_getClass("GEOCountryConfiguration");
        if (geoCls) {
            Method m1 = class_getInstanceMethod(geoCls, NSSelectorFromString(@"countryCode"));
            if (m1) {
                orig_countryCode = (void *)method_getImplementation(m1);
                method_setImplementation(m1, (IMP)hook_countryCode);
            }
            Method m1b = class_getInstanceMethod(geoCls, NSSelectorFromString(@"_countryCode"));
            if (m1b) {
                method_setImplementation(m1b, (IMP)hook_countryCode);
            }
        }
        Class platformCls = objc_getClass("GEOPlatform");
        if (platformCls) {
            Method mChina = class_getInstanceMethod(platformCls, NSSelectorFromString(@"isChina"));
            if (mChina) {
                orig_isChina = (void *)method_getImplementation(mChina);
                method_setImplementation(mChina, (IMP)hook_isChina);
            }
        }

        uint32_t imgCount = _dyld_image_count();
        for (uint32_t i = 0; i < imgCount; i++) {
            const struct mach_header *hdr = _dyld_get_image_header(i);
            intptr_t slide = _dyld_get_image_vmaddr_slide(i);
            rebind_symbol_in_image(hdr, slide, "CNCopyCurrentNetworkInfo", (void *)hook_CNCopyCurrentNetworkInfo, (void **)&orig_CNCopyCurrentNetworkInfo);
            rebind_symbol_in_image(hdr, slide, "CNCopySupportedInterfaces", (void *)hook_CNCopySupportedInterfaces, (void **)&orig_CNCopySupportedInterfaces);
        }
    }
}
