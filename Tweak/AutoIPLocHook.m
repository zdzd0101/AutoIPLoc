#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <CoreLocation/CoreLocation.h>
#import <CoreTelephony/CTCarrier.h>
#import <CoreTelephony/CTTelephonyNetworkInfo.h>
#import <SystemConfiguration/CaptiveNetwork.h>
#import <CFNetwork/CFNetwork.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <mach/mach.h>
#import <mach/vm_map.h>
#import <ifaddrs.h>
#import <dlfcn.h>
#import <stdlib.h>
#import <string.h>

typedef void (*MSHookFunction_t)(void *symbol, void *replace, void **result);
typedef void (*MSHookMessageEx_t)(Class _class, SEL message, IMP hook, IMP *old);

static MSHookFunction_t g_MSHookFunction = NULL;
static MSHookMessageEx_t g_MSHookMessageEx = NULL;

struct rebinding_entry {
    const char *name;
    void *replacement;
    void **replaced;
};

static void rebind_symbols_for_image(const struct mach_header *header, intptr_t slide, struct rebinding_entry *rebindings, size_t rebindings_nel) {
    if (!header) return;
    struct segment_command_64 *cur_seg_cmd;
    struct segment_command_64 *linkedit_segment = NULL;
    struct symtab_command *symtab_cmd = NULL;
    struct dysymtab_command *dysymtab_cmd = NULL;

    uintptr_t cur = (uintptr_t)header + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < header->ncmds; i++, cur += cur_seg_cmd->cmdsize) {
        cur_seg_cmd = (struct segment_command_64 *)cur;
        if (cur_seg_cmd->cmd == LC_SEGMENT_64) {
            if (strcmp(cur_seg_cmd->segname, SEG_LINKEDIT) == 0) {
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
    for (uint32_t i = 0; i < header->ncmds; i++, cur += cur_seg_cmd->cmdsize) {
        cur_seg_cmd = (struct segment_command_64 *)cur;
        if (cur_seg_cmd->cmd == LC_SEGMENT_64) {
            if (strcmp(cur_seg_cmd->segname, SEG_DATA) != 0 && strcmp(cur_seg_cmd->segname, "__DATA_CONST") != 0) {
                continue;
            }
            for (uint32_t j = 0; j < cur_seg_cmd->nsects; j++) {
                struct section_64 *sect = (struct section_64 *)(cur + sizeof(struct segment_command_64)) + j;
                uint32_t type = sect->flags & SECTION_TYPE;
                if (type != S_LAZY_SYMBOL_POINTERS && type != S_NON_LAZY_SYMBOL_POINTERS) continue;

                uint32_t *indirect_symbol_indices = indirect_symtab + sect->reserved1;
                void **indirect_symbol_bindings = (void **)((uintptr_t)slide + sect->addr);
                size_t count = sect->size / sizeof(void *);

                vm_protect(mach_task_self(), (vm_address_t)indirect_symbol_bindings, sect->size, 0, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);

                for (size_t k = 0; k < count; k++) {
                    uint32_t symtab_index = indirect_symbol_indices[k];
                    if (symtab_index == INDIRECT_SYMBOL_ABS || symtab_index == INDIRECT_SYMBOL_LOCAL ||
                        symtab_index == (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS)) {
                        continue;
                    }
                    uint32_t strtab_offset = symtab[symtab_index].n_un.n_strx;
                    char *symbol_name = strtab + strtab_offset;
                    if (strnlen(symbol_name, 2) < 2) continue;

                    for (size_t r = 0; r < rebindings_nel; r++) {
                        if (strcmp(&symbol_name[1], rebindings[r].name) == 0) {
                            if (rebindings[r].replaced != NULL && *(rebindings[r].replaced) == NULL) {
                                *(rebindings[r].replaced) = indirect_symbol_bindings[k];
                            }
                            indirect_symbol_bindings[k] = rebindings[r].replacement;
                            break;
                        }
                    }
                }
            }
        }
    }
}

// 从当前动态库自身磁盘路径提取 RootHide .jbroot 中的 libellekit.dylib（确保 arm64e PAC 指针正确签名）
static void ResolveElleKitFromSelfPath(void *selfSymbolAddr) {
    g_MSHookFunction = (MSHookFunction_t)dlsym(RTLD_DEFAULT, "MSHookFunction");
    g_MSHookMessageEx = (MSHookMessageEx_t)dlsym(RTLD_DEFAULT, "MSHookMessageEx");
    if (g_MSHookFunction && g_MSHookMessageEx) return;

    Dl_info selfInfo;
    if (dladdr(selfSymbolAddr, &selfInfo) != 0 && selfInfo.dli_fname != NULL) {
        const char *libMarker = strstr(selfInfo.dli_fname, "/Library/");
        if (libMarker != NULL) {
            size_t rootLen = (size_t)(libMarker - selfInfo.dli_fname);
            if (rootLen > 0 && rootLen < 512) {
                char jbRoot[512] = {0};
                memcpy(jbRoot, selfInfo.dli_fname, rootLen);

                const char *relPaths[] = {
                    "/usr/lib/libellekit.dylib",
                    "/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate",
                    "/usr/lib/libsubstrate.dylib",
                    "/usr/lib/TweakInject.dylib"
                };
                for (int i = 0; i < 4; i++) {
                    char fullPath[768] = {0};
                    snprintf(fullPath, sizeof(fullPath), "%s%s", jbRoot, relPaths[i]);
                    void *h = dlopen(fullPath, RTLD_NOW | RTLD_GLOBAL);
                    if (h) {
                        if (!g_MSHookFunction) g_MSHookFunction = (MSHookFunction_t)dlsym(h, "MSHookFunction");
                        if (!g_MSHookMessageEx) g_MSHookMessageEx = (MSHookMessageEx_t)dlsym(h, "MSHookMessageEx");
                        if (g_MSHookFunction && g_MSHookMessageEx) return;
                    }
                }
            }
        }
    }
}

static void HookObjCMethod(Class cls, SEL sel, IMP newImp, IMP *oldImp) {
    if (!cls || !sel || !newImp) return;
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return;
    if (g_MSHookMessageEx) {
        g_MSHookMessageEx(cls, sel, newImp, oldImp);
    } else {
        IMP prev = method_setImplementation(m, newImp);
        if (oldImp && *oldImp == NULL) *oldImp = prev;
    }
}

static NSString *const kGeoPrefPath = @"/var/mobile/Library/Preferences/com.autoiploc.geo.plist";
static NSString *const kWifiPrefPath = @"/var/mobile/Library/Preferences/com.autoiploc.wifi.plist";

static NSDictionary *LoadGeoConfig(void) {
    return [NSDictionary dictionaryWithContentsOfFile:kGeoPrefPath];
}

static NSString *GetTargetCountryCode(void) {
    NSDictionary *cfg = LoadGeoConfig();
    NSString *cc = cfg[@"countryCode"];
    if (cc && cc.length == 2 && ![cc isEqualToString:@"--"]) {
        return cc.uppercaseString;
    }
    return @"US";
}

static NSString *GetTargetTimeZoneName(void) {
    NSDictionary *cfg = LoadGeoConfig();
    NSString *tz = cfg[@"timezone"];
    if (tz && tz.length > 3 && ![tz isEqualToString:@"-"]) {
        return tz;
    }
    return nil;
}

// 1. 白名单屏蔽所有非系统动态库路径（消除 [功能插件注入] 与 [RootHide底座]）
static BOOL IsSensitiveDylibPath(const char *path) {
    if (!path) return NO;
    if (strncmp(path, "/System/", 8) == 0) return NO;
    if (strncmp(path, "/usr/lib/", 9) == 0) return NO;
    if (strncmp(path, "/Developer/", 11) == 0) return NO;
    if (strstr(path, ".app/") != NULL) return NO;
    return YES;
}

static const char *(*orig_dyld_get_image_name)(uint32_t image_index) = NULL;
static const char *hook_dyld_get_image_name(uint32_t image_index) {
    const char *name = orig_dyld_get_image_name ? orig_dyld_get_image_name(image_index) : _dyld_get_image_name(image_index);
    if (IsSensitiveDylibPath(name)) {
        return "/usr/lib/libobjc.A.dylib";
    }
    return name;
}

static int (*orig_dladdr)(const void *addr, Dl_info *info) = NULL;
static int hook_dladdr(const void *addr, Dl_info *info) {
    int ret = orig_dladdr ? orig_dladdr(addr, info) : dladdr(addr, info);
    if (ret != 0 && info && info->dli_fname && IsSensitiveDylibPath(info->dli_fname)) {
        info->dli_fname = "/usr/lib/libobjc.A.dylib";
    }
    return ret;
}

// 2. 接管 NSTimeZone 与 CFTimeZone
static NSTimeZone *(*orig_systemTimeZone)(id self, SEL _cmd) = NULL;
static NSTimeZone *hook_systemTimeZone(id self, SEL _cmd) {
    NSString *tzName = GetTargetTimeZoneName();
    if (tzName) {
        NSTimeZone *tz = [NSTimeZone timeZoneWithName:tzName];
        if (tz) return tz;
    }
    return orig_systemTimeZone ? orig_systemTimeZone(self, _cmd) : [NSTimeZone timeZoneWithName:@"America/New_York"];
}

static NSTimeZone *(*orig_defaultTimeZone)(id self, SEL _cmd) = NULL;
static NSTimeZone *hook_defaultTimeZone(id self, SEL _cmd) {
    NSString *tzName = GetTargetTimeZoneName();
    if (tzName) {
        NSTimeZone *tz = [NSTimeZone timeZoneWithName:tzName];
        if (tz) return tz;
    }
    return orig_defaultTimeZone ? orig_defaultTimeZone(self, _cmd) : [NSTimeZone timeZoneWithName:@"America/New_York"];
}

static NSTimeZone *(*orig_localTimeZone)(id self, SEL _cmd) = NULL;
static NSTimeZone *hook_localTimeZone(id self, SEL _cmd) {
    NSString *tzName = GetTargetTimeZoneName();
    if (tzName) {
        NSTimeZone *tz = [NSTimeZone timeZoneWithName:tzName];
        if (tz) return tz;
    }
    return orig_localTimeZone ? orig_localTimeZone(self, _cmd) : [NSTimeZone timeZoneWithName:@"America/New_York"];
}

static CFTimeZoneRef (*orig_CFTimeZoneCopySystem)(void) = NULL;
static CFTimeZoneRef hook_CFTimeZoneCopySystem(void) {
    NSString *tzName = GetTargetTimeZoneName();
    if (tzName) {
        CFTimeZoneRef tz = CFTimeZoneCreateWithName(kCFAllocatorDefault, (__bridge CFStringRef)tzName, true);
        if (tz) return tz;
    }
    return orig_CFTimeZoneCopySystem ? orig_CFTimeZoneCopySystem() : CFTimeZoneCopySystem();
}

// 3. 补全双卡槽基带与蜂窝网络特征（统一修正为美国 T-Mobile 310/260 LTE）
static NSString *(*orig_carrierName)(id self, SEL _cmd) = NULL;
static NSString *hook_carrierName(id self, SEL _cmd) {
    NSString *orig = orig_carrierName ? orig_carrierName(self, _cmd) : nil;
    if (orig.length == 0 || [orig isEqualToString:@"--"] || [orig isEqualToString:@"Carrier"] || [orig isEqualToString:@"EE"]) {
        return @"T-Mobile";
    }
    return orig;
}

static NSString *(*orig_mobileCountryCode)(id self, SEL _cmd) = NULL;
static NSString *hook_mobileCountryCode(id self, SEL _cmd) {
    NSString *orig = orig_mobileCountryCode ? orig_mobileCountryCode(self, _cmd) : nil;
    if (orig.length == 0 || [orig isEqualToString:@"460"] || [orig isEqualToString:@"454"] || [orig isEqualToString:@"455"] || [orig isEqualToString:@"234"]) {
        return @"310";
    }
    return orig;
}

static NSString *(*orig_mobileNetworkCode)(id self, SEL _cmd) = NULL;
static NSString *hook_mobileNetworkCode(id self, SEL _cmd) {
    NSString *orig = orig_mobileNetworkCode ? orig_mobileNetworkCode(self, _cmd) : nil;
    if (orig.length == 0 || [orig isEqualToString:@"65535"] || [orig isEqualToString:@"30"]) {
        return @"260";
    }
    return orig;
}

static NSString *(*orig_isoCountryCode)(id self, SEL _cmd) = NULL;
static NSString *hook_isoCountryCode(id self, SEL _cmd) {
    NSString *orig = orig_isoCountryCode ? orig_isoCountryCode(self, _cmd) : nil;
    if (orig.length == 0 || [orig.lowercaseString isEqualToString:@"cn"] || [orig.lowercaseString isEqualToString:@"hk"] || [orig.lowercaseString isEqualToString:@"mo"] || [orig.lowercaseString isEqualToString:@"gb"]) {
        return GetTargetCountryCode().lowercaseString;
    }
    return orig;
}

static NSDictionary<NSString *, NSString *> *(*orig_serviceRadioTech)(id self, SEL _cmd) = NULL;
static NSDictionary<NSString *, NSString *> *hook_serviceRadioTech(id self, SEL _cmd) {
    NSDictionary<NSString *, NSString *> *orig = orig_serviceRadioTech ? orig_serviceRadioTech(self, _cmd) : nil;
    if (orig.count > 0) return orig;
    return @{
        @"0000000100000001": @"CTRadioAccessTechnologyLTE",
        @"0000000100000002": @"CTRadioAccessTechnologyLTE"
    };
}

static NSString *(*orig_currentRadioTech)(id self, SEL _cmd) = NULL;
static NSString *hook_currentRadioTech(id self, SEL _cmd) {
    NSString *orig = orig_currentRadioTech ? orig_currentRadioTech(self, _cmd) : nil;
    if (orig.length > 0) return orig;
    return @"CTRadioAccessTechnologyLTE";
}

static BOOL hook_returnYES(id self, SEL _cmd) {
    return YES;
}

// 4. 隐藏系统 HTTP/HTTPS/SOCKS5/PAC 显式代理（仅对系统底层网络库放行联网）
static BOOL IsSystemNetworkingCaller(void *retAddr) {
    if (!retAddr) return NO;
    Dl_info info;
    int ok = orig_dladdr ? orig_dladdr(retAddr, &info) : dladdr(retAddr, &info);
    if (ok != 0 && info.dli_fname != NULL) {
        if (strstr(info.dli_fname, "CFNetwork") != NULL ||
            strstr(info.dli_fname, "WebKit") != NULL ||
            strstr(info.dli_fname, "libnetwork") != NULL ||
            strstr(info.dli_fname, "Network.framework") != NULL ||
            strstr(info.dli_fname, "Foundation") != NULL ||
            strstr(info.dli_fname, "Security") != NULL) {
            return YES;
        }
    }
    return NO;
}

static CFDictionaryRef CreateCleanProxyDict(void) {
    NSDictionary *cleanProxy = @{
        @"HTTPEnable": @0,
        @"HTTPSEnable": @0,
        @"SOCKSEnable": @0,
        @"ProxyAutoConfigEnable": @0,
        @"FTPPassive": @1,
        @"ExceptionsList": @[@"*.local", @"169.254/16"]
    };
    return (__bridge_retained CFDictionaryRef)cleanProxy;
}

static CFDictionaryRef (*orig_CFNetworkCopySystemProxySettings)(void) = NULL;
static CFDictionaryRef hook_CFNetworkCopySystemProxySettings(void) {
    if (IsSystemNetworkingCaller(__builtin_return_address(0)) && orig_CFNetworkCopySystemProxySettings) {
        return orig_CFNetworkCopySystemProxySettings();
    }
    return CreateCleanProxyDict();
}

static CFDictionaryRef (*orig_SCDynamicStoreCopyProxies)(void *store) = NULL;
static CFDictionaryRef hook_SCDynamicStoreCopyProxies(void *store) {
    if (IsSystemNetworkingCaller(__builtin_return_address(0)) && orig_SCDynamicStoreCopyProxies) {
        return orig_SCDynamicStoreCopyProxies(store);
    }
    return CreateCleanProxyDict();
}

static NSDictionary *(*orig_connectionProxyDictionary)(id self, SEL _cmd) = NULL;
static NSDictionary *hook_connectionProxyDictionary(id self, SEL _cmd) {
    return @{};
}

// 5. 过滤 Shadowrocket 产生的 utun / ipsec / ppp 虚拟隧道网卡
static BOOL IsVirtualVPNInterface(const char *ifname) {
    if (!ifname) return NO;
    return (strncmp(ifname, "utun", 4) == 0 ||
            strncmp(ifname, "ipsec", 5) == 0 ||
            strncmp(ifname, "ppp", 3) == 0 ||
            strncmp(ifname, "tun", 3) == 0 ||
            strncmp(ifname, "wg", 2) == 0);
}

static int (*orig_getifaddrs)(struct ifaddrs **ifap) = NULL;
static int hook_getifaddrs(struct ifaddrs **ifap) {
    int ret = orig_getifaddrs ? orig_getifaddrs(ifap) : getifaddrs(ifap);
    if (ret == 0 && ifap && *ifap) {
        struct ifaddrs *head = *ifap;
        while (head && IsVirtualVPNInterface(head->ifa_name) && head->ifa_next != NULL) {
            struct ifaddrs *nextNode = head->ifa_next;
            memcpy(head, nextNode, sizeof(struct ifaddrs));
        }
        struct ifaddrs *curr = head;
        while (curr && curr->ifa_next != NULL) {
            if (IsVirtualVPNInterface(curr->ifa_next->ifa_name)) {
                curr->ifa_next = curr->ifa_next->ifa_next;
            } else {
                curr = curr->ifa_next;
            }
        }
    }
    return ret;
}

// 6. 屏蔽工具类 URL Scheme 暴露 (apple-magnifier://, sileo://, zbra:// 等)
static BOOL IsBlockedURLScheme(NSString *scheme) {
    if (scheme.length == 0) return NO;
    NSSet *blocked = [NSSet setWithArray:@[
        @"apple-magnifier", @"sileo", @"zbra", @"cydia",
        @"filza", @"santander", @"trollstore", @"dopamine", @"roothide",
        @"shadowrocket", @"quantumult", @"surge", @"loon", @"stash"
    ]];
    return [blocked containsObject:scheme.lowercaseString];
}

static BOOL (*orig_canOpenURL)(id self, SEL _cmd, NSURL *url) = NULL;
static BOOL hook_canOpenURL(id self, SEL _cmd, NSURL *url) {
    if (IsBlockedURLScheme(url.scheme)) return NO;
    return orig_canOpenURL ? orig_canOpenURL(self, _cmd, url) : NO;
}

static BOOL (*orig_privCanOpenURL)(id self, SEL _cmd, NSURL *url, BOOL publicOnly) = NULL;
static BOOL hook_privCanOpenURL(id self, SEL _cmd, NSURL *url, BOOL publicOnly) {
    if (IsBlockedURLScheme(url.scheme)) return NO;
    return orig_privCanOpenURL ? orig_privCanOpenURL(self, _cmd, url, publicOnly) : NO;
}

static NSArray *(*orig_appsForScheme)(id self, SEL _cmd, NSString *scheme) = NULL;
static NSArray *hook_appsForScheme(id self, SEL _cmd, NSString *scheme) {
    if (IsBlockedURLScheme(scheme)) return @[];
    return orig_appsForScheme ? orig_appsForScheme(self, _cmd, scheme) : @[];
}

static NSURL *(*orig_urlOverride)(id self, SEL _cmd, NSURL *url) = NULL;
static NSURL *hook_urlOverride(id self, SEL _cmd, NSURL *url) {
    if (IsBlockedURLScheme(url.scheme)) return nil;
    return orig_urlOverride ? orig_urlOverride(self, _cmd, url) : nil;
}

// 7. 彻底抹除软件模拟定位标记 (isSimulatedBySoftware = NO) 与锁定国际地图国家码
static BOOL hook_returnNO(id self, SEL _cmd) {
    return NO;
}

static id (*orig_initWithSimState)(id self, SEL _cmd, BOOL isSimulated, BOOL isAccessory) = NULL;
static id hook_initWithSimState(id self, SEL _cmd, BOOL isSimulated, BOOL isAccessory) {
    if (orig_initWithSimState) {
        return orig_initWithSimState(self, _cmd, NO, NO);
    }
    return self;
}

static id (*orig_sourceInformation)(id self, SEL _cmd) = NULL;
static id hook_sourceInformation(id self, SEL _cmd) {
    Class srcInfoCls = objc_getClass("CLLocationSourceInformation");
    if (srcInfoCls) {
        SEL initSel = NSSelectorFromString(@"initWithSoftwareSimulationState:externalAccessoryState:");
        id obj = [srcInfoCls alloc];
        if ([obj respondsToSelector:initSel]) {
            return ((id (*)(id, SEL, BOOL, BOOL))objc_msgSend)(obj, initSel, NO, NO);
        }
        return [obj init];
    }
    return orig_sourceInformation ? orig_sourceInformation(self, _cmd) : nil;
}

static NSString *hook_targetCountryCode(id self, SEL _cmd) {
    return GetTargetCountryCode();
}

// 8. 注入当前关联 US Wi-Fi（主热点 + 周边热点）
static NSArray<NSDictionary *> *GetMockWiFiList(void) {
    NSDictionary *wifiCfg = [NSDictionary dictionaryWithContentsOfFile:kWifiPrefPath];
    if ([wifiCfg[@"enabled"] boolValue]) {
        NSArray *nets = wifiCfg[@"networks"];
        if ([nets isKindOfClass:[NSArray class]] && nets.count > 0) {
            return nets;
        }
    }
    return nil;
}

static CFArrayRef (*orig_CNCopySupportedInterfaces)(void) = NULL;
static CFArrayRef hook_CNCopySupportedInterfaces(void) {
    if (GetMockWiFiList() != nil) {
        return (__bridge_retained CFArrayRef)@[@"en0"];
    }
    return orig_CNCopySupportedInterfaces ? orig_CNCopySupportedInterfaces() : (__bridge_retained CFArrayRef)@[@"en0"];
}

static CFDictionaryRef (*orig_CNCopyCurrentNetworkInfo)(CFStringRef interfaceName) = NULL;
static CFDictionaryRef hook_CNCopyCurrentNetworkInfo(CFStringRef interfaceName) {
    NSArray<NSDictionary *> *nets = GetMockWiFiList();
    if (nets.count > 0) {
        NSDictionary *topAP = nets[0];
        NSString *ssid = topAP[@"SSID"] ?: @"NETGEAR-5285";
        NSString *bssid = topAP[@"BSSID"] ?: @"44:E9:DD:41:C0:EE";
        NSMutableDictionary *result = [@{
            (__bridge NSString *)kCNNetworkInfoKeySSID: ssid,
            (__bridge NSString *)kCNNetworkInfoKeyBSSID: bssid,
            (__bridge NSString *)kCNNetworkInfoKeySSIDData: [ssid dataUsingEncoding:NSUTF8StringEncoding]
        } mutableCopy];
        if (nets.count > 1) {
            result[@"NearbyAP1"] = [NSString stringWithFormat:@"%@ (%@)", nets[1][@"SSID"] ?: @"", nets[1][@"BSSID"] ?: @""];
        }
        if (nets.count > 2) {
            result[@"NearbyAP2"] = [NSString stringWithFormat:@"%@ (%@)", nets[2][@"SSID"] ?: @"", nets[2][@"BSSID"] ?: @""];
        }
        return (__bridge_retained CFDictionaryRef)result;
    }
    return orig_CNCopyCurrentNetworkInfo ? orig_CNCopyCurrentNetworkInfo(interfaceName) : NULL;
}

static void ApplyAllCRebindings(void) {
    struct rebinding_entry entries[] = {
        {"_dyld_get_image_name", (void *)hook_dyld_get_image_name, (void **)&orig_dyld_get_image_name},
        {"dladdr", (void *)hook_dladdr, (void **)&orig_dladdr},
        {"CFTimeZoneCopySystem", (void *)hook_CFTimeZoneCopySystem, (void **)&orig_CFTimeZoneCopySystem},
        {"CFNetworkCopySystemProxySettings", (void *)hook_CFNetworkCopySystemProxySettings, (void **)&orig_CFNetworkCopySystemProxySettings},
        {"SCDynamicStoreCopyProxies", (void *)hook_SCDynamicStoreCopyProxies, (void **)&orig_SCDynamicStoreCopyProxies},
        {"getifaddrs", (void *)hook_getifaddrs, (void **)&orig_getifaddrs},
        {"CNCopyCurrentNetworkInfo", (void *)hook_CNCopyCurrentNetworkInfo, (void **)&orig_CNCopyCurrentNetworkInfo},
        {"CNCopySupportedInterfaces", (void *)hook_CNCopySupportedInterfaces, (void **)&orig_CNCopySupportedInterfaces}
    };
    size_t n = sizeof(entries) / sizeof(entries[0]);
    uint32_t imgCount = _dyld_image_count();
    for (uint32_t i = 0; i < imgCount; i++) {
        const char *imgName = _dyld_get_image_name(i);
        if (!imgName) continue;
        if (strstr(imgName, ".app/") != NULL || strstr(imgName, "CFNetwork") != NULL || strstr(imgName, "CoreLocation") != NULL) {
            rebind_symbols_for_image(_dyld_get_image_header(i), _dyld_get_image_vmaddr_slide(i), entries, n);
        }
    }

    if (g_MSHookFunction) {
        g_MSHookFunction((void *)_dyld_get_image_name, (void *)hook_dyld_get_image_name, (void **)&orig_dyld_get_image_name);
        g_MSHookFunction((void *)dladdr, (void *)hook_dladdr, (void **)&orig_dladdr);
        void *symCFTimeZone = dlsym(RTLD_DEFAULT, "CFTimeZoneCopySystem");
        if (symCFTimeZone) g_MSHookFunction(symCFTimeZone, (void *)hook_CFTimeZoneCopySystem, (void **)&orig_CFTimeZoneCopySystem);
        g_MSHookFunction((void *)CFNetworkCopySystemProxySettings, (void *)hook_CFNetworkCopySystemProxySettings, (void **)&orig_CFNetworkCopySystemProxySettings);
        void *symSCDyn = dlsym(RTLD_DEFAULT, "SCDynamicStoreCopyProxies");
        if (symSCDyn) g_MSHookFunction(symSCDyn, (void *)hook_SCDynamicStoreCopyProxies, (void **)&orig_SCDynamicStoreCopyProxies);
        g_MSHookFunction((void *)getifaddrs, (void *)hook_getifaddrs, (void **)&orig_getifaddrs);
        g_MSHookFunction((void *)CNCopyCurrentNetworkInfo, (void *)hook_CNCopyCurrentNetworkInfo, (void **)&orig_CNCopyCurrentNetworkInfo);
        g_MSHookFunction((void *)CNCopySupportedInterfaces, (void *)hook_CNCopySupportedInterfaces, (void **)&orig_CNCopySupportedInterfaces);
    }
}

__attribute__((constructor))
static void AutoIPLocHookEntry(void) {
    @autoreleasepool {
        const char *prog = getprogname();
        if (!prog) return;
        if (strcmp(prog, "SpringBoard") == 0 ||
            strcmp(prog, "backboardd") == 0 ||
            strcmp(prog, "Preferences") == 0 ||
            strcmp(prog, "AutoIPLoc") == 0 ||
            strcmp(prog, "Shadowrocket") == 0 ||
            strcmp(prog, "Dopamine") == 0 ||
            strcmp(prog, "Sileo") == 0 ||
            strcmp(prog, "TrollStore") == 0 ||
            strcmp(prog, "Filza") == 0) {
            return;
        }

        char execBuf[1024] = {0};
        uint32_t execSize = sizeof(execBuf);
        if (_NSGetExecutablePath(execBuf, &execSize) != 0) return;
        if (strstr(execBuf, ".app/") == NULL) return;

        dlopen("/System/Library/Frameworks/CoreLocation.framework/CoreLocation", RTLD_NOW);
        dlopen("/System/Library/Frameworks/CoreTelephony.framework/CoreTelephony", RTLD_NOW);
        dlopen("/System/Library/PrivateFrameworks/GeoServices.framework/GeoServices", RTLD_NOW);
        ResolveElleKitFromSelfPath((void *)&AutoIPLocHookEntry);

        NSString *initTZ = GetTargetTimeZoneName();
        if (initTZ) {
            setenv("TZ", initTZ.UTF8String, 1);
            tzset();
            [NSTimeZone resetSystemTimeZone];
        }
        Class tzMeta = objc_getMetaClass("NSTimeZone");
        if (tzMeta) {
            HookObjCMethod(tzMeta, @selector(systemTimeZone), (IMP)hook_systemTimeZone, (IMP *)&orig_systemTimeZone);
            HookObjCMethod(tzMeta, @selector(defaultTimeZone), (IMP)hook_defaultTimeZone, (IMP *)&orig_defaultTimeZone);
            HookObjCMethod(tzMeta, @selector(localTimeZone), (IMP)hook_localTimeZone, (IMP *)&orig_localTimeZone);
        }

        Class appCls = objc_getClass("UIApplication");
        if (appCls) {
            HookObjCMethod(appCls, @selector(canOpenURL:), (IMP)hook_canOpenURL, (IMP *)&orig_canOpenURL);
            HookObjCMethod(appCls, NSSelectorFromString(@"_canOpenURL:publicURLsOnly:"), (IMP)hook_privCanOpenURL, (IMP *)&orig_privCanOpenURL);
        }
        Class wsCls = objc_getClass("LSApplicationWorkspace");
        if (wsCls) {
            HookObjCMethod(wsCls, NSSelectorFromString(@"applicationsAvailableForHandlingURLScheme:"), (IMP)hook_appsForScheme, (IMP *)&orig_appsForScheme);
            HookObjCMethod(wsCls, NSSelectorFromString(@"URLOverrideForURL:"), (IMP)hook_urlOverride, (IMP *)&orig_urlOverride);
        }

        Class sessionCfgCls = objc_getClass("NSURLSessionConfiguration");
        if (sessionCfgCls) {
            HookObjCMethod(sessionCfgCls, @selector(connectionProxyDictionary), (IMP)hook_connectionProxyDictionary, (IMP *)&orig_connectionProxyDictionary);
        }

        Class carrierCls = objc_getClass("CTCarrier");
        if (carrierCls) {
            HookObjCMethod(carrierCls, NSSelectorFromString(@"carrierName"), (IMP)hook_carrierName, (IMP *)&orig_carrierName);
            HookObjCMethod(carrierCls, NSSelectorFromString(@"mobileCountryCode"), (IMP)hook_mobileCountryCode, (IMP *)&orig_mobileCountryCode);
            HookObjCMethod(carrierCls, NSSelectorFromString(@"mobileNetworkCode"), (IMP)hook_mobileNetworkCode, (IMP *)&orig_mobileNetworkCode);
            HookObjCMethod(carrierCls, NSSelectorFromString(@"isoCountryCode"), (IMP)hook_isoCountryCode, (IMP *)&orig_isoCountryCode);
            HookObjCMethod(carrierCls, NSSelectorFromString(@"allowsVOIP"), (IMP)hook_returnYES, NULL);
        }
        Class netInfoCls = objc_getClass("CTTelephonyNetworkInfo");
        if (netInfoCls) {
            HookObjCMethod(netInfoCls, NSSelectorFromString(@"serviceCurrentRadioAccessTechnology"), (IMP)hook_serviceRadioTech, (IMP *)&orig_serviceRadioTech);
            HookObjCMethod(netInfoCls, NSSelectorFromString(@"currentRadioAccessTechnology"), (IMP)hook_currentRadioTech, (IMP *)&orig_currentRadioTech);
        }

        Class srcInfoCls = objc_getClass("CLLocationSourceInformation");
        if (srcInfoCls) {
            HookObjCMethod(srcInfoCls, NSSelectorFromString(@"isSimulatedBySoftware"), (IMP)hook_returnNO, NULL);
            HookObjCMethod(srcInfoCls, NSSelectorFromString(@"isProducedByAccessory"), (IMP)hook_returnNO, NULL);
            HookObjCMethod(srcInfoCls, NSSelectorFromString(@"initWithSoftwareSimulationState:externalAccessoryState:"), (IMP)hook_initWithSimState, (IMP *)&orig_initWithSimState);
        }
        Class locCls = objc_getClass("CLLocation");
        if (locCls) {
            HookObjCMethod(locCls, NSSelectorFromString(@"isSimulatedBySoftware"), (IMP)hook_returnNO, NULL);
            HookObjCMethod(locCls, NSSelectorFromString(@"_isSimulated"), (IMP)hook_returnNO, NULL);
            HookObjCMethod(locCls, NSSelectorFromString(@"sourceInformation"), (IMP)hook_sourceInformation, (IMP *)&orig_sourceInformation);
        }

        Class geoCls = objc_getClass("GEOCountryConfiguration");
        if (geoCls) {
            NSArray *sels = @[@"countryCode", @"_countryCode", @"currentCountryCode", @"sourceCountryCode"];
            for (NSString *selName in sels) {
                HookObjCMethod(geoCls, NSSelectorFromString(selName), (IMP)hook_targetCountryCode, NULL);
            }
        }
        Class platformCls = objc_getClass("GEOPlatform");
        if (platformCls) {
            HookObjCMethod(platformCls, NSSelectorFromString(@"isChina"), (IMP)hook_returnNO, NULL);
        }

        ApplyAllCRebindings();
    }
}
