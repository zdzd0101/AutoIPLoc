#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <CoreLocation/CoreLocation.h>
#import <CoreTelephony/CTCarrier.h>
#import <CoreTelephony/CTTelephonyNetworkInfo.h>
#import <SystemConfiguration/CaptiveNetwork.h>
#import <CFNetwork/CFNetwork.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <ifaddrs.h>
#import <dlfcn.h>
#import <sys/stat.h>
#import <unistd.h>
#import <errno.h>
#import <string.h>

#if __has_include(<ptrauth.h>)
#include <ptrauth.h>
#endif

typedef void (*MSHookFunction_t)(void *symbol, void *replace, void **result);

static NSString *const kGeoPrefPath = @"/var/mobile/Library/Preferences/com.autoiploc.geo.plist";
static NSString *const kWifiPrefPath = @"/var/mobile/Library/Preferences/com.autoiploc.wifi.plist";

// 零外部依赖：直接从进程已加载的 ElleKit/TweakInject 句柄动态获取 PAC 安全的 MSHookFunction
static MSHookFunction_t ResolvePACSafeHookFunction(void) {
    void *sym = dlsym(RTLD_DEFAULT, "MSHookFunction");
    if (sym) return (MSHookFunction_t)sym;

    uint32_t imgCount = _dyld_image_count();
    for (uint32_t i = 1; i < imgCount; i++) {
        const char *imgPath = _dyld_get_image_name(i);
        if (!imgPath || strstr(imgPath, "AutoIPLocHook") != NULL) continue;

        if (strstr(imgPath, "ellekit") != NULL ||
            strstr(imgPath, "TweakInject") != NULL ||
            strstr(imgPath, "Substrate") != NULL ||
            strstr(imgPath, "jbroot") != NULL) {
            void *handle = dlopen(imgPath, RTLD_NOLOAD | RTLD_NOW);
            if (handle) {
                sym = dlsym(handle, "MSHookFunction");
                if (sym) return (MSHookFunction_t)sym;
            }
        }
    }

    // 兜底：直接解析内存镜像 Mach-O 符号表并签署 arm64e PAC 指针
    for (uint32_t i = 1; i < imgCount; i++) {
        const char *imgPath = _dyld_get_image_name(i);
        if (!imgPath || strstr(imgPath, "AutoIPLocHook") != NULL) continue;

        const struct mach_header_64 *hdr = (const struct mach_header_64 *)_dyld_get_image_header(i);
        if (!hdr || hdr->magic != MH_MAGIC_64) continue;
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);

        struct segment_command_64 *linkedit = NULL;
        struct symtab_command *symtab_cmd = NULL;
        uintptr_t cur = (uintptr_t)hdr + sizeof(struct mach_header_64);
        for (uint32_t j = 0; j < hdr->ncmds; j++) {
            struct load_command *lc = (struct load_command *)cur;
            if (lc->cmd == LC_SEGMENT_64) {
                struct segment_command_64 *seg = (struct segment_command_64 *)lc;
                if (strcmp(seg->segname, "__LINKEDIT") == 0) linkedit = seg;
            } else if (lc->cmd == LC_SYMTAB) {
                symtab_cmd = (struct symtab_command *)lc;
            }
            cur += lc->cmdsize;
        }

        if (!linkedit || !symtab_cmd) continue;
        uintptr_t linkedit_base = (uintptr_t)slide + linkedit->vmaddr - linkedit->fileoff;
        struct nlist_64 *syms = (struct nlist_64 *)(linkedit_base + symtab_cmd->symoff);
        char *strs = (char *)(linkedit_base + symtab_cmd->stroff);

        for (uint32_t k = 0; k < symtab_cmd->nsyms; k++) {
            if ((syms[k].n_type & N_TYPE) != N_SECT || syms[k].n_value == 0) continue;
            const char *sname = strs + syms[k].n_un.n_strx;
            if (strcmp(sname, "_MSHookFunction") == 0) {
                void *fnPtr = (void *)((uintptr_t)slide + syms[k].n_value);
#ifdef __arm64e__
                fnPtr = ptrauth_sign_unauthenticated(fnPtr, ptrauth_key_function_pointer, 0);
#endif
                return (MSHookFunction_t)fnPtr;
            }
        }
    }
    return NULL;
}

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

// 1. 隐藏所有插件与 RootHide 底座动态库特征（消除 [功能插件注入] 与 [RootHide底座]）
static BOOL IsSensitiveDylibPath(const char *path) {
    if (!path) return NO;
    return (strstr(path, "AutoIPLocHook") != NULL ||
            strstr(path, "ellekit") != NULL ||
            strstr(path, "TweakInject") != NULL ||
            strstr(path, "MobileSubstrate") != NULL ||
            strstr(path, "roothide") != NULL ||
            strstr(path, "jbroot") != NULL ||
            strstr(path, "/var/jb") != NULL ||
            strstr(path, "Crane") != NULL ||
            strstr(path, "AntiLocDetect") != NULL ||
            strstr(path, "Choicy") != NULL ||
            strstr(path, "amg") != NULL);
}

static const char *(*orig_dyld_get_image_name)(uint32_t image_index);
static const char *hook_dyld_get_image_name(uint32_t image_index) {
    const char *name = orig_dyld_get_image_name ? orig_dyld_get_image_name(image_index) : NULL;
    if (IsSensitiveDylibPath(name)) {
        return "/usr/lib/libobjc.A.dylib";
    }
    return name;
}

static int (*orig_dladdr)(const void *addr, Dl_info *info);
static int hook_dladdr(const void *addr, Dl_info *info) {
    int res = orig_dladdr ? orig_dladdr(addr, info) : 0;
    if (res != 0 && info && IsSensitiveDylibPath(info->dli_fname)) {
        info->dli_fname = "/usr/lib/libobjc.A.dylib";
        info->dli_sname = "objc_msgSend";
    }
    return res;
}

// 2. 屏蔽越狱与插件目录路径探测
static BOOL IsRestrictedJailbreakPath(const char *path) {
    if (!path) return NO;
    if (strstr(path, "com.autoiploc") != NULL) return NO;
    return (strstr(path, "/var/jb") != NULL ||
            strstr(path, "jbroot") != NULL ||
            strstr(path, "roothide") != NULL ||
            strstr(path, "ellekit") != NULL ||
            strstr(path, "MobileSubstrate") != NULL ||
            strstr(path, "/Applications/Sileo.app") != NULL ||
            strstr(path, "/Applications/TrollStore.app") != NULL ||
            strstr(path, "/Applications/Filza.app") != NULL ||
            strstr(path, "/Applications/Dopamine.app") != NULL);
}

static int (*orig_access)(const char *path, int amode);
static int hook_access(const char *path, int amode) {
    if (IsRestrictedJailbreakPath(path)) {
        errno = ENOENT;
        return -1;
    }
    return orig_access ? orig_access(path, amode) : -1;
}

static int (*orig_stat)(const char *path, struct stat *buf);
static int hook_stat(const char *path, struct stat *buf) {
    if (IsRestrictedJailbreakPath(path)) {
        errno = ENOENT;
        return -1;
    }
    return orig_stat ? orig_stat(path, buf) : -1;
}

static int (*orig_lstat)(const char *path, struct stat *buf);
static int hook_lstat(const char *path, struct stat *buf) {
    if (IsRestrictedJailbreakPath(path)) {
        errno = ENOENT;
        return -1;
    }
    return orig_lstat ? orig_lstat(path, buf) : -1;
}

// 3. 接管 NSTimeZone 与 CFTimeZone
static NSTimeZone *(*orig_systemTimeZone)(id self, SEL _cmd);
static NSTimeZone *hook_systemTimeZone(id self, SEL _cmd) {
    NSString *tzName = GetTargetTimeZoneName();
    if (tzName) {
        NSTimeZone *tz = [NSTimeZone timeZoneWithName:tzName];
        if (tz) return tz;
    }
    return orig_systemTimeZone ? orig_systemTimeZone(self, _cmd) : [NSTimeZone timeZoneWithName:@"America/New_York"];
}

static NSTimeZone *(*orig_defaultTimeZone)(id self, SEL _cmd);
static NSTimeZone *hook_defaultTimeZone(id self, SEL _cmd) {
    NSString *tzName = GetTargetTimeZoneName();
    if (tzName) {
        NSTimeZone *tz = [NSTimeZone timeZoneWithName:tzName];
        if (tz) return tz;
    }
    return orig_defaultTimeZone ? orig_defaultTimeZone(self, _cmd) : [NSTimeZone timeZoneWithName:@"America/New_York"];
}

static NSTimeZone *(*orig_localTimeZone)(id self, SEL _cmd);
static NSTimeZone *hook_localTimeZone(id self, SEL _cmd) {
    NSString *tzName = GetTargetTimeZoneName();
    if (tzName) {
        NSTimeZone *tz = [NSTimeZone timeZoneWithName:tzName];
        if (tz) return tz;
    }
    return orig_localTimeZone ? orig_localTimeZone(self, _cmd) : [NSTimeZone timeZoneWithName:@"America/New_York"];
}

static CFTimeZoneRef (*orig_CFTimeZoneCopySystem)(void);
static CFTimeZoneRef hook_CFTimeZoneCopySystem(void) {
    NSString *tzName = GetTargetTimeZoneName();
    if (tzName) {
        CFTimeZoneRef tz = CFTimeZoneCreateWithName(kCFAllocatorDefault, (__bridge CFStringRef)tzName, true);
        if (tz) return tz;
    }
    return orig_CFTimeZoneCopySystem ? orig_CFTimeZoneCopySystem() : CFTimeZoneCopySystem();
}

// 4. 补全基带与蜂窝网络特征（飞行模式下依然保持 T-Mobile 310/260 LTE 参数，消除 [基带特征] 告警）
static NSString *(*orig_carrierName)(id self, SEL _cmd);
static NSString *hook_carrierName(id self, SEL _cmd) {
    NSString *orig = orig_carrierName ? orig_carrierName(self, _cmd) : nil;
    if (orig.length == 0 || [orig isEqualToString:@"--"] || [orig isEqualToString:@"Carrier"]) {
        return @"T-Mobile";
    }
    return orig;
}

static NSString *(*orig_mobileCountryCode)(id self, SEL _cmd);
static NSString *hook_mobileCountryCode(id self, SEL _cmd) {
    NSString *orig = orig_mobileCountryCode ? orig_mobileCountryCode(self, _cmd) : nil;
    if (orig.length == 0 || [orig isEqualToString:@"460"] || [orig isEqualToString:@"454"] || [orig isEqualToString:@"455"]) {
        return @"310";
    }
    return orig;
}

static NSString *(*orig_mobileNetworkCode)(id self, SEL _cmd);
static NSString *hook_mobileNetworkCode(id self, SEL _cmd) {
    NSString *orig = orig_mobileNetworkCode ? orig_mobileNetworkCode(self, _cmd) : nil;
    if (orig.length == 0 || [orig isEqualToString:@"65535"]) {
        return @"260";
    }
    return orig;
}

static NSString *(*orig_isoCountryCode)(id self, SEL _cmd);
static NSString *hook_isoCountryCode(id self, SEL _cmd) {
    NSString *orig = orig_isoCountryCode ? orig_isoCountryCode(self, _cmd) : nil;
    if (orig.length == 0 || [orig.lowercaseString isEqualToString:@"cn"] || [orig.lowercaseString isEqualToString:@"hk"] || [orig.lowercaseString isEqualToString:@"mo"]) {
        return GetTargetCountryCode().lowercaseString;
    }
    return orig;
}

static NSDictionary<NSString *, NSString *> *(*orig_serviceRadioTech)(id self, SEL _cmd);
static NSDictionary<NSString *, NSString *> *hook_serviceRadioTech(id self, SEL _cmd) {
    NSDictionary<NSString *, NSString *> *orig = orig_serviceRadioTech ? orig_serviceRadioTech(self, _cmd) : nil;
    if (orig.count > 0) return orig;
    return @{
        @"0000000100000001": @"CTRadioAccessTechnologyLTE",
        @"0000000100000002": @"CTRadioAccessTechnologyLTE"
    };
}

static NSString *(*orig_currentRadioTech)(id self, SEL _cmd);
static NSString *hook_currentRadioTech(id self, SEL _cmd) {
    NSString *orig = orig_currentRadioTech ? orig_currentRadioTech(self, _cmd) : nil;
    if (orig.length > 0) return orig;
    return @"CTRadioAccessTechnologyLTE";
}

// 5. 隐藏系统 HTTP/HTTPS/SOCKS5/PAC 显式代理（消除 [系统代理] 告警）
static BOOL IsSystemNetworkingCaller(void *retAddr) {
    if (!retAddr) return NO;
    Dl_info info;
    if (orig_dladdr && orig_dladdr(retAddr, &info) != 0 && info.dli_fname != NULL) {
        if (strstr(info.dli_fname, "CFNetwork") != NULL ||
            strstr(info.dli_fname, "WebKit") != NULL ||
            strstr(info.dli_fname, "libnetwork") != NULL ||
            strstr(info.dli_fname, "Network.framework") != NULL) {
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

static CFDictionaryRef (*orig_CFNetworkCopySystemProxySettings)(void);
static CFDictionaryRef hook_CFNetworkCopySystemProxySettings(void) {
    if (IsSystemNetworkingCaller(__builtin_return_address(0)) && orig_CFNetworkCopySystemProxySettings) {
        return orig_CFNetworkCopySystemProxySettings();
    }
    return CreateCleanProxyDict();
}

static CFDictionaryRef (*orig_SCDynamicStoreCopyProxies)(void *store);
static CFDictionaryRef hook_SCDynamicStoreCopyProxies(void *store) {
    if (IsSystemNetworkingCaller(__builtin_return_address(0)) && orig_SCDynamicStoreCopyProxies) {
        return orig_SCDynamicStoreCopyProxies(store);
    }
    return CreateCleanProxyDict();
}

static NSDictionary *(*orig_connectionProxyDictionary)(id self, SEL _cmd);
static NSDictionary *hook_connectionProxyDictionary(id self, SEL _cmd) {
    return @{};
}

// 6. 过滤 Shadowrocket 产生的 utun / ipsec / ppp 虚拟隧道网卡（消除 [VPN网卡] 告警）
static BOOL IsVirtualVPNInterface(const char *ifname) {
    if (!ifname) return NO;
    return (strncmp(ifname, "utun", 4) == 0 ||
            strncmp(ifname, "ipsec", 5) == 0 ||
            strncmp(ifname, "ppp", 3) == 0);
}

static int (*orig_getifaddrs)(struct ifaddrs **ifap);
static int hook_getifaddrs(struct ifaddrs **ifap) {
    int ret = orig_getifaddrs ? orig_getifaddrs(ifap) : -1;
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

// 7. 彻底屏蔽 URL Scheme 暴露 (apple-magnifier://, sileo://, zbra:// 等)
static BOOL IsBlockedURLScheme(NSString *scheme) {
    if (scheme.length == 0) return NO;
    NSSet *blocked = [NSSet setWithArray:@[
        @"apple-magnifier", @"sileo", @"zbra", @"cydia",
        @"filza", @"santander", @"trollstore", @"dopamine", @"roothide",
        @"shadowrocket", @"quantumult", @"surge", @"loon", @"stash"
    ]];
    return [blocked containsObject:scheme.lowercaseString];
}

static BOOL (*orig_canOpenURL)(id self, SEL _cmd, NSURL *url);
static BOOL hook_canOpenURL(id self, SEL _cmd, NSURL *url) {
    if (IsBlockedURLScheme(url.scheme)) return NO;
    return orig_canOpenURL ? orig_canOpenURL(self, _cmd, url) : NO;
}

static BOOL (*orig_privCanOpenURL)(id self, SEL _cmd, NSURL *url, BOOL publicOnly);
static BOOL hook_privCanOpenURL(id self, SEL _cmd, NSURL *url, BOOL publicOnly) {
    if (IsBlockedURLScheme(url.scheme)) return NO;
    return orig_privCanOpenURL ? orig_privCanOpenURL(self, _cmd, url, publicOnly) : NO;
}

static NSArray *(*orig_appsForScheme)(id self, SEL _cmd, NSString *scheme);
static NSArray *hook_appsForScheme(id self, SEL _cmd, NSString *scheme) {
    if (IsBlockedURLScheme(scheme)) return @[];
    return orig_appsForScheme ? orig_appsForScheme(self, _cmd, scheme) : @[];
}

static NSURL *(*orig_urlOverride)(id self, SEL _cmd, NSURL *url);
static NSURL *hook_urlOverride(id self, SEL _cmd, NSURL *url) {
    if (IsBlockedURLScheme(url.scheme)) return nil;
    return orig_urlOverride ? orig_urlOverride(self, _cmd, url) : nil;
}

// 8. 抹除软件模拟定位标记与强制国际版地图国家码
static BOOL hook_returnNO(id self, SEL _cmd) {
    return NO;
}

static NSString *hook_targetCountryCode(id self, SEL _cmd) {
    return GetTargetCountryCode();
}

// 9. 将 IP 周边模拟 US Wi-Fi（主热点 + 周边 1～2 个邻近热点）写入系统网络信息接口
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

static CFArrayRef (*orig_CNCopySupportedInterfaces)(void);
static CFArrayRef hook_CNCopySupportedInterfaces(void) {
    if (GetMockWiFiList() != nil) {
        return (__bridge_retained CFArrayRef)@[@"en0"];
    }
    return orig_CNCopySupportedInterfaces ? orig_CNCopySupportedInterfaces() : (__bridge_retained CFArrayRef)@[@"en0"];
}

static CFDictionaryRef (*orig_CNCopyCurrentNetworkInfo)(CFStringRef interfaceName);
static CFDictionaryRef hook_CNCopyCurrentNetworkInfo(CFStringRef interfaceName) {
    NSArray<NSDictionary *> *nets = GetMockWiFiList();
    if (nets.count > 0) {
        NSDictionary *topAP = nets[0];
        NSString *ssid = topAP[@"SSID"] ?: @"GoogleFiber-DFF8";
        NSString *bssid = topAP[@"BSSID"] ?: @"20:4E:7F:90:C0:27";
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

__attribute__((constructor))
static void AutoIPLocHookEntry(void) {
    @autoreleasepool {
        // 保护自身主程序、Shadowrocket 与桌面核心进程不被钩子干扰
        NSString *bid = [[NSBundle mainBundle] bundleIdentifier];
        if ([bid isEqualToString:@"com.local.autoiploc"] ||
            [bid isEqualToString:@"com.liguangming.Shadowrocket"] ||
            [bid isEqualToString:@"com.apple.springboard"] ||
            [bid hasPrefix:@"com.opa334."]) {
            return;
        }

        // A. 同步全局时区
        NSString *initTZ = GetTargetTimeZoneName();
        if (initTZ) {
            setenv("TZ", initTZ.UTF8String, 1);
            tzset();
            [NSTimeZone resetSystemTimeZone];
        }
        Class tzMeta = objc_getMetaClass("NSTimeZone");
        if (tzMeta) {
            Method mSys = class_getInstanceMethod(tzMeta, @selector(systemTimeZone));
            if (mSys) {
                orig_systemTimeZone = (void *)method_getImplementation(mSys);
                method_setImplementation(mSys, (IMP)hook_systemTimeZone);
            }
            Method mDef = class_getInstanceMethod(tzMeta, @selector(defaultTimeZone));
            if (mDef) {
                orig_defaultTimeZone = (void *)method_getImplementation(mDef);
                method_setImplementation(mDef, (IMP)hook_defaultTimeZone);
            }
            Method mLoc = class_getInstanceMethod(tzMeta, @selector(localTimeZone));
            if (mLoc) {
                orig_localTimeZone = (void *)method_getImplementation(mLoc);
                method_setImplementation(mLoc, (IMP)hook_localTimeZone);
            }
        }

        // B. 拦截 URL Scheme 暴露
        Class appCls = objc_getClass("UIApplication");
        if (appCls) {
            Method mOpen = class_getInstanceMethod(appCls, @selector(canOpenURL:));
            if (mOpen) {
                orig_canOpenURL = (void *)method_getImplementation(mOpen);
                method_setImplementation(mOpen, (IMP)hook_canOpenURL);
            }
            Method mPrivOpen = class_getInstanceMethod(appCls, NSSelectorFromString(@"_canOpenURL:publicURLsOnly:"));
            if (mPrivOpen) {
                orig_privCanOpenURL = (void *)method_getImplementation(mPrivOpen);
                method_setImplementation(mPrivOpen, (IMP)hook_privCanOpenURL);
            }
        }
        Class wsCls = objc_getClass("LSApplicationWorkspace");
        if (wsCls) {
            Method mWs = class_getInstanceMethod(wsCls, NSSelectorFromString(@"applicationsAvailableForHandlingURLScheme:"));
            if (mWs) {
                orig_appsForScheme = (void *)method_getImplementation(mWs);
                method_setImplementation(mWs, (IMP)hook_appsForScheme);
            }
            Method mOverride = class_getInstanceMethod(wsCls, NSSelectorFromString(@"URLOverrideForURL:"));
            if (mOverride) {
                orig_urlOverride = (void *)method_getImplementation(mOverride);
                method_setImplementation(mOverride, (IMP)hook_urlOverride);
            }
        }

        // C. 隐藏 NSURLSessionConfiguration 代理字典
        Class sessionCfgCls = objc_getClass("NSURLSessionConfiguration");
        if (sessionCfgCls) {
            Method mProxyDict = class_getInstanceMethod(sessionCfgCls, @selector(connectionProxyDictionary));
            if (mProxyDict) {
                orig_connectionProxyDictionary = (void *)method_getImplementation(mProxyDict);
                method_setImplementation(mProxyDict, (IMP)hook_connectionProxyDictionary);
            }
        }

        // D. 补全基带与蜂窝运营商参数（飞行模式下依然保持美国 LTE 基带特征）
        Class carrierCls = objc_getClass("CTCarrier");
        if (carrierCls) {
            Method mName = class_getInstanceMethod(carrierCls, NSSelectorFromString(@"carrierName"));
            if (mName) {
                orig_carrierName = (void *)method_getImplementation(mName);
                method_setImplementation(mName, (IMP)hook_carrierName);
            }
            Method mMCC = class_getInstanceMethod(carrierCls, NSSelectorFromString(@"mobileCountryCode"));
            if (mMCC) {
                orig_mobileCountryCode = (void *)method_getImplementation(mMCC);
                method_setImplementation(mMCC, (IMP)hook_mobileCountryCode);
            }
            Method mMNC = class_getInstanceMethod(carrierCls, NSSelectorFromString(@"mobileNetworkCode"));
            if (mMNC) {
                orig_mobileNetworkCode = (void *)method_getImplementation(mMNC);
                method_setImplementation(mMNC, (IMP)hook_mobileNetworkCode);
            }
            Method mISO = class_getInstanceMethod(carrierCls, NSSelectorFromString(@"isoCountryCode"));
            if (mISO) {
                orig_isoCountryCode = (void *)method_getImplementation(mISO);
                method_setImplementation(mISO, (IMP)hook_isoCountryCode);
            }
        }
        Class netInfoCls = objc_getClass("CTTelephonyNetworkInfo");
        if (netInfoCls) {
            Method mSvcRadio = class_getInstanceMethod(netInfoCls, NSSelectorFromString(@"serviceCurrentRadioAccessTechnology"));
            if (mSvcRadio) {
                orig_serviceRadioTech = (void *)method_getImplementation(mSvcRadio);
                method_setImplementation(mSvcRadio, (IMP)hook_serviceRadioTech);
            }
            Method mCurRadio = class_getInstanceMethod(netInfoCls, NSSelectorFromString(@"currentRadioAccessTechnology"));
            if (mCurRadio) {
                orig_currentRadioTech = (void *)method_getImplementation(mCurRadio);
                method_setImplementation(mCurRadio, (IMP)hook_currentRadioTech);
            }
        }

        // E. 抹除模拟定位标记 (isSimulatedBySoftware = NO)
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

            Method mSrcInfo = class_getInstanceMethod(locCls, NSSelectorFromString(@"sourceInformation"));
            if (mSrcInfo && srcInfoCls) {
                IMP cleanSrcIMP = imp_implementationWithBlock(^id(id _self) {
                    return [[srcInfoCls alloc] init];
                });
                method_setImplementation(mSrcInfo, cleanSrcIMP);
            }
        }

        // F. 锁定国际地图国家码，阻断高德切换
        Class geoCls = objc_getClass("GEOCountryConfiguration");
        if (geoCls) {
            NSArray *sels = @[@"countryCode", @"_countryCode", @"currentCountryCode", @"sourceCountryCode"];
            for (NSString *selName in sels) {
                Method m = class_getInstanceMethod(geoCls, NSSelectorFromString(selName));
                if (m) method_setImplementation(m, (IMP)hook_targetCountryCode);
            }
        }
        Class platformCls = objc_getClass("GEOPlatform");
        if (platformCls) {
            Method mChina = class_getInstanceMethod(platformCls, NSSelectorFromString(@"isChina"));
            if (mChina) method_setImplementation(mChina, (IMP)hook_returnNO);
        }

        // G. 运行时动态提取 ElleKit MSHookFunction 接管底层 C 函数
        MSHookFunction_t hookFn = ResolvePACSafeHookFunction();
        if (hookFn) {
            hookFn((void *)_dyld_get_image_name, (void *)hook_dyld_get_image_name, (void **)&orig_dyld_get_image_name);
            hookFn((void *)dladdr, (void *)hook_dladdr, (void **)&orig_dladdr);
            hookFn((void *)access, (void *)hook_access, (void **)&orig_access);
            hookFn((void *)stat, (void *)hook_stat, (void **)&orig_stat);
            hookFn((void *)lstat, (void *)hook_lstat, (void **)&orig_lstat);

            void *symCFTimeZone = dlsym(RTLD_DEFAULT, "CFTimeZoneCopySystem");
            if (symCFTimeZone) hookFn(symCFTimeZone, (void *)hook_CFTimeZoneCopySystem, (void **)&orig_CFTimeZoneCopySystem);

            hookFn((void *)CFNetworkCopySystemProxySettings, (void *)hook_CFNetworkCopySystemProxySettings, (void **)&orig_CFNetworkCopySystemProxySettings);

            void *symSCDyn = dlsym(RTLD_DEFAULT, "SCDynamicStoreCopyProxies");
            if (symSCDyn) hookFn(symSCDyn, (void *)hook_SCDynamicStoreCopyProxies, (void **)&orig_SCDynamicStoreCopyProxies);

            hookFn((void *)getifaddrs, (void *)hook_getifaddrs, (void **)&orig_getifaddrs);
            hookFn((void *)CNCopyCurrentNetworkInfo, (void *)hook_CNCopyCurrentNetworkInfo, (void **)&orig_CNCopyCurrentNetworkInfo);
            hookFn((void *)CNCopySupportedInterfaces, (void *)hook_CNCopySupportedInterfaces, (void **)&orig_CNCopySupportedInterfaces);
        }
    }
}
