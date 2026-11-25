#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <CoreLocation/CoreLocation.h>
#import <CoreTelephony/CTCarrier.h>
#import <CoreTelephony/CTTelephonyNetworkInfo.h>
#import <SystemConfiguration/CaptiveNetwork.h>
#import <CFNetwork/CFNetwork.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <ifaddrs.h>
#import <dlfcn.h>
#import <stdlib.h>
#import <string.h>

extern void MSHookFunction(void *symbol, void *replace, void **result);
extern void MSHookMessageEx(Class _class, SEL message, IMP hook, IMP *old);

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

// 1. 隐藏内存中加载的所有插件与 RootHide 底座动态库特征（消除 [功能插件注入] 与 [RootHide底座]）
static BOOL IsSensitiveDylibPath(const char *path) {
    if (!path) return NO;
    return (strstr(path, "AutoIPLocHook") != NULL ||
            strstr(path, "ellekit") != NULL ||
            strstr(path, "TweakInject") != NULL ||
            strstr(path, "MobileSubstrate") != NULL ||
            strstr(path, "libsubstrate") != NULL ||
            strstr(path, "CydiaSubstrate") != NULL ||
            strstr(path, "roothide") != NULL ||
            strstr(path, "jbroot") != NULL ||
            strstr(path, "/var/jb") != NULL ||
            strstr(path, "Crane") != NULL ||
            strstr(path, "AntiLocDetect") != NULL ||
            strstr(path, "Choicy") != NULL ||
            strstr(path, "Safari18Stealth") != NULL ||
            strstr(path, "PreferenceLoader") != NULL ||
            strstr(path, "libSandy") != NULL ||
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

// 2. 接管 NSTimeZone 与 CFTimeZone
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

// 3. 补全基带与蜂窝网络特征（飞行模式下依然保持 T-Mobile 310/260 LTE 参数，消除 [基带特征]）
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

// 4. 隐藏系统 HTTP/HTTPS/SOCKS5/PAC 显式代理（仅对系统底层网络库放行联网）
static BOOL IsSystemNetworkingCaller(void *retAddr) {
    if (!retAddr) return NO;
    Dl_info info;
    if (dladdr(retAddr, &info) != 0 && info.dli_fname != NULL) {
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

// 5. 过滤 Shadowrocket 产生的 utun / ipsec / ppp 虚拟隧道网卡
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

// 7. 抹除软件模拟定位标记与强制国际版地图国家码
static BOOL hook_returnNO(id self, SEL _cmd) {
    return NO;
}

static id (*orig_sourceInformation)(id self, SEL _cmd);
static id hook_sourceInformation(id self, SEL _cmd) {
    Class srcInfoCls = objc_getClass("CLLocationSourceInformation");
    if (srcInfoCls) {
        return [[srcInfoCls alloc] init];
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
        NSString *ssid = topAP[@"SSID"] ?: @"Johnson_5G";
        NSString *bssid = topAP[@"BSSID"] ?: @"00:26:F2:CD:D6:55";
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
        // 第一道防线：按内核进程名精确跳过系统桌面、守护进程与控制工具，100% 杜绝黑屏
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

        // 第二道防线：仅在包含 .app/ 的前台应用包中执行
        char execBuf[1024] = {0};
        uint32_t execSize = sizeof(execBuf);
        if (_NSGetExecutablePath(execBuf, &execSize) != 0) return;
        if (strstr(execBuf, ".app/") == NULL) return;

        // 显式加载目标系统框架，确保所有 Objective-C 类在 Hook 前已完成注册
        dlopen("/System/Library/Frameworks/CoreLocation.framework/CoreLocation", RTLD_NOW);
        dlopen("/System/Library/Frameworks/CoreTelephony.framework/CoreTelephony", RTLD_NOW);
        dlopen("/System/Library/PrivateFrameworks/GeoServices.framework/GeoServices", RTLD_NOW);

        // A. 使用 MSHookMessageEx 接管时区（兼容 iOS 16 arm64e 共享缓存相对方法表）
        NSString *initTZ = GetTargetTimeZoneName();
        if (initTZ) {
            setenv("TZ", initTZ.UTF8String, 1);
            tzset();
            [NSTimeZone resetSystemTimeZone];
        }
        Class tzMeta = objc_getMetaClass("NSTimeZone");
        if (tzMeta) {
            MSHookMessageEx(tzMeta, @selector(systemTimeZone), (IMP)hook_systemTimeZone, (IMP *)&orig_systemTimeZone);
            MSHookMessageEx(tzMeta, @selector(defaultTimeZone), (IMP)hook_defaultTimeZone, (IMP *)&orig_defaultTimeZone);
            MSHookMessageEx(tzMeta, @selector(localTimeZone), (IMP)hook_localTimeZone, (IMP *)&orig_localTimeZone);
        }

        // B. 拦截 URL Scheme 暴露
        Class appCls = objc_getClass("UIApplication");
        if (appCls) {
            MSHookMessageEx(appCls, @selector(canOpenURL:), (IMP)hook_canOpenURL, (IMP *)&orig_canOpenURL);
            SEL privOpenSel = NSSelectorFromString(@"_canOpenURL:publicURLsOnly:");
            if (class_getInstanceMethod(appCls, privOpenSel)) {
                MSHookMessageEx(appCls, privOpenSel, (IMP)hook_privCanOpenURL, (IMP *)&orig_privCanOpenURL);
            }
        }
        Class wsCls = objc_getClass("LSApplicationWorkspace");
        if (wsCls) {
            SEL wsSel = NSSelectorFromString(@"applicationsAvailableForHandlingURLScheme:");
            if (class_getInstanceMethod(wsCls, wsSel)) {
                MSHookMessageEx(wsCls, wsSel, (IMP)hook_appsForScheme, (IMP *)&orig_appsForScheme);
            }
            SEL ovSel = NSSelectorFromString(@"URLOverrideForURL:");
            if (class_getInstanceMethod(wsCls, ovSel)) {
                MSHookMessageEx(wsCls, ovSel, (IMP)hook_urlOverride, (IMP *)&orig_urlOverride);
            }
        }

        // C. 隐藏 NSURLSessionConfiguration 代理字典
        Class sessionCfgCls = objc_getClass("NSURLSessionConfiguration");
        if (sessionCfgCls) {
            MSHookMessageEx(sessionCfgCls, @selector(connectionProxyDictionary), (IMP)hook_connectionProxyDictionary, (IMP *)&orig_connectionProxyDictionary);
        }

        // D. 补全基带与蜂窝运营商参数（飞行模式下依然保持 T-Mobile 310/260 LTE 特征）
        Class carrierCls = objc_getClass("CTCarrier");
        if (carrierCls) {
            MSHookMessageEx(carrierCls, NSSelectorFromString(@"carrierName"), (IMP)hook_carrierName, (IMP *)&orig_carrierName);
            MSHookMessageEx(carrierCls, NSSelectorFromString(@"mobileCountryCode"), (IMP)hook_mobileCountryCode, (IMP *)&orig_mobileCountryCode);
            MSHookMessageEx(carrierCls, NSSelectorFromString(@"mobileNetworkCode"), (IMP)hook_mobileNetworkCode, (IMP *)&orig_mobileNetworkCode);
            MSHookMessageEx(carrierCls, NSSelectorFromString(@"isoCountryCode"), (IMP)hook_isoCountryCode, (IMP *)&orig_isoCountryCode);
        }
        Class netInfoCls = objc_getClass("CTTelephonyNetworkInfo");
        if (netInfoCls) {
            SEL svcSel = NSSelectorFromString(@"serviceCurrentRadioAccessTechnology");
            if (class_getInstanceMethod(netInfoCls, svcSel)) {
                MSHookMessageEx(netInfoCls, svcSel, (IMP)hook_serviceRadioTech, (IMP *)&orig_serviceRadioTech);
            }
            SEL curSel = NSSelectorFromString(@"currentRadioAccessTechnology");
            if (class_getInstanceMethod(netInfoCls, curSel)) {
                MSHookMessageEx(netInfoCls, curSel, (IMP)hook_currentRadioTech, (IMP *)&orig_currentRadioTech);
            }
        }

        // E. 抹除模拟定位标记 (isSimulatedBySoftware = NO)
        Class srcInfoCls = objc_getClass("CLLocationSourceInformation");
        if (srcInfoCls) {
            SEL simSel = NSSelectorFromString(@"isSimulatedBySoftware");
            if (class_getInstanceMethod(srcInfoCls, simSel)) {
                MSHookMessageEx(srcInfoCls, simSel, (IMP)hook_returnNO, NULL);
            }
            SEL accSel = NSSelectorFromString(@"isProducedByAccessory");
            if (class_getInstanceMethod(srcInfoCls, accSel)) {
                MSHookMessageEx(srcInfoCls, accSel, (IMP)hook_returnNO, NULL);
            }
        }
        Class locCls = objc_getClass("CLLocation");
        if (locCls) {
            SEL locSimSel = NSSelectorFromString(@"isSimulatedBySoftware");
            if (class_getInstanceMethod(locCls, locSimSel)) {
                MSHookMessageEx(locCls, locSimSel, (IMP)hook_returnNO, NULL);
            }
            SEL locPrivSel = NSSelectorFromString(@"_isSimulated");
            if (class_getInstanceMethod(locCls, locPrivSel)) {
                MSHookMessageEx(locCls, locPrivSel, (IMP)hook_returnNO, NULL);
            }
            SEL srcSel = NSSelectorFromString(@"sourceInformation");
            if (class_getInstanceMethod(locCls, srcSel)) {
                MSHookMessageEx(locCls, srcSel, (IMP)hook_sourceInformation, (IMP *)&orig_sourceInformation);
            }
        }

        // F. 锁定国际地图国家码，阻断高德切换
        Class geoCls = objc_getClass("GEOCountryConfiguration");
        if (geoCls) {
            NSArray *sels = @[@"countryCode", @"_countryCode", @"currentCountryCode", @"sourceCountryCode"];
            for (NSString *selName in sels) {
                SEL s = NSSelectorFromString(selName);
                if (class_getInstanceMethod(geoCls, s)) {
                    MSHookMessageEx(geoCls, s, (IMP)hook_targetCountryCode, NULL);
                }
            }
        }
        Class platformCls = objc_getClass("GEOPlatform");
        if (platformCls) {
            SEL chinaSel = NSSelectorFromString(@"isChina");
            if (class_getInstanceMethod(platformCls, chinaSel)) {
                MSHookMessageEx(platformCls, chinaSel, (IMP)hook_returnNO, NULL);
            }
        }

        // G. 接管系统底层 C 函数（由 RootHide Patcher 自动绑定至 libellekit）
        MSHookFunction((void *)_dyld_get_image_name, (void *)hook_dyld_get_image_name, (void **)&orig_dyld_get_image_name);

        void *symCFTimeZone = dlsym(RTLD_DEFAULT, "CFTimeZoneCopySystem");
        if (symCFTimeZone) MSHookFunction(symCFTimeZone, (void *)hook_CFTimeZoneCopySystem, (void **)&orig_CFTimeZoneCopySystem);

        MSHookFunction((void *)CFNetworkCopySystemProxySettings, (void *)hook_CFNetworkCopySystemProxySettings, (void **)&orig_CFNetworkCopySystemProxySettings);

        void *symSCDyn = dlsym(RTLD_DEFAULT, "SCDynamicStoreCopyProxies");
        if (symSCDyn) MSHookFunction(symSCDyn, (void *)hook_SCDynamicStoreCopyProxies, (void **)&orig_SCDynamicStoreCopyProxies);

        MSHookFunction((void *)getifaddrs, (void *)hook_getifaddrs, (void **)&orig_getifaddrs);
        MSHookFunction((void *)CNCopyCurrentNetworkInfo, (void *)hook_CNCopyCurrentNetworkInfo, (void **)&orig_CNCopyCurrentNetworkInfo);
        MSHookFunction((void *)CNCopySupportedInterfaces, (void *)hook_CNCopySupportedInterfaces, (void **)&orig_CNCopySupportedInterfaces);
    }
}
