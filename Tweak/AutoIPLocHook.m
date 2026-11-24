#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <CoreLocation/CoreLocation.h>
#import <SystemConfiguration/CaptiveNetwork.h>
#import <CFNetwork/CFNetwork.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <ifaddrs.h>
#import <dlfcn.h>
#import <string.h>

typedef void (*MSHookFunction_t)(void *symbol, void *replace, void **result);

static NSString *const kGeoPrefPath = @"/var/mobile/Library/Preferences/com.autoiploc.geo.plist";
static NSString *const kWifiPrefPath = @"/var/mobile/Library/Preferences/com.autoiploc.wifi.plist";

// 直接从内存中已加载的 ElleKit 镜像获取 MSHookFunction（无需链接外部 libsubstrate，100% 加载成功）
static MSHookFunction_t ResolveElleKitHook(void) {
    void *fn = dlsym(RTLD_DEFAULT, "MSHookFunction");
    if (fn) return (MSHookFunction_t)fn;

    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *path = _dyld_get_image_name(i);
        if (path && (strstr(path, "ellekit") || strstr(path, "TweakInject") || strstr(path, "Substrate"))) {
            void *handle = dlopen(path, RTLD_NOLOAD | RTLD_NOW);
            if (handle) {
                fn = dlsym(handle, "MSHookFunction");
                if (fn) return (MSHookFunction_t)fn;
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

// 1. 隐藏内存中加载的插件与 RootHide 引导库特征（防止 dyld 遍历扫出动态库注入）
static const char *(*orig_dyld_get_image_name)(uint32_t image_index);
static const char *hook_dyld_get_image_name(uint32_t image_index) {
    const char *name = orig_dyld_get_image_name ? orig_dyld_get_image_name(image_index) : NULL;
    if (name && (strstr(name, "AutoIPLocHook") != NULL ||
                 strstr(name, "ellekit") != NULL ||
                 strstr(name, "TweakInject") != NULL ||
                 strstr(name, "MobileSubstrate") != NULL ||
                 strstr(name, "roothide") != NULL ||
                 strstr(name, "/var/jb") != NULL)) {
        return "/usr/lib/libSystem.B.dylib";
    }
    return name;
}

// 2. 接管 NSTimeZone（所有 App 与探针即时同步最新 IP 时区）
static NSTimeZone *(*orig_systemTimeZone)(id self, SEL _cmd);
static NSTimeZone *hook_systemTimeZone(id self, SEL _cmd) {
    NSString *tzName = GetTargetTimeZoneName();
    if (tzName) {
        NSTimeZone *tz = [NSTimeZone timeZoneWithName:tzName];
        if (tz) return tz;
    }
    return orig_systemTimeZone ? orig_systemTimeZone(self, _cmd) : [NSTimeZone timeZoneWithName:@"America/Los_Angeles"];
}

static NSTimeZone *(*orig_defaultTimeZone)(id self, SEL _cmd);
static NSTimeZone *hook_defaultTimeZone(id self, SEL _cmd) {
    NSString *tzName = GetTargetTimeZoneName();
    if (tzName) {
        NSTimeZone *tz = [NSTimeZone timeZoneWithName:tzName];
        if (tz) return tz;
    }
    return orig_defaultTimeZone ? orig_defaultTimeZone(self, _cmd) : [NSTimeZone timeZoneWithName:@"America/Los_Angeles"];
}

static NSTimeZone *(*orig_localTimeZone)(id self, SEL _cmd);
static NSTimeZone *hook_localTimeZone(id self, SEL _cmd) {
    NSString *tzName = GetTargetTimeZoneName();
    if (tzName) {
        NSTimeZone *tz = [NSTimeZone timeZoneWithName:tzName];
        if (tz) return tz;
    }
    return orig_localTimeZone ? orig_localTimeZone(self, _cmd) : [NSTimeZone timeZoneWithName:@"America/Los_Angeles"];
}

// 3. 接管 MobileGestalt 区域码
static CFPropertyListRef (*orig_MGCopyAnswer)(CFStringRef prop);
static CFPropertyListRef hook_MGCopyAnswer(CFStringRef prop) {
    if (prop != NULL) {
        NSDictionary *cfg = LoadGeoConfig();
        if ([cfg[@"forceAppleMaps"] boolValue]) {
            NSString *key = (__bridge NSString *)prop;
            NSString *targetCC = GetTargetCountryCode();
            if ([key isEqualToString:@"RegionCode"]) {
                return (__bridge_retained CFPropertyListRef)targetCC;
            }
            if ([key isEqualToString:@"RegionInfo"]) {
                NSString *regionInfo = [targetCC isEqualToString:@"US"] ? @"LL/A" : [NSString stringWithFormat:@"%@/A", targetCC];
                return (__bridge_retained CFPropertyListRef)regionInfo;
            }
        }
    }
    return orig_MGCopyAnswer ? orig_MGCopyAnswer(prop) : NULL;
}

// 4. 屏蔽漫游基站 460 国家码（防止纯流量下地图切回高德）
static NSString *(*orig_mobileCountryCode)(id self, SEL _cmd);
static NSString *hook_mobileCountryCode(id self, SEL _cmd) {
    NSString *orig = orig_mobileCountryCode ? orig_mobileCountryCode(self, _cmd) : nil;
    if (orig == nil || [orig isEqualToString:@"460"] || [orig isEqualToString:@"454"] || [orig isEqualToString:@"455"]) {
        return @"310";
    }
    return orig;
}

static NSString *(*orig_isoCountryCode)(id self, SEL _cmd);
static NSString *hook_isoCountryCode(id self, SEL _cmd) {
    NSString *orig = orig_isoCountryCode ? orig_isoCountryCode(self, _cmd) : nil;
    if (orig == nil || [orig.lowercaseString isEqualToString:@"cn"] || [orig.lowercaseString isEqualToString:@"hk"] || [orig.lowercaseString isEqualToString:@"mo"]) {
        return GetTargetCountryCode().lowercaseString;
    }
    return orig;
}

// 5. 隐藏系统 HTTP/HTTPS/SOCKS5/PAC 显式代理（仅对系统底层网络库放行联网）
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

// 6. 过滤 Shadowrocket 等产生的 utun / ipsec / ppp 虚拟隧道网卡
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
        @"filza", @"santander", @"trollstore", @"dopamine", @"roothide"
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

// 8. 抹除软件模拟定位标记
static BOOL hook_returnNO(id self, SEL _cmd) {
    return NO;
}

// 9. 强制苹果国际原生地图国家码与数据源
static NSString *hook_targetCountryCode(id self, SEL _cmd) {
    return GetTargetCountryCode();
}

static void hook_noop(id self, SEL _cmd) {
}

// 10. 接管系统 Wi-Fi 信息接口返回模拟美国热点
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
        NSString *ssid = topAP[@"SSID"] ?: @"TMOBILE-7F0F";
        NSString *bssid = topAP[@"BSSID"] ?: @"14:91:82:ED:DA:F3";
        NSDictionary *result = @{
            (__bridge NSString *)kCNNetworkInfoKeySSID: ssid,
            (__bridge NSString *)kCNNetworkInfoKeyBSSID: bssid,
            (__bridge NSString *)kCNNetworkInfoKeySSIDData: [ssid dataUsingEncoding:NSUTF8StringEncoding]
        };
        return (__bridge_retained CFDictionaryRef)result;
    }
    return orig_CNCopyCurrentNetworkInfo ? orig_CNCopyCurrentNetworkInfo(interfaceName) : NULL;
}

__attribute__((constructor))
static void AutoIPLocHookEntry(void) {
    @autoreleasepool {
        // A. 同步全局时区
        NSString *initTZ = GetTargetTimeZoneName();
        if (initTZ) {
            setenv("TZ", initTZ.UTF8String, 1);
            tzset();
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

        // D. 屏蔽漫游基站 460 国家码
        Class carrierCls = objc_getClass("CTCarrier");
        if (carrierCls) {
            Method mMCC = class_getInstanceMethod(carrierCls, NSSelectorFromString(@"mobileCountryCode"));
            if (mMCC) {
                orig_mobileCountryCode = (void *)method_getImplementation(mMCC);
                method_setImplementation(mMCC, (IMP)hook_mobileCountryCode);
            }
            Method mISO = class_getInstanceMethod(carrierCls, NSSelectorFromString(@"isoCountryCode"));
            if (mISO) {
                orig_isoCountryCode = (void *)method_getImplementation(mISO);
                method_setImplementation(mISO, (IMP)hook_isoCountryCode);
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

        // F. 强制苹果国际原生地图配置与阻断高德切换
        Class geoCls = objc_getClass("GEOCountryConfiguration");
        if (geoCls) {
            NSArray *sels = @[@"countryCode", @"_countryCode", @"currentCountryCode", @"sourceCountryCode"];
            for (NSString *selName in sels) {
                Method m = class_getInstanceMethod(geoCls, NSSelectorFromString(selName));
                if (m) method_setImplementation(m, (IMP)hook_targetCountryCode);
            }
            Method mUpdate = class_getInstanceMethod(geoCls, NSSelectorFromString(@"updateProvidersForCurrentCountry"));
            if (mUpdate) method_setImplementation(mUpdate, (IMP)hook_noop);
        }
        Class platformCls = objc_getClass("GEOPlatform");
        if (platformCls) {
            Method mChina = class_getInstanceMethod(platformCls, NSSelectorFromString(@"isChina"));
            if (mChina) method_setImplementation(mChina, (IMP)hook_returnNO);
        }

        // G. 内存直接解析 ElleKit MSHookFunction 接管系统底层 C 函数
        MSHookFunction_t hookFn = ResolveElleKitHook();
        if (hookFn) {
            hookFn((void *)_dyld_get_image_name, (void *)hook_dyld_get_image_name, (void **)&orig_dyld_get_image_name);

            dlopen("/usr/lib/libMobileGestalt.dylib", RTLD_LAZY);
            void *symMG = dlsym(RTLD_DEFAULT, "MGCopyAnswer");
            if (symMG) hookFn(symMG, (void *)hook_MGCopyAnswer, (void **)&orig_MGCopyAnswer);

            void *symProxy = dlsym(RTLD_DEFAULT, "CFNetworkCopySystemProxySettings");
            if (symProxy) hookFn(symProxy, (void *)hook_CFNetworkCopySystemProxySettings, (void **)&orig_CFNetworkCopySystemProxySettings);

            void *symSCDyn = dlsym(RTLD_DEFAULT, "SCDynamicStoreCopyProxies");
            if (symSCDyn) hookFn(symSCDyn, (void *)hook_SCDynamicStoreCopyProxies, (void **)&orig_SCDynamicStoreCopyProxies);

            void *symIfaddrs = dlsym(RTLD_DEFAULT, "getifaddrs");
            if (symIfaddrs) hookFn(symIfaddrs, (void *)hook_getifaddrs, (void **)&orig_getifaddrs);

            void *symCurNet = dlsym(RTLD_DEFAULT, "CNCopyCurrentNetworkInfo");
            if (symCurNet) hookFn(symCurNet, (void *)hook_CNCopyCurrentNetworkInfo, (void **)&orig_CNCopyCurrentNetworkInfo);

            void *symSupIf = dlsym(RTLD_DEFAULT, "CNCopySupportedInterfaces");
            if (symSupIf) hookFn(symSupIf, (void *)hook_CNCopySupportedInterfaces, (void **)&orig_CNCopySupportedInterfaces);
        }
    }
}
