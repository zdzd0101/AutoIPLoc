#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <CoreLocation/CoreLocation.h>
#import <SystemConfiguration/SystemConfiguration.h>
#import <SystemConfiguration/CaptiveNetwork.h>
#import <CFNetwork/CFNetwork.h>
#import <objc/runtime.h>
#import <ifaddrs.h>
#import <string.h>

// 声明由 libsubstrate.tbd 导出的底层钩子函数（RootHide Patcher 会自动重绑定至 ElleKit）
extern void MSHookFunction(void *symbol, void *replace, void **result);

static NSString *const kGeoPrefPath = @"/var/mobile/Library/Preferences/com.autoiploc.geo.plist";
static NSString *const kWifiPrefPath = @"/var/mobile/Library/Preferences/com.autoiploc.wifi.plist";

// 1. 接管 CFNetworkCopySystemProxySettings（返回无代理配置）
static CFDictionaryRef (*orig_CFNetworkCopySystemProxySettings)(void);
static CFDictionaryRef hook_CFNetworkCopySystemProxySettings(void) {
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

// 2. 接管 SCDynamicStoreCopyProxies（彻底消除 [系统代理] 检测）
static CFDictionaryRef (*orig_SCDynamicStoreCopyProxies)(SCDynamicStoreRef store);
static CFDictionaryRef hook_SCDynamicStoreCopyProxies(SCDynamicStoreRef store) {
    NSDictionary *cleanProxy = @{
        @"FTPPassive": @1,
        @"ExceptionsList": @[@"*.local", @"169.254/16"]
    };
    return (__bridge_retained CFDictionaryRef)cleanProxy;
}

// 3. 过滤本地 VPN 虚拟隧道网卡 (utun / ipsec / ppp)
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

// 4. 屏蔽工具类 URL Scheme 探测 (apple-magnifier://, sileo://, filza:// 等)
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
    if (IsBlockedURLScheme(url.scheme)) {
        return NO;
    }
    return orig_canOpenURL ? orig_canOpenURL(self, _cmd, url) : NO;
}

static NSArray *(*orig_appsForScheme)(id self, SEL _cmd, NSString *scheme);
static NSArray *hook_appsForScheme(id self, SEL _cmd, NSString *scheme) {
    if (IsBlockedURLScheme(scheme)) {
        return @[];
    }
    return orig_appsForScheme ? orig_appsForScheme(self, _cmd, scheme) : @[];
}

// 5. 抹除软件模拟定位标记
static BOOL hook_returnNO(id self, SEL _cmd) {
    return NO;
}

// 6. 强制苹果国际原生地图国家码
static NSString *(*orig_countryCode)(id self, SEL _cmd);
static NSString *hook_countryCode(id self, SEL _cmd) {
    NSDictionary *cfg = [NSDictionary dictionaryWithContentsOfFile:kGeoPrefPath];
    NSString *cc = cfg[@"countryCode"];
    if (cc && cc.length == 2 && ![cc isEqualToString:@"--"]) {
        return cc;
    }
    return orig_countryCode ? orig_countryCode(self, _cmd) : @"US";
}

// 7. 接管系统 Wi-Fi 信息接口返回模拟美国热点
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

__attribute__((constructor))
static void AutoIPLocHookEntry(void) {
    @autoreleasepool {
        // A. 屏蔽 URL Scheme 暴露
        Class appCls = objc_getClass("UIApplication");
        if (appCls) {
            Method mOpen = class_getInstanceMethod(appCls, @selector(canOpenURL:));
            if (mOpen) {
                orig_canOpenURL = (void *)method_getImplementation(mOpen);
                method_setImplementation(mOpen, (IMP)hook_canOpenURL);
            }
        }
        Class wsCls = objc_getClass("LSApplicationWorkspace");
        if (wsCls) {
            Method mWs = class_getInstanceMethod(wsCls, NSSelectorFromString(@"applicationsAvailableForHandlingURLScheme:"));
            if (mWs) {
                orig_appsForScheme = (void *)method_getImplementation(mWs);
                method_setImplementation(mWs, (IMP)hook_appsForScheme);
            }
        }

        // B. 抹除模拟定位标记
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

        // C. 强制苹果国际原生地图
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

        // D. 原生 MSHookFunction 接管系统代理、VPN 网卡与 Wi-Fi 接口
        MSHookFunction((void *)CFNetworkCopySystemProxySettings, (void *)hook_CFNetworkCopySystemProxySettings, (void **)&orig_CFNetworkCopySystemProxySettings);
        MSHookFunction((void *)SCDynamicStoreCopyProxies, (void *)hook_SCDynamicStoreCopyProxies, (void **)&orig_SCDynamicStoreCopyProxies);
        MSHookFunction((void *)getifaddrs, (void *)hook_getifaddrs, (void **)&orig_getifaddrs);
        MSHookFunction((void *)CNCopyCurrentNetworkInfo, (void *)hook_CNCopyCurrentNetworkInfo, (void **)&orig_CNCopyCurrentNetworkInfo);
        MSHookFunction((void *)CNCopySupportedInterfaces, (void *)hook_CNCopySupportedInterfaces, (void **)&orig_CNCopySupportedInterfaces);
    }
}
