#import <Foundation/Foundation.h>
#import <SystemConfiguration/CaptiveNetwork.h>
#import <objc/runtime.h>

static NSString *const kGeoPrefPath = @"/var/mobile/Library/Preferences/com.autoiploc.geo.plist";
static NSString *const kWifiPrefPath = @"/var/mobile/Library/Preferences/com.autoiploc.wifi.plist";

// 1. 强制 GEOCountryConfiguration 返回当前 IP 国家码（彻底清除高德地图）
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

// 3. 接管系统 CNCopyCurrentNetworkInfo 返回模拟周边排名第一的美国 Wi-Fi SSID 与 BSSID
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
            Method m2 = class_getInstanceMethod(geoCls, NSSelectorFromString(@"currentCountrySupportsNavigation"));
            if (m2) {
                // 保持默认导航支持
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
    }
}
