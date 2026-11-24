#import <Foundation/Foundation.h>
#import <SystemConfiguration/CaptiveNetwork.h>
#import <objc/runtime.h>
#import <dlfcn.h>

static NSDictionary *LoadPlistFallback(NSString *jbPath, NSString *mobilePath) {
    NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:jbPath];
    if (!d) d = [NSDictionary dictionaryWithContentsOfFile:mobilePath];
    return d;
}

// 1. Hook GEOCountryConfiguration 强制返回当前 IP 国家码，彻底去除高德水印
static NSString *(*orig_countryCode)(id self, SEL _cmd);
static NSString *hook_countryCode(id self, SEL _cmd) {
    NSDictionary *cfg = LoadPlistFallback(
        @"/var/jb/var/mobile/Library/Preferences/com.autoiploc.geo.plist",
        @"/var/mobile/Library/Preferences/com.autoiploc.geo.plist"
    );
    NSString *cc = cfg[@"countryCode"];
    if (cc && cc.length == 2 && ![cc isEqualToString:@"--"]) {
        return cc;
    }
    return orig_countryCode ? orig_countryCode(self, _cmd) : @"US";
}

// 2. Hook CNCopyCurrentNetworkInfo 返回模拟周边排名第一的 Wi-Fi SSID 与 BSSID
static CFDictionaryRef (*orig_CNCopyCurrentNetworkInfo)(CFStringRef interfaceName);
static CFDictionaryRef hook_CNCopyCurrentNetworkInfo(CFStringRef interfaceName) {
    NSDictionary *wifiCfg = LoadPlistFallback(
        @"/var/jb/var/mobile/Library/Preferences/com.autoiploc.wifi.plist",
        @"/var/mobile/Library/Preferences/com.autoiploc.wifi.plist"
    );
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
            Method m = class_getInstanceMethod(geoCls, NSSelectorFromString(@"countryCode"));
            if (m) {
                orig_countryCode = (void *)method_getImplementation(m);
                method_setImplementation(m, (IMP)hook_countryCode);
            }
        }
    }
}
