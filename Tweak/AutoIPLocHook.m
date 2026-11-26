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
#import <ifaddrs.h>
#import <dlfcn.h>
#import <sys/stat.h>
#import <unistd.h>
#import <errno.h>
#import <stdlib.h>
#import <string.h>

extern void MSHookFunction(void *symbol, void *replace, void **result);
extern void MSHookMessageEx(Class _class, SEL message, IMP hook, IMP *old);

static int (*orig_dladdr)(const void *addr, Dl_info *info) = NULL;

static BOOL IsSelfCaller(void *retAddr) {
    if (!retAddr) return NO;
    Dl_info info;
    int ok = orig_dladdr ? orig_dladdr(retAddr, &info) : dladdr(retAddr, &info);
    if (ok != 0 && info.dli_fname != NULL) {
        if (strstr(info.dli_fname, "AutoIPLocHook") != NULL) {
            return YES;
        }
    }
    return NO;
}

static NSDictionary *LoadGeoConfig(void) {
    NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:@"/var/mobile/Library/Preferences/com.autoiploc.geo.plist"];
    if (!d) d = [NSDictionary dictionaryWithContentsOfFile:@"/var/tmp/com.autoiploc.geo.plist"];
    return d;
}

static NSDictionary *LoadWiFiConfig(void) {
    NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:@"/var/mobile/Library/Preferences/com.autoiploc.wifi.plist"];
    if (!d) d = [NSDictionary dictionaryWithContentsOfFile:@"/var/tmp/com.autoiploc.wifi.plist"];
    return d;
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

// 1. 白名单屏蔽所有非系统动态库路径（消除 [功能插件注入]、[RootHide底座] 与 GeoComply 动态库扫描）
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
    const char *name = orig_dyld_get_image_name ? orig_dyld_get_image_name(image_index) : NULL;
    if (IsSensitiveDylibPath(name)) {
        return "/usr/lib/libobjc.A.dylib";
    }
    return name;
}

static int hook_dladdr(const void *addr, Dl_info *info) {
    int ret = orig_dladdr ? orig_dladdr(addr, info) : 0;
    if (ret != 0 && info && info->dli_fname && IsSensitiveDylibPath(info->dli_fname)) {
        info->dli_fname = "/usr/lib/libobjc.A.dylib";
    }
    return ret;
}

// 2. 隐藏环境变量与越狱文件/进程特征（绕过 GeoComply 篡改检测）
static char *(*orig_getenv)(const char *name) = NULL;
static char *hook_getenv(const char *name) {
    if (name && (strcmp(name, "DYLD_INSERT_LIBRARIES") == 0 ||
                 strcmp(name, "_MSSafeMode") == 0 ||
                 strcmp(name, "SUBSTRATE_SAFE_MODE") == 0 ||
                 strcmp(name, "JBROOT") == 0)) {
        return NULL;
    }
    return orig_getenv ? orig_getenv(name) : NULL;
}

static BOOL IsJailbreakPath(const char *path) {
    if (!path) return NO;
    return (strstr(path, "/var/jb") != NULL ||
            strstr(path, ".jbroot") != NULL ||
            strstr(path, "roothide") != NULL ||
            strstr(path, "RootHide") != NULL ||
            strstr(path, "Bootstrap") != NULL ||
            strstr(path, "MobileSubstrate") != NULL ||
            strstr(path, "CydiaSubstrate") != NULL ||
            strstr(path, "libsubstrate") != NULL ||
            strstr(path, "ellekit") != NULL ||
            strstr(path, "TweakInject") != NULL ||
            strstr(path, "Cydia.app") != NULL ||
            strstr(path, "Sileo.app") != NULL ||
            strstr(path, "Zebra.app") != NULL ||
            strstr(path, "Filza.app") != NULL ||
            strstr(path, "TrollStore") != NULL ||
            strstr(path, "Dopamine") != NULL ||
            strstr(path, "Crane") != NULL ||
            strstr(path, "/usr/bin/sshd") != NULL ||
            strstr(path, "/etc/apt") != NULL ||
            strstr(path, "/bin/bash") != NULL ||
            strstr(path, "/bin/sh") != NULL ||
            strstr(path, "autoiploc") != NULL);
}

static int (*orig_access)(const char *path, int mode) = NULL;
static int hook_access(const char *path, int mode) {
    if (!IsSelfCaller(__builtin_return_address(0)) && IsJailbreakPath(path)) {
        errno = ENOENT;
        return -1;
    }
    return orig_access ? orig_access(path, mode) : -1;
}

static int (*orig_stat)(const char *path, struct stat *buf) = NULL;
static int hook_stat(const char *path, struct stat *buf) {
    if (!IsSelfCaller(__builtin_return_address(0)) && IsJailbreakPath(path)) {
        errno = ENOENT;
        return -1;
    }
    return orig_stat ? orig_stat(path, buf) : -1;
}

static int (*orig_lstat)(const char *path, struct stat *buf) = NULL;
static int hook_lstat(const char *path, struct stat *buf) {
    if (!IsSelfCaller(__builtin_return_address(0)) && IsJailbreakPath(path)) {
        errno = ENOENT;
        return -1;
    }
    return orig_lstat ? orig_lstat(path, buf) : -1;
}

static FILE *(*orig_fopen)(const char *filename, const char *mode) = NULL;
static FILE *hook_fopen(const char *filename, const char *mode) {
    if (!IsSelfCaller(__builtin_return_address(0)) && IsJailbreakPath(filename)) {
        errno = ENOENT;
        return NULL;
    }
    return orig_fopen ? orig_fopen(filename, mode) : NULL;
}

static BOOL (*orig_fileExists)(id self, SEL _cmd, NSString *path) = NULL;
static BOOL hook_fileExists(id self, SEL _cmd, NSString *path) {
    if (!IsSelfCaller(__builtin_return_address(0)) && IsJailbreakPath(path.UTF8String)) {
        return NO;
    }
    return orig_fileExists ? orig_fileExists(self, _cmd, path) : NO;
}

static BOOL (*orig_fileExistsIsDir)(id self, SEL _cmd, NSString *path, BOOL *isDir) = NULL;
static BOOL hook_fileExistsIsDir(id self, SEL _cmd, NSString *path, BOOL *isDir) {
    if (!IsSelfCaller(__builtin_return_address(0)) && IsJailbreakPath(path.UTF8String)) {
        return NO;
    }
    return orig_fileExistsIsDir ? orig_fileExistsIsDir(self, _cmd, path, isDir) : NO;
}

static pid_t (*orig_fork)(void) = NULL;
static pid_t hook_fork(void) {
    errno = EPERM;
    return -1;
}

// 3. 接管 NSTimeZone 与 CFTimeZone
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

// 4. 补全双卡槽基带与蜂窝网络特征（统一修正为美国 T-Mobile 310/260 LTE）
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

// 5. 隐藏系统 HTTP/HTTPS/SOCKS5/PAC 显式代理（仅对系统底层网络库放行联网，消除 GeoComply 代理弹窗）
static BOOL IsSystemNetworkingCaller(void *retAddr) {
    if (!retAddr) return NO;
    Dl_info info;
    int ok = orig_dladdr ? orig_dladdr(retAddr, &info) : dladdr(retAddr, &info);
    if (ok != 0 && info.dli_fname != NULL) {
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

// 6. 过滤 Shadowrocket 产生的 utun / ipsec / ppp 虚拟隧道网卡
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

// 7. 屏蔽工具类 URL Scheme 暴露 (apple-magnifier://, sileo://, zbra:// 等)
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

// 8. 彻底抹除软件模拟定位标记 (isSimulatedBySoftware = NO) 与锁定国际地图国家码
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

// 9. 注入当前关联 US Wi-Fi（主热点 + 周边热点）
static NSArray<NSDictionary *> *GetMockWiFiList(void) {
    NSDictionary *wifiCfg = LoadWiFiConfig();
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
        NSString *ssid = topAP[@"SSID"] ?: @"Fios-7CE9-5G";
        NSString *bssid = topAP[@"BSSID"] ?: @"C8:D7:19:1C:73:9A";
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

        // A. 接管时区
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

        // B. 拦截 URL Scheme 与越狱文件路径检测
        Class appCls = objc_getClass("UIApplication");
        if (appCls) {
            MSHookMessageEx(appCls, @selector(canOpenURL:), (IMP)hook_canOpenURL, (IMP *)&orig_canOpenURL);
            SEL privSel = NSSelectorFromString(@"_canOpenURL:publicURLsOnly:");
            if (class_getInstanceMethod(appCls, privSel)) {
                MSHookMessageEx(appCls, privSel, (IMP)hook_privCanOpenURL, (IMP *)&orig_privCanOpenURL);
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
        Class fmCls = objc_getClass("NSFileManager");
        if (fmCls) {
            MSHookMessageEx(fmCls, @selector(fileExistsAtPath:), (IMP)hook_fileExists, (IMP *)&orig_fileExists);
            MSHookMessageEx(fmCls, @selector(fileExistsAtPath:isDirectory:), (IMP)hook_fileExistsIsDir, (IMP *)&orig_fileExistsIsDir);
        }

        // C. 隐藏 NSURLSessionConfiguration 代理字典
        Class sessionCfgCls = objc_getClass("NSURLSessionConfiguration");
        if (sessionCfgCls) {
            MSHookMessageEx(sessionCfgCls, @selector(connectionProxyDictionary), (IMP)hook_connectionProxyDictionary, (IMP *)&orig_connectionProxyDictionary);
        }

        // D. 补全双卡槽基带与蜂窝运营商参数
        Class carrierCls = objc_getClass("CTCarrier");
        if (carrierCls) {
            MSHookMessageEx(carrierCls, NSSelectorFromString(@"carrierName"), (IMP)hook_carrierName, (IMP *)&orig_carrierName);
            MSHookMessageEx(carrierCls, NSSelectorFromString(@"mobileCountryCode"), (IMP)hook_mobileCountryCode, (IMP *)&orig_mobileCountryCode);
            MSHookMessageEx(carrierCls, NSSelectorFromString(@"mobileNetworkCode"), (IMP)hook_mobileNetworkCode, (IMP *)&orig_mobileNetworkCode);
            MSHookMessageEx(carrierCls, NSSelectorFromString(@"isoCountryCode"), (IMP)hook_isoCountryCode, (IMP *)&orig_isoCountryCode);
            SEL voipSel = NSSelectorFromString(@"allowsVOIP");
            if (class_getInstanceMethod(carrierCls, voipSel)) {
                MSHookMessageEx(carrierCls, voipSel, (IMP)hook_returnYES, NULL);
            }
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

        // E. 彻底抹除模拟定位标记 (isSimulatedBySoftware = NO)
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
            SEL initSimSel = NSSelectorFromString(@"initWithSoftwareSimulationState:externalAccessoryState:");
            if (class_getInstanceMethod(srcInfoCls, initSimSel)) {
                MSHookMessageEx(srcInfoCls, initSimSel, (IMP)hook_initWithSimState, (IMP *)&orig_initWithSimState);
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

        // F. 锁定国际地图国家码
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

        // G. 接管系统底层 C 函数（由 RootHide Patcher 绑定至 ElleKit）
        MSHookFunction((void *)_dyld_get_image_name, (void *)hook_dyld_get_image_name, (void **)&orig_dyld_get_image_name);
        MSHookFunction((void *)dladdr, (void *)hook_dladdr, (void **)&orig_dladdr);
        MSHookFunction((void *)getenv, (void *)hook_getenv, (void **)&orig_getenv);
        MSHookFunction((void *)access, (void *)hook_access, (void **)&orig_access);
        MSHookFunction((void *)stat, (void *)hook_stat, (void **)&orig_stat);
        MSHookFunction((void *)lstat, (void *)hook_lstat, (void **)&orig_lstat);
        MSHookFunction((void *)fopen, (void *)hook_fopen, (void **)&orig_fopen);
        MSHookFunction((void *)fork, (void *)hook_fork, (void **)&orig_fork);

        void *symCFTimeZone = dlsym(RTLD_DEFAULT, "CFTimeZoneCopySystem");
        if (symCFTimeZone) MSHookFunction(symCFTimeZone, (void *)hook_CFTimeZoneCopySystem, (void **)&orig_CFTimeZoneCopySystem);

        MSHookFunction((void *)CFNetworkCopySystemProxySettings, (void *)hook_CFNetworkCopySystemProxySettings, (void **)&orig_CFNetworkCopySystemProxySettings);

        void *symSCDyn = dlsym(RTLD_DEFAULT, "SCDynamicStoreCopyProxies");
        if (symSCDyn) MSHookFunction(symSCDyn, (void *)hook_SCDynamicStoreCopyProxies, (void **)&orig_SCDynamicStoreCopyProxies);

        MSHookFunction((void *)getifaddrs, (void *)hook_getifaddrs, (void **)&orig_getifaddrs);
        MSHookFunction((void *)CNCopyCurrentNetworkInfo, (void *)hook_CNCopyCurrentNetworkInfo, (void **)&orig_CNCopyCurrentNetworkInfo);
        MSHookFunction((void *)CNCopySupportedInterfaces, (void *)hook_CNCopySupportedInterfaces, (void **)&orig_CNCopySupportedInterfaces);

        // 写入激活状态供 AutoIPLoc 主界面实时读取
        NSDictionary *status = @{
            @"active": @YES,
            @"version": @"3.6.0",
            @"lastProc": [NSString stringWithUTF8String:prog],
            @"cHookReady": @(orig_dyld_get_image_name != NULL)
        };
        [status writeToFile:@"/var/mobile/Library/Preferences/com.autoiploc.hookstatus.plist" atomically:YES];
        [status writeToFile:@"/var/tmp/com.autoiploc.hookstatus.plist" atomically:YES];
        chmod("/var/tmp/com.autoiploc.hookstatus.plist", 0666);
    }
}
