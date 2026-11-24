#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <CoreLocation/CoreLocation.h>
#import <SystemConfiguration/CaptiveNetwork.h>
#import <CFNetwork/CFNetwork.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <ifaddrs.h>
#import <dlfcn.h>
#import <string.h>

#if __has_include(<ptrauth.h>)
#include <ptrauth.h>
#endif

typedef void (*MSHookFunction_t)(void *symbol, void *replace, void **result);

static NSString *const kGeoPrefPath = @"/var/mobile/Library/Preferences/com.autoiploc.geo.plist";
static NSString *const kWifiPrefPath = @"/var/mobile/Library/Preferences/com.autoiploc.wifi.plist";

// 直接遍历进程加载的 Mach-O 镜像符号表定位 _MSHookFunction（绕过 RootHide 路径隐藏）
static MSHookFunction_t FindElleKitHookFunction(void) {
    void *sym = dlsym(RTLD_DEFAULT, "MSHookFunction");
    if (sym) return (MSHookFunction_t)sym;

    uint32_t imgCount = _dyld_image_count();
    for (uint32_t i = 0; i < imgCount; i++) {
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
                if (strcmp(seg->segname, "__LINKEDIT") == 0) {
                    linkedit = seg;
                }
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

// 仅对系统网络/WebKit 放行真实 SOCKS5 代理，对诊断/业务 App 隐藏显式代理
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

// 过滤 Shadowrocket 等产生的 utun / ipsec / ppp 虚拟隧道网卡
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

// 屏蔽工具 URL Scheme 暴露 (apple-magnifier:// 等)
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

static NSArray *(*orig_appsForScheme)(id self, SEL _cmd, NSString *scheme);
static NSArray *hook_appsForScheme(id self, SEL _cmd, NSString *scheme) {
    if (IsBlockedURLScheme(scheme)) return @[];
    return orig_appsForScheme ? orig_appsForScheme(self, _cmd, scheme) : @[];
}

// 抹除软件模拟定位标记
static BOOL hook_returnNO(id self, SEL _cmd) {
    return NO;
}

// 强制苹果国际原生地图国家码
static NSString *(*orig_countryCode)(id self, SEL _cmd);
static NSString *hook_countryCode(id self, SEL _cmd) {
    NSDictionary *cfg = [NSDictionary dictionaryWithContentsOfFile:kGeoPrefPath];
    NSString *cc = cfg[@"countryCode"];
    if (cc && cc.length == 2 && ![cc isEqualToString:@"--"]) {
        return cc;
    }
    return orig_countryCode ? orig_countryCode(self, _cmd) : @"US";
}

// 接管系统 Wi-Fi 信息返回模拟美国热点
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
        NSString *ssid = topAP[@"SSID"] ?: @"TMOBILE-5G-4BAA";
        NSString *bssid = topAP[@"BSSID"] ?: @"44:94:FC:C4:A3:C4";
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

        MSHookFunction_t hookFn = FindElleKitHookFunction();
        if (hookFn) {
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
