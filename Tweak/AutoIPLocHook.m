#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>
#import <CoreLocation/CoreLocation.h>
#import <CoreTelephony/CTCarrier.h>
#import <CoreTelephony/CTTelephonyNetworkInfo.h>
#import <SystemConfiguration/CaptiveNetwork.h>
#import <CFNetwork/CFNetwork.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <mach-o/dyld.h>
#import <os/lock.h>
#import <net/if.h>
#import <ifaddrs.h>
#import <notify.h>
#import <dlfcn.h>
#import <sys/stat.h>
#import <unistd.h>
#import <errno.h>
#import <stdlib.h>
#import <string.h>

#if __has_feature(ptrauth_calls)
#include <ptrauth.h>
#endif

#define HOOK_VER_MAJOR 5
#define HOOK_VER_MINOR 3
#define HOOK_VER_PATCH 0
#define HOOK_VER_STR   @"5.3.0"
#define HOOK_SCHEMA    530

typedef void (*MSHookFunction_t)(void *symbol, void *replace, void **result);
typedef void (*MSHookMessageEx_t)(Class _class, SEL message, IMP hook, IMP *old);

static MSHookFunction_t g_MSHookFunction = NULL;
static MSHookMessageEx_t g_MSHookMessageEx = NULL;
static char g_selfDirPath[768] = {0};

// ============================================================================
// 1. PAC 指针剥离 & 线程局部重入守卫 (TLS)
// ============================================================================

static inline void *StripReturnAddressPAC(void *addr) {
#if __has_feature(ptrauth_calls)
    return addr ? ptrauth_strip(addr, ptrauth_key_return_address) : NULL;
#else
    return addr;
#endif
}

static inline void *StripFunctionPointerPAC(void *addr) {
#if __has_feature(ptrauth_calls)
    return addr ? ptrauth_strip(addr, ptrauth_key_function_pointer) : NULL;
#else
    return addr;
#endif
}

static _Thread_local int g_selfCallDepth = 0;
static _Thread_local int g_tzHookDepth = 0;
static _Thread_local int g_localeHookDepth = 0;
static _Thread_local int g_defaultsHookDepth = 0;
static _Thread_local int g_proxyHookDepth = 0;
static _Thread_local int g_ifHookDepth = 0;
static _Thread_local int g_wifiHookDepth = 0;
static _Thread_local int g_reqHookDepth = 0;
static _Thread_local int g_wkHookDepth = 0;

// ============================================================================
// 2. 自身目录解析 & ElleKit / Substrate 动态解析
// ============================================================================

static void CaptureSelfDirectory(void *selfSymbolAddr) {
    Dl_info selfInfo;
    void *cleanAddr = StripFunctionPointerPAC(selfSymbolAddr);
    if (dladdr(cleanAddr, &selfInfo) != 0 && selfInfo.dli_fname != NULL) {
        const char *lastSlash = strrchr(selfInfo.dli_fname, '/');
        if (lastSlash != NULL) {
            size_t len = (size_t)(lastSlash - selfInfo.dli_fname);
            if (len > 0 && len < sizeof(g_selfDirPath) - 1) {
                memcpy(g_selfDirPath, selfInfo.dli_fname, len);
                g_selfDirPath[len] = '\0';
            }
        }
    }
}

static BOOL TryLoadElleKitFromRoot(const char *jbRoot) {
    if (!jbRoot || jbRoot[0] == '\0') return NO;
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
            if (g_MSHookFunction && g_MSHookMessageEx) return YES;
        }
    }
    return NO;
}

static void ResolveElleKitRuntime(void *selfSymbolAddr) {
    g_selfCallDepth++;
    g_MSHookFunction = (MSHookFunction_t)dlsym(RTLD_DEFAULT, "MSHookFunction");
    g_MSHookMessageEx = (MSHookMessageEx_t)dlsym(RTLD_DEFAULT, "MSHookMessageEx");
    if (!g_MSHookFunction) g_MSHookFunction = (MSHookFunction_t)dlsym(RTLD_NEXT, "MSHookFunction");
    if (!g_MSHookMessageEx) g_MSHookMessageEx = (MSHookMessageEx_t)dlsym(RTLD_NEXT, "MSHookMessageEx");
    if (g_MSHookFunction && g_MSHookMessageEx) {
        g_selfCallDepth--;
        return;
    }

    if (g_selfDirPath[0] != '\0') {
        const char *libMarker = strstr(g_selfDirPath, "/usr/lib/");
        if (!libMarker) libMarker = strstr(g_selfDirPath, "/Library/");
        if (libMarker != NULL) {
            size_t rootLen = (size_t)(libMarker - g_selfDirPath);
            if (rootLen > 0 && rootLen < 512) {
                char jbRoot[512] = {0};
                memcpy(jbRoot, g_selfDirPath, rootLen);
                if (TryLoadElleKitFromRoot(jbRoot)) {
                    g_selfCallDepth--;
                    return;
                }
            }
        }
    }

    NSString *savedRoot = [NSString stringWithContentsOfFile:@"/var/tmp/com.autoiploc.jbroot.txt" encoding:NSUTF8StringEncoding error:nil];
    if (savedRoot.length > 0) {
        NSString *trimmed = [savedRoot stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
        if (TryLoadElleKitFromRoot(trimmed.UTF8String)) {
            g_selfCallDepth--;
            return;
        }
    }

    uint32_t count = _dyld_image_count();
    for (uint32_t i = 1; i < count; i++) {
        const char *img = _dyld_get_image_name(i);
        if (!img) continue;
        if (strstr(img, "ellekit") != NULL || strstr(img, "substrate") != NULL ||
            strstr(img, "Substrate") != NULL || strstr(img, "TweakInject") != NULL) {
            void *h = dlopen(img, RTLD_NOLOAD | RTLD_LAZY);
            if (!h) h = dlopen(img, RTLD_NOW | RTLD_GLOBAL);
            if (h) {
                if (!g_MSHookFunction) g_MSHookFunction = (MSHookFunction_t)dlsym(h, "MSHookFunction");
                if (!g_MSHookMessageEx) g_MSHookMessageEx = (MSHookMessageEx_t)dlsym(h, "MSHookMessageEx");
                if (g_MSHookFunction && g_MSHookMessageEx) {
                    g_selfCallDepth--;
                    return;
                }
            }
        }
    }
    g_selfCallDepth--;
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

// ============================================================================
// 3. 多通道沙盒可读配置读取（优先读取插件同目录 + 3秒 TTL 内存缓存）
// ============================================================================

static os_unfair_lock g_cfgLock = OS_UNFAIR_LOCK_INIT;
static NSDictionary *g_cachedGeo = nil;
static CFAbsoluteTime g_lastGeoLoad = 0;
static NSDictionary *g_cachedWiFi = nil;
static CFAbsoluteTime g_lastWiFiLoad = 0;
static const CFAbsoluteTime kConfigCacheTTL = 3.0;

static NSDictionary *LoadPlistMultiPath(const char *selfFileName, NSString *tmpPath, NSString *prefPath) {
    NSDictionary *d = nil;
    if (g_selfDirPath[0] != '\0') {
        char selfCfgPath[1024] = {0};
        snprintf(selfCfgPath, sizeof(selfCfgPath), "%s/%s", g_selfDirPath, selfFileName);
        d = [NSDictionary dictionaryWithContentsOfFile:[NSString stringWithUTF8String:selfCfgPath]];
    }
    if (!d) d = [NSDictionary dictionaryWithContentsOfFile:tmpPath];
    if (!d) d = [NSDictionary dictionaryWithContentsOfFile:prefPath];
    return d;
}

static NSDictionary *LoadGeoConfig(void) {
    CFAbsoluteTime now = CFAbsoluteTimeGetCurrent();
    os_unfair_lock_lock(&g_cfgLock);
    if (g_lastGeoLoad > 0 && (now - g_lastGeoLoad) < kConfigCacheTTL) {
        NSDictionary *cached = g_cachedGeo;
        os_unfair_lock_unlock(&g_cfgLock);
        return cached;
    }
    os_unfair_lock_unlock(&g_cfgLock);

    g_selfCallDepth++;
    NSDictionary *d = LoadPlistMultiPath(
        "AutoIPLoc.geo.plist",
        @"/var/tmp/com.autoiploc.geo.plist",
        @"/var/mobile/Library/Preferences/com.autoiploc.geo.plist"
    );
    g_selfCallDepth--;

    os_unfair_lock_lock(&g_cfgLock);
    g_cachedGeo = d;
    g_lastGeoLoad = now;
    os_unfair_lock_unlock(&g_cfgLock);
    return d;
}

static NSDictionary *LoadWiFiConfig(void) {
    CFAbsoluteTime now = CFAbsoluteTimeGetCurrent();
    os_unfair_lock_lock(&g_cfgLock);
    if (g_lastWiFiLoad > 0 && (now - g_lastWiFiLoad) < kConfigCacheTTL) {
        NSDictionary *cached = g_cachedWiFi;
        os_unfair_lock_unlock(&g_cfgLock);
        return cached;
    }
    os_unfair_lock_unlock(&g_cfgLock);

    g_selfCallDepth++;
    NSDictionary *d = LoadPlistMultiPath(
        "AutoIPLoc.wifi.plist",
        @"/var/tmp/com.autoiploc.wifi.plist",
        @"/var/mobile/Library/Preferences/com.autoiploc.wifi.plist"
    );
    g_selfCallDepth--;

    os_unfair_lock_lock(&g_cfgLock);
    g_cachedWiFi = d;
    g_lastWiFiLoad = now;
    os_unfair_lock_unlock(&g_cfgLock);
    return d;
}

static BOOL IsGeoSpoofEnabled(void) {
    NSDictionary *cfg = LoadGeoConfig();
    return cfg && [cfg[@"enabled"] boolValue];
}

static BOOL IsLocaleSpoofEnabled(void) {
    NSDictionary *cfg = LoadGeoConfig();
    if (!cfg || ![cfg[@"enabled"] boolValue]) return NO;
    id flag = cfg[@"spoofLocale"];
    return (flag == nil) ? YES : [flag boolValue];
}

static BOOL IsCarrierSpoofEnabled(void) {
    NSDictionary *cfg = LoadGeoConfig();
    if (!cfg || ![cfg[@"enabled"] boolValue]) return NO;
    id flag = cfg[@"spoofCarrier"];
    return (flag == nil) ? YES : [flag boolValue];
}

static BOOL IsProxyStealthEnabled(void) {
    NSDictionary *cfg = LoadGeoConfig();
    if (!cfg) return YES;
    id flag = cfg[@"spoofProxy"];
    return (flag == nil) ? YES : [flag boolValue];
}

static BOOL IsWebViewStealthEnabled(void) {
    NSDictionary *cfg = LoadGeoConfig();
    if (!cfg || ![cfg[@"enabled"] boolValue]) return NO;
    id flag = cfg[@"spoofWebView"];
    return (flag == nil) ? YES : [flag boolValue];
}

static BOOL IsDeviceSpoofEnabled(void) {
    NSDictionary *cfg = LoadGeoConfig();
    if (!cfg || ![cfg[@"enabled"] boolValue]) return NO;
    id flag = cfg[@"spoofDevice"];
    return (flag == nil) ? YES : [flag boolValue];
}

static BOOL IsDelegateIdfvToCrane(void) {
    NSDictionary *cfg = LoadGeoConfig();
    if (!cfg) return YES;
    id flag = cfg[@"delegateIdfvToCrane"];
    return (flag == nil) ? YES : [flag boolValue];
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
    if (!IsGeoSpoofEnabled()) return nil;
    NSDictionary *cfg = LoadGeoConfig();
    NSString *tz = cfg[@"timezone"];
    if (tz && tz.length > 3 && ![tz isEqualToString:@"-"]) {
        return tz;
    }
    return nil;
}

static NSString *GetTargetDeviceName(void) {
    NSDictionary *cfg = LoadGeoConfig();
    NSString *dn = cfg[@"deviceName"];
    if ([dn isKindOfClass:[NSString class]] && dn.length > 0) {
        return dn;
    }
    return @"iPhone";
}

static NSString *GetTargetIDFVString(void) {
    NSDictionary *cfg = LoadGeoConfig();
    NSString *idfv = cfg[@"idfv"];
    if ([idfv isKindOfClass:[NSString class]] && idfv.length >= 32) {
        return idfv;
    }
    return nil;
}

// ============================================================================
// 4. 国家 -> 运营商 & 语言区域联合映射表（14个常见地区）
// ============================================================================

typedef struct {
    const char *cc;
    const char *carrier;
    const char *mcc;
    const char *mnc;
    const char *localeId;
    const char *langCode;
    const char *acceptLang;
} CountryProfilePreset;

static const CountryProfilePreset *GetCountryPresetForTarget(void) {
    static const CountryProfilePreset kPresets[] = {
        {"US", "T-Mobile",    "310", "260", "en_US", "en-US",      "en-US,en;q=0.9"},
        {"GB", "Vodafone UK", "234", "15",  "en_GB", "en-GB",      "en-GB,en;q=0.9"},
        {"CA", "Rogers",      "302", "720", "en_CA", "en-CA",      "en-CA,en;q=0.9"},
        {"AU", "Telstra",     "505", "01",  "en_AU", "en-AU",      "en-AU,en;q=0.9"},
        {"JP", "NTT DOCOMO",  "440", "10",  "ja_JP", "ja-JP",      "ja-JP,ja;q=0.9,en-US;q=0.8"},
        {"DE", "Telekom.de",  "262", "01",  "de_DE", "de-DE",      "de-DE,de;q=0.9,en-US;q=0.8"},
        {"FR", "Orange F",    "208", "01",  "fr_FR", "fr-FR",      "fr-FR,fr;q=0.9,en-US;q=0.8"},
        {"SG", "Singtel",     "525", "01",  "en_SG", "en-SG",      "en-SG,en;q=0.9"},
        {"KR", "SKTelecom",   "450", "05",  "ko_KR", "ko-KR",      "ko-KR,ko;q=0.9,en-US;q=0.8"},
        {"TW", "Chunghwa",    "466", "92",  "zh_TW", "zh-Hant-TW", "zh-TW,zh;q=0.9,en-US;q=0.8"},
        {"NL", "KPN",         "204", "08",  "nl_NL", "nl-NL",      "nl-NL,nl;q=0.9,en-US;q=0.8"},
        {"IT", "TIM",         "222", "01",  "it_IT", "it-IT",      "it-IT,it;q=0.9,en-US;q=0.8"},
        {"ES", "Movistar",    "214", "07",  "es_ES", "es-ES",      "es-ES,es;q=0.9,en-US;q=0.8"},
        {"BR", "Vivo",        "724", "06",  "pt_BR", "pt-BR",      "pt-BR,pt;q=0.9,en-US;q=0.8"}
    };
    NSString *cc = GetTargetCountryCode();
    const char *ccStr = cc.UTF8String;
    if (ccStr) {
        size_t count = sizeof(kPresets) / sizeof(kPresets[0]);
        for (size_t i = 0; i < count; i++) {
            if (strcmp(kPresets[i].cc, ccStr) == 0) {
                return &kPresets[i];
            }
        }
    }
    return &kPresets[0];
}

// ============================================================================
// 5. 反越狱、路径隐身与环境变量净化（RootHide 安全版）
// ============================================================================

static char *(*orig_getenv)(const char *name) = NULL;
static char *hook_getenv(const char *name) {
    if (g_selfCallDepth == 0 && name != NULL) {
        g_selfCallDepth++;
        BOOL blocked = (strcmp(name, "DYLD_INSERT_LIBRARIES") == 0 ||
                        strcmp(name, "_MSSafeMode") == 0 ||
                        strcmp(name, "SUBSTRATE_SAFE_MODE") == 0 ||
                        strcmp(name, "JBROOT") == 0);
        g_selfCallDepth--;
        if (blocked) return NULL;
    }
    return orig_getenv ? orig_getenv(name) : NULL;
}

static NSDictionary<NSString *, NSString *> *(*orig_procEnvironment)(id self, SEL _cmd) = NULL;
static NSDictionary<NSString *, NSString *> *hook_procEnvironment(id self, SEL _cmd) {
    NSDictionary<NSString *, NSString *> *env = orig_procEnvironment ? orig_procEnvironment(self, _cmd) : @{};
    if (g_selfCallDepth == 0 && env.count > 0) {
        if (env[@"DYLD_INSERT_LIBRARIES"] || env[@"_MSSafeMode"] ||
            env[@"SUBSTRATE_SAFE_MODE"] || env[@"JBROOT"]) {
            NSMutableDictionary *clean = [env mutableCopy];
            [clean removeObjectForKey:@"DYLD_INSERT_LIBRARIES"];
            [clean removeObjectForKey:@"_MSSafeMode"];
            [clean removeObjectForKey:@"SUBSTRATE_SAFE_MODE"];
            [clean removeObjectForKey:@"JBROOT"];
            return clean;
        }
    }
    return env;
}

static BOOL IsJailbreakPath(const char *path) {
    if (!path) return NO;
    return (strstr(path, "/var/jb") != NULL ||
            strstr(path, ".jbroot") != NULL ||
            strstr(path, "roothide") != NULL ||
            strstr(path, "RootHide") != NULL ||
            strstr(path, "Bootstrap") != NULL ||
            strstr(path, "procursus") != NULL ||
            strstr(path, "MobileSubstrate") != NULL ||
            strstr(path, "CydiaSubstrate") != NULL ||
            strstr(path, "libsubstrate") != NULL ||
            strstr(path, "Substitute") != NULL ||
            strstr(path, "libhooker") != NULL ||
            strstr(path, "ellekit") != NULL ||
            strstr(path, "TweakInject") != NULL ||
            strstr(path, "Choicy") != NULL ||
            strstr(path, "Shadow.dylib") != NULL ||
            strstr(path, "Cydia.app") != NULL ||
            strstr(path, "Sileo.app") != NULL ||
            strstr(path, "Zebra.app") != NULL ||
            strstr(path, "Filza.app") != NULL ||
            strstr(path, "TrollStore") != NULL ||
            strstr(path, "Dopamine") != NULL ||
            strstr(path, "Crane") != NULL ||
            strstr(path, "Geranium") != NULL ||
            strstr(path, "var/lib/dpkg") != NULL ||
            strstr(path, "var/lib/apt") != NULL ||
            strstr(path, "var/cache/apt") != NULL ||
            strstr(path, "/usr/bin/sshd") != NULL ||
            strstr(path, "/etc/apt") != NULL ||
            strstr(path, "/bin/bash") != NULL ||
            strstr(path, "/bin/sh") != NULL ||
            strstr(path, "autoiploc") != NULL ||
            strstr(path, "AutoIPLoc") != NULL);
}

static BOOL (*orig_fileExists)(id self, SEL _cmd, NSString *path) = NULL;
static BOOL hook_fileExists(id self, SEL _cmd, NSString *path) {
    if (g_selfCallDepth == 0 && IsJailbreakPath(path.UTF8String)) return NO;
    return orig_fileExists ? orig_fileExists(self, _cmd, path) : NO;
}

static BOOL (*orig_fileExistsIsDir)(id self, SEL _cmd, NSString *path, BOOL *isDir) = NULL;
static BOOL hook_fileExistsIsDir(id self, SEL _cmd, NSString *path, BOOL *isDir) {
    if (g_selfCallDepth == 0 && IsJailbreakPath(path.UTF8String)) return NO;
    return orig_fileExistsIsDir ? orig_fileExistsIsDir(self, _cmd, path, isDir) : NO;
}

static BOOL (*orig_isReadableFile)(id self, SEL _cmd, NSString *path) = NULL;
static BOOL hook_isReadableFile(id self, SEL _cmd, NSString *path) {
    if (g_selfCallDepth == 0 && IsJailbreakPath(path.UTF8String)) return NO;
    return orig_isReadableFile ? orig_isReadableFile(self, _cmd, path) : NO;
}

static NSArray<NSString *> *(*orig_contentsOfDir)(id self, SEL _cmd, NSString *path, NSError **error) = NULL;
static NSArray<NSString *> *hook_contentsOfDir(id self, SEL _cmd, NSString *path, NSError **error) {
    if (g_selfCallDepth == 0 && IsJailbreakPath(path.UTF8String)) {
        if (error) {
            *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileReadNoSuchFileError userInfo:nil];
        }
        return nil;
    }
    NSArray<NSString *> *items = orig_contentsOfDir ? orig_contentsOfDir(self, _cmd, path, error) : nil;
    if (g_selfCallDepth == 0 && items.count > 0 && path.length > 0) {
        const char *p = path.UTF8String;
        if (p && (strcmp(p, "/") == 0 || strcmp(p, "/var") == 0 || strcmp(p, "/private/var") == 0 ||
                  strcmp(p, "/var/tmp") == 0 || strcmp(p, "/private/var/tmp") == 0 ||
                  strcmp(p, "/Applications") == 0 || strstr(p, "Bundle/Application") != NULL)) {
            NSMutableArray<NSString *> *filtered = [NSMutableArray arrayWithCapacity:items.count];
            for (NSString *name in items) {
                if (!IsJailbreakPath(name.UTF8String)) [filtered addObject:name];
            }
            return filtered;
        }
    }
    return items;
}

// ============================================================================
// 6. 全局时区伪造（带 TLS 严格防重入守卫）
// ============================================================================

static NSTimeZone *(*orig_systemTimeZone)(id self, SEL _cmd) = NULL;
static NSTimeZone *hook_systemTimeZone(id self, SEL _cmd) {
    if (g_selfCallDepth == 0 && g_tzHookDepth == 0) {
        g_tzHookDepth++;
        g_selfCallDepth++;
        NSString *tzName = GetTargetTimeZoneName();
        NSTimeZone *tz = tzName ? [NSTimeZone timeZoneWithName:tzName] : nil;
        g_selfCallDepth--;
        g_tzHookDepth--;
        if (tz) return tz;
    }
    return orig_systemTimeZone ? orig_systemTimeZone(self, _cmd) : [NSTimeZone timeZoneWithName:@"America/New_York"];
}

static NSTimeZone *(*orig_defaultTimeZone)(id self, SEL _cmd) = NULL;
static NSTimeZone *hook_defaultTimeZone(id self, SEL _cmd) {
    if (g_selfCallDepth == 0 && g_tzHookDepth == 0) {
        g_tzHookDepth++;
        g_selfCallDepth++;
        NSString *tzName = GetTargetTimeZoneName();
        NSTimeZone *tz = tzName ? [NSTimeZone timeZoneWithName:tzName] : nil;
        g_selfCallDepth--;
        g_tzHookDepth--;
        if (tz) return tz;
    }
    return orig_defaultTimeZone ? orig_defaultTimeZone(self, _cmd) : [NSTimeZone timeZoneWithName:@"America/New_York"];
}

static NSTimeZone *(*orig_localTimeZone)(id self, SEL _cmd) = NULL;
static NSTimeZone *hook_localTimeZone(id self, SEL _cmd) {
    if (g_selfCallDepth == 0 && g_tzHookDepth == 0) {
        g_tzHookDepth++;
        g_selfCallDepth++;
        NSString *tzName = GetTargetTimeZoneName();
        NSTimeZone *tz = tzName ? [NSTimeZone timeZoneWithName:tzName] : nil;
        g_selfCallDepth--;
        g_tzHookDepth--;
        if (tz) return tz;
    }
    return orig_localTimeZone ? orig_localTimeZone(self, _cmd) : [NSTimeZone timeZoneWithName:@"America/New_York"];
}

static CFTimeZoneRef (*orig_CFTimeZoneCopySystem)(void) = NULL;
static CFTimeZoneRef hook_CFTimeZoneCopySystem(void) {
    if (g_selfCallDepth == 0 && g_tzHookDepth == 0) {
        g_tzHookDepth++;
        g_selfCallDepth++;
        NSString *tzName = GetTargetTimeZoneName();
        CFTimeZoneRef tz = tzName ? CFTimeZoneCreateWithName(kCFAllocatorDefault, (__bridge CFStringRef)tzName, true) : NULL;
        g_selfCallDepth--;
        g_tzHookDepth--;
        if (tz) return tz;
    }
    return orig_CFTimeZoneCopySystem ? orig_CFTimeZoneCopySystem() : NULL;
}

static CFTimeZoneRef (*orig_CFTimeZoneCopyDefault)(void) = NULL;
static CFTimeZoneRef hook_CFTimeZoneCopyDefault(void) {
    if (g_selfCallDepth == 0 && g_tzHookDepth == 0) {
        g_tzHookDepth++;
        g_selfCallDepth++;
        NSString *tzName = GetTargetTimeZoneName();
        CFTimeZoneRef tz = tzName ? CFTimeZoneCreateWithName(kCFAllocatorDefault, (__bridge CFStringRef)tzName, true) : NULL;
        g_selfCallDepth--;
        g_tzHookDepth--;
        if (tz) return tz;
    }
    return orig_CFTimeZoneCopyDefault ? orig_CFTimeZoneCopyDefault() : NULL;
}

// ============================================================================
// 7. 语言、区域与 HTTP Accept-Language 请求头闭环
// ============================================================================

static NSLocale *(*orig_currentLocale)(id self, SEL _cmd) = NULL;
static NSLocale *hook_currentLocale(id self, SEL _cmd) {
    if (g_selfCallDepth == 0 && g_localeHookDepth == 0) {
        g_localeHookDepth++;
        g_selfCallDepth++;
        NSLocale *loc = nil;
        if (IsLocaleSpoofEnabled()) {
            const CountryProfilePreset *p = GetCountryPresetForTarget();
            loc = [NSLocale localeWithLocaleIdentifier:[NSString stringWithUTF8String:p->localeId]];
        }
        g_selfCallDepth--;
        g_localeHookDepth--;
        if (loc) return loc;
    }
    return orig_currentLocale ? orig_currentLocale(self, _cmd) : [NSLocale systemLocale];
}

static NSLocale *(*orig_autoupdatingCurrentLocale)(id self, SEL _cmd) = NULL;
static NSLocale *hook_autoupdatingCurrentLocale(id self, SEL _cmd) {
    if (g_selfCallDepth == 0 && g_localeHookDepth == 0) {
        g_localeHookDepth++;
        g_selfCallDepth++;
        NSLocale *loc = nil;
        if (IsLocaleSpoofEnabled()) {
            const CountryProfilePreset *p = GetCountryPresetForTarget();
            loc = [NSLocale localeWithLocaleIdentifier:[NSString stringWithUTF8String:p->localeId]];
        }
        g_selfCallDepth--;
        g_localeHookDepth--;
        if (loc) return loc;
    }
    return orig_autoupdatingCurrentLocale ? orig_autoupdatingCurrentLocale(self, _cmd) : [NSLocale systemLocale];
}

static NSArray<NSString *> *(*orig_preferredLanguages)(id self, SEL _cmd) = NULL;
static NSArray<NSString *> *hook_preferredLanguages(id self, SEL _cmd) {
    if (g_selfCallDepth == 0 && g_localeHookDepth == 0) {
        g_localeHookDepth++;
        g_selfCallDepth++;
        NSArray<NSString *> *langs = nil;
        if (IsLocaleSpoofEnabled()) {
            const CountryProfilePreset *p = GetCountryPresetForTarget();
            NSString *primary = [NSString stringWithUTF8String:p->langCode];
            langs = [primary isEqualToString:@"en-US"] ? @[primary] : @[primary, @"en-US"];
        }
        g_selfCallDepth--;
        g_localeHookDepth--;
        if (langs) return langs;
    }
    return orig_preferredLanguages ? orig_preferredLanguages(self, _cmd) : @[@"en-US"];
}

static CFLocaleRef (*orig_CFLocaleCopyCurrent)(void) = NULL;
static CFLocaleRef hook_CFLocaleCopyCurrent(void) {
    if (g_selfCallDepth == 0 && g_localeHookDepth == 0) {
        g_localeHookDepth++;
        g_selfCallDepth++;
        CFLocaleRef loc = NULL;
        if (IsLocaleSpoofEnabled()) {
            const CountryProfilePreset *p = GetCountryPresetForTarget();
            CFStringRef locStr = CFStringCreateWithCString(kCFAllocatorDefault, p->localeId, kCFStringEncodingUTF8);
            if (locStr) {
                loc = CFLocaleCreate(kCFAllocatorDefault, locStr);
                CFRelease(locStr);
            }
        }
        g_selfCallDepth--;
        g_localeHookDepth--;
        if (loc) return loc;
    }
    return orig_CFLocaleCopyCurrent ? orig_CFLocaleCopyCurrent() : NULL;
}

static CFArrayRef (*orig_CFLocaleCopyPreferredLanguages)(void) = NULL;
static CFArrayRef hook_CFLocaleCopyPreferredLanguages(void) {
    if (g_selfCallDepth == 0 && g_localeHookDepth == 0) {
        g_localeHookDepth++;
        g_selfCallDepth++;
        NSArray<NSString *> *langs = nil;
        if (IsLocaleSpoofEnabled()) {
            const CountryProfilePreset *p = GetCountryPresetForTarget();
            NSString *primary = [NSString stringWithUTF8String:p->langCode];
            langs = [primary isEqualToString:@"en-US"] ? @[primary] : @[primary, @"en-US"];
        }
        g_selfCallDepth--;
        g_localeHookDepth--;
        if (langs) return (__bridge_retained CFArrayRef)langs;
    }
    return orig_CFLocaleCopyPreferredLanguages ? orig_CFLocaleCopyPreferredLanguages() : NULL;
}

static id (*orig_defaultsObjectForKey)(id self, SEL _cmd, NSString *defaultName) = NULL;
static id hook_defaultsObjectForKey(id self, SEL _cmd, NSString *defaultName) {
    if (g_selfCallDepth == 0 && g_defaultsHookDepth == 0 && defaultName) {
        BOOL isLang = [defaultName isEqualToString:@"AppleLanguages"];
        BOOL isLoc = !isLang && [defaultName isEqualToString:@"AppleLocale"];
        if (isLang || isLoc) {
            g_defaultsHookDepth++;
            g_selfCallDepth++;
            BOOL enabled = IsLocaleSpoofEnabled();
            const CountryProfilePreset *p = enabled ? GetCountryPresetForTarget() : NULL;
            g_selfCallDepth--;
            g_defaultsHookDepth--;
            if (enabled && p) {
                if (isLang) {
                    NSString *primary = [NSString stringWithUTF8String:p->langCode];
                    return [primary isEqualToString:@"en-US"] ? @[primary] : @[primary, @"en-US"];
                }
                return [NSString stringWithUTF8String:p->localeId];
            }
        }
    }
    return orig_defaultsObjectForKey ? orig_defaultsObjectForKey(self, _cmd, defaultName) : nil;
}

static void (*orig_reqSetValue)(id self, SEL _cmd, NSString *value, NSString *field) = NULL;
static void hook_reqSetValue(id self, SEL _cmd, NSString *value, NSString *field) {
    if (g_selfCallDepth == 0 && g_reqHookDepth == 0 && field != nil &&
        [field caseInsensitiveCompare:@"Accept-Language"] == NSOrderedSame) {
        g_reqHookDepth++;
        g_selfCallDepth++;
        NSString *spoofed = nil;
        if (IsLocaleSpoofEnabled()) {
            const CountryProfilePreset *p = GetCountryPresetForTarget();
            spoofed = [NSString stringWithUTF8String:p->acceptLang];
        }
        g_selfCallDepth--;
        g_reqHookDepth--;
        if (spoofed && orig_reqSetValue) {
            orig_reqSetValue(self, _cmd, spoofed, field);
            return;
        }
    }
    if (orig_reqSetValue) orig_reqSetValue(self, _cmd, value, field);
}

static void (*orig_reqAddValue)(id self, SEL _cmd, NSString *value, NSString *field) = NULL;
static void hook_reqAddValue(id self, SEL _cmd, NSString *value, NSString *field) {
    if (g_selfCallDepth == 0 && g_reqHookDepth == 0 && field != nil &&
        [field caseInsensitiveCompare:@"Accept-Language"] == NSOrderedSame) {
        g_reqHookDepth++;
        g_selfCallDepth++;
        NSString *spoofed = nil;
        if (IsLocaleSpoofEnabled()) {
            const CountryProfilePreset *p = GetCountryPresetForTarget();
            spoofed = [NSString stringWithUTF8String:p->acceptLang];
        }
        g_selfCallDepth--;
        g_reqHookDepth--;
        if (spoofed && orig_reqSetValue) {
            orig_reqSetValue(self, @selector(setValue:forHTTPHeaderField:), spoofed, field);
            return;
        }
    }
    if (orig_reqAddValue) orig_reqAddValue(self, _cmd, value, field);
}

// ============================================================================
// 8. 设备名、IDFV（支持 Crane 托管）、IDFA 归零与中文键盘隐藏
// ============================================================================

static NSString *(*orig_deviceName)(id self, SEL _cmd) = NULL;
static NSString *hook_deviceName(id self, SEL _cmd) {
    if (g_selfCallDepth == 0 && IsDeviceSpoofEnabled()) {
        return GetTargetDeviceName();
    }
    return orig_deviceName ? orig_deviceName(self, _cmd) : @"iPhone";
}

static NSUUID *(*orig_identifierForVendor)(id self, SEL _cmd) = NULL;
static NSUUID *hook_identifierForVendor(id self, SEL _cmd) {
    if (g_selfCallDepth == 0 && IsDeviceSpoofEnabled() && !IsDelegateIdfvToCrane()) {
        NSString *idfvStr = GetTargetIDFVString();
        if (idfvStr) {
            NSUUID *u = [[NSUUID alloc] initWithUUIDString:idfvStr];
            if (u) return u;
        }
    }
    return orig_identifierForVendor ? orig_identifierForVendor(self, _cmd) : [NSUUID UUID];
}

static NSUUID *(*orig_advertisingIdentifier)(id self, SEL _cmd) = NULL;
static NSUUID *hook_advertisingIdentifier(id self, SEL _cmd) {
    if (g_selfCallDepth == 0 && IsDeviceSpoofEnabled()) {
        return [[NSUUID alloc] initWithUUIDString:@"00000000-0000-0000-0000-000000000000"];
    }
    return orig_advertisingIdentifier ? orig_advertisingIdentifier(self, _cmd) : [[NSUUID alloc] initWithUUIDString:@"00000000-0000-0000-0000-000000000000"];
}

static BOOL IsSystemTextInputCaller(void *retAddr) {
    void *cleanAddr = StripReturnAddressPAC(retAddr);
    if (!cleanAddr) return YES;
    Dl_info info;
    if (dladdr(cleanAddr, &info) != 0 && info.dli_fname != NULL) {
        if (strstr(info.dli_fname, "UIKitCore") != NULL ||
            strstr(info.dli_fname, "TextInput") != NULL ||
            strstr(info.dli_fname, "InputUI") != NULL ||
            strstr(info.dli_fname, "Keyboard") != NULL ||
            strstr(info.dli_fname, "WebKit") != NULL ||
            strstr(info.dli_fname, "Foundation") != NULL) {
            return YES;
        }
    }
    return NO;
}

static NSString *(*orig_primaryLanguage)(id self, SEL _cmd) = NULL;
static NSString *hook_primaryLanguage(id self, SEL _cmd) {
    if (g_selfCallDepth == 0 && !IsSystemTextInputCaller(__builtin_return_address(0)) &&
        IsDeviceSpoofEnabled() && IsLocaleSpoofEnabled()) {
        const CountryProfilePreset *p = GetCountryPresetForTarget();
        return [NSString stringWithUTF8String:p->langCode];
    }
    return orig_primaryLanguage ? orig_primaryLanguage(self, _cmd) : @"en-US";
}

// ============================================================================
// 9. WKWebView 内嵌网页前置注入（时区 / 语言 / WebRTC 防泄露）
// ============================================================================

static char kAutoIPLocWKInjectedKey;

static NSString *SanitizeJSValue(NSString *raw, NSString *fallback) {
    if (!raw || raw.length == 0 || raw.length > 64) return fallback;
    NSCharacterSet *allowed = [NSCharacterSet characterSetWithCharactersInString:@"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/_+-"];
    if ([raw rangeOfCharacterFromSet:[allowed invertedSet]].location != NSNotFound) {
        return fallback;
    }
    return raw;
}

static NSString *BuildWebViewStealthJS(void) {
    NSString *tzName = SanitizeJSValue(GetTargetTimeZoneName() ?: @"America/New_York", @"America/New_York");
    const CountryProfilePreset *p = GetCountryPresetForTarget();
    NSString *langCode = SanitizeJSValue([NSString stringWithUTF8String:p->langCode], @"en-US");
    BOOL blockWebRTC = IsProxyStealthEnabled();

    NSTimeZone *tz = [NSTimeZone timeZoneWithName:tzName] ?: [NSTimeZone timeZoneWithName:@"America/New_York"];
    NSInteger jsOffsetMinutes = -([tz secondsFromGMTForDate:[NSDate date]] / 60);

    NSString *langsArray = [langCode isEqualToString:@"en-US"]
        ? @"['en-US','en']"
        : [NSString stringWithFormat:@"['%@','en-US','en']", langCode];

    NSMutableString *js = [NSMutableString stringWithFormat:
        @"(function(){"
        @"try{"
        @"if(window.__autoiploc_v530)return;window.__autoiploc_v530=1;"
        @"var tz='%@',lg='%@',lgs=%@,off=%ld;"
        @"var oRO=Intl.DateTimeFormat.prototype.resolvedOptions;"
        @"Intl.DateTimeFormat.prototype.resolvedOptions=function(){"
        @"var r=oRO.apply(this,arguments);r.timeZone=tz;r.locale=lg;return r;};"
        @"Date.prototype.getTimezoneOffset=function(){return off;};"
        @"Object.defineProperty(navigator,'language',{get:function(){return lg;},configurable:true});"
        @"Object.defineProperty(navigator,'languages',{get:function(){return Object.freeze(lgs.slice());},configurable:true});"
        @"Object.defineProperty(navigator,'webdriver',{get:function(){return false;},configurable:true});"
        @"}catch(e){}",
        tzName, langCode, langsArray, (long)jsOffsetMinutes
    ];

    if (blockWebRTC) {
        [js appendString:
            @"try{"
            @"var bad=/typ\\s+host|\\.local\\b|192\\.168\\.|10\\.\\d+\\.|172\\.(1[6-9]|2\\d|3[01])\\.|169\\.254\\.|fe80:/i;"
            @"['RTCPeerConnection','webkitRTCPeerConnection'].forEach(function(k){"
            @"var O=window[k];if(!O)return;"
            @"function W(c,d){"
            @"var pc=d!==undefined?new O(c,d):new O(c);"
            @"var oAdd=pc.addEventListener.bind(pc);"
            @"pc.addEventListener=function(t,fn,opt){"
            @"if(t==='icecandidate'&&typeof fn==='function'){"
            @"return oAdd(t,function(e){if(e&&e.candidate&&e.candidate.candidate&&bad.test(e.candidate.candidate))return;fn.call(this,e);},opt);"
            @"}return oAdd(t,fn,opt);};"
            @"var desc=Object.getOwnPropertyDescriptor(O.prototype,'onicecandidate');"
            @"if(desc&&desc.set){"
            @"Object.defineProperty(pc,'onicecandidate',{"
            @"get:function(){return desc.get?desc.get.call(pc):null;},"
            @"set:function(fn){if(typeof fn!=='function'){desc.set.call(pc,fn);return;}"
            @"desc.set.call(pc,function(e){if(e&&e.candidate&&e.candidate.candidate&&bad.test(e.candidate.candidate))return;fn.call(this,e);});},"
            @"configurable:true});"
            @"}"
            @"return pc;}"
            @"W.prototype=O.prototype;window[k]=W;});"
            @"}catch(e){}"
        ];
    }

    [js appendString:@"})();"];
    return js;
}

static void InjectStealthScriptIntoConfig(WKWebViewConfiguration *cfg) {
    if (!cfg) return;
    WKUserContentController *ucc = cfg.userContentController;
    if (!ucc) {
        ucc = [[WKUserContentController alloc] init];
        cfg.userContentController = ucc;
    }
    if (objc_getAssociatedObject(ucc, &kAutoIPLocWKInjectedKey) != nil) return;
    objc_setAssociatedObject(ucc, &kAutoIPLocWKInjectedKey, @YES, OBJC_ASSOCIATION_RETAIN_NONATOMIC);

    NSString *jsSource = BuildWebViewStealthJS();
    WKUserScript *script = [[WKUserScript alloc] initWithSource:jsSource
                                                  injectionTime:WKUserScriptInjectionTimeAtDocumentStart
                                               forMainFrameOnly:NO];
    [ucc addUserScript:script];
}

typedef void *(*orig_wkInit_t)(void *selfPtr, SEL _cmd, CGRect frame, void *configPtr);
static orig_wkInit_t orig_wkInit = NULL;

static void *hook_wkInit(void *selfPtr, SEL _cmd, CGRect frame, void *configPtr) {
    if (g_selfCallDepth == 0 && g_wkHookDepth == 0 && configPtr != NULL) {
        g_wkHookDepth++;
        g_selfCallDepth++;
        if (IsWebViewStealthEnabled()) {
            WKWebViewConfiguration *cfg = (__bridge WKWebViewConfiguration *)configPtr;
            InjectStealthScriptIntoConfig(cfg);
        }
        g_selfCallDepth--;
        g_wkHookDepth--;
    }
    return orig_wkInit ? orig_wkInit(selfPtr, _cmd, frame, configPtr) : selfPtr;
}

// ============================================================================
// 10. 运营商伪造（14国动态映射 + 无 SIM 卡设备兜底）
// ============================================================================

static NSString *(*orig_carrierName)(id self, SEL _cmd) = NULL;
static NSString *hook_carrierName(id self, SEL _cmd) {
    if (g_selfCallDepth == 0 && IsCarrierSpoofEnabled()) {
        const CountryProfilePreset *p = GetCountryPresetForTarget();
        return [NSString stringWithUTF8String:p->carrier];
    }
    return orig_carrierName ? orig_carrierName(self, _cmd) : nil;
}

static NSString *(*orig_mobileCountryCode)(id self, SEL _cmd) = NULL;
static NSString *hook_mobileCountryCode(id self, SEL _cmd) {
    if (g_selfCallDepth == 0 && IsCarrierSpoofEnabled()) {
        const CountryProfilePreset *p = GetCountryPresetForTarget();
        return [NSString stringWithUTF8String:p->mcc];
    }
    return orig_mobileCountryCode ? orig_mobileCountryCode(self, _cmd) : nil;
}

static NSString *(*orig_mobileNetworkCode)(id self, SEL _cmd) = NULL;
static NSString *hook_mobileNetworkCode(id self, SEL _cmd) {
    if (g_selfCallDepth == 0 && IsCarrierSpoofEnabled()) {
        const CountryProfilePreset *p = GetCountryPresetForTarget();
        return [NSString stringWithUTF8String:p->mnc];
    }
    return orig_mobileNetworkCode ? orig_mobileNetworkCode(self, _cmd) : nil;
}

static NSString *(*orig_isoCountryCode)(id self, SEL _cmd) = NULL;
static NSString *hook_isoCountryCode(id self, SEL _cmd) {
    if (g_selfCallDepth == 0 && IsCarrierSpoofEnabled()) {
        return GetTargetCountryCode().lowercaseString;
    }
    return orig_isoCountryCode ? orig_isoCountryCode(self, _cmd) : nil;
}

static NSDictionary<NSString *, CTCarrier *> *(*orig_serviceProviders)(id self, SEL _cmd) = NULL;
static NSDictionary<NSString *, CTCarrier *> *hook_serviceProviders(id self, SEL _cmd) {
    NSDictionary<NSString *, CTCarrier *> *orig = orig_serviceProviders ? orig_serviceProviders(self, _cmd) : nil;
    if (orig.count > 0 || g_selfCallDepth > 0 || !IsCarrierSpoofEnabled()) return orig;
    Class carrierCls = objc_getClass("CTCarrier");
    if (carrierCls) {
        CTCarrier *fake = [[carrierCls alloc] init];
        if (fake) return @{@"0000000100000001": fake};
    }
    return orig;
}

static CTCarrier *(*orig_subscriberProvider)(id self, SEL _cmd) = NULL;
static CTCarrier *hook_subscriberProvider(id self, SEL _cmd) {
    CTCarrier *orig = orig_subscriberProvider ? orig_subscriberProvider(self, _cmd) : nil;
    if (orig || g_selfCallDepth > 0 || !IsCarrierSpoofEnabled()) return orig;
    Class carrierCls = objc_getClass("CTCarrier");
    return carrierCls ? [[carrierCls alloc] init] : nil;
}

static NSDictionary<NSString *, NSString *> *(*orig_serviceRadioTech)(id self, SEL _cmd) = NULL;
static NSDictionary<NSString *, NSString *> *hook_serviceRadioTech(id self, SEL _cmd) {
    NSDictionary<NSString *, NSString *> *orig = orig_serviceRadioTech ? orig_serviceRadioTech(self, _cmd) : nil;
    if (orig.count > 0 || g_selfCallDepth > 0 || !IsCarrierSpoofEnabled()) return orig;
    return @{
        @"0000000100000001": @"CTRadioAccessTechnologyLTE",
        @"0000000100000002": @"CTRadioAccessTechnologyLTE"
    };
}

static NSString *(*orig_currentRadioTech)(id self, SEL _cmd) = NULL;
static NSString *hook_currentRadioTech(id self, SEL _cmd) {
    NSString *orig = orig_currentRadioTech ? orig_currentRadioTech(self, _cmd) : nil;
    if (orig.length > 0 || g_selfCallDepth > 0 || !IsCarrierSpoofEnabled()) return orig;
    return @"CTRadioAccessTechnologyLTE";
}

static NSString *(*orig_dataServiceIdentifier)(id self, SEL _cmd) = NULL;
static NSString *hook_dataServiceIdentifier(id self, SEL _cmd) {
    NSString *orig = orig_dataServiceIdentifier ? orig_dataServiceIdentifier(self, _cmd) : nil;
    if (orig.length > 0 || g_selfCallDepth > 0 || !IsCarrierSpoofEnabled()) return orig;
    return @"0000000100000001";
}

static BOOL hook_returnYES(id self, SEL _cmd) {
    return YES;
}

// ============================================================================
// 11. 代理、VPN 网卡与 NEVPNConnection 状态隐身
// ============================================================================

static BOOL IsSystemNetworkingCaller(void *retAddr) {
    void *cleanAddr = StripReturnAddressPAC(retAddr);
    if (!cleanAddr) return NO;
    Dl_info info;
    if (dladdr(cleanAddr, &info) != 0 && info.dli_fname != NULL) {
        if (strstr(info.dli_fname, "CFNetwork") != NULL ||
            strstr(info.dli_fname, "WebKit") != NULL ||
            strstr(info.dli_fname, "libnetwork") != NULL ||
            strstr(info.dli_fname, "Network.framework") != NULL ||
            strstr(info.dli_fname, "GeoServices") != NULL ||
            strstr(info.dli_fname, "MapKit") != NULL ||
            strstr(info.dli_fname, "VectorKit") != NULL ||
            strstr(info.dli_fname, "Foundation") != NULL ||
            strstr(info.dli_fname, "CoreFoundation") != NULL) {
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
    if (g_selfCallDepth > 0 || g_proxyHookDepth > 0) {
        return orig_CFNetworkCopySystemProxySettings ? orig_CFNetworkCopySystemProxySettings() : NULL;
    }
    void *retAddr = __builtin_return_address(0);
    g_proxyHookDepth++;
    g_selfCallDepth++;
    BOOL bypass = IsSystemNetworkingCaller(retAddr) || !IsProxyStealthEnabled();
    CFDictionaryRef clean = bypass ? NULL : CreateCleanProxyDict();
    g_selfCallDepth--;
    g_proxyHookDepth--;
    if (!bypass && clean) return clean;
    return orig_CFNetworkCopySystemProxySettings ? orig_CFNetworkCopySystemProxySettings() : CreateCleanProxyDict();
}

static CFDictionaryRef (*orig_SCDynamicStoreCopyProxies)(void *store) = NULL;
static CFDictionaryRef hook_SCDynamicStoreCopyProxies(void *store) {
    if (g_selfCallDepth > 0 || g_proxyHookDepth > 0) {
        return orig_SCDynamicStoreCopyProxies ? orig_SCDynamicStoreCopyProxies(store) : NULL;
    }
    void *retAddr = __builtin_return_address(0);
    g_proxyHookDepth++;
    g_selfCallDepth++;
    BOOL bypass = IsSystemNetworkingCaller(retAddr) || !IsProxyStealthEnabled();
    CFDictionaryRef clean = bypass ? NULL : CreateCleanProxyDict();
    g_selfCallDepth--;
    g_proxyHookDepth--;
    if (!bypass && clean) return clean;
    return orig_SCDynamicStoreCopyProxies ? orig_SCDynamicStoreCopyProxies(store) : CreateCleanProxyDict();
}

static NSDictionary *(*orig_connectionProxyDictionary)(id self, SEL _cmd) = NULL;
static NSDictionary *hook_connectionProxyDictionary(id self, SEL _cmd) {
    if (g_selfCallDepth > 0 || g_proxyHookDepth > 0) {
        return orig_connectionProxyDictionary ? orig_connectionProxyDictionary(self, _cmd) : nil;
    }
    void *retAddr = __builtin_return_address(0);
    g_proxyHookDepth++;
    g_selfCallDepth++;
    BOOL bypass = IsSystemNetworkingCaller(retAddr) || !IsProxyStealthEnabled();
    g_selfCallDepth--;
    g_proxyHookDepth--;
    if (bypass && orig_connectionProxyDictionary) {
        return orig_connectionProxyDictionary(self, _cmd);
    }
    return nil;
}

static NSInteger (*orig_vpnStatus)(id self, SEL _cmd) = NULL;
static NSInteger hook_vpnStatus(id self, SEL _cmd) {
    if (g_selfCallDepth == 0 && IsProxyStealthEnabled()) {
        return 1; // NEVPNStatusDisconnected
    }
    return orig_vpnStatus ? orig_vpnStatus(self, _cmd) : 1;
}

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
    if (!orig_getifaddrs) return -1;
    int ret = orig_getifaddrs(ifap);
    if (g_selfCallDepth > 0 || g_ifHookDepth > 0 || ret != 0 || !ifap || !*ifap) return ret;
    g_ifHookDepth++;
    g_selfCallDepth++;
    if (IsProxyStealthEnabled()) {
        struct ifaddrs *head = *ifap;
        while (head && IsVirtualVPNInterface(head->ifa_name) && head->ifa_next != NULL) {
            struct ifaddrs *nextNode = head->ifa_next;
            memcpy(head, nextNode, sizeof(struct ifaddrs));
        }
        if (head && IsVirtualVPNInterface(head->ifa_name) && head->ifa_next == NULL) {
            freeifaddrs(*ifap);
            *ifap = NULL;
        } else {
            struct ifaddrs *curr = head;
            while (curr && curr->ifa_next != NULL) {
                if (IsVirtualVPNInterface(curr->ifa_next->ifa_name)) {
                    curr->ifa_next = curr->ifa_next->ifa_next;
                } else {
                    curr = curr->ifa_next;
                }
            }
        }
    }
    g_selfCallDepth--;
    g_ifHookDepth--;
    return ret;
}

static unsigned int (*orig_if_nametoindex)(const char *ifname) = NULL;
static unsigned int hook_if_nametoindex(const char *ifname) {
    if (g_selfCallDepth == 0 && g_ifHookDepth == 0 && ifname != NULL) {
        g_ifHookDepth++;
        g_selfCallDepth++;
        BOOL hide = IsProxyStealthEnabled() && IsVirtualVPNInterface(ifname);
        g_selfCallDepth--;
        g_ifHookDepth--;
        if (hide) return 0;
    }
    return orig_if_nametoindex ? orig_if_nametoindex(ifname) : 0;
}

static struct if_nameindex *(*orig_if_nameindex)(void) = NULL;
static struct if_nameindex *hook_if_nameindex(void) {
    if (!orig_if_nameindex) return NULL;
    struct if_nameindex *list = orig_if_nameindex();
    if (!list || g_selfCallDepth > 0 || g_ifHookDepth > 0) return list;
    g_ifHookDepth++;
    g_selfCallDepth++;
    if (IsProxyStealthEnabled()) {
        size_t w = 0;
        for (size_t i = 0; list[i].if_index != 0 || list[i].if_name != NULL; i++) {
            if (!IsVirtualVPNInterface(list[i].if_name)) {
                list[w++] = list[i];
            }
        }
        list[w].if_index = 0;
        list[w].if_name = NULL;
    }
    g_selfCallDepth--;
    g_ifHookDepth--;
    return list;
}

// ============================================================================
// 12. URL Scheme 与已安装越狱/代理应用探测拦截
// ============================================================================

static BOOL IsBlockedURLScheme(NSString *scheme) {
    if (scheme.length == 0) return NO;
    static NSSet *blocked = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        blocked = [NSSet setWithArray:@[
            @"apple-magnifier", @"sileo", @"zbra", @"zebra", @"cydia",
            @"filza", @"santander", @"trollstore", @"dopamine", @"roothide", @"choicy",
            @"geranium", @"locsim", @"shadowrocket", @"quantumult", @"surge", @"loon",
            @"stash", @"potatso", @"clash", @"v2box", @"hiddify", @"streisand", @"karing", @"sing-box"
        ]];
    });
    return [blocked containsObject:scheme.lowercaseString];
}

static BOOL IsBlockedBundleIdentifier(NSString *bundleId) {
    if (bundleId.length == 0) return NO;
    NSString *lower = bundleId.lowercaseString;
    static NSArray<NSString *> *keywords = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        keywords = @[
            @"sileo", @"zebra", @"cydia", @"filza", @"trollstore", @"dopamine",
            @"roothide", @"choicy", @"geranium", @"autoiploc", @"shadowrocket",
            @"quantumult", @"surge", @"loon", @"stash", @"v2box", @"karing"
        ];
    });
    for (NSString *kw in keywords) {
        if ([lower containsString:kw]) return YES;
    }
    return NO;
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

static BOOL (*orig_appIsInstalled)(id self, SEL _cmd, NSString *bundleId) = NULL;
static BOOL hook_appIsInstalled(id self, SEL _cmd, NSString *bundleId) {
    if (IsBlockedBundleIdentifier(bundleId)) return NO;
    return orig_appIsInstalled ? orig_appIsInstalled(self, _cmd, bundleId) : NO;
}

// ============================================================================
// 13. 模拟定位标记抹除（纯 void* 精确桥接，100% 平衡 ARC 引用计数）
// ============================================================================

static BOOL hook_returnNO(id self, SEL _cmd) {
    return NO;
}

typedef void *(*orig_initWithSimState_t)(void *selfPtr, SEL _cmd, BOOL isSimulated, BOOL isAccessory);
static orig_initWithSimState_t orig_initWithSimState = NULL;

static void *hook_initWithSimState(void *selfPtr, SEL _cmd, BOOL isSimulated, BOOL isAccessory) {
    if (orig_initWithSimState) return orig_initWithSimState(selfPtr, _cmd, NO, NO);
    return selfPtr;
}

static id CreateCleanLocationSourceInfo(void) {
    Class srcInfoCls = objc_getClass("CLLocationSourceInformation");
    if (!srcInfoCls) return nil;
    SEL initSel = NSSelectorFromString(@"initWithSoftwareSimulationState:externalAccessoryState:");
    if ([srcInfoCls instancesRespondToSelector:initSel]) {
        void *rawAlloc = ((void *(*)(Class, SEL))objc_msgSend)(srcInfoCls, @selector(alloc));
        if (!rawAlloc) return nil;
        void *rawInit = orig_initWithSimState
            ? orig_initWithSimState(rawAlloc, initSel, NO, NO)
            : ((void *(*)(void *, SEL, BOOL, BOOL))objc_msgSend)(rawAlloc, initSel, NO, NO);
        return (__bridge_transfer id)rawInit;
    }
    return [[srcInfoCls alloc] init];
}

typedef void *(*orig_initWithCoder_t)(void *selfPtr, SEL _cmd, void *coderPtr);
static orig_initWithCoder_t orig_srcInfoInitWithCoder = NULL;

static void *hook_srcInfoInitWithCoder(void *selfPtr, SEL _cmd, void *coderPtr) {
    void *origObj = orig_srcInfoInitWithCoder ? orig_srcInfoInitWithCoder(selfPtr, _cmd, coderPtr) : selfPtr;
    id clean = CreateCleanLocationSourceInfo();
    if (clean) {
        if (origObj) {
            id consumed = (__bridge_transfer id)origObj;
            (void)consumed;
        }
        return (__bridge_retained void *)clean;
    }
    return origObj;
}

static id (*orig_sourceInformation)(id self, SEL _cmd) = NULL;
static id hook_sourceInformation(id self, SEL _cmd) {
    id clean = CreateCleanLocationSourceInfo();
    if (clean) return clean;
    return orig_sourceInformation ? orig_sourceInformation(self, _cmd) : nil;
}

typedef void *(*orig_copyWithZone_t)(void *selfPtr, SEL _cmd, NSZone *zone);
static orig_copyWithZone_t orig_srcInfoCopyWithZone = NULL;

static void *hook_srcInfoCopyWithZone(void *selfPtr, SEL _cmd, NSZone *zone) {
    id clean = CreateCleanLocationSourceInfo();
    if (clean) return (__bridge_retained void *)clean;
    if (orig_srcInfoCopyWithZone) return orig_srcInfoCopyWithZone(selfPtr, _cmd, zone);
    return (__bridge_retained void *)(__bridge id)selfPtr;
}

static orig_initWithCoder_t orig_locInitWithCoder = NULL;
static void *hook_locInitWithCoder(void *selfPtr, SEL _cmd, void *coderPtr) {
    void *rawObj = orig_locInitWithCoder ? orig_locInitWithCoder(selfPtr, _cmd, coderPtr) : selfPtr;
    if (rawObj) {
        id obj = (__bridge id)rawObj;
        Ivar ivar = class_getInstanceVariable([CLLocation class], "_sourceInformation");
        if (ivar) {
            id clean = CreateCleanLocationSourceInfo();
            if (clean) object_setIvar(obj, ivar, clean);
        }
    }
    return rawObj;
}

// ============================================================================
// 14. GeoServices 国家与地区码伪造
// ============================================================================

#define DEFINE_GEO_CC_HOOK(name) \
static NSString *(*orig_##name)(id self, SEL _cmd) = NULL; \
static NSString *hook_##name(id self, SEL _cmd) { \
    if (g_selfCallDepth == 0 && IsGeoSpoofEnabled()) return GetTargetCountryCode(); \
    return orig_##name ? orig_##name(self, _cmd) : @"US"; \
}

DEFINE_GEO_CC_HOOK(geo_countryCode)
DEFINE_GEO_CC_HOOK(geo__countryCode)
DEFINE_GEO_CC_HOOK(geo_currentCountryCode)
DEFINE_GEO_CC_HOOK(geo_sourceCountryCode)

static BOOL (*orig_isChina)(id self, SEL _cmd) = NULL;
static BOOL hook_isChina(id self, SEL _cmd) {
    if (g_selfCallDepth == 0 && IsGeoSpoofEnabled()) return NO;
    return orig_isChina ? orig_isChina(self, _cmd) : NO;
}

static void InstallGeoServicesHooks(void) {
    dlopen("/System/Library/PrivateFrameworks/GeoServices.framework/GeoServices", RTLD_NOW);
    Class geoCls = objc_getClass("GEOCountryConfiguration");
    if (geoCls) {
        HookObjCMethod(geoCls, NSSelectorFromString(@"countryCode"), (IMP)hook_geo_countryCode, (IMP *)&orig_geo_countryCode);
        HookObjCMethod(geoCls, NSSelectorFromString(@"_countryCode"), (IMP)hook_geo__countryCode, (IMP *)&orig_geo__countryCode);
        HookObjCMethod(geoCls, NSSelectorFromString(@"currentCountryCode"), (IMP)hook_geo_currentCountryCode, (IMP *)&orig_geo_currentCountryCode);
        HookObjCMethod(geoCls, NSSelectorFromString(@"sourceCountryCode"), (IMP)hook_geo_sourceCountryCode, (IMP *)&orig_geo_sourceCountryCode);
    }
    Class platformCls = objc_getClass("GEOPlatform");
    if (platformCls) {
        HookObjCMethod(platformCls, NSSelectorFromString(@"isChina"), (IMP)hook_isChina, (IMP *)&orig_isChina);
    }
}

// ============================================================================
// 15. Wi-Fi 伪造（CaptiveNetwork 原生三字段 + iOS 15+ NEHotspotNetwork）
// ============================================================================

static NSArray<NSDictionary *> *GetMockWiFiList(void) {
    NSDictionary *wifiCfg = LoadWiFiConfig();
    if ([wifiCfg[@"enabled"] boolValue]) {
        NSArray *nets = wifiCfg[@"networks"];
        if ([nets isKindOfClass:[NSArray class]] && nets.count > 0) return nets;
    }
    return nil;
}

static CFArrayRef (*orig_CNCopySupportedInterfaces)(void) = NULL;
static CFArrayRef hook_CNCopySupportedInterfaces(void) {
    if (g_selfCallDepth == 0 && g_wifiHookDepth == 0) {
        g_wifiHookDepth++;
        g_selfCallDepth++;
        BOOL hasMock = (GetMockWiFiList() != nil);
        g_selfCallDepth--;
        g_wifiHookDepth--;
        if (hasMock) return (__bridge_retained CFArrayRef)@[@"en0"];
    }
    return orig_CNCopySupportedInterfaces ? orig_CNCopySupportedInterfaces() : (__bridge_retained CFArrayRef)@[@"en0"];
}

static CFDictionaryRef (*orig_CNCopyCurrentNetworkInfo)(CFStringRef interfaceName) = NULL;
static CFDictionaryRef hook_CNCopyCurrentNetworkInfo(CFStringRef interfaceName) {
    if (g_selfCallDepth == 0 && g_wifiHookDepth == 0) {
        g_wifiHookDepth++;
        g_selfCallDepth++;
        NSArray<NSDictionary *> *nets = GetMockWiFiList();
        NSDictionary *result = nil;
        if (nets.count > 0) {
            NSDictionary *topAP = nets[0];
            NSString *ssid = topAP[@"SSID"] ?: @"NETGEAR-C27B-5G";
            NSString *bssid = topAP[@"BSSID"] ?: @"20:4E:7F:67:BC:7F";
            result = @{
                (__bridge NSString *)kCNNetworkInfoKeySSID: ssid,
                (__bridge NSString *)kCNNetworkInfoKeyBSSID: bssid,
                (__bridge NSString *)kCNNetworkInfoKeySSIDData: [ssid dataUsingEncoding:NSUTF8StringEncoding]
            };
        }
        g_selfCallDepth--;
        g_wifiHookDepth--;
        if (result) return (__bridge_retained CFDictionaryRef)result;
    }
    return orig_CNCopyCurrentNetworkInfo ? orig_CNCopyCurrentNetworkInfo(interfaceName) : NULL;
}

static NSString *(*orig_hotspotSSID)(id self, SEL _cmd) = NULL;
static NSString *hook_hotspotSSID(id self, SEL _cmd) {
    if (g_selfCallDepth == 0 && g_wifiHookDepth == 0) {
        g_wifiHookDepth++;
        g_selfCallDepth++;
        NSArray<NSDictionary *> *nets = GetMockWiFiList();
        NSString *ssid = (nets.count > 0) ? nets[0][@"SSID"] : nil;
        g_selfCallDepth--;
        g_wifiHookDepth--;
        if (ssid) return ssid;
    }
    return orig_hotspotSSID ? orig_hotspotSSID(self, _cmd) : nil;
}

static NSString *(*orig_hotspotBSSID)(id self, SEL _cmd) = NULL;
static NSString *hook_hotspotBSSID(id self, SEL _cmd) {
    if (g_selfCallDepth == 0 && g_wifiHookDepth == 0) {
        g_wifiHookDepth++;
        g_selfCallDepth++;
        NSArray<NSDictionary *> *nets = GetMockWiFiList();
        NSString *bssid = (nets.count > 0) ? nets[0][@"BSSID"] : nil;
        g_selfCallDepth--;
        g_wifiHookDepth--;
        if (bssid) return bssid;
    }
    return orig_hotspotBSSID ? orig_hotspotBSSID(self, _cmd) : nil;
}

// ============================================================================
// 16. 跨沙盒实时心跳上报（自身沙盒 Caches/tmp + 持久 Darwin token）
// ============================================================================

static int g_hbNotifyToken = 0;
static BOOL g_hbNotifyRegistered = NO;
static char g_hbProgName[128] = {0};
static BOOL g_hbCHookReady = NO;

static void PublishHookHeartbeat(const char *prog, BOOL cHookReady) {
    g_selfCallDepth++;

    uint64_t ts = (uint64_t)[[NSDate date] timeIntervalSince1970];
    uint64_t state = ((uint64_t)(HOOK_VER_MAJOR & 0xFF) << 56) |
                     ((uint64_t)(HOOK_VER_MINOR & 0xFF) << 48) |
                     ((uint64_t)(HOOK_VER_PATCH & 0x7F) << 41) |
                     ((uint64_t)(cHookReady ? 1 : 0) << 40) |
                     (ts & 0xFFFFFFFFFFULL);

    if (!g_hbNotifyRegistered) {
        if (notify_register_check("com.autoiploc.hook.heartbeat", &g_hbNotifyToken) == NOTIFY_STATUS_OK) {
            g_hbNotifyRegistered = YES;
        }
    }
    if (g_hbNotifyRegistered) {
        notify_set_state(g_hbNotifyToken, state);
        notify_post("com.autoiploc.hook.heartbeat");
    }

    NSString *bundleId = [[NSBundle mainBundle] bundleIdentifier] ?: @"";
    NSDictionary *status = @{
        @"active": @YES,
        @"version": HOOK_VER_STR,
        @"schemaVersion": @(HOOK_SCHEMA),
        @"lastProc": [NSString stringWithUTF8String:(prog && prog[0]) ? prog : "App"],
        @"bundleId": bundleId,
        @"cHookReady": @(cHookReady),
        @"timestamp": @((double)ts)
    };

    NSData *plistData = [NSPropertyListSerialization dataWithPropertyList:status
                                                                   format:NSPropertyListXMLFormat_v1_0
                                                                  options:0
                                                                    error:nil];
    if (plistData) {
        NSString *cachesDir = NSSearchPathForDirectoriesInDomains(NSCachesDirectory, NSUserDomainMask, YES).firstObject;
        if (cachesDir.length > 0) {
            [[NSFileManager defaultManager] createDirectoryAtPath:cachesDir withIntermediateDirectories:YES attributes:nil error:nil];
            NSString *cacheFile = [cachesDir stringByAppendingPathComponent:@"com.autoiploc.hookstatus.plist"];
            [plistData writeToFile:cacheFile options:NSDataWritingFileProtectionNone error:nil];
        }
        NSString *tmpDir = NSTemporaryDirectory();
        if (tmpDir.length > 0) {
            NSString *tmpFile = [tmpDir stringByAppendingPathComponent:@"com.autoiploc.hookstatus.plist"];
            [plistData writeToFile:tmpFile options:NSDataWritingFileProtectionNone error:nil];
        }
    }

    if (g_selfDirPath[0] != '\0') {
        char selfStatusPath[1024] = {0};
        snprintf(selfStatusPath, sizeof(selfStatusPath), "%s/AutoIPLoc.hookstatus.plist", g_selfDirPath);
        [status writeToFile:[NSString stringWithUTF8String:selfStatusPath] atomically:NO];
    }
    [status writeToFile:@"/var/tmp/com.autoiploc.hookstatus.plist" atomically:NO];

    g_selfCallDepth--;
}

// ============================================================================
// 17. 入口构造器
// ============================================================================

__attribute__((constructor))
static void AutoIPLocHookEntry(void) {
    @autoreleasepool {
        const char *prog = getprogname();
        if (!prog) return;

        CaptureSelfDirectory((void *)&AutoIPLocHookEntry);

        static const char *kSkipProcs[] = {
            "SpringBoard", "backboardd", "Preferences", "AutoIPLoc",
            "Shadowrocket", "QuantumultX", "Surge", "Loon", "Stash", "SingBox", "Karing",
            "Dopamine", "Sileo", "Zebra", "TrollStore", "Filza", "RootHide", "Bootstrap",
            "NewTerm", "Terminal", "amg"
        };
        size_t skipCount = sizeof(kSkipProcs) / sizeof(kSkipProcs[0]);
        for (size_t i = 0; i < skipCount; i++) {
            if (strcmp(prog, kSkipProcs[i]) == 0) return;
        }

        char execBuf[1024] = {0};
        uint32_t execSize = sizeof(execBuf);
        if (_NSGetExecutablePath(execBuf, &execSize) != 0) return;
        if (strstr(execBuf, ".app/") == NULL) return;

        dlopen("/System/Library/Frameworks/CoreLocation.framework/CoreLocation", RTLD_NOW);
        dlopen("/System/Library/Frameworks/CoreTelephony.framework/CoreTelephony", RTLD_NOW);
        ResolveElleKitRuntime((void *)&AutoIPLocHookEntry);

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

        Class localeMeta = objc_getMetaClass("NSLocale");
        if (localeMeta) {
            HookObjCMethod(localeMeta, @selector(currentLocale), (IMP)hook_currentLocale, (IMP *)&orig_currentLocale);
            HookObjCMethod(localeMeta, @selector(autoupdatingCurrentLocale), (IMP)hook_autoupdatingCurrentLocale, (IMP *)&orig_autoupdatingCurrentLocale);
            HookObjCMethod(localeMeta, @selector(preferredLanguages), (IMP)hook_preferredLanguages, (IMP *)&orig_preferredLanguages);
        }
        Class defaultsCls = objc_getClass("NSUserDefaults");
        if (defaultsCls) {
            HookObjCMethod(defaultsCls, @selector(objectForKey:), (IMP)hook_defaultsObjectForKey, (IMP *)&orig_defaultsObjectForKey);
        }
        Class reqCls = objc_getClass("NSMutableURLRequest");
        if (reqCls) {
            HookObjCMethod(reqCls, @selector(setValue:forHTTPHeaderField:), (IMP)hook_reqSetValue, (IMP *)&orig_reqSetValue);
            HookObjCMethod(reqCls, @selector(addValue:forHTTPHeaderField:), (IMP)hook_reqAddValue, (IMP *)&orig_reqAddValue);
        }

        Class procInfoCls = objc_getClass("NSProcessInfo");
        if (procInfoCls) {
            HookObjCMethod(procInfoCls, @selector(environment), (IMP)hook_procEnvironment, (IMP *)&orig_procEnvironment);
        }

        Class deviceCls = objc_getClass("UIDevice");
        if (deviceCls) {
            HookObjCMethod(deviceCls, @selector(name), (IMP)hook_deviceName, (IMP *)&orig_deviceName);
            HookObjCMethod(deviceCls, @selector(identifierForVendor), (IMP)hook_identifierForVendor, (IMP *)&orig_identifierForVendor);
        }
        Class asIdCls = objc_getClass("ASIdentifierManager");
        if (asIdCls) {
            HookObjCMethod(asIdCls, NSSelectorFromString(@"advertisingIdentifier"), (IMP)hook_advertisingIdentifier, (IMP *)&orig_advertisingIdentifier);
        }
        Class inputModeCls = objc_getClass("UITextInputMode");
        if (inputModeCls) {
            HookObjCMethod(inputModeCls, @selector(primaryLanguage), (IMP)hook_primaryLanguage, (IMP *)&orig_primaryLanguage);
        }

        Class wkCls = objc_getClass("WKWebView");
        if (wkCls) {
            HookObjCMethod(wkCls, @selector(initWithFrame:configuration:), (IMP)hook_wkInit, (IMP *)&orig_wkInit);
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
            HookObjCMethod(wsCls, NSSelectorFromString(@"applicationIsInstalled:"), (IMP)hook_appIsInstalled, (IMP *)&orig_appIsInstalled);
        }
        Class fmCls = objc_getClass("NSFileManager");
        if (fmCls) {
            HookObjCMethod(fmCls, @selector(fileExistsAtPath:), (IMP)hook_fileExists, (IMP *)&orig_fileExists);
            HookObjCMethod(fmCls, @selector(fileExistsAtPath:isDirectory:), (IMP)hook_fileExistsIsDir, (IMP *)&orig_fileExistsIsDir);
            HookObjCMethod(fmCls, @selector(isReadableFileAtPath:), (IMP)hook_isReadableFile, (IMP *)&orig_isReadableFile);
            HookObjCMethod(fmCls, @selector(contentsOfDirectoryAtPath:error:), (IMP)hook_contentsOfDir, (IMP *)&orig_contentsOfDir);
        }

        Class sessionCfgCls = objc_getClass("NSURLSessionConfiguration");
        if (sessionCfgCls) {
            HookObjCMethod(sessionCfgCls, @selector(connectionProxyDictionary), (IMP)hook_connectionProxyDictionary, (IMP *)&orig_connectionProxyDictionary);
        }
        Class vpnConnCls = objc_getClass("NEVPNConnection");
        if (vpnConnCls) {
            HookObjCMethod(vpnConnCls, NSSelectorFromString(@"status"), (IMP)hook_vpnStatus, (IMP *)&orig_vpnStatus);
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
            HookObjCMethod(netInfoCls, NSSelectorFromString(@"serviceSubscriberCellularProviders"), (IMP)hook_serviceProviders, (IMP *)&orig_serviceProviders);
            HookObjCMethod(netInfoCls, NSSelectorFromString(@"subscriberCellularProvider"), (IMP)hook_subscriberProvider, (IMP *)&orig_subscriberProvider);
            HookObjCMethod(netInfoCls, NSSelectorFromString(@"serviceCurrentRadioAccessTechnology"), (IMP)hook_serviceRadioTech, (IMP *)&orig_serviceRadioTech);
            HookObjCMethod(netInfoCls, NSSelectorFromString(@"currentRadioAccessTechnology"), (IMP)hook_currentRadioTech, (IMP *)&orig_currentRadioTech);
            HookObjCMethod(netInfoCls, NSSelectorFromString(@"dataServiceIdentifier"), (IMP)hook_dataServiceIdentifier, (IMP *)&orig_dataServiceIdentifier);
        }

        Class hotspotCls = objc_getClass("NEHotspotNetwork");
        if (hotspotCls) {
            HookObjCMethod(hotspotCls, NSSelectorFromString(@"SSID"), (IMP)hook_hotspotSSID, (IMP *)&orig_hotspotSSID);
            HookObjCMethod(hotspotCls, NSSelectorFromString(@"BSSID"), (IMP)hook_hotspotBSSID, (IMP *)&orig_hotspotBSSID);
        }

        Class srcInfoCls = objc_getClass("CLLocationSourceInformation");
        if (srcInfoCls) {
            HookObjCMethod(srcInfoCls, NSSelectorFromString(@"isSimulatedBySoftware"), (IMP)hook_returnNO, NULL);
            HookObjCMethod(srcInfoCls, NSSelectorFromString(@"isProducedByAccessory"), (IMP)hook_returnNO, NULL);
            HookObjCMethod(srcInfoCls, NSSelectorFromString(@"initWithSoftwareSimulationState:externalAccessoryState:"), (IMP)hook_initWithSimState, (IMP *)&orig_initWithSimState);
            HookObjCMethod(srcInfoCls, @selector(initWithCoder:), (IMP)hook_srcInfoInitWithCoder, (IMP *)&orig_srcInfoInitWithCoder);
            HookObjCMethod(srcInfoCls, @selector(copyWithZone:), (IMP)hook_srcInfoCopyWithZone, (IMP *)&orig_srcInfoCopyWithZone);
        }
        Class locCls = objc_getClass("CLLocation");
        if (locCls) {
            HookObjCMethod(locCls, NSSelectorFromString(@"isSimulatedBySoftware"), (IMP)hook_returnNO, NULL);
            HookObjCMethod(locCls, NSSelectorFromString(@"_isSimulated"), (IMP)hook_returnNO, NULL);
            HookObjCMethod(locCls, NSSelectorFromString(@"sourceInformation"), (IMP)hook_sourceInformation, (IMP *)&orig_sourceInformation);
            HookObjCMethod(locCls, @selector(initWithCoder:), (IMP)hook_locInitWithCoder, (IMP *)&orig_locInitWithCoder);
        }

        InstallGeoServicesHooks();

        if (g_MSHookFunction) {
            g_MSHookFunction((void *)getenv, (void *)hook_getenv, (void **)&orig_getenv);

            void *symCFTimeZoneSys = dlsym(RTLD_DEFAULT, "CFTimeZoneCopySystem");
            if (symCFTimeZoneSys) g_MSHookFunction(symCFTimeZoneSys, (void *)hook_CFTimeZoneCopySystem, (void **)&orig_CFTimeZoneCopySystem);

            void *symCFTimeZoneDef = dlsym(RTLD_DEFAULT, "CFTimeZoneCopyDefault");
            if (symCFTimeZoneDef) g_MSHookFunction(symCFTimeZoneDef, (void *)hook_CFTimeZoneCopyDefault, (void **)&orig_CFTimeZoneCopyDefault);

            void *symCFLocaleCur = dlsym(RTLD_DEFAULT, "CFLocaleCopyCurrent");
            if (symCFLocaleCur) g_MSHookFunction(symCFLocaleCur, (void *)hook_CFLocaleCopyCurrent, (void **)&orig_CFLocaleCopyCurrent);

            void *symCFLocaleLangs = dlsym(RTLD_DEFAULT, "CFLocaleCopyPreferredLanguages");
            if (symCFLocaleLangs) g_MSHookFunction(symCFLocaleLangs, (void *)hook_CFLocaleCopyPreferredLanguages, (void **)&orig_CFLocaleCopyPreferredLanguages);

            g_MSHookFunction((void *)CFNetworkCopySystemProxySettings, (void *)hook_CFNetworkCopySystemProxySettings, (void **)&orig_CFNetworkCopySystemProxySettings);

            void *symSCDyn = dlsym(RTLD_DEFAULT, "SCDynamicStoreCopyProxies");
            if (symSCDyn) g_MSHookFunction(symSCDyn, (void *)hook_SCDynamicStoreCopyProxies, (void **)&orig_SCDynamicStoreCopyProxies);

            g_MSHookFunction((void *)getifaddrs, (void *)hook_getifaddrs, (void **)&orig_getifaddrs);
            g_MSHookFunction((void *)if_nametoindex, (void *)hook_if_nametoindex, (void **)&orig_if_nametoindex);
            g_MSHookFunction((void *)if_nameindex, (void *)hook_if_nameindex, (void **)&orig_if_nameindex);

            g_MSHookFunction((void *)CNCopyCurrentNetworkInfo, (void *)hook_CNCopyCurrentNetworkInfo, (void **)&orig_CNCopyCurrentNetworkInfo);
            g_MSHookFunction((void *)CNCopySupportedInterfaces, (void *)hook_CNCopySupportedInterfaces, (void **)&orig_CNCopySupportedInterfaces);
        }

        strlcpy(g_hbProgName, prog, sizeof(g_hbProgName));
        g_hbCHookReady = (g_MSHookFunction != NULL && g_MSHookMessageEx != NULL);
        PublishHookHeartbeat(g_hbProgName, g_hbCHookReady);

        [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidBecomeActiveNotification
                                                          object:nil
                                                           queue:nil
                                                      usingBlock:^(__unused NSNotification *note) {
            PublishHookHeartbeat(g_hbProgName, g_hbCHookReady);
        }];
    }
}
