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
#import <os/lock.h>
#import <ifaddrs.h>
#import <dlfcn.h>
#import <dirent.h>
#import <sys/stat.h>
#import <unistd.h>
#import <errno.h>
#import <stdlib.h>
#import <string.h>

#if __has_feature(ptrauth_calls)
#include <ptrauth.h>
#endif

typedef void (*MSHookFunction_t)(void *symbol, void *replace, void **result);
typedef void (*MSHookMessageEx_t)(Class _class, SEL message, IMP hook, IMP *old);

static MSHookFunction_t g_MSHookFunction = NULL;
static MSHookMessageEx_t g_MSHookMessageEx = NULL;
static int (*orig_dladdr)(const void *addr, Dl_info *info) = NULL;

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
static _Thread_local int g_localeHookDepth = 0;

// ============================================================================
// 2. ElleKit / Substrate 动态解析
// ============================================================================

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

    NSString *savedRoot = [NSString stringWithContentsOfFile:@"/var/tmp/com.autoiploc.jbroot.txt" encoding:NSUTF8StringEncoding error:nil];
    if (savedRoot.length > 0) {
        NSString *trimmed = [savedRoot stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
        if (TryLoadElleKitFromRoot(trimmed.UTF8String)) {
            g_selfCallDepth--;
            return;
        }
    }

    Dl_info selfInfo;
    void *cleanSelfAddr = StripFunctionPointerPAC(selfSymbolAddr);
    if (dladdr(cleanSelfAddr, &selfInfo) != 0 && selfInfo.dli_fname != NULL) {
        const char *libMarker = strstr(selfInfo.dli_fname, "/Library/");
        if (libMarker != NULL) {
            size_t rootLen = (size_t)(libMarker - selfInfo.dli_fname);
            if (rootLen > 0 && rootLen < 512) {
                char jbRoot[512] = {0};
                memcpy(jbRoot, selfInfo.dli_fname, rootLen);
                if (TryLoadElleKitFromRoot(jbRoot)) {
                    g_selfCallDepth--;
                    return;
                }
            }
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
// 3. 带内存缓存与 TLS 放行的配置读取（3秒 TTL，无锁内磁盘 I/O）
// ============================================================================

static os_unfair_lock g_cfgLock = OS_UNFAIR_LOCK_INIT;
static NSDictionary *g_cachedGeo = nil;
static CFAbsoluteTime g_lastGeoLoad = 0;
static NSDictionary *g_cachedWiFi = nil;
static CFAbsoluteTime g_lastWiFiLoad = 0;
static const CFAbsoluteTime kConfigCacheTTL = 3.0;

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
    NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:@"/var/mobile/Library/Preferences/com.autoiploc.geo.plist"];
    if (!d) d = [NSDictionary dictionaryWithContentsOfFile:@"/var/tmp/com.autoiploc.geo.plist"];
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
    NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:@"/var/mobile/Library/Preferences/com.autoiploc.wifi.plist"];
    if (!d) d = [NSDictionary dictionaryWithContentsOfFile:@"/var/tmp/com.autoiploc.wifi.plist"];
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

// ============================================================================
// 4. 国家 -> 运营商 & 语言区域联合映射表
// ============================================================================

typedef struct {
    const char *cc;
    const char *carrier;
    const char *mcc;
    const char *mnc;
    const char *localeId;
    const char *langCode;
} CountryProfilePreset;

static const CountryProfilePreset *GetCountryPresetForTarget(void) {
    static const CountryProfilePreset kPresets[] = {
        {"US", "T-Mobile",    "310", "260", "en_US", "en-US"},
        {"GB", "Vodafone UK", "234", "15",  "en_GB", "en-GB"},
        {"CA", "Rogers",      "302", "720", "en_CA", "en-CA"},
        {"AU", "Telstra",     "505", "01",  "en_AU", "en-AU"},
        {"JP", "NTT DOCOMO",  "440", "10",  "ja_JP", "ja-JP"},
        {"DE", "Telekom.de",  "262", "01",  "de_DE", "de-DE"},
        {"FR", "Orange F",    "208", "01",  "fr_FR", "fr-FR"},
        {"SG", "Singtel",     "525", "01",  "en_SG", "en-SG"},
        {"KR", "SKTelecom",   "450", "05",  "ko_KR", "ko-KR"},
        {"TW", "Chunghwa",    "466", "92",  "zh_TW", "zh-Hant-TW"},
        {"NL", "KPN",         "204", "08",  "nl_NL", "nl-NL"},
        {"IT", "TIM",         "222", "01",  "it_IT", "it-IT"},
        {"ES", "Movistar",    "214", "07",  "es_ES", "es-ES"},
        {"BR", "Vivo",        "724", "06",  "pt_BR", "pt-BR"}
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
// 5. 反越狱与路径隐身（统一使用 TLS g_selfCallDepth 放行）
// ============================================================================

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
    if (g_selfCallDepth == 0 && IsSensitiveDylibPath(name)) {
        return "/usr/lib/libobjc.A.dylib";
    }
    return name;
}

static int hook_dladdr(const void *addr, Dl_info *info) {
    int ret = orig_dladdr ? orig_dladdr(addr, info) : dladdr(addr, info);
    if (g_selfCallDepth == 0 && ret != 0 && info && info->dli_fname && IsSensitiveDylibPath(info->dli_fname)) {
        info->dli_fname = "/usr/lib/libobjc.A.dylib";
    }
    return ret;
}

static char *(*orig_getenv)(const char *name) = NULL;
static char *hook_getenv(const char *name) {
    if (g_selfCallDepth == 0 && name &&
        (strcmp(name, "DYLD_INSERT_LIBRARIES") == 0 ||
         strcmp(name, "_MSSafeMode") == 0 ||
         strcmp(name, "SUBSTRATE_SAFE_MODE") == 0 ||
         strcmp(name, "JBROOT") == 0)) {
        return NULL;
    }
    return orig_getenv ? orig_getenv(name) : getenv(name);
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
            strstr(path, "Geranium") != NULL ||
            strstr(path, "/usr/bin/sshd") != NULL ||
            strstr(path, "/etc/apt") != NULL ||
            strstr(path, "/bin/bash") != NULL ||
            strstr(path, "/bin/sh") != NULL ||
            strstr(path, "autoiploc") != NULL);
}

static int (*orig_access)(const char *path, int mode) = NULL;
static int hook_access(const char *path, int mode) {
    if (g_selfCallDepth == 0 && IsJailbreakPath(path)) {
        errno = ENOENT;
        return -1;
    }
    return orig_access ? orig_access(path, mode) : access(path, mode);
}

static int (*orig_stat)(const char *path, struct stat *buf) = NULL;
static int hook_stat(const char *path, struct stat *buf) {
    if (g_selfCallDepth == 0 && IsJailbreakPath(path)) {
        errno = ENOENT;
        return -1;
    }
    return orig_stat ? orig_stat(path, buf) : stat(path, buf);
}

static int (*orig_lstat)(const char *path, struct stat *buf) = NULL;
static int hook_lstat(const char *path, struct stat *buf) {
    if (g_selfCallDepth == 0 && IsJailbreakPath(path)) {
        errno = ENOENT;
        return -1;
    }
    return orig_lstat ? orig_lstat(path, buf) : lstat(path, buf);
}

static FILE *(*orig_fopen)(const char *filename, const char *mode) = NULL;
static FILE *hook_fopen(const char *filename, const char *mode) {
    if (g_selfCallDepth == 0 && IsJailbreakPath(filename)) {
        errno = ENOENT;
        return NULL;
    }
    return orig_fopen ? orig_fopen(filename, mode) : fopen(filename, mode);
}

static DIR *(*orig_opendir)(const char *filename) = NULL;
static DIR *hook_opendir(const char *filename) {
    if (g_selfCallDepth == 0 && IsJailbreakPath(filename)) {
        errno = ENOENT;
        return NULL;
    }
    return orig_opendir ? orig_opendir(filename) : opendir(filename);
}

static BOOL (*orig_fileExists)(id self, SEL _cmd, NSString *path) = NULL;
static BOOL hook_fileExists(id self, SEL _cmd, NSString *path) {
    if (g_selfCallDepth == 0 && IsJailbreakPath(path.UTF8String)) {
        return NO;
    }
    return orig_fileExists ? orig_fileExists(self, _cmd, path) : NO;
}

static BOOL (*orig_fileExistsIsDir)(id self, SEL _cmd, NSString *path, BOOL *isDir) = NULL;
static BOOL hook_fileExistsIsDir(id self, SEL _cmd, NSString *path, BOOL *isDir) {
    if (g_selfCallDepth == 0 && IsJailbreakPath(path.UTF8String)) {
        return NO;
    }
    return orig_fileExistsIsDir ? orig_fileExistsIsDir(self, _cmd, path, isDir) : NO;
}

static pid_t (*orig_fork)(void) = NULL;
static pid_t hook_fork(void) {
    errno = EPERM;
    return -1;
}

// ============================================================================
// 6. 全局时区伪造
// ============================================================================

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

static CFTimeZoneRef (*orig_CFTimeZoneCopyDefault)(void) = NULL;
static CFTimeZoneRef hook_CFTimeZoneCopyDefault(void) {
    NSString *tzName = GetTargetTimeZoneName();
    if (tzName) {
        CFTimeZoneRef tz = CFTimeZoneCreateWithName(kCFAllocatorDefault, (__bridge CFStringRef)tzName, true);
        if (tz) return tz;
    }
    return orig_CFTimeZoneCopyDefault ? orig_CFTimeZoneCopyDefault() : CFTimeZoneCopyDefault();
}

// ============================================================================
// 7. 语言与区域伪造（NSLocale & CFLocale，带防递归守卫）
// ============================================================================

static NSLocale *(*orig_currentLocale)(id self, SEL _cmd) = NULL;
static NSLocale *hook_currentLocale(id self, SEL _cmd) {
    if (g_localeHookDepth == 0 && IsGeoSpoofEnabled()) {
        const CountryProfilePreset *p = GetCountryPresetForTarget();
        g_localeHookDepth++;
        NSLocale *loc = [NSLocale localeWithLocaleIdentifier:[NSString stringWithUTF8String:p->localeId]];
        g_localeHookDepth--;
        if (loc) return loc;
    }
    return orig_currentLocale ? orig_currentLocale(self, _cmd) : [NSLocale systemLocale];
}

static NSLocale *(*orig_autoupdatingCurrentLocale)(id self, SEL _cmd) = NULL;
static NSLocale *hook_autoupdatingCurrentLocale(id self, SEL _cmd) {
    if (g_localeHookDepth == 0 && IsGeoSpoofEnabled()) {
        const CountryProfilePreset *p = GetCountryPresetForTarget();
        g_localeHookDepth++;
        NSLocale *loc = [NSLocale localeWithLocaleIdentifier:[NSString stringWithUTF8String:p->localeId]];
        g_localeHookDepth--;
        if (loc) return loc;
    }
    return orig_autoupdatingCurrentLocale ? orig_autoupdatingCurrentLocale(self, _cmd) : [NSLocale systemLocale];
}

static NSArray<NSString *> *(*orig_preferredLanguages)(id self, SEL _cmd) = NULL;
static NSArray<NSString *> *hook_preferredLanguages(id self, SEL _cmd) {
    if (g_localeHookDepth == 0 && IsGeoSpoofEnabled()) {
        const CountryProfilePreset *p = GetCountryPresetForTarget();
        NSString *primary = [NSString stringWithUTF8String:p->langCode];
        return [primary isEqualToString:@"en-US"] ? @[primary] : @[primary, @"en-US"];
    }
    return orig_preferredLanguages ? orig_preferredLanguages(self, _cmd) : @[@"en-US"];
}

static CFLocaleRef (*orig_CFLocaleCopyCurrent)(void) = NULL;
static CFLocaleRef hook_CFLocaleCopyCurrent(void) {
    if (g_localeHookDepth == 0 && IsGeoSpoofEnabled()) {
        const CountryProfilePreset *p = GetCountryPresetForTarget();
        g_localeHookDepth++;
        CFStringRef locStr = CFStringCreateWithCString(kCFAllocatorDefault, p->localeId, kCFStringEncodingUTF8);
        CFLocaleRef loc = locStr ? CFLocaleCreate(kCFAllocatorDefault, locStr) : NULL;
        if (locStr) CFRelease(locStr);
        g_localeHookDepth--;
        if (loc) return loc;
    }
    return orig_CFLocaleCopyCurrent ? orig_CFLocaleCopyCurrent() : CFLocaleCopyCurrent();
}

static CFArrayRef (*orig_CFLocaleCopyPreferredLanguages)(void) = NULL;
static CFArrayRef hook_CFLocaleCopyPreferredLanguages(void) {
    if (g_localeHookDepth == 0 && IsGeoSpoofEnabled()) {
        const CountryProfilePreset *p = GetCountryPresetForTarget();
        NSString *primary = [NSString stringWithUTF8String:p->langCode];
        NSArray<NSString *> *langs = [primary isEqualToString:@"en-US"] ? @[primary] : @[primary, @"en-US"];
        return (__bridge_retained CFArrayRef)langs;
    }
    return orig_CFLocaleCopyPreferredLanguages ? orig_CFLocaleCopyPreferredLanguages() : CFLocaleCopyPreferredLanguages();
}

// ============================================================================
// 8. 运营商伪造（按目标国家码动态映射，联动启停开关）
// ============================================================================

static NSString *(*orig_carrierName)(id self, SEL _cmd) = NULL;
static NSString *hook_carrierName(id self, SEL _cmd) {
    if (IsGeoSpoofEnabled()) {
        const CountryProfilePreset *p = GetCountryPresetForTarget();
        return [NSString stringWithUTF8String:p->carrier];
    }
    return orig_carrierName ? orig_carrierName(self, _cmd) : nil;
}

static NSString *(*orig_mobileCountryCode)(id self, SEL _cmd) = NULL;
static NSString *hook_mobileCountryCode(id self, SEL _cmd) {
    if (IsGeoSpoofEnabled()) {
        const CountryProfilePreset *p = GetCountryPresetForTarget();
        return [NSString stringWithUTF8String:p->mcc];
    }
    return orig_mobileCountryCode ? orig_mobileCountryCode(self, _cmd) : nil;
}

static NSString *(*orig_mobileNetworkCode)(id self, SEL _cmd) = NULL;
static NSString *hook_mobileNetworkCode(id self, SEL _cmd) {
    if (IsGeoSpoofEnabled()) {
        const CountryProfilePreset *p = GetCountryPresetForTarget();
        return [NSString stringWithUTF8String:p->mnc];
    }
    return orig_mobileNetworkCode ? orig_mobileNetworkCode(self, _cmd) : nil;
}

static NSString *(*orig_isoCountryCode)(id self, SEL _cmd) = NULL;
static NSString *hook_isoCountryCode(id self, SEL _cmd) {
    if (IsGeoSpoofEnabled()) {
        return GetTargetCountryCode().lowercaseString;
    }
    return orig_isoCountryCode ? orig_isoCountryCode(self, _cmd) : nil;
}

static NSDictionary<NSString *, NSString *> *(*orig_serviceRadioTech)(id self, SEL _cmd) = NULL;
static NSDictionary<NSString *, NSString *> *hook_serviceRadioTech(id self, SEL _cmd) {
    NSDictionary<NSString *, NSString *> *orig = orig_serviceRadioTech ? orig_serviceRadioTech(self, _cmd) : nil;
    if (orig.count > 0 || !IsGeoSpoofEnabled()) return orig;
    return @{
        @"0000000100000001": @"CTRadioAccessTechnologyLTE",
        @"0000000100000002": @"CTRadioAccessTechnologyLTE"
    };
}

static NSString *(*orig_currentRadioTech)(id self, SEL _cmd) = NULL;
static NSString *hook_currentRadioTech(id self, SEL _cmd) {
    NSString *orig = orig_currentRadioTech ? orig_currentRadioTech(self, _cmd) : nil;
    if (orig.length > 0 || !IsGeoSpoofEnabled()) return orig;
    return @"CTRadioAccessTechnologyLTE";
}

static NSString *(*orig_dataServiceIdentifier)(id self, SEL _cmd) = NULL;
static NSString *hook_dataServiceIdentifier(id self, SEL _cmd) {
    NSString *orig = orig_dataServiceIdentifier ? orig_dataServiceIdentifier(self, _cmd) : nil;
    if (orig.length > 0 || !IsGeoSpoofEnabled()) return orig;
    return @"0000000100000002";
}

static BOOL hook_returnYES(id self, SEL _cmd) {
    return YES;
}

// ============================================================================
// 9. 代理与 VPN 网卡隐身（带 PAC 剥离与单节点链表修复）
// ============================================================================

static BOOL IsSystemNetworkingCaller(void *retAddr) {
    void *cleanAddr = StripReturnAddressPAC(retAddr);
    if (!cleanAddr) return NO;
    Dl_info info;
    int ok = orig_dladdr ? orig_dladdr(cleanAddr, &info) : dladdr(cleanAddr, &info);
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
        if (head && IsVirtualVPNInterface(head->ifa_name) && head->ifa_next == NULL) {
            freeifaddrs(*ifap);
            *ifap = NULL;
            return ret;
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

// ============================================================================
// 10. URL Scheme 探测拦截
// ============================================================================

static BOOL IsBlockedURLScheme(NSString *scheme) {
    if (scheme.length == 0) return NO;
    static NSSet *blocked = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        blocked = [NSSet setWithArray:@[
            @"apple-magnifier", @"sileo", @"zbra", @"cydia",
            @"filza", @"santander", @"trollstore", @"dopamine", @"roothide",
            @"geranium", @"locsim", @"shadowrocket", @"quantumult", @"surge", @"loon", @"stash"
        ]];
    });
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

// ============================================================================
// 11. 模拟定位标记抹除（纯 void* 精确桥接，100% 平衡 ARC 引用计数）
// ============================================================================

static BOOL hook_returnNO(id self, SEL _cmd) {
    return NO;
}

typedef void *(*orig_initWithSimState_t)(void *selfPtr, SEL _cmd, BOOL isSimulated, BOOL isAccessory);
static orig_initWithSimState_t orig_initWithSimState = NULL;

static void *hook_initWithSimState(void *selfPtr, SEL _cmd, BOOL isSimulated, BOOL isAccessory) {
    if (orig_initWithSimState) {
        return orig_initWithSimState(selfPtr, _cmd, NO, NO);
    }
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
    if (clean) {
        return (__bridge_retained void *)clean;
    }
    if (orig_srcInfoCopyWithZone) {
        return orig_srcInfoCopyWithZone(selfPtr, _cmd, zone);
    }
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
// 12. GeoServices 国家与地区码伪造
// ============================================================================

#define DEFINE_GEO_CC_HOOK(name) \
static NSString *(*orig_##name)(id self, SEL _cmd) = NULL; \
static NSString *hook_##name(id self, SEL _cmd) { \
    if (IsGeoSpoofEnabled()) return GetTargetCountryCode(); \
    return orig_##name ? orig_##name(self, _cmd) : @"US"; \
}

DEFINE_GEO_CC_HOOK(geo_countryCode)
DEFINE_GEO_CC_HOOK(geo__countryCode)
DEFINE_GEO_CC_HOOK(geo_currentCountryCode)
DEFINE_GEO_CC_HOOK(geo_sourceCountryCode)

static BOOL (*orig_isChina)(id self, SEL _cmd) = NULL;
static BOOL hook_isChina(id self, SEL _cmd) {
    if (IsGeoSpoofEnabled()) return NO;
    return orig_isChina ? orig_isChina(self, _cmd) : NO;
}

// ============================================================================
// 13. Wi-Fi 伪造（仅返回原生合法三字段，无非法扩展 Key）
// ============================================================================

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
        NSString *ssid = topAP[@"SSID"] ?: @"NETGEAR-C27B-5G";
        NSString *bssid = topAP[@"BSSID"] ?: @"20:4E:7F:67:BC:7F";
        NSDictionary *result = @{
            (__bridge NSString *)kCNNetworkInfoKeySSID: ssid,
            (__bridge NSString *)kCNNetworkInfoKeyBSSID: bssid,
            (__bridge NSString *)kCNNetworkInfoKeySSIDData: [ssid dataUsingEncoding:NSUTF8StringEncoding]
        };
        return (__bridge_retained CFDictionaryRef)result;
    }
    return orig_CNCopyCurrentNetworkInfo ? orig_CNCopyCurrentNetworkInfo(interfaceName) : NULL;
}

// ============================================================================
// 14. 入口构造器
// ============================================================================

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
        Class fmCls = objc_getClass("NSFileManager");
        if (fmCls) {
            HookObjCMethod(fmCls, @selector(fileExistsAtPath:), (IMP)hook_fileExists, (IMP *)&orig_fileExists);
            HookObjCMethod(fmCls, @selector(fileExistsAtPath:isDirectory:), (IMP)hook_fileExistsIsDir, (IMP *)&orig_fileExistsIsDir);
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
            HookObjCMethod(netInfoCls, NSSelectorFromString(@"dataServiceIdentifier"), (IMP)hook_dataServiceIdentifier, (IMP *)&orig_dataServiceIdentifier);
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

        if (g_MSHookFunction) {
            g_MSHookFunction((void *)_dyld_get_image_name, (void *)hook_dyld_get_image_name, (void **)&orig_dyld_get_image_name);
            g_MSHookFunction((void *)dladdr, (void *)hook_dladdr, (void **)&orig_dladdr);
            g_MSHookFunction((void *)getenv, (void *)hook_getenv, (void **)&orig_getenv);
            g_MSHookFunction((void *)access, (void *)hook_access, (void **)&orig_access);
            g_MSHookFunction((void *)stat, (void *)hook_stat, (void **)&orig_stat);
            g_MSHookFunction((void *)lstat, (void *)hook_lstat, (void **)&orig_lstat);
            g_MSHookFunction((void *)fopen, (void *)hook_fopen, (void **)&orig_fopen);
            g_MSHookFunction((void *)opendir, (void *)hook_opendir, (void **)&orig_opendir);
            g_MSHookFunction((void *)fork, (void *)hook_fork, (void **)&orig_fork);

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
            g_MSHookFunction((void *)CNCopyCurrentNetworkInfo, (void *)hook_CNCopyCurrentNetworkInfo, (void **)&orig_CNCopyCurrentNetworkInfo);
            g_MSHookFunction((void *)CNCopySupportedInterfaces, (void *)hook_CNCopySupportedInterfaces, (void **)&orig_CNCopySupportedInterfaces);
        }

        // 写入插件激活状态时开启 TLS 自放行，防止被刚挂载的文件 Hook 拦截
        g_selfCallDepth++;
        NSDictionary *status = @{
            @"active": @YES,
            @"version": @"4.4.0",
            @"lastProc": [NSString stringWithUTF8String:prog],
            @"cHookReady": @(g_MSHookFunction != NULL && g_MSHookMessageEx != NULL),
            @"timestamp": @([[NSDate date] timeIntervalSince1970])
        };
        [status writeToFile:@"/var/mobile/Library/Preferences/com.autoiploc.hookstatus.plist" atomically:YES];
        [status writeToFile:@"/var/tmp/com.autoiploc.hookstatus.plist" atomically:YES];
        chmod("/var/tmp/com.autoiploc.hookstatus.plist", 0666);
        g_selfCallDepth--;
    }
}
