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
#import <dirent.h>
#import <sys/stat.h>
#import <unistd.h>
#import <errno.h>
#import <stdlib.h>
#import <string.h>
#import <stdio.h>
#import <stdint.h>
#import <pthread.h>

typedef void (*MSHookFunction_t)(void *symbol, void *replace, void **result);
typedef void (*MSHookMessageEx_t)(Class _class, SEL message, IMP hook, IMP *old);

static MSHookFunction_t g_MSHookFunction = NULL;
static MSHookMessageEx_t g_MSHookMessageEx = NULL;
static int (*orig_dladdr)(const void *addr, Dl_info *info) = NULL;
static unsigned int g_installedCHookCount = 0;
static unsigned int g_installedObjCHookCount = 0;
static __thread unsigned int g_internalIODepth = 0;

static void BeginInternalIO(void) {
    g_internalIODepth++;
}

static void EndInternalIO(void) {
    if (g_internalIODepth > 0) g_internalIODepth--;
}

#define INSTALL_C_FUNCTION_HOOK(target, replacement, originalStorage) \
    do { \
        void *capturedOriginal = NULL; \
        g_MSHookFunction((void *)(target), (void *)(replacement), &capturedOriginal); \
        if (capturedOriginal != NULL) { \
            (originalStorage) = (__typeof__(originalStorage))capturedOriginal; \
            g_installedCHookCount++; \
        } \
    } while (0)

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
        int pathLength = snprintf(fullPath, sizeof(fullPath), "%s%s", jbRoot, relPaths[i]);
        if (pathLength <= 0 || (size_t)pathLength >= sizeof(fullPath)) continue;
        BeginInternalIO();
        void *h = dlopen(fullPath, RTLD_NOW | RTLD_GLOBAL);
        EndInternalIO();
        if (h) {
            if (!g_MSHookFunction) g_MSHookFunction = (MSHookFunction_t)dlsym(h, "MSHookFunction");
            if (!g_MSHookMessageEx) g_MSHookMessageEx = (MSHookMessageEx_t)dlsym(h, "MSHookMessageEx");
            if (g_MSHookFunction && g_MSHookMessageEx) return YES;
        }
    }
    return NO;
}

static void ResolveElleKitRuntime(void *selfSymbolAddr) {
    g_MSHookFunction = (MSHookFunction_t)dlsym(RTLD_DEFAULT, "MSHookFunction");
    g_MSHookMessageEx = (MSHookMessageEx_t)dlsym(RTLD_DEFAULT, "MSHookMessageEx");
    if (!g_MSHookFunction) g_MSHookFunction = (MSHookFunction_t)dlsym(RTLD_NEXT, "MSHookFunction");
    if (!g_MSHookMessageEx) g_MSHookMessageEx = (MSHookMessageEx_t)dlsym(RTLD_NEXT, "MSHookMessageEx");
    if (g_MSHookFunction && g_MSHookMessageEx) return;

    NSString *savedRoot = nil;
    BeginInternalIO();
    @try {
        savedRoot = [NSString stringWithContentsOfFile:@"/var/tmp/com.autoiploc.jbroot.txt"
                                               encoding:NSUTF8StringEncoding
                                                  error:nil];
    } @finally {
        EndInternalIO();
    }
    if (savedRoot.length > 0) {
        NSCharacterSet *separators = [NSCharacterSet whitespaceAndNewlineCharacterSet];
        for (NSString *rawRoot in [savedRoot componentsSeparatedByCharactersInSet:separators]) {
            NSString *trimmed = [rawRoot stringByTrimmingCharactersInSet:separators];
            if (![trimmed hasPrefix:@"/var/containers/Bundle/Application/.jbroot-"]) continue;
            if (TryLoadElleKitFromRoot(trimmed.UTF8String)) return;
        }
    }

    Dl_info selfInfo;
    if (dladdr(selfSymbolAddr, &selfInfo) != 0 && selfInfo.dli_fname != NULL) {
        const char *libMarker = strstr(selfInfo.dli_fname, "/Library/");
        if (libMarker != NULL) {
            size_t rootLen = (size_t)(libMarker - selfInfo.dli_fname);
            if (rootLen > 0 && rootLen < 512) {
                char jbRoot[512] = {0};
                memcpy(jbRoot, selfInfo.dli_fname, rootLen);
                if (TryLoadElleKitFromRoot(jbRoot)) return;
            }
        }
    }

    uint32_t count = _dyld_image_count();
    for (uint32_t i = 1; i < count; i++) {
        const char *img = _dyld_get_image_name(i);
        if (!img) continue;
        if (strstr(img, "ellekit") != NULL || strstr(img, "substrate") != NULL ||
            strstr(img, "Substrate") != NULL || strstr(img, "TweakInject") != NULL) {
            BeginInternalIO();
            void *h = dlopen(img, RTLD_NOLOAD | RTLD_LAZY);
            if (!h) h = dlopen(img, RTLD_NOW | RTLD_GLOBAL);
            EndInternalIO();
            if (h) {
                if (!g_MSHookFunction) g_MSHookFunction = (MSHookFunction_t)dlsym(h, "MSHookFunction");
                if (!g_MSHookMessageEx) g_MSHookMessageEx = (MSHookMessageEx_t)dlsym(h, "MSHookMessageEx");
                if (g_MSHookFunction && g_MSHookMessageEx) return;
            }
        }
    }
}

static char ObjCTypeCode(const char *encoding) {
    if (!encoding) return '\0';
    while (*encoding && strchr("rnNoORV", *encoding) != NULL) encoding++;
    return *encoding;
}

static BOOL ObjCTypeMatches(const char *encoding, char expected) {
    char actual = ObjCTypeCode(encoding);
    if (expected == 'B') return actual == 'B' || actual == 'c';
    return actual == expected;
}

static BOOL MethodHasExpectedSignature(Method method, char expectedReturn, const char *expectedArguments) {
    if (!method || !expectedArguments) return NO;

    size_t expectedArgumentCount = strlen(expectedArguments);
    if (method_getNumberOfArguments(method) != expectedArgumentCount + 2) return NO;

    char *returnType = method_copyReturnType(method);
    char *selfType = method_copyArgumentType(method, 0);
    char *selectorType = method_copyArgumentType(method, 1);

    BOOL matches = ObjCTypeMatches(returnType, expectedReturn) &&
                   (ObjCTypeCode(selfType) == '@' || ObjCTypeCode(selfType) == '#') &&
                   ObjCTypeCode(selectorType) == ':';

    free(returnType);
    free(selfType);
    free(selectorType);
    if (!matches) return NO;

    for (size_t index = 0; index < expectedArgumentCount; index++) {
        char *argumentType = method_copyArgumentType(method, (unsigned int)index + 2);
        matches = ObjCTypeMatches(argumentType, expectedArguments[index]);
        free(argumentType);
        if (!matches) return NO;
    }
    return YES;
}

static BOOL HookObjCMethod(Class cls, SEL sel, IMP newImp, IMP *oldImp,
                           char expectedReturn, const char *expectedArguments) {
    if (!cls || !sel || !newImp) return NO;

    Method method = class_getInstanceMethod(cls, sel);
    if (!MethodHasExpectedSignature(method, expectedReturn, expectedArguments)) return NO;

    IMP previous = method_getImplementation(method);
    if (g_MSHookMessageEx) {
        IMP hookOriginal = NULL;
        g_MSHookMessageEx(cls, sel, newImp, &hookOriginal);
        if (hookOriginal != NULL) previous = hookOriginal;
    } else {
        IMP replaced = method_setImplementation(method, newImp);
        if (replaced != NULL) previous = replaced;
    }

    if (oldImp) *oldImp = previous;
    g_installedObjCHookCount++;
    return YES;
}

#define HOOK_OBJC_METHOD_TYPED(cls, sel, replacement, originalStorage, returnKind, argumentKinds) \
    do { \
        IMP capturedOriginal = NULL; \
        if (HookObjCMethod((cls), (sel), (replacement), &capturedOriginal, (returnKind), (argumentKinds))) { \
            (originalStorage) = (__typeof__(originalStorage))capturedOriginal; \
        } \
    } while (0)

static BOOL IsSelfCaller(void *retAddr) {
    if (!retAddr || !orig_dladdr) return NO;
    Dl_info info;
    int ok = orig_dladdr(retAddr, &info);
    if (ok != 0 && info.dli_fname != NULL) {
        if (strstr(info.dli_fname, "AutoIPLocHook") != NULL) {
            return YES;
        }
    }
    return NO;
}

static NSDictionary *LoadGeoConfig(void) {
    NSDictionary *config = nil;
    BeginInternalIO();
    @try {
        config = [NSDictionary dictionaryWithContentsOfFile:@"/var/mobile/Library/Preferences/com.autoiploc.geo.plist"];
        if (!config) config = [NSDictionary dictionaryWithContentsOfFile:@"/var/tmp/com.autoiploc.geo.plist"];
    } @finally {
        EndInternalIO();
    }
    return config;
}

static NSDictionary *LoadWiFiConfig(void) {
    NSDictionary *config = nil;
    BeginInternalIO();
    @try {
        config = [NSDictionary dictionaryWithContentsOfFile:@"/var/mobile/Library/Preferences/com.autoiploc.wifi.plist"];
        if (!config) config = [NSDictionary dictionaryWithContentsOfFile:@"/var/tmp/com.autoiploc.wifi.plist"];
    } @finally {
        EndInternalIO();
    }
    return config;
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
    if (!orig_dyld_get_image_name) return NULL;
    const char *name = orig_dyld_get_image_name(image_index);
    if (IsSensitiveDylibPath(name)) {
        return "/usr/lib/libobjc.A.dylib";
    }
    return name;
}

static int hook_dladdr(const void *addr, Dl_info *info) {
    if (!orig_dladdr) return 0;
    int ret = orig_dladdr(addr, info);
    if (ret != 0 && info && info->dli_fname && IsSensitiveDylibPath(info->dli_fname)) {
        info->dli_fname = "/usr/lib/libobjc.A.dylib";
    }
    return ret;
}

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
            strstr(path, "Geranium") != NULL ||
            strstr(path, "/usr/bin/sshd") != NULL ||
            strstr(path, "/etc/apt") != NULL ||
            strstr(path, "/bin/bash") != NULL ||
            strstr(path, "/bin/sh") != NULL ||
            strstr(path, "autoiploc") != NULL);
}

static BOOL ShouldHidePath(const char *path, void *returnAddress) {
    if (g_internalIODepth > 0 || IsSelfCaller(returnAddress)) return NO;
    return IsJailbreakPath(path);
}

static int (*orig_access)(const char *path, int mode) = NULL;
static int hook_access(const char *path, int mode) {
    if (ShouldHidePath(path, __builtin_return_address(0))) {
        errno = ENOENT;
        return -1;
    }
    if (!orig_access) { errno = ENOSYS; return -1; }
    return orig_access(path, mode);
}

static int (*orig_stat)(const char *path, struct stat *buf) = NULL;
static int hook_stat(const char *path, struct stat *buf) {
    if (ShouldHidePath(path, __builtin_return_address(0))) {
        errno = ENOENT;
        return -1;
    }
    if (!orig_stat) { errno = ENOSYS; return -1; }
    return orig_stat(path, buf);
}

static int (*orig_lstat)(const char *path, struct stat *buf) = NULL;
static int hook_lstat(const char *path, struct stat *buf) {
    if (ShouldHidePath(path, __builtin_return_address(0))) {
        errno = ENOENT;
        return -1;
    }
    if (!orig_lstat) { errno = ENOSYS; return -1; }
    return orig_lstat(path, buf);
}

static FILE *(*orig_fopen)(const char *filename, const char *mode) = NULL;
static FILE *hook_fopen(const char *filename, const char *mode) {
    if (ShouldHidePath(filename, __builtin_return_address(0))) {
        errno = ENOENT;
        return NULL;
    }
    if (!orig_fopen) { errno = ENOSYS; return NULL; }
    return orig_fopen(filename, mode);
}

static DIR *(*orig_opendir)(const char *filename) = NULL;
static DIR *hook_opendir(const char *filename) {
    if (ShouldHidePath(filename, __builtin_return_address(0))) {
        errno = ENOENT;
        return NULL;
    }
    if (!orig_opendir) { errno = ENOSYS; return NULL; }
    return orig_opendir(filename);
}

static BOOL (*orig_fileExists)(id self, SEL _cmd, NSString *path) = NULL;
static BOOL hook_fileExists(id self, SEL _cmd, NSString *path) {
    if (ShouldHidePath(path.UTF8String, __builtin_return_address(0))) {
        return NO;
    }
    return orig_fileExists ? orig_fileExists(self, _cmd, path) : NO;
}

static BOOL (*orig_fileExistsIsDir)(id self, SEL _cmd, NSString *path, BOOL *isDir) = NULL;
static BOOL hook_fileExistsIsDir(id self, SEL _cmd, NSString *path, BOOL *isDir) {
    if (ShouldHidePath(path.UTF8String, __builtin_return_address(0))) {
        if (isDir) *isDir = NO;
        return NO;
    }
    return orig_fileExistsIsDir ? orig_fileExistsIsDir(self, _cmd, path, isDir) : NO;
}

static pid_t (*orig_fork)(void) = NULL;
static pid_t hook_fork(void) {
    if (orig_fork) return orig_fork();
    errno = ENOSYS;
    return -1;
}

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
    return orig_CFTimeZoneCopySystem ? orig_CFTimeZoneCopySystem() : NULL;
}

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

static NSString *(*orig_dataServiceIdentifier)(id self, SEL _cmd) = NULL;
static NSString *hook_dataServiceIdentifier(id self, SEL _cmd) {
    NSString *orig = orig_dataServiceIdentifier ? orig_dataServiceIdentifier(self, _cmd) : nil;
    if (orig.length > 0) return orig;
    return @"0000000100000002";
}

static BOOL hook_returnYES(id self, SEL _cmd) {
    return YES;
}

static BOOL IsSystemNetworkingCaller(void *retAddr) {
    if (!retAddr) return NO;
    Dl_info info;
    if (!orig_dladdr) return NO;
    int ok = orig_dladdr(retAddr, &info);
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
static void (*orig_freeifaddrs)(struct ifaddrs *ifap) = NULL;

#define AUTOIPLOC_IFADDRS_MAX_NODES 4096

typedef struct AutoIPLocIfaddrsAllocation {
    struct AutoIPLocIfaddrsAllocation *registryNext;
    struct ifaddrs *originalHead;
    size_t visibleCount;
    struct ifaddrs nodes[];
} AutoIPLocIfaddrsAllocation;

static pthread_mutex_t g_ifaddrsRegistryLock = PTHREAD_MUTEX_INITIALIZER;
static AutoIPLocIfaddrsAllocation *g_ifaddrsAllocations = NULL;

static int hook_getifaddrs(struct ifaddrs **ifap) {
    if (!orig_getifaddrs) {
        errno = ENOSYS;
        return -1;
    }

    int ret = orig_getifaddrs(ifap);
    if (ret != 0 || !ifap || !*ifap || !orig_freeifaddrs) return ret;

    size_t totalCount = 0;
    size_t visibleCount = 0;
    for (struct ifaddrs *node = *ifap; node != NULL; node = node->ifa_next) {
        if (++totalCount > AUTOIPLOC_IFADDRS_MAX_NODES) return ret;
        if (!IsVirtualVPNInterface(node->ifa_name)) visibleCount++;
    }

    // Keep the original allocation untouched if filtering is unnecessary or
    // would otherwise return an empty list with ambiguous caller expectations.
    if (visibleCount == 0 || visibleCount == totalCount) return ret;
    if (visibleCount > (SIZE_MAX - sizeof(AutoIPLocIfaddrsAllocation)) / sizeof(struct ifaddrs)) {
        return ret;
    }

    size_t allocationSize = sizeof(AutoIPLocIfaddrsAllocation) + visibleCount * sizeof(struct ifaddrs);
    AutoIPLocIfaddrsAllocation *allocation = calloc(1, allocationSize);
    if (!allocation) return ret;

    allocation->originalHead = *ifap;
    allocation->visibleCount = visibleCount;

    size_t index = 0;
    for (struct ifaddrs *node = *ifap; node != NULL; node = node->ifa_next) {
        if (IsVirtualVPNInterface(node->ifa_name)) continue;
        allocation->nodes[index] = *node;
        allocation->nodes[index].ifa_next =
            (index + 1 < visibleCount) ? &allocation->nodes[index + 1] : NULL;
        index++;
    }

    pthread_mutex_lock(&g_ifaddrsRegistryLock);
    allocation->registryNext = g_ifaddrsAllocations;
    g_ifaddrsAllocations = allocation;
    pthread_mutex_unlock(&g_ifaddrsRegistryLock);

    *ifap = &allocation->nodes[0];
    return ret;
}

static void hook_freeifaddrs(struct ifaddrs *ifap) {
    if (!ifap) {
        if (orig_freeifaddrs) orig_freeifaddrs(NULL);
        return;
    }

    AutoIPLocIfaddrsAllocation *matched = NULL;
    pthread_mutex_lock(&g_ifaddrsRegistryLock);
    AutoIPLocIfaddrsAllocation **cursor = &g_ifaddrsAllocations;
    while (*cursor != NULL) {
        if (&(*cursor)->nodes[0] == ifap) {
            matched = *cursor;
            *cursor = matched->registryNext;
            break;
        }
        cursor = &(*cursor)->registryNext;
    }
    pthread_mutex_unlock(&g_ifaddrsRegistryLock);

    if (matched != NULL) {
        if (orig_freeifaddrs && matched->originalHead) {
            orig_freeifaddrs(matched->originalHead);
        }
        free(matched);
        return;
    }

    if (orig_freeifaddrs) {
        orig_freeifaddrs(ifap);
    } else {
        errno = ENOSYS;
    }
}

static BOOL IsBlockedURLScheme(NSString *scheme) {
    if (scheme.length == 0) return NO;
    NSSet *blocked = [NSSet setWithArray:@[
        @"apple-magnifier", @"sileo", @"zbra", @"cydia",
        @"filza", @"santander", @"trollstore", @"dopamine", @"roothide",
        @"geranium", @"locsim", @"shadowrocket", @"quantumult", @"surge", @"loon", @"stash"
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

// 彻底抹除模拟定位标记（覆盖 getter、构造器、copyWithZone 与 XPC initWithCoder 内部 ivar）
static BOOL hook_returnNO(id self, SEL _cmd) {
    return NO;
}

typedef id AutoIPLocInitWithSimStateIMP(id, SEL, BOOL, BOOL) __attribute__((ns_returns_retained));
typedef id AutoIPLocInitWithCoderIMP(id, SEL, NSCoder *) __attribute__((ns_returns_retained));
typedef id AutoIPLocCopyWithZoneIMP(id, SEL, NSZone *) __attribute__((ns_returns_retained));

static AutoIPLocInitWithSimStateIMP *orig_initWithSimState = NULL;
static id hook_initWithSimState(id self, SEL _cmd, BOOL isSimulated, BOOL isAccessory) __attribute__((ns_returns_retained));
static id hook_initWithSimState(id self, SEL _cmd, BOOL isSimulated, BOOL isAccessory) {
    if (!orig_initWithSimState) return nil;
    return orig_initWithSimState(self, _cmd, NO, NO);
}

static id CreateCleanLocationSourceInfo(void) {
    Class srcInfoCls = objc_getClass("CLLocationSourceInformation");
    if (!srcInfoCls) return nil;
    SEL initSel = NSSelectorFromString(@"initWithSoftwareSimulationState:externalAccessoryState:");
    id obj = [srcInfoCls alloc];
    if ([obj respondsToSelector:initSel]) {
        if (!orig_initWithSimState) return nil;
        return orig_initWithSimState(obj, initSel, NO, NO);
    }
    return [obj init];
}

static AutoIPLocInitWithCoderIMP *orig_srcInfoInitWithCoder = NULL;
static id hook_srcInfoInitWithCoder(id self, SEL _cmd, NSCoder *coder) __attribute__((ns_returns_retained));
static id hook_srcInfoInitWithCoder(id self, SEL _cmd, NSCoder *coder) {
    if (!orig_srcInfoInitWithCoder) return nil;
    id decoded = orig_srcInfoInitWithCoder(self, _cmd, coder);
    if (!decoded) return nil;
    id clean = CreateCleanLocationSourceInfo();
    return clean ?: decoded;
}

static id (*orig_sourceInformation)(id self, SEL _cmd) = NULL;
static id hook_sourceInformation(id self, SEL _cmd) {
    id clean = CreateCleanLocationSourceInfo();
    if (clean) return clean;
    return orig_sourceInformation ? orig_sourceInformation(self, _cmd) : nil;
}

static AutoIPLocCopyWithZoneIMP *orig_srcInfoCopyWithZone = NULL;
static id hook_srcInfoCopyWithZone(id self, SEL _cmd, NSZone *zone) __attribute__((ns_returns_retained));
static id hook_srcInfoCopyWithZone(id self, SEL _cmd, NSZone *zone) {
    id clean = CreateCleanLocationSourceInfo();
    if (clean) return clean;
    return orig_srcInfoCopyWithZone ? orig_srcInfoCopyWithZone(self, _cmd, zone) : self;
}

static AutoIPLocInitWithCoderIMP *orig_locInitWithCoder = NULL;
static id hook_locInitWithCoder(id self, SEL _cmd, NSCoder *coder) __attribute__((ns_returns_retained));
static id hook_locInitWithCoder(id self, SEL _cmd, NSCoder *coder) {
    if (!orig_locInitWithCoder) return nil;
    id decoded = orig_locInitWithCoder(self, _cmd, coder);
    if (!decoded) return nil;

    Ivar ivar = class_getInstanceVariable([CLLocation class], "_sourceInformation");
    const char *ivarType = ivar ? ivar_getTypeEncoding(ivar) : NULL;
    if (ivar && ObjCTypeCode(ivarType) == '@') {
        id clean = CreateCleanLocationSourceInfo();
        if (clean) object_setIvarWithStrongDefault(decoded, ivar, clean);
    }
    return decoded;
}

static NSString *hook_targetCountryCode(id self, SEL _cmd) {
    return GetTargetCountryCode();
}

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
        ResolveElleKitRuntime((void *)&AutoIPLocHookEntry);

        NSString *initTZ = GetTargetTimeZoneName();
        if (initTZ) {
            setenv("TZ", initTZ.UTF8String, 1);
            tzset();
            [NSTimeZone resetSystemTimeZone];
        }
        Class tzMeta = objc_getMetaClass("NSTimeZone");
        if (tzMeta) {
            HOOK_OBJC_METHOD_TYPED(tzMeta, @selector(systemTimeZone), (IMP)hook_systemTimeZone, orig_systemTimeZone, '@', "");
            HOOK_OBJC_METHOD_TYPED(tzMeta, @selector(defaultTimeZone), (IMP)hook_defaultTimeZone, orig_defaultTimeZone, '@', "");
            HOOK_OBJC_METHOD_TYPED(tzMeta, @selector(localTimeZone), (IMP)hook_localTimeZone, orig_localTimeZone, '@', "");
        }

        Class appCls = objc_getClass("UIApplication");
        if (appCls) {
            HOOK_OBJC_METHOD_TYPED(appCls, @selector(canOpenURL:), (IMP)hook_canOpenURL, orig_canOpenURL, 'B', "@");
            HOOK_OBJC_METHOD_TYPED(appCls, NSSelectorFromString(@"_canOpenURL:publicURLsOnly:"), (IMP)hook_privCanOpenURL, orig_privCanOpenURL, 'B', "@B");
        }
        Class wsCls = objc_getClass("LSApplicationWorkspace");
        if (wsCls) {
            HOOK_OBJC_METHOD_TYPED(wsCls, NSSelectorFromString(@"applicationsAvailableForHandlingURLScheme:"), (IMP)hook_appsForScheme, orig_appsForScheme, '@', "@");
            HOOK_OBJC_METHOD_TYPED(wsCls, NSSelectorFromString(@"URLOverrideForURL:"), (IMP)hook_urlOverride, orig_urlOverride, '@', "@");
        }
        Class fmCls = objc_getClass("NSFileManager");
        if (fmCls) {
            HOOK_OBJC_METHOD_TYPED(fmCls, @selector(fileExistsAtPath:), (IMP)hook_fileExists, orig_fileExists, 'B', "@");
            HOOK_OBJC_METHOD_TYPED(fmCls, @selector(fileExistsAtPath:isDirectory:), (IMP)hook_fileExistsIsDir, orig_fileExistsIsDir, 'B', "@^");
        }

        Class sessionCfgCls = objc_getClass("NSURLSessionConfiguration");
        if (sessionCfgCls) {
            HOOK_OBJC_METHOD_TYPED(sessionCfgCls, @selector(connectionProxyDictionary), (IMP)hook_connectionProxyDictionary, orig_connectionProxyDictionary, '@', "");
        }

        Class carrierCls = objc_getClass("CTCarrier");
        if (carrierCls) {
            HOOK_OBJC_METHOD_TYPED(carrierCls, NSSelectorFromString(@"carrierName"), (IMP)hook_carrierName, orig_carrierName, '@', "");
            HOOK_OBJC_METHOD_TYPED(carrierCls, NSSelectorFromString(@"mobileCountryCode"), (IMP)hook_mobileCountryCode, orig_mobileCountryCode, '@', "");
            HOOK_OBJC_METHOD_TYPED(carrierCls, NSSelectorFromString(@"mobileNetworkCode"), (IMP)hook_mobileNetworkCode, orig_mobileNetworkCode, '@', "");
            HOOK_OBJC_METHOD_TYPED(carrierCls, NSSelectorFromString(@"isoCountryCode"), (IMP)hook_isoCountryCode, orig_isoCountryCode, '@', "");
            HookObjCMethod(carrierCls, NSSelectorFromString(@"allowsVOIP"), (IMP)hook_returnYES, NULL, 'B', "");
        }
        Class netInfoCls = objc_getClass("CTTelephonyNetworkInfo");
        if (netInfoCls) {
            HOOK_OBJC_METHOD_TYPED(netInfoCls, NSSelectorFromString(@"serviceCurrentRadioAccessTechnology"), (IMP)hook_serviceRadioTech, orig_serviceRadioTech, '@', "");
            HOOK_OBJC_METHOD_TYPED(netInfoCls, NSSelectorFromString(@"currentRadioAccessTechnology"), (IMP)hook_currentRadioTech, orig_currentRadioTech, '@', "");
            HOOK_OBJC_METHOD_TYPED(netInfoCls, NSSelectorFromString(@"dataServiceIdentifier"), (IMP)hook_dataServiceIdentifier, orig_dataServiceIdentifier, '@', "");
        }

        Class srcInfoCls = objc_getClass("CLLocationSourceInformation");
        if (srcInfoCls) {
            HookObjCMethod(srcInfoCls, NSSelectorFromString(@"isSimulatedBySoftware"), (IMP)hook_returnNO, NULL, 'B', "");
            HookObjCMethod(srcInfoCls, NSSelectorFromString(@"isProducedByAccessory"), (IMP)hook_returnNO, NULL, 'B', "");
            HOOK_OBJC_METHOD_TYPED(srcInfoCls, NSSelectorFromString(@"initWithSoftwareSimulationState:externalAccessoryState:"), (IMP)hook_initWithSimState, orig_initWithSimState, '@', "BB");
            HOOK_OBJC_METHOD_TYPED(srcInfoCls, @selector(initWithCoder:), (IMP)hook_srcInfoInitWithCoder, orig_srcInfoInitWithCoder, '@', "@");
            HOOK_OBJC_METHOD_TYPED(srcInfoCls, @selector(copyWithZone:), (IMP)hook_srcInfoCopyWithZone, orig_srcInfoCopyWithZone, '@', "^");
        }
        Class locCls = objc_getClass("CLLocation");
        if (locCls) {
            HookObjCMethod(locCls, NSSelectorFromString(@"isSimulatedBySoftware"), (IMP)hook_returnNO, NULL, 'B', "");
            HookObjCMethod(locCls, NSSelectorFromString(@"_isSimulated"), (IMP)hook_returnNO, NULL, 'B', "");
            HOOK_OBJC_METHOD_TYPED(locCls, NSSelectorFromString(@"sourceInformation"), (IMP)hook_sourceInformation, orig_sourceInformation, '@', "");
            HOOK_OBJC_METHOD_TYPED(locCls, @selector(initWithCoder:), (IMP)hook_locInitWithCoder, orig_locInitWithCoder, '@', "@");
        }

        Class geoCls = objc_getClass("GEOCountryConfiguration");
        if (geoCls) {
            NSArray *sels = @[@"countryCode", @"_countryCode", @"currentCountryCode", @"sourceCountryCode"];
            for (NSString *selName in sels) {
                HookObjCMethod(geoCls, NSSelectorFromString(selName), (IMP)hook_targetCountryCode, NULL, '@', "");
            }
        }
        Class platformCls = objc_getClass("GEOPlatform");
        if (platformCls) {
            HookObjCMethod(platformCls, NSSelectorFromString(@"isChina"), (IMP)hook_returnNO, NULL, 'B', "");
        }

        if (g_MSHookFunction) {
            INSTALL_C_FUNCTION_HOOK(_dyld_get_image_name, hook_dyld_get_image_name, orig_dyld_get_image_name);
            INSTALL_C_FUNCTION_HOOK(dladdr, hook_dladdr, orig_dladdr);
            INSTALL_C_FUNCTION_HOOK(getenv, hook_getenv, orig_getenv);
            INSTALL_C_FUNCTION_HOOK(access, hook_access, orig_access);
            INSTALL_C_FUNCTION_HOOK(stat, hook_stat, orig_stat);
            INSTALL_C_FUNCTION_HOOK(lstat, hook_lstat, orig_lstat);
            INSTALL_C_FUNCTION_HOOK(fopen, hook_fopen, orig_fopen);
            INSTALL_C_FUNCTION_HOOK(opendir, hook_opendir, orig_opendir);
            INSTALL_C_FUNCTION_HOOK(fork, hook_fork, orig_fork);

            void *symCFTimeZone = dlsym(RTLD_DEFAULT, "CFTimeZoneCopySystem");
            if (symCFTimeZone) {
                INSTALL_C_FUNCTION_HOOK(symCFTimeZone, hook_CFTimeZoneCopySystem, orig_CFTimeZoneCopySystem);
            }

            INSTALL_C_FUNCTION_HOOK(CFNetworkCopySystemProxySettings,
                                    hook_CFNetworkCopySystemProxySettings,
                                    orig_CFNetworkCopySystemProxySettings);

            void *symSCDyn = dlsym(RTLD_DEFAULT, "SCDynamicStoreCopyProxies");
            if (symSCDyn) {
                INSTALL_C_FUNCTION_HOOK(symSCDyn, hook_SCDynamicStoreCopyProxies, orig_SCDynamicStoreCopyProxies);
            }

            // Install freeifaddrs before exposing filtered getifaddrs lists so
            // each cloned list has a matching original-list deallocation path.
            INSTALL_C_FUNCTION_HOOK(freeifaddrs, hook_freeifaddrs, orig_freeifaddrs);
            INSTALL_C_FUNCTION_HOOK(getifaddrs, hook_getifaddrs, orig_getifaddrs);
            INSTALL_C_FUNCTION_HOOK(CNCopyCurrentNetworkInfo, hook_CNCopyCurrentNetworkInfo, orig_CNCopyCurrentNetworkInfo);
            INSTALL_C_FUNCTION_HOOK(CNCopySupportedInterfaces, hook_CNCopySupportedInterfaces, orig_CNCopySupportedInterfaces);
        }

        NSDictionary *status = @{
            @"active": @(g_installedCHookCount > 0 || g_installedObjCHookCount > 0),
            @"version": @"4.3.1",
            @"lastProc": [NSString stringWithUTF8String:prog],
            @"cHookReady": @(orig_dladdr != NULL && orig_getifaddrs != NULL && orig_freeifaddrs != NULL),
            @"cHookCount": @(g_installedCHookCount),
            @"objcHookCount": @(g_installedObjCHookCount),
            @"timestamp": @([[NSDate date] timeIntervalSince1970])
        };
        BeginInternalIO();
        @try {
            [status writeToFile:@"/var/mobile/Library/Preferences/com.autoiploc.hookstatus.plist" atomically:YES];
            [status writeToFile:@"/var/tmp/com.autoiploc.hookstatus.plist" atomically:YES];
        } @finally {
            EndInternalIO();
        }
        chmod("/var/tmp/com.autoiploc.hookstatus.plist", 0644);
    }
}
