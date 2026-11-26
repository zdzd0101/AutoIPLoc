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
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <mach/mach.h>
#import <mach/vm_map.h>
#import <ifaddrs.h>
#import <dlfcn.h>
#import <dirent.h>
#import <sys/stat.h>
#import <unistd.h>
#import <errno.h>
#import <stdlib.h>
#import <string.h>

typedef void (*MSHookFunction_t)(void *symbol, void *replace, void **result);
typedef void (*MSHookMessageEx_t)(Class _class, SEL message, IMP hook, IMP *old);

static MSHookFunction_t g_MSHookFunction = NULL;
static MSHookMessageEx_t g_MSHookMessageEx = NULL;
static int (*orig_dladdr)(const void *addr, Dl_info *info) = NULL;

struct rebinding_entry {
    const char *name;
    void *replacement;
    void **replaced;
};

static void rebind_symbols_for_image(const struct mach_header *header, intptr_t slide, struct rebinding_entry *rebindings, size_t rebindings_nel) {
    if (!header) return;
    struct segment_command_64 *cur_seg_cmd;
    struct segment_command_64 *linkedit_segment = NULL;
    struct symtab_command *symtab_cmd = NULL;
    struct dysymtab_command *dysymtab_cmd = NULL;

    uintptr_t cur = (uintptr_t)header + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < header->ncmds; i++, cur += cur_seg_cmd->cmdsize) {
        cur_seg_cmd = (struct segment_command_64 *)cur;
        if (cur_seg_cmd->cmd == LC_SEGMENT_64) {
            if (strcmp(cur_seg_cmd->segname, SEG_LINKEDIT) == 0) {
                linkedit_segment = cur_seg_cmd;
            }
        } else if (cur_seg_cmd->cmd == LC_SYMTAB) {
            symtab_cmd = (struct symtab_command *)cur_seg_cmd;
        } else if (cur_seg_cmd->cmd == LC_DYSYMTAB) {
            dysymtab_cmd = (struct dysymtab_command *)cur_seg_cmd;
        }
    }

    if (!symtab_cmd || !dysymtab_cmd || !linkedit_segment || !dysymtab_cmd->nindirectsyms) return;

    uintptr_t linkedit_base = (uintptr_t)slide + linkedit_segment->vmaddr - linkedit_segment->fileoff;
    struct nlist_64 *symtab = (struct nlist_64 *)(linkedit_base + symtab_cmd->symoff);
    char *strtab = (char *)(linkedit_base + symtab_cmd->stroff);
    uint32_t *indirect_symtab = (uint32_t *)(linkedit_base + dysymtab_cmd->indirectsymoff);

    cur = (uintptr_t)header + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < header->ncmds; i++, cur += cur_seg_cmd->cmdsize) {
        cur_seg_cmd = (struct segment_command_64 *)cur;
        if (cur_seg_cmd->cmd == LC_SEGMENT_64) {
            if (strcmp(cur_seg_cmd->segname, SEG_DATA) != 0 && strcmp(cur_seg_cmd->segname, "__DATA_CONST") != 0) {
                continue;
            }
            for (uint32_t j = 0; j < cur_seg_cmd->nsects; j++) {
                struct section_64 *sect = (struct section_64 *)(cur + sizeof(struct segment_command_64)) + j;
                uint32_t type = sect->flags & SECTION_TYPE;
                if (type != S_LAZY_SYMBOL_POINTERS && type != S_NON_LAZY_SYMBOL_POINTERS) continue;

                uint32_t *indirect_symbol_indices = indirect_symtab + sect->reserved1;
                void **indirect_symbol_bindings = (void **)((uintptr_t)slide + sect->addr);
                size_t count = sect->size / sizeof(void *);

                vm_protect(mach_task_self(), (vm_address_t)indirect_symbol_bindings, sect->size, 0, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);

                for (size_t k = 0; k < count; k++) {
                    uint32_t symtab_index = indirect_symbol_indices[k];
                    if (symtab_index == INDIRECT_SYMBOL_ABS || symtab_index == INDIRECT_SYMBOL_LOCAL ||
                        symtab_index == (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS)) {
                        continue;
                    }
                    uint32_t strtab_offset = symtab[symtab_index].n_un.n_strx;
                    char *symbol_name = strtab + strtab_offset;
                    if (strnlen(symbol_name, 2) < 2) continue;

                    for (size_t r = 0; r < rebindings_nel; r++) {
                        if (strcmp(&symbol_name[1], rebindings[r].name) == 0) {
                            if (rebindings[r].replaced != NULL && *(rebindings[r].replaced) == NULL) {
                                *(rebindings[r].replaced) = indirect_symbol_bindings[k];
                            }
                            indirect_symbol_bindings[k] = rebindings[r].replacement;
                            break;
                        }
                    }
                }
            }
        }
    }
}

static void ResolveElleKitRuntime(void *selfSymbolAddr) {
    g_MSHookFunction = (MSHookFunction_t)dlsym(RTLD_DEFAULT, "MSHookFunction");
    g_MSHookMessageEx = (MSHookMessageEx_t)dlsym(RTLD_DEFAULT, "MSHookMessageEx");
    if (!g_MSHookFunction) g_MSHookFunction = (MSHookFunction_t)dlsym(RTLD_NEXT, "MSHookFunction");
    if (!g_MSHookMessageEx) g_MSHookMessageEx = (MSHookMessageEx_t)dlsym(RTLD_NEXT, "MSHookMessageEx");
    if (g_MSHookFunction && g_MSHookMessageEx) return;

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
                if (g_MSHookFunction && g_MSHookMessageEx) return;
            }
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
                        if (g_MSHookFunction && g_MSHookMessageEx) return;
                    }
                }
            }
        }
    }
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
    if (IsSensitiveDylibPath(name)) {
        return "/usr/lib/libobjc.A.dylib";
    }
    return name;
}

static int hook_dladdr(const void *addr, Dl_info *info) {
    int ret = orig_dladdr ? orig_dladdr(addr, info) : dladdr(addr, info);
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
    if (!IsSelfCaller(__builtin_return_address(0)) && IsJailbreakPath(path)) {
        errno = ENOENT;
        return -1;
    }
    return orig_access ? orig_access(path, mode) : access(path, mode);
}

static int (*orig_stat)(const char *path, struct stat *buf) = NULL;
static int hook_stat(const char *path, struct stat *buf) {
    if (!IsSelfCaller(__builtin_return_address(0)) && IsJailbreakPath(path)) {
        errno = ENOENT;
        return -1;
    }
    return orig_stat ? orig_stat(path, buf) : stat(path, buf);
}

static int (*orig_lstat)(const char *path, struct stat *buf) = NULL;
static int hook_lstat(const char *path, struct stat *buf) {
    if (!IsSelfCaller(__builtin_return_address(0)) && IsJailbreakPath(path)) {
        errno = ENOENT;
        return -1;
    }
    return orig_lstat ? orig_lstat(path, buf) : lstat(path, buf);
}

static FILE *(*orig_fopen)(const char *filename, const char *mode) = NULL;
static FILE *hook_fopen(const char *filename, const char *mode) {
    if (!IsSelfCaller(__builtin_return_address(0)) && IsJailbreakPath(filename)) {
        errno = ENOENT;
        return NULL;
    }
    return orig_fopen ? orig_fopen(filename, mode) : fopen(filename, mode);
}

static DIR *(*orig_opendir)(const char *filename) = NULL;
static DIR *hook_opendir(const char *filename) {
    if (!IsSelfCaller(__builtin_return_address(0)) && IsJailbreakPath(filename)) {
        errno = ENOENT;
        return NULL;
    }
    return orig_opendir ? orig_opendir(filename) : opendir(filename);
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
        NSString *ssid = topAP[@"SSID"] ?: @"Linksys-352B";
        NSString *bssid = topAP[@"BSSID"] ?: @"20:4E:7F:6E:BB:D3";
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

static void ApplyFishhookFallback(void) {
    struct rebinding_entry entries[] = {
        {"_dyld_get_image_name", (void *)hook_dyld_get_image_name, (void **)&orig_dyld_get_image_name},
        {"dladdr", (void *)hook_dladdr, (void **)&orig_dladdr},
        {"getenv", (void *)hook_getenv, (void **)&orig_getenv},
        {"access", (void *)hook_access, (void **)&orig_access},
        {"stat", (void *)hook_stat, (void **)&orig_stat},
        {"lstat", (void *)hook_lstat, (void **)&orig_lstat},
        {"fopen", (void *)hook_fopen, (void **)&orig_fopen},
        {"opendir", (void *)hook_opendir, (void **)&orig_opendir},
        {"fork", (void *)hook_fork, (void **)&orig_fork},
        {"CFTimeZoneCopySystem", (void *)hook_CFTimeZoneCopySystem, (void **)&orig_CFTimeZoneCopySystem},
        {"CFNetworkCopySystemProxySettings", (void *)hook_CFNetworkCopySystemProxySettings, (void **)&orig_CFNetworkCopySystemProxySettings},
        {"SCDynamicStoreCopyProxies", (void *)hook_SCDynamicStoreCopyProxies, (void **)&orig_SCDynamicStoreCopyProxies},
        {"getifaddrs", (void *)hook_getifaddrs, (void **)&orig_getifaddrs},
        {"CNCopyCurrentNetworkInfo", (void *)hook_CNCopyCurrentNetworkInfo, (void **)&orig_CNCopyCurrentNetworkInfo},
        {"CNCopySupportedInterfaces", (void *)hook_CNCopySupportedInterfaces, (void **)&orig_CNCopySupportedInterfaces}
    };
    size_t n = sizeof(entries) / sizeof(entries[0]);
    uint32_t imgCount = _dyld_image_count();
    for (uint32_t i = 0; i < imgCount; i++) {
        const char *imgName = _dyld_get_image_name(i);
        if (!imgName) continue;
        if (strstr(imgName, ".app/") != NULL || strstr(imgName, "CFNetwork") != NULL || strstr(imgName, "CoreLocation") != NULL) {
            rebind_symbols_for_image(_dyld_get_image_header(i), _dyld_get_image_vmaddr_slide(i), entries, n);
        }
    }
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
            HookObjCMethod(tzMeta, @selector(systemTimeZone), (IMP)hook_systemTimeZone, (IMP *)&orig_systemTimeZone);
            HookObjCMethod(tzMeta, @selector(defaultTimeZone), (IMP)hook_defaultTimeZone, (IMP *)&orig_defaultTimeZone);
            HookObjCMethod(tzMeta, @selector(localTimeZone), (IMP)hook_localTimeZone, (IMP *)&orig_localTimeZone);
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
        }

        Class srcInfoCls = objc_getClass("CLLocationSourceInformation");
        if (srcInfoCls) {
            HookObjCMethod(srcInfoCls, NSSelectorFromString(@"isSimulatedBySoftware"), (IMP)hook_returnNO, NULL);
            HookObjCMethod(srcInfoCls, NSSelectorFromString(@"isProducedByAccessory"), (IMP)hook_returnNO, NULL);
            HookObjCMethod(srcInfoCls, NSSelectorFromString(@"initWithSoftwareSimulationState:externalAccessoryState:"), (IMP)hook_initWithSimState, (IMP *)&orig_initWithSimState);
        }
        Class locCls = objc_getClass("CLLocation");
        if (locCls) {
            HookObjCMethod(locCls, NSSelectorFromString(@"isSimulatedBySoftware"), (IMP)hook_returnNO, NULL);
            HookObjCMethod(locCls, NSSelectorFromString(@"_isSimulated"), (IMP)hook_returnNO, NULL);
            HookObjCMethod(locCls, NSSelectorFromString(@"sourceInformation"), (IMP)hook_sourceInformation, (IMP *)&orig_sourceInformation);
        }

        Class geoCls = objc_getClass("GEOCountryConfiguration");
        if (geoCls) {
            NSArray *sels = @[@"countryCode", @"_countryCode", @"currentCountryCode", @"sourceCountryCode"];
            for (NSString *selName in sels) {
                HookObjCMethod(geoCls, NSSelectorFromString(selName), (IMP)hook_targetCountryCode, NULL);
            }
        }
        Class platformCls = objc_getClass("GEOPlatform");
        if (platformCls) {
            HookObjCMethod(platformCls, NSSelectorFromString(@"isChina"), (IMP)hook_returnNO, NULL);
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

            void *symCFTimeZone = dlsym(RTLD_DEFAULT, "CFTimeZoneCopySystem");
            if (symCFTimeZone) g_MSHookFunction(symCFTimeZone, (void *)hook_CFTimeZoneCopySystem, (void **)&orig_CFTimeZoneCopySystem);

            g_MSHookFunction((void *)CFNetworkCopySystemProxySettings, (void *)hook_CFNetworkCopySystemProxySettings, (void **)&orig_CFNetworkCopySystemProxySettings);

            void *symSCDyn = dlsym(RTLD_DEFAULT, "SCDynamicStoreCopyProxies");
            if (symSCDyn) g_MSHookFunction(symSCDyn, (void *)hook_SCDynamicStoreCopyProxies, (void **)&orig_SCDynamicStoreCopyProxies);

            g_MSHookFunction((void *)getifaddrs, (void *)hook_getifaddrs, (void **)&orig_getifaddrs);
            g_MSHookFunction((void *)CNCopyCurrentNetworkInfo, (void *)hook_CNCopyCurrentNetworkInfo, (void **)&orig_CNCopyCurrentNetworkInfo);
            g_MSHookFunction((void *)CNCopySupportedInterfaces, (void *)hook_CNCopySupportedInterfaces, (void **)&orig_CNCopySupportedInterfaces);
        } else {
            ApplyFishhookFallback();
        }

        NSDictionary *status = @{
            @"active": @YES,
            @"version": @"3.8.0",
            @"lastProc": [NSString stringWithUTF8String:prog],
            @"cHookReady": @(g_MSHookFunction != NULL)
        };
        [status writeToFile:@"/var/mobile/Library/Preferences/com.autoiploc.hookstatus.plist" atomically:YES];
        [status writeToFile:@"/var/tmp/com.autoiploc.hookstatus.plist" atomically:YES];
        chmod("/var/tmp/com.autoiploc.hookstatus.plist", 0666);
    }
}
