#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <CoreLocation/CoreLocation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dlfcn.h>

// ==========================================
// 模块 A：强制 GeoServices & 运营商国家码为 US（彻底替换高德地图为苹果原生美区地图）
// ==========================================
static IMP orig_geo_countryCode = NULL;
static NSString *hooked_geo_countryCode(id self, SEL _cmd) {
    return [NSString stringWithUTF8String:"US"];
}

static IMP orig_geo_deviceCountryCode = NULL;
static NSString *hooked_geo_deviceCountryCode(id self, SEL _cmd) {
    return [NSString stringWithUTF8String:"US"];
}

static IMP orig_ct_isoCountryCode = NULL;
static NSString *hooked_ct_isoCountryCode(id self, SEL _cmd) {
    return [NSString stringWithUTF8String:"us"];
}

static IMP orig_ct_mcc = NULL;
static NSString *hooked_ct_mcc(id self, SEL _cmd) {
    return [NSString stringWithUTF8String:"310"];
}

// ==========================================
// 模块 B：每次切换生成 10-15 个随机美区周边 Wi-Fi (SSID + 美区厂商 BSSID + RSSI)
// ==========================================
static NSArray<NSDictionary *> *GenerateUSNearbyWiFiPool(void) {
    static const char *prefixes[] = {
        "Xfinity", "xfinitywifi", "SpectrumSetup-", "MySpectrumWiFi",
        "ATT-WIFI-", "ATT5G-", "CenturyLink", "NETGEAR",
        "TP-Link_", "linksys", "eero-", "ASUS_",
        "Verizon_", "Frontier", "CoxWiFi", "Ring-Chime-"
    };
    // 美区常见路由器厂商 OUI MAC 前缀 (Netgear / Linksys / Cisco / Arris / Belkin / Ubiquiti)
    static const char *ouis[] = {
        "00:14:BF", "C0:56:27", "E4:F4:C6", "20:4E:7F",
        "44:D9:E7", "74:83:C2", "18:E8:29", "B4:75:0E",
        "58:6D:8F", "9C:3D:CF", "00:24:A5", "88:DC:96"
    };

    int totalPrefixes = sizeof(prefixes) / sizeof(prefixes[0]);
    int totalOuis = sizeof(ouis) / sizeof(ouis[0]);
    // 每次随机生成 10 到 15 个热点
    int count = 10 + arc4random_uniform(6);

    NSMutableArray *list = [NSMutableArray arrayWithCapacity:count];
    NSMutableSet *usedSSIDs = [NSMutableSet set];

    while ((int)list.count < count) {
        const char *p = prefixes[arc4random_uniform(totalPrefixes)];
        NSString *ssid = nil;
        if (strcmp(p, "Xfinity") == 0 || strcmp(p, "xfinitywifi") == 0 ||
            strcmp(p, "linksys") == 0 || strcmp(p, "CoxWiFi") == 0) {
            ssid = [NSString stringWithFormat:@"%s_%02X", p, arc4random_uniform(256)];
        } else {
            ssid = [NSString stringWithFormat:@"%s%04u", p, 1000 + arc4random_uniform(9000)];
        }
        if ([usedSSIDs containsObject:ssid]) continue;
        [usedSSIDs addObject:ssid];

        const char *oui = ouis[arc4random_uniform(totalOuis)];
        NSString *bssid = [NSString stringWithFormat:@"%s:%02x:%02x:%02x",
                           oui,
                           arc4random_uniform(256),
                           arc4random_uniform(256),
                           arc4random_uniform(256)];
        int rssi = -(46 + (int)arc4random_uniform(38)); // -46 dBm ~ -83 dBm
        int channel = (arc4random_uniform(2) == 0) ? (1 + arc4random_uniform(11)) : (36 + 4 * arc4random_uniform(12));

        [list addObject:@{
            @"SSID": ssid,
            @"BSSID": bssid,
            @"RSSI": @(rssi),
            @"CHANNEL": @(channel)
        }];
    }
    return list;
}

// 读取共享池文件（由 AutoIPLoc App 每次点击“立即同步”时写入刷新）
static NSArray<NSDictionary *> *LoadActiveVirtualWiFiList(void) {
    NSString *poolPath = [NSString stringWithUTF8String:"/var/mobile/Library/Preferences/com.autoiploc.wifipool.plist"];
    NSArray *saved = [NSArray arrayWithContentsOfFile:poolPath];
    if (saved && saved.count >= 10) {
        return saved;
    }
    NSArray *fresh = GenerateUSNearbyWiFiPool();
    [fresh writeToFile:poolPath atomically:YES];
    return fresh;
}

// Hook MobileWiFi.framework 扫描结果，屏蔽真实国内周围热点
typedef void (*MSHookFunction_t)(void *symbol, void *replace, void **result);
static CFArrayRef (*orig_WiFiDeviceClientCopyCurrentNetworks)(void *client) = NULL;
static CFArrayRef hooked_WiFiDeviceClientCopyCurrentNetworks(void *client) {
    NSArray *pool = LoadActiveVirtualWiFiList();
    if (pool.count > 0) {
        return (__bridge_retained CFArrayRef)pool;
    }
    return orig_WiFiDeviceClientCopyCurrentNetworks ? orig_WiFiDeviceClientCopyCurrentNetworks(client) : NULL;
}

static void HookInstanceMethod(Class cls, const char *selName, IMP newImp, IMP *origOut) {
    if (!cls) return;
    SEL sel = sel_registerName(selName);
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return;
    const char *types = method_getTypeEncoding(m);
    IMP prev = method_getImplementation(m);
    if (origOut) *origOut = prev;
    if (!class_addMethod(cls, sel, newImp, types)) {
        method_setImplementation(m, newImp);
    }
}

__attribute__((constructor))
static void InitAutoIPLocEnhancements(void) {
    // 1. 强制地图国家码为 US
    dlopen("/System/Library/PrivateFrameworks/GeoServices.framework/GeoServices", RTLD_LAZY);
    Class geoCfg = objc_getClass("GEOCountryConfiguration");
    HookInstanceMethod(geoCfg, "countryCode", (IMP)hooked_geo_countryCode, &orig_geo_countryCode);
    HookInstanceMethod(geoCfg, "deviceCountryCode", (IMP)hooked_geo_deviceCountryCode, &orig_geo_deviceCountryCode);

    // 2. 强制蜂窝国家码为 US (310)，即使开飞行模式也保持美区环境
    dlopen("/System/Library/Frameworks/CoreTelephony.framework/CoreTelephony", RTLD_LAZY);
    Class ctCarrier = objc_getClass("CTCarrier");
    HookInstanceMethod(ctCarrier, "isoCountryCode", (IMP)hooked_ct_isoCountryCode, &orig_ct_isoCountryCode);
    HookInstanceMethod(ctCarrier, "mobileCountryCode", (IMP)hooked_ct_mcc, &orig_ct_mcc);

    // 3. 拦截系统周边 Wi-Fi 扫描列表
    MSHookFunction_t hookFn = (MSHookFunction_t)dlsym(RTLD_DEFAULT, "MSHookFunction");
    void *wifiHandle = dlopen("/System/Library/PrivateFrameworks/MobileWiFi.framework/MobileWiFi", RTLD_LAZY);
    void *copyNetSym = wifiHandle ? dlsym(wifiHandle, "WiFiDeviceClientCopyCurrentNetworks") : NULL;
    if (hookFn && copyNetSym) {
        hookFn(copyNetSym, (void *)hooked_WiFiDeviceClientCopyCurrentNetworks, (void **)&orig_WiFiDeviceClientCopyCurrentNetworks);
    }
}
