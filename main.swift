import SwiftUI
import UIKit
import CoreLocation
import Network
import Darwin

@_silgen_name("notify_register_check")
private func c_notify_register_check(_ name: UnsafePointer<CChar>, _ outToken: UnsafeMutablePointer<Int32>) -> UInt32

@_silgen_name("notify_get_state")
private func c_notify_get_state(_ token: Int32, _ state64: UnsafeMutablePointer<UInt64>) -> UInt32

@_silgen_name("notify_cancel")
private func c_notify_cancel(_ token: Int32) -> UInt32

struct GeoProfile: Codable {
    var ip: String
    var countryCode: String
    var region: String
    var city: String
    var timezone: String
    var latitude: Double
    var longitude: Double
    var street: String
    var zip: String
    var isp: String
    var isProxy: Bool?
    var isHosting: Bool?
}

struct AuditItem: Identifiable {
    let id = UUID()
    let title: String
    let detail: String
    let passed: Bool
    let isWarning: Bool
}

struct InstalledAppInfo: Identifiable, Hashable {
    var id: String { bundleId }
    let name: String
    let bundleId: String
    let isSystem: Bool
}

final class LocationEngine: NSObject, ObservableObject, CLLocationManagerDelegate {
    static let shared = LocationEngine()
    static let expectedHookVersion = "5.2.0"

    @Published var isSimulating = false
    @Published var isSyncing = false
    @Published var isAuditing = false
    @Published var statusError: String? = nil
    @Published var versionMismatchWarning: String? = nil
    @Published var mapResetMessage: String? = nil
    @Published var whitelistFeedback: String? = nil
    @Published var whitelistHasError = false
    @Published var exitIP = "未获取 [--]"
    @Published var ispText = "--"
    @Published var timezoneName = "- (待同步)"
    @Published var coordText = "- (0.0000, 0.0000)"
    @Published var mappedProfileText = "待同步"
    @Published var streetAddress = "等待同步解析附近精确街道地址..."
    @Published var zipCode = "--"
    @Published var hookStatusText = "正在检测插件状态..."
    @Published var hookIsActive = false
    @Published var autoSyncOnNetworkChange = true
    @Published var lockSessionGeo = true
    @Published var spoofLocale = true {
        didSet { persistCurrentGeoIfActive() }
    }
    @Published var spoofCarrier = true {
        didSet { persistCurrentGeoIfActive() }
    }
    @Published var spoofProxy = true {
        didSet { persistCurrentGeoIfActive() }
    }
    @Published var naturalGpsJitter = true {
        didSet {
            if isSimulating {
                if naturalGpsJitter { startGpsDriftTimer() } else { stopGpsDriftTimer() }
            }
        }
    }
    @Published var wifiList: [[String: String]] = []
    @Published var auditItems: [AuditItem] = []
    @Published var installedApps: [InstalledAppInfo] = []
    @Published var enabledBundleIDs: Set<String> = ["com.apple.Maps"]

    private let locationManager = CLLocationManager()
    private lazy var simManager = CLSimulationManager()
    private let pathMonitor = NWPathMonitor()
    private let monitorQueue = DispatchQueue(label: "com.autoiploc.netmonitor")
    private var lastPathStatus: NWPath.Status?
    private var lockedProfile: GeoProfile?
    private var lastWiFiCountry: String = "US"
    private var gpsDriftTimer: Timer?

    override init() {
        super.init()
        locationManager.delegate = self
        locationManager.requestAlwaysAuthorization()
        ensureWritableHookStatusFiles()
        loadSavedState()
        loadInstalledAppsAndWhitelist()
        refreshHookStatus()
        startNetworkMonitor()
    }

    private func findTweakDirectory() -> String? {
        let fm = FileManager.default
        let baseDir = "/var/containers/Bundle/Application"
        if let items = try? fm.contentsOfDirectory(atPath: baseDir) {
            for item in items where item.hasPrefix(".jbroot-") {
                let tweakInject = "\(baseDir)/\(item)/usr/lib/TweakInject"
                if fm.fileExists(atPath: tweakInject) {
                    return tweakInject
                }
                let dynLibs = "\(baseDir)/\(item)/Library/MobileSubstrate/DynamicLibraries"
                if fm.fileExists(atPath: dynLibs) {
                    return dynLibs
                }
            }
        }
        let fallbackDir = "/var/jb/Library/MobileSubstrate/DynamicLibraries"
        return fm.fileExists(atPath: fallbackDir) ? fallbackDir : nil
    }

    private func findHookFilterPlistPaths() -> [String] {
        let fm = FileManager.default
        var rawPaths: [String] = []
        let baseDir = "/var/containers/Bundle/Application"
        if let items = try? fm.contentsOfDirectory(atPath: baseDir) {
            for item in items where item.hasPrefix(".jbroot-") {
                let p1 = "\(baseDir)/\(item)/usr/lib/TweakInject/AutoIPLocHook.plist"
                let p2 = "\(baseDir)/\(item)/Library/MobileSubstrate/DynamicLibraries/AutoIPLocHook.plist"
                if fm.fileExists(atPath: "\(baseDir)/\(item)/usr/lib/TweakInject") {
                    rawPaths.append(p1)
                }
                if fm.fileExists(atPath: "\(baseDir)/\(item)/Library/MobileSubstrate/DynamicLibraries") {
                    rawPaths.append(p2)
                }
            }
        }
        let fallback = "/var/jb/Library/MobileSubstrate/DynamicLibraries/AutoIPLocHook.plist"
        if fm.fileExists(atPath: "/var/jb/Library/MobileSubstrate/DynamicLibraries") {
            rawPaths.append(fallback)
        }
        var seen = Set<String>()
        var unique: [String] = []
        for p in rawPaths {
            let resolved = URL(fileURLWithPath: p).resolvingSymlinksInPath().path
            if !seen.contains(resolved) {
                seen.insert(resolved)
                unique.append(p)
            }
        }
        return unique
    }

    private var geoPlistPaths: [String] {
        var paths = [
            "/var/tmp/com.autoiploc.geo.plist",
            "/var/mobile/Library/Preferences/com.autoiploc.geo.plist"
        ]
        if let dir = findTweakDirectory() {
            paths.insert("\(dir)/AutoIPLoc.geo.plist", at: 0)
        }
        return paths
    }

    private var wifiPlistPaths: [String] {
        var paths = [
            "/var/tmp/com.autoiploc.wifi.plist",
            "/var/mobile/Library/Preferences/com.autoiploc.wifi.plist"
        ]
        if let dir = findTweakDirectory() {
            paths.insert("\(dir)/AutoIPLoc.wifi.plist", at: 0)
        }
        return paths
    }

    private var hookStatusPaths: [String] {
        var paths = [
            "/var/tmp/com.autoiploc.hookstatus.plist",
            "/var/mobile/Library/Preferences/com.autoiploc.hookstatus.plist"
        ]
        if let dir = findTweakDirectory() {
            paths.insert("\(dir)/AutoIPLoc.hookstatus.plist", at: 0)
        }
        return paths
    }

    // MARK: - 可视化 App 定向白名单管理

    func loadInstalledAppsAndWhitelist() {
        var loadedSet = Set<String>()
        for path in findHookFilterPlistPaths() {
            if let dict = NSDictionary(contentsOfFile: path) as? [String: Any],
               let filter = dict["Filter"] as? [String: Any],
               let bundles = filter["Bundles"] as? [String] {
                for b in bundles where b != "com.apple.UIKit" {
                    loadedSet.insert(b)
                }
                break
            }
        }
        if loadedSet.isEmpty {
            loadedSet.insert("com.apple.Maps")
        }
        self.enabledBundleIDs = loadedSet

        let systemPresets: [InstalledAppInfo] = [
            InstalledAppInfo(name: "苹果地图 (Apple Maps)", bundleId: "com.apple.Maps", isSystem: true),
            InstalledAppInfo(name: "Safari 浏览器", bundleId: "com.apple.mobilesafari", isSystem: true),
            InstalledAppInfo(name: "App Store", bundleId: "com.apple.AppStore", isSystem: true),
            InstalledAppInfo(name: "天气 (Weather)", bundleId: "com.apple.weather", isSystem: true)
        ]

        let blockedKeywords = [
            "autoiploc", "shadowrocket", "quantumult", "surge", "loon", "stash",
            "dopamine", "sileo", "zebra", "cydia", "filza", "trollstore",
            "roothide", "choicy", "newterm", "terminal", "amg456", "karing", "v2box"
        ]

        var appsByID: [String: InstalledAppInfo] = [:]
        for sys in systemPresets {
            appsByID[sys.bundleId] = sys
        }

        let fm = FileManager.default
        let appContainerDir = "/var/containers/Bundle/Application"
        if let uuids = try? fm.contentsOfDirectory(atPath: appContainerDir) {
            for uuid in uuids where !uuid.hasPrefix(".") {
                let uuidPath = "\(appContainerDir)/\(uuid)"
                guard let subItems = try? fm.contentsOfDirectory(atPath: uuidPath) else { continue }
                for item in subItems where item.hasSuffix(".app") {
                    let infoPath = "\(uuidPath)/\(item)/Info.plist"
                    guard let info = NSDictionary(contentsOfFile: infoPath) as? [String: Any],
                          let bid = info["CFBundleIdentifier"] as? String, !bid.isEmpty else { continue }
                    let lower = bid.lowercased()
                    if blockedKeywords.contains(where: { lower.contains($0) }) { continue }

                    let displayName = (info["CFBundleDisplayName"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines)
                    let bundleName = (info["CFBundleName"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines)
                    let finalName = (displayName?.isEmpty == false ? displayName! : (bundleName?.isEmpty == false ? bundleName! : bid))
                    appsByID[bid] = InstalledAppInfo(name: finalName, bundleId: bid, isSystem: false)
                }
            }
        }

        // 把已开启但未扫描到的自定义 Bundle ID 也补进列表
        for bid in loadedSet where appsByID[bid] == nil {
            appsByID[bid] = InstalledAppInfo(name: "自定义应用", bundleId: bid, isSystem: false)
        }

        self.installedApps = appsByID.values.sorted { lhs, rhs in
            let lOn = loadedSet.contains(lhs.bundleId)
            let rOn = loadedSet.contains(rhs.bundleId)
            if lOn != rOn { return lOn }
            if lhs.isSystem != rhs.isSystem { return lhs.isSystem }
            return lhs.name.localizedCaseInsensitiveCompare(rhs.name) == .orderedAscending
        }
    }

    func setBundleEnabled(_ bundleId: String, enabled: Bool) {
        let trimmed = bundleId.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, trimmed != "com.apple.UIKit" else { return }
        if enabled {
            enabledBundleIDs.insert(trimmed)
        } else {
            enabledBundleIDs.remove(trimmed)
        }
        saveHookFilterPlist()
    }

    func addCustomBundleID(_ bundleId: String) {
        let trimmed = bundleId.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, trimmed.contains("."), trimmed != "com.apple.UIKit" else {
            whitelistHasError = true
            whitelistFeedback = "请输入正确的 Bundle ID（如 com.example.app）"
            return
        }
        enabledBundleIDs.insert(trimmed)
        if !installedApps.contains(where: { $0.bundleId == trimmed }) {
            installedApps.insert(InstalledAppInfo(name: "自定义应用", bundleId: trimmed, isSystem: false), at: 0)
        }
        saveHookFilterPlist()
    }

    func saveHookFilterPlist() {
        let sortedBundles = Array(enabledBundleIDs).sorted()
        let plistDict: [String: Any] = [
            "Filter": [
                "Bundles": sortedBundles
            ]
        ]
        guard let xmlData = try? PropertyListSerialization.data(fromPropertyList: plistDict, format: .xml, options: 0) else {
            whitelistHasError = true
            whitelistFeedback = "生成过滤配置失败"
            return
        }

        let targetPaths = findHookFilterPlistPaths()
        if targetPaths.isEmpty {
            whitelistHasError = true
            whitelistFeedback = "未找到 AutoIPLocHook.plist，请先通过 RootHide Patcher 安装 v5.2.0 插件。"
            return
        }

        var successCount = 0
        for path in targetPaths {
            let resolvedURL = URL(fileURLWithPath: path).resolvingSymlinksInPath()
            do {
                try xmlData.write(to: resolvedURL, options: [])
                Darwin.chmod(resolvedURL.path, 0o666)
                successCount += 1
            } catch {
                // 跳过无权写入的兜底路径
            }
        }

        if successCount > 0 {
            whitelistHasError = false
            whitelistFeedback = "已保存（共 \(sortedBundles.count) 个目标 App）。划掉目标 App 重开即可生效，无需重启手机。"
        } else {
            whitelistHasError = true
            whitelistFeedback = "没有写入权限！请在终端运行一次：sudo chmod 666 /usr/lib/TweakInject/AutoIPLocHook.plist 后再切开关。"
        }
    }

    // MARK: - 共享配置与状态监控

    private func ensureWritableHookStatusFiles() {
        let fm = FileManager.default
        for path in hookStatusPaths {
            if fm.fileExists(atPath: path) {
                Darwin.chmod(path, 0o666)
            } else {
                let placeholder: NSDictionary = ["active": false, "timestamp": 0]
                placeholder.write(toFile: path, atomically: false)
                Darwin.chmod(path, 0o666)
            }
        }
    }

    private func persistCurrentGeoIfActive() {
        if isSimulating, let profile = lockedProfile {
            writeGeoPlist(profile)
            updateMappedProfileSummary(for: profile.countryCode)
        }
    }

    private func writeSharedPlist(_ dict: [String: Any], paths: [String]) {
        let nsDict = dict as NSDictionary
        for path in paths {
            nsDict.write(toFile: path, atomically: true)
            Darwin.chmod(path, 0o666)
        }
    }

    private func readSharedPlist(paths: [String]) -> [String: Any]? {
        for path in paths {
            if let dict = NSDictionary(contentsOfFile: path) as? [String: Any] {
                return dict
            }
        }
        return nil
    }

    private func updateMappedProfileSummary(for cc: String) {
        let map: [String: (String, String)] = [
            "US": ("T-Mobile (310/260)", "en_US"),
            "GB": ("Vodafone UK (234/15)", "en_GB"),
            "CA": ("Rogers (302/720)", "en_CA"),
            "AU": ("Telstra (505/01)", "en_AU"),
            "JP": ("NTT DOCOMO (440/10)", "ja_JP"),
            "DE": ("Telekom.de (262/01)", "de_DE"),
            "FR": ("Orange F (208/01)", "fr_FR"),
            "SG": ("Singtel (525/01)", "en_SG"),
            "KR": ("SKTelecom (450/05)", "ko_KR"),
            "TW": ("Chunghwa (466/92)", "zh_TW"),
            "NL": ("KPN (204/08)", "nl_NL"),
            "IT": ("TIM (222/01)", "it_IT"),
            "ES": ("Movistar (214/07)", "es_ES"),
            "BR": ("Vivo (724/06)", "pt_BR")
        ]
        let (carrier, locale) = map[cc.uppercased()] ?? ("T-Mobile (310/260)", "en_US")
        let carrierPart = spoofCarrier ? carrier : "原机运营商"
        let localePart = spoofLocale ? locale : "原机语言区"
        self.mappedProfileText = "\(carrierPart) · \(localePart)"
    }

    private func findInstalledHookDylib() -> String? {
        if let dir = findTweakDirectory() {
            let candidate = "\(dir)/AutoIPLocHook.dylib"
            if FileManager.default.fileExists(atPath: candidate) {
                return candidate
            }
        }
        return nil
    }

    private func readDarwinHeartbeat() -> (version: String, cHookReady: Bool, timestamp: Double)? {
        var token: Int32 = 0
        let status = "com.autoiploc.hook.heartbeat".withCString { c_notify_register_check($0, &token) }
        guard status == 0 else { return nil }
        defer { _ = c_notify_cancel(token) }

        var state: UInt64 = 0
        guard c_notify_get_state(token, &state) == 0, state != 0 else { return nil }
        let major = (state >> 56) & 0xFF
        let minor = (state >> 48) & 0xFF
        let patch = (state >> 41) & 0x7F
        let cHookReady = ((state >> 40) & 0x1) == 1
        let ts = Double(state & 0xFFFFFFFFFF)
        guard major > 0, ts > 1_700_000_000 else { return nil }
        return ("\(major).\(minor).\(patch)", cHookReady, ts)
    }

    private func formatAgeText(_ ageSec: Int) -> String {
        if ageSec < 60 {
            return "\(ageSec)秒前"
        } else if ageSec < 3600 {
            return "\(ageSec / 60)分钟前"
        } else {
            return "\(ageSec / 3600)小时前"
        }
    }

    func refreshHookStatus() {
        let now = Date().timeIntervalSince1970
        var bestVer: String? = nil
        var bestProc: String = "目标应用"
        var bestHookOk = false
        var bestTS: Double = -1

        if let hb = readDarwinHeartbeat() {
            bestVer = hb.version
            bestHookOk = hb.cHookReady
            bestTS = hb.timestamp
        }

        for path in hookStatusPaths {
            if let dict = NSDictionary(contentsOfFile: path) as? [String: Any],
               let active = dict["active"] as? Bool, active {
                let ts = (dict["timestamp"] as? Double) ?? 0
                let ver = dict["version"] as? String ?? "0.0.0"
                let proc = dict["lastProc"] as? String ?? "目标应用"
                let hookOk = (dict["cHookReady"] as? Bool) ?? false

                if ts > bestTS {
                    bestTS = ts
                    bestVer = ver
                    bestProc = proc
                    bestHookOk = hookOk
                } else if abs(ts - bestTS) <= 2.0, ver == bestVer {
                    bestProc = proc
                }
            }
        }

        if let ver = bestVer, bestTS > 0 {
            let ageSec = Int(max(0, now - bestTS))
            let ageText = formatAgeText(ageSec)

            if ver != Self.expectedHookVersion {
                self.versionMismatchWarning = "检测到手机正在运行旧版插件 v\(ver)（当前应为 v\(Self.expectedHookVersion)）。请用 RootHide Patcher 转换新版 AutoIPLocHook.deb 覆盖安装并重启用户空间。"
            } else {
                self.versionMismatchWarning = nil
            }

            if ageSec <= 86400 && bestHookOk {
                self.hookIsActive = (ver == Self.expectedHookVersion)
                self.hookStatusText = "已激活 v\(ver) · arm64e就绪（\(bestProc) · \(ageText)）"
                return
            } else if !bestHookOk {
                self.hookIsActive = false
                self.hookStatusText = "v\(ver) 仅 OC 生效，C 层 Hook 未就绪（\(bestProc)）"
                return
            } else {
                self.hookIsActive = false
                self.hookStatusText = "上次注入已超过 24 小时（请打开白名单内任意 App 刷新）"
                return
            }
        }

        self.versionMismatchWarning = nil
        if let dylibPath = findInstalledHookDylib() {
            if let handle = dlopen(dylibPath, RTLD_NOW) {
                dlclose(handle)
                self.hookIsActive = false
                self.hookStatusText = "插件已就绪（请打开白名单内任意 App 触发激活）"
            } else {
                let errStr = dlerror().map { String(cString: $0) } ?? "未知加载错误"
                self.hookIsActive = false
                self.hookStatusText = "加载失败: \(errStr)"
            }
        } else {
            self.hookIsActive = false
            self.hookStatusText = "未找到 AutoIPLocHook.dylib（请用 RootHide Patcher 安装）"
        }
    }

    private func startNetworkMonitor() {
        pathMonitor.pathUpdateHandler = { [weak self] path in
            guard let self = self else { return }
            defer { self.lastPathStatus = path.status }
            guard let prev = self.lastPathStatus, prev != path.status, path.status == .satisfied else { return }
            DispatchQueue.main.async {
                if self.autoSyncOnNetworkChange && !(self.lockSessionGeo && self.isSimulating) {
                    self.syncEnvironment(forceReanchor: false)
                }
            }
        }
        pathMonitor.start(queue: monitorQueue)
    }

    private func loadSavedState() {
        if let dict = readSharedPlist(paths: geoPlistPaths) {
            if let sl = dict["spoofLocale"] as? Bool { self.spoofLocale = sl }
            if let sc = dict["spoofCarrier"] as? Bool { self.spoofCarrier = sc }
            if let sp = dict["spoofProxy"] as? Bool { self.spoofProxy = sp }

            if let enabled = dict["enabled"] as? Bool, enabled,
               let ip = dict["ip"] as? String,
               let cc = dict["countryCode"] as? String,
               let tz = dict["timezone"] as? String,
               let lat = dict["lat"] as? Double,
               let lon = dict["lon"] as? Double {
                let street = dict["street"] as? String ?? "742 Evergreen Terrace"
                let zip = dict["zip"] as? String ?? "10001"
                let city = dict["city"] as? String ?? ""
                let region = dict["region"] as? String ?? ""
                let isp = dict["isp"] as? String ?? "Residential Broadband"
                let profile = GeoProfile(
                    ip: ip, countryCode: cc, region: region, city: city,
                    timezone: tz, latitude: lat, longitude: lon,
                    street: street, zip: zip, isp: isp,
                    isProxy: dict["isProxy"] as? Bool,
                    isHosting: dict["isHosting"] as? Bool
                )
                self.lockedProfile = profile
                self.lastWiFiCountry = cc
                self.isSimulating = true
                self.exitIP = "\(ip) [\(cc)]"
                self.ispText = isp
                self.timezoneName = tz
                self.coordText = String(format: "%.5f, %.5f", lat, lon)
                self.streetAddress = street
                self.zipCode = zip
                self.updateMappedProfileSummary(for: cc)
                self.writeGeoPlist(profile)
                if self.naturalGpsJitter {
                    self.startGpsDriftTimer()
                }
            }
        }
        if let wDict = readSharedPlist(paths: wifiPlistPaths),
           let nets = wDict["networks"] as? [[String: String]] {
            self.wifiList = nets
            self.saveWiFiPlist(enabled: isSimulating)
        }
    }

    func syncEnvironment(forceReanchor: Bool = true) {
        refreshHookStatus()
        guard !isSyncing else { return }
        isSyncing = true
        statusError = nil

        let endpoints = [
            "http://ip-api.com/json/?fields=status,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,proxy,hosting,query",
            "https://ipwho.is/",
            "https://freeipapi.com/api/json",
            "https://ipinfo.io/json",
            "https://api.ip.sb/geoip"
        ]

        let cfg = URLSessionConfiguration.default
        cfg.timeoutIntervalForRequest = 15.0
        cfg.timeoutIntervalForResource = 20.0
        cfg.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        let session = URLSession(configuration: cfg)

        let lock = NSLock()
        var settled = false
        var completedCount = 0
        var lastErrorMsg = "超时"

        for urlStr in endpoints {
            guard let url = URL(string: urlStr) else { continue }
            var req = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalAndRemoteCacheData, timeoutInterval: 15.0)
            req.setValue("Mozilla/5.0 (iPhone; CPU iPhone OS 16_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.2 Mobile/15E148 Safari/604.1", forHTTPHeaderField: "User-Agent")
            req.setValue("application/json", forHTTPHeaderField: "Accept")

            session.dataTask(with: req) { [weak self] data, response, error in
                guard let self = self else { return }

                var parsedProfile: GeoProfile? = nil
                if let http = response as? HTTPURLResponse, (200...299).contains(http.statusCode),
                   let data = data {
                    parsedProfile = self.parseGeoJSON(data: data)
                }

                lock.lock()
                if settled {
                    lock.unlock()
                    return
                }
                if let valid = parsedProfile {
                    settled = true
                    lock.unlock()
                    session.invalidateAndCancel()
                    DispatchQueue.main.async {
                        self.applyDetectedProfile(valid, forceReanchor: forceReanchor)
                    }
                    return
                }

                completedCount += 1
                let code = (response as? HTTPURLResponse)?.statusCode ?? (error as NSError?)?.code ?? -1
                lastErrorMsg = "code:\(code)"
                let allFailed = (completedCount >= endpoints.count)
                if allFailed {
                    settled = true
                }
                lock.unlock()

                if allFailed {
                    session.finishTasksAndInvalidate()
                    DispatchQueue.main.async {
                        self.isSyncing = false
                        self.statusError = "当前节点无法连接 IP 探测接口（\(lastErrorMsg)），请切换节点后重试。"
                    }
                }
            }.resume()
        }
    }

    private func parseGeoJSON(data: Data) -> GeoProfile? {
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
        if let status = json["status"] as? String, status.lowercased() == "fail" { return nil }
        if let success = json["success"] as? Bool, !success { return nil }

        let ip = (json["query"] as? String)
            ?? (json["ip"] as? String)
            ?? (json["ipAddress"] as? String)
            ?? ""
        guard !ip.isEmpty else { return nil }

        let cc = ((json["countryCode"] as? String)
            ?? (json["country_code"] as? String)
            ?? (json["country"] as? String)
            ?? "US").uppercased()
        if cc == "CN" || cc == "HK" || cc == "MO" { return nil }

        let region = (json["regionName"] as? String)
            ?? (json["region"] as? String)
            ?? ""
        let city = (json["city"] as? String)
            ?? (json["cityName"] as? String)
            ?? ""
        let isp = (json["isp"] as? String)
            ?? ((json["connection"] as? [String: Any])?["isp"] as? String)
            ?? (json["org"] as? String)
            ?? "Residential Broadband"
        let zip = (json["zip"] as? String)
            ?? (json["postal"] as? String)
            ?? (json["zipCode"] as? String)
            ?? ""

        let isProxy = (json["proxy"] as? Bool)
            ?? ((json["security"] as? [String: Any])?["proxy"] as? Bool)
        let isHosting = (json["hosting"] as? Bool)
            ?? ((json["security"] as? [String: Any])?["hosting"] as? Bool)

        var tz = "America/New_York"
        if let tzDict = json["timezone"] as? [String: Any], let tzId = tzDict["id"] as? String, !tzId.isEmpty {
            tz = tzId
        } else if let tzStr = json["timezone"] as? String, !tzStr.isEmpty {
            tz = tzStr
        } else if let tzArr = json["timeZones"] as? [String], let firstTz = tzArr.first, !firstTz.isEmpty {
            tz = firstTz
        }

        var lat = (json["lat"] as? Double)
            ?? (json["latitude"] as? Double)
            ?? 0.0
        var lon = (json["lon"] as? Double)
            ?? (json["longitude"] as? Double)
            ?? 0.0
        if (lat == 0.0 || lon == 0.0), let locStr = json["loc"] as? String {
            let parts = locStr.split(separator: ",")
            if parts.count == 2, let la = Double(parts[0]), let lo = Double(parts[1]) {
                lat = la
                lon = lo
            }
        }
        if lat == 0.0 && lon == 0.0 {
            lat = 39.0438
            lon = -77.4874
        }

        return GeoProfile(
            ip: ip, countryCode: cc, region: region, city: city,
            timezone: tz, latitude: lat, longitude: lon,
            street: "", zip: zip, isp: isp,
            isProxy: isProxy, isHosting: isHosting
        )
    }

    private func applyDetectedProfile(_ raw: GeoProfile, forceReanchor: Bool) {
        if lockSessionGeo, isSimulating, let locked = lockedProfile,
           locked.countryCode == raw.countryCode, locked.timezone == raw.timezone, !forceReanchor {
            self.exitIP = "\(raw.ip) [\(raw.countryCode)]"
            self.ispText = raw.isp
            self.isSyncing = false
            return
        }

        let jitterLat = raw.latitude + Double.random(in: -0.0065...0.0065)
        let jitterLon = raw.longitude + Double.random(in: -0.0065...0.0065)
        let loc = CLLocation(latitude: jitterLat, longitude: jitterLon)

        let fallbackCity = raw.city.isEmpty ? (raw.countryCode == "US" ? "Austin" : raw.countryCode) : raw.city
        let fallbackRegion = raw.region.isEmpty ? raw.countryCode : raw.region
        let fallbackStreet = "\(Int.random(in: 112...4890)) Oakridge Ave, \(fallbackCity), \(fallbackRegion)"
        let fallbackZip = raw.zip.isEmpty ? String(Int.random(in: 10001...98199)) : raw.zip

        let finalized = GeoProfile(
            ip: raw.ip, countryCode: raw.countryCode, region: raw.region,
            city: raw.city, timezone: raw.timezone,
            latitude: jitterLat, longitude: jitterLon,
            street: fallbackStreet, zip: fallbackZip, isp: raw.isp,
            isProxy: raw.isProxy, isHosting: raw.isHosting
        )
        self.commitSimulation(finalized)

        CLGeocoder().reverseGeocodeLocation(loc) { [weak self] placemarks, _ in
            guard let self = self, let pm = placemarks?.first else { return }
            let num = pm.subThoroughfare ?? "\(Int.random(in: 105...3980))"
            let road = pm.thoroughfare ?? "Maple Creek Dr"
            let c = pm.locality ?? fallbackCity
            let st = pm.administrativeArea ?? fallbackRegion
            let resolvedStreet = "\(num) \(road), \(c), \(st)"
            let resolvedZip = (pm.postalCode?.isEmpty == false) ? pm.postalCode! : fallbackZip

            DispatchQueue.main.async {
                self.streetAddress = resolvedStreet
                self.zipCode = resolvedZip
                if var current = self.lockedProfile {
                    current.street = resolvedStreet
                    current.zip = resolvedZip
                    self.lockedProfile = current
                    self.writeGeoPlist(current)
                }
            }
        }
    }

    private func writeGeoPlist(_ profile: GeoProfile) {
        var geoDict: [String: Any] = [
            "enabled": true,
            "spoofLocale": spoofLocale,
            "spoofCarrier": spoofCarrier,
            "spoofProxy": spoofProxy,
            "ip": profile.ip,
            "countryCode": profile.countryCode,
            "region": profile.region,
            "city": profile.city,
            "timezone": profile.timezone,
            "lat": profile.latitude,
            "lon": profile.longitude,
            "street": profile.street,
            "zip": profile.zip,
            "isp": profile.isp
        ]
        if let proxy = profile.isProxy { geoDict["isProxy"] = proxy }
        if let hosting = profile.isHosting { geoDict["isHosting"] = hosting }
        writeSharedPlist(geoDict, paths: geoPlistPaths)
    }

    private func pushSimulatedCoordinate(lat: Double, lon: Double) {
        let hAcc = naturalGpsJitter ? Double.random(in: 5.5...14.5) : 5.0
        let vAcc = naturalGpsJitter ? Double.random(in: 4.0...11.0) : 8.0
        let simLocation = CLLocation(
            coordinate: CLLocationCoordinate2D(latitude: lat, longitude: lon),
            altitude: Double.random(in: 18.0...145.0),
            horizontalAccuracy: hAcc,
            verticalAccuracy: vAcc,
            course: -1,
            speed: 0,
            timestamp: Date()
        )
        simManager.stopLocationSimulation()
        simManager.clearSimulatedLocations()
        simManager.appendSimulatedLocation(simLocation)
        simManager.flush()
        simManager.startLocationSimulation()
    }

    private func startGpsDriftTimer() {
        stopGpsDriftTimer()
        gpsDriftTimer = Timer.scheduledTimer(withTimeInterval: 45.0, repeats: true) { [weak self] _ in
            guard let self = self, self.isSimulating, self.naturalGpsJitter, let anchor = self.lockedProfile else { return }
            let dLat = anchor.latitude + Double.random(in: -0.000025...0.000025)
            let dLon = anchor.longitude + Double.random(in: -0.000025...0.000025)
            self.pushSimulatedCoordinate(lat: dLat, lon: dLon)
        }
    }

    private func stopGpsDriftTimer() {
        gpsDriftTimer?.invalidate()
        gpsDriftTimer = nil
    }

    private func commitSimulation(_ profile: GeoProfile) {
        self.lockedProfile = profile
        self.isSimulating = true
        self.isSyncing = false
        self.statusError = nil
        self.exitIP = "\(profile.ip) [\(profile.countryCode)]"
        self.ispText = profile.isp
        self.timezoneName = profile.timezone
        self.coordText = String(format: "%.5f, %.5f", profile.latitude, profile.longitude)
        self.streetAddress = profile.street
        self.zipCode = profile.zip
        self.updateMappedProfileSummary(for: profile.countryCode)

        if self.wifiList.isEmpty || self.lastWiFiCountry != profile.countryCode {
            self.lastWiFiCountry = profile.countryCode
            regenerateWiFiList(for: profile.countryCode, save: false)
        }

        writeGeoPlist(profile)
        saveWiFiPlist(enabled: true)
        pushSimulatedCoordinate(lat: profile.latitude, lon: profile.longitude)
        if naturalGpsJitter {
            startGpsDriftTimer()
        }
    }

    func regenerateWiFiList(for countryCode: String? = nil, save: Bool = true) {
        let cc = (countryCode ?? lockedProfile?.countryCode ?? lastWiFiCountry).uppercased()
        let prefixMap: [String: [String]] = [
            "US": ["Xfinity", "SpectrumSetup", "ATT-FIBER", "Fios", "MySpectrumWiFi", "NETGEAR", "Linksys"],
            "GB": ["BTWi-fi", "SKY", "VM", "TalkTalk", "Plusnet", "Vodafone", "EE-Hub"],
            "JP": ["aterm", "Buffalo-A", "elecom", "docomo", "SoftBank", "TP-Link"],
            "DE": ["FRITZ!Box", "WLAN", "Vodafone", "o2-WLAN", "Telekom"],
            "CA": ["BELL", "ROGERS", "TELUS", "Shaw", "Videotron"],
            "AU": ["Telstra", "Optus", "TPG", "Belong", "AussieBB"],
            "SG": ["Singtel", "StarHub", "M1-Fibre", "MyRepublic", "ASUS"],
            "KR": ["KT_GiGA", "SK_WiFiGIGA", "U+Net", "iptime"]
        ]
        let prefixes = prefixMap[cc] ?? ["NETGEAR", "TP-Link", "ASUS", "Linksys", "HOME-WIFI"]
        let ouis = ["20:4E:7F", "00:26:F2", "E4:F0:42", "B8:3A:08", "C8:D7:19", "44:E9:DD"]
        var generated: [[String: String]] = []

        for _ in 0..<14 {
            let p = prefixes.randomElement()!
            let suffix = String(format: "%04X", Int.random(in: 0x1000...0xFFFF))
            let band = Bool.random() ? "-5G" : ""
            let oui = ouis.randomElement()!
            let mac = String(format: "%@:%02X:%02X:%02X", oui, Int.random(in: 0...255), Int.random(in: 0...255), Int.random(in: 0...255))
            generated.append(["SSID": "\(p)-\(suffix)\(band)", "BSSID": mac])
        }
        self.wifiList = generated
        self.lastWiFiCountry = cc
        if save {
            saveWiFiPlist(enabled: isSimulating)
        }
    }

    private func saveWiFiPlist(enabled: Bool) {
        let dict: [String: Any] = [
            "enabled": enabled,
            "networks": wifiList
        ]
        writeSharedPlist(dict, paths: wifiPlistPaths)
    }

    func runEnvironmentAudit() {
        guard !isAuditing else { return }
        isAuditing = true
        refreshHookStatus()

        let group = DispatchGroup()
        var ipv6LeakedIP: String? = nil
        var ipRiskDetail = "未同步节点，请先点击同步"
        var ipRiskPassed = false
        var ipRiskWarn = true

        if let p = lockedProfile {
            if p.isHosting == true || p.isProxy == true {
                let tags = [p.isHosting == true ? "机房(Hosting)" : nil, p.isProxy == true ? "代理(Proxy)" : nil].compactMap { $0 }.joined(separator: " / ")
                ipRiskDetail = "\(p.ip) · 检测到风险标签: \(tags)（ISP: \(p.isp)）"
                ipRiskPassed = false
                ipRiskWarn = true
            } else if p.isHosting == false && p.isProxy == false {
                ipRiskDetail = "\(p.ip) · 住宅/非机房特征良好（ISP: \(p.isp)）"
                ipRiskPassed = true
                ipRiskWarn = false
            } else {
                ipRiskDetail = "\(p.ip) · ISP: \(p.isp)（当前接口未返回风险标签）"
                ipRiskPassed = true
                ipRiskWarn = true
            }
        }

        group.enter()
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = 3.5
        cfg.timeoutIntervalForResource = 4.0
        let session = URLSession(configuration: cfg)
        if let v6Url = URL(string: "https://api6.ipify.org?format=json") {
            session.dataTask(with: v6Url) { data, response, _ in
                if let http = response as? HTTPURLResponse, (200...299).contains(http.statusCode),
                   let data = data,
                   let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                   let ip = obj["ip"] as? String, ip.contains(":") {
                    ipv6LeakedIP = ip
                }
                session.finishTasksAndInvalidate()
                group.leave()
            }.resume()
        } else {
            group.leave()
        }

        group.notify(queue: .main) { [weak self] in
            guard let self = self else { return }
            var results: [AuditItem] = []

            results.append(AuditItem(
                title: "底层隐身插件 (目标 v\(Self.expectedHookVersion))",
                detail: self.versionMismatchWarning ?? self.hookStatusText,
                passed: self.hookIsActive && self.versionMismatchWarning == nil,
                isWarning: !self.hookIsActive || self.versionMismatchWarning != nil
            ))

            results.append(AuditItem(
                title: "出口 IP 纯净度",
                detail: ipRiskDetail,
                passed: ipRiskPassed,
                isWarning: ipRiskWarn
            ))

            if let v6 = ipv6LeakedIP {
                results.append(AuditItem(
                    title: "IPv6 防泄露检测",
                    detail: "检测到活跃 IPv6 出口 (\(v6))，建议在路由器或代理中关闭 IPv6 防止真实地址泄露",
                    passed: false,
                    isWarning: true
                ))
            } else {
                results.append(AuditItem(
                    title: "IPv6 防泄露检测",
                    detail: "已阻断或无活跃 IPv6 泄露，纯 IPv4 出口正常",
                    passed: true,
                    isWarning: false
                ))
            }

            let consistencyOk = self.isSimulating && self.lockedProfile != nil
            results.append(AuditItem(
                title: "定位 / 时区 / 运营商 / 语言联动",
                detail: consistencyOk
                    ? "\(self.lockedProfile!.countryCode) · \(self.timezoneName) · \(self.mappedProfileText)（白名单已选 \(self.enabledBundleIDs.count) 个 App）"
                    : "尚未开启模拟，目标 App 将读取本机真实参数",
                passed: consistencyOk,
                isWarning: !consistencyOk
            ))

            self.auditItems = results
            self.isAuditing = false
        }
    }

    func resetAppleMapsCache() {
        let fm = FileManager.default
        let paths = [
            "/var/mobile/Library/Caches/com.apple.Maps",
            "/var/mobile/Library/Caches/com.apple.geod",
            "/var/mobile/Library/Caches/GeoServices",
            "/var/mobile/Library/GeoServices",
            "/var/mobile/Library/Preferences/com.apple.GEO.plist"
        ]
        var cleared = 0
        for p in paths {
            if fm.fileExists(atPath: p) {
                do {
                    try fm.removeItem(atPath: p)
                    cleared += 1
                } catch {}
            }
        }
        let targetCC = (lockedProfile?.countryCode ?? "US") as CFString
        CFPreferencesSetValue("CountryProviders" as CFString, nil, "com.apple.GEO" as CFString, kCFPreferencesCurrentUser, kCFPreferencesAnyHost)
        CFPreferencesSetValue("GEOCountryConfigurationCountryCode" as CFString, targetCC, "com.apple.GEO" as CFString, kCFPreferencesCurrentUser, kCFPreferencesAnyHost)
        CFPreferencesSynchronize("com.apple.GEO" as CFString, kCFPreferencesCurrentUser, kCFPreferencesAnyHost)

        mapResetMessage = "已清理 \(cleared) 处地图缓存并重置地区键为 \(targetCC)。若地图仍显示网格，请把代理中苹果 IPv6 规则改为 REJECT 后重开地图。"
    }

    func stopSimulation() {
        stopGpsDriftTimer()
        simManager.stopLocationSimulation()
        simManager.clearSimulatedLocations()
        simManager.flush()

        isSimulating = false
        lockedProfile = nil
        exitIP = "未获取 [--]"
        ispText = "--"
        timezoneName = "- (待同步)"
        coordText = "- (0.0000, 0.0000)"
        mappedProfileText = "已恢复原机参数"
        streetAddress = "等待同步解析附近精确街道地址..."
        zipCode = "--"
        statusError = nil
        mapResetMessage = nil
        auditItems = []

        let geoDict: [String: Any] = [
            "enabled": false,
            "spoofLocale": spoofLocale,
            "spoofCarrier": spoofCarrier,
            "spoofProxy": spoofProxy
        ]
        writeSharedPlist(geoDict, paths: geoPlistPaths)
        saveWiFiPlist(enabled: false)
    }
}

struct WhitelistManagerView: View {
    @ObservedObject var engine: LocationEngine
    @State private var searchText = ""
    @State private var customBundleInput = ""

    private var filteredApps: [InstalledAppInfo] {
        let q = searchText.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if q.isEmpty { return engine.installedApps }
        return engine.installedApps.filter {
            $0.name.lowercased().contains(q) || $0.bundleId.lowercased().contains(q)
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 8) {
                Text("仅对下方打开开关的 App 注入 AutoIPLocHook（隐藏小火箭代理/VPN网卡/模拟定位标记，伪造时区与运营商）。工具软件已自动排除防闪退。")
                    .font(.caption)
                    .foregroundColor(.secondary)
                Text("提示：Amazon 等极高风控原生 App 请保持关闭，改去 RootHide 黑名单 + 路由器代理。")
                    .font(.caption2.bold())
                    .foregroundColor(.orange)

                if let fb = engine.whitelistFeedback {
                    Text(fb)
                        .font(.caption.bold())
                        .foregroundColor(.white)
                        .padding(8)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(engine.whitelistHasError ? Color.red : Color.green)
                        .cornerRadius(8)
                }

                TextField("搜索 App 名称或 Bundle ID...", text: $searchText)
                    .textFieldStyle(RoundedBorderTextFieldStyle())
                    .autocapitalization(.none)
                    .disableAutocorrection(true)

                HStack(spacing: 8) {
                    TextField("手动添加 Bundle ID（可选）", text: $customBundleInput)
                        .textFieldStyle(RoundedBorderTextFieldStyle())
                        .autocapitalization(.none)
                        .disableAutocorrection(true)
                        .font(.caption)
                    Button("添加") {
                        engine.addCustomBundleID(customBundleInput)
                        customBundleInput = ""
                    }
                    .buttonStyle(.borderedProminent)
                    .font(.caption)
                }
            }
            .padding()
            .background(Color(.secondarySystemBackground))

            List {
                ForEach(filteredApps) { app in
                    Toggle(isOn: Binding(
                        get: { engine.enabledBundleIDs.contains(app.bundleId) },
                        set: { engine.setBundleEnabled(app.bundleId, enabled: $0) }
                    )) {
                        VStack(alignment: .leading, spacing: 2) {
                            HStack(spacing: 6) {
                                Text(app.name)
                                    .font(.subheadline.weight(.medium))
                                if app.isSystem {
                                    Text("系统")
                                        .font(.caption2)
                                        .padding(.horizontal, 5)
                                        .padding(.vertical, 1)
                                        .background(Color.blue.opacity(0.15))
                                        .foregroundColor(.blue)
                                        .cornerRadius(4)
                                }
                            }
                            Text(app.bundleId)
                                .font(.caption2.monospaced())
                                .foregroundColor(.secondary)
                        }
                    }
                }
            }
            .listStyle(PlainListStyle())
        }
        .navigationTitle("定向伪装 App 管理")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                Button("重扫") {
                    engine.loadInstalledAppsAndWhitelist()
                }
            }
        }
        .onAppear {
            engine.loadInstalledAppsAndWhitelist()
        }
    }
}

struct ContentView: View {
    @ObservedObject private var engine = LocationEngine.shared

    var body: some View {
        NavigationView {
            ScrollView {
                VStack(spacing: 14) {
                    if let mismatch = engine.versionMismatchWarning {
                        Text("🚨 \(mismatch)")
                            .font(.footnote.bold())
                            .foregroundColor(.white)
                            .padding(12)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(Color.orange)
                            .cornerRadius(12)
                    }

                    if let err = engine.statusError {
                        Text("⚠️ \(err)")
                            .font(.footnote.bold())
                            .foregroundColor(.white)
                            .padding(10)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(Color.red)
                            .cornerRadius(10)
                    }

                    // 核心状态卡片
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Image(systemName: engine.isSimulating ? "checkmark.circle.fill" : "stop.circle.fill")
                                .foregroundColor(engine.isSimulating ? .green : .gray)
                            Text(engine.isSimulating ? "正在模拟海外住宅环境" : "已停止模拟")
                                .font(.headline)
                        }
                        Text("出口 IP: \(engine.exitIP)")
                            .font(.subheadline.monospaced())
                        Text("运营商/ISP: \(engine.ispText)")
                            .font(.caption)
                            .foregroundColor(.secondary)
                        Text("全局时区: \(engine.timezoneName)")
                            .font(.subheadline)
                        Text("伪造身份: \(engine.mappedProfileText)")
                            .font(.caption.bold())
                            .foregroundColor(.blue)
                        Text("模拟坐标: \(engine.coordText)")
                            .font(.caption.monospaced())
                            .foregroundColor(.secondary)
                        Divider()
                        HStack {
                            Circle()
                                .fill(engine.hookIsActive ? Color.green : Color.orange)
                                .frame(width: 8, height: 8)
                            Text("底层隐身插件: \(engine.hookStatusText)")
                                .font(.caption.bold())
                                .foregroundColor(engine.hookIsActive ? .green : .orange)
                            Spacer()
                            Button("刷新") {
                                engine.refreshHookStatus()
                            }
                            .font(.caption)
                        }
                        Divider()
                        Text("IP 附近精确住宅街道地址")
                            .font(.caption)
                            .foregroundColor(.secondary)
                        Text(engine.streetAddress)
                            .font(.subheadline.weight(.medium))
                        HStack {
                            Text("ZIP 邮编: \(engine.zipCode)")
                                .font(.subheadline.bold())
                            Spacer()
                            Button("复制 ZIP") {
                                UIPasteboard.general.string = engine.zipCode
                            }
                            .buttonStyle(.bordered)
                            Button("复制地址") {
                                UIPasteboard.general.string = engine.streetAddress
                            }
                            .buttonStyle(.borderedProminent)
                            .tint(.green)
                        }
                    }
                    .padding()
                    .background(Color(.secondarySystemBackground))
                    .cornerRadius(14)

                    // 可视化定向白名单入口
                    NavigationLink(destination: WhitelistManagerView(engine: engine)) {
                        HStack {
                            Image(systemName: "checklist")
                                .font(.title3)
                                .foregroundColor(.white)
                                .frame(width: 34, height: 34)
                                .background(Color.indigo)
                                .cornerRadius(8)
                            VStack(alignment: .leading, spacing: 2) {
                                Text("定向伪装 App 白名单管理")
                                    .font(.subheadline.bold())
                                    .foregroundColor(.primary)
                                Text("已勾选 \(engine.enabledBundleIDs.count) 个目标 App · 点此勾选隐身与代理隐藏对象")
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                            }
                            Spacer()
                            Image(systemName: "chevron.right")
                                .foregroundColor(.secondary)
                        }
                        .padding()
                        .background(Color(.secondarySystemBackground))
                        .cornerRadius(14)
                    }

                    // 主同步按钮
                    Button(action: { engine.syncEnvironment(forceReanchor: true) }) {
                        HStack(spacing: 8) {
                            if engine.isSyncing {
                                ProgressView()
                                    .progressViewStyle(CircularProgressViewStyle(tint: .white))
                            }
                            Text(engine.isSyncing ? "正在探测当前海外出口 IP..." : "立即同步当前 IP 定位与全局环境")
                                .font(.headline)
                        }
                        .foregroundColor(.white)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 14)
                        .background(engine.isSyncing ? Color.blue.opacity(0.75) : Color.blue)
                        .cornerRadius(12)
                    }
                    .disabled(engine.isSyncing)

                    // 一键环境与防泄露体检
                    VStack(alignment: .leading, spacing: 10) {
                        HStack {
                            Text("环境一致性与防泄露体检")
                                .font(.subheadline.bold())
                            Spacer()
                            Button(action: { engine.runEnvironmentAudit() }) {
                                HStack(spacing: 4) {
                                    if engine.isAuditing {
                                        ProgressView().scaleEffect(0.75)
                                    }
                                    Text(engine.isAuditing ? "检测中..." : "开始体检")
                                        .font(.caption.bold())
                                }
                            }
                            .buttonStyle(.bordered)
                            .disabled(engine.isAuditing)
                        }
                        if engine.auditItems.isEmpty {
                            Text("点击“开始体检”检测插件版本、IP 机房风险及 IPv6 泄露状态。")
                                .font(.caption)
                                .foregroundColor(.secondary)
                        } else {
                            ForEach(engine.auditItems) { item in
                                HStack(alignment: .top, spacing: 8) {
                                    Image(systemName: item.passed ? "checkmark.shield.fill" : (item.isWarning ? "exclamationmark.triangle.fill" : "xmark.octagon.fill"))
                                        .foregroundColor(item.passed ? .green : (item.isWarning ? .orange : .red))
                                        .font(.subheadline)
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(item.title)
                                            .font(.caption.bold())
                                        Text(item.detail)
                                            .font(.caption2)
                                            .foregroundColor(.secondary)
                                    }
                                }
                            }
                        }
                    }
                    .padding()
                    .background(Color(.secondarySystemBackground))
                    .cornerRadius(14)

                    // 模块化风控开关
                    VStack(spacing: 10) {
                        Toggle("网络与代理切换自动同步 IP + 时区 + Wi-Fi", isOn: $engine.autoSyncOnNetworkChange)
                            .font(.subheadline)
                        Toggle("防旋转 IP 跳变锁定（同会话固定坐标与时区）", isOn: $engine.lockSessionGeo)
                            .font(.subheadline)
                        Divider()
                        Toggle("伪造目标 App 语言与区域 (NSLocale)", isOn: $engine.spoofLocale)
                            .font(.subheadline)
                        Toggle("伪造运营商与 SIM 卡信息 (CTCarrier)", isOn: $engine.spoofCarrier)
                            .font(.subheadline)
                        Toggle("隐藏系统代理与 VPN 网卡特征", isOn: $engine.spoofProxy)
                            .font(.subheadline)
                        Toggle("GPS 自然精度与微幅漂移保活（45秒刷新）", isOn: $engine.naturalGpsJitter)
                            .font(.subheadline)
                    }
                    .padding()
                    .background(Color(.secondarySystemBackground))
                    .cornerRadius(14)

                    // 周边 Wi-Fi 卡片
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Text("已注入周边 Wi-Fi（\(engine.wifiList.count) 个）")
                                .font(.subheadline.bold())
                            Spacer()
                            Button("换一批") {
                                engine.regenerateWiFiList(save: true)
                            }
                            .buttonStyle(.bordered)
                        }
                        if let first = engine.wifiList.first {
                            Text("主关联热点: \(first["SSID"] ?? "") (\(first["BSSID"] ?? ""))")
                                .font(.caption.monospaced())
                                .foregroundColor(.secondary)
                        }
                    }
                    .padding()
                    .background(Color(.secondarySystemBackground))
                    .cornerRadius(14)

                    // 彻底重置地图与缓存
                    VStack(alignment: .leading, spacing: 6) {
                        Button(action: { engine.resetAppleMapsCache() }) {
                            Text("彻底重置苹果国际地图（清除高德与地理缓存）")
                                .font(.subheadline.bold())
                                .foregroundColor(.blue)
                                .frame(maxWidth: .infinity)
                                .padding(.vertical, 12)
                                .background(Color.blue.opacity(0.12))
                                .cornerRadius(12)
                        }
                        if let msg = engine.mapResetMessage {
                            Text(msg)
                                .font(.caption2)
                                .foregroundColor(.secondary)
                                .padding(.horizontal, 4)
                        }
                    }

                    Button(action: { engine.stopSimulation() }) {
                        Text("一键停止模拟并立即恢复真实定位")
                            .font(.subheadline)
                            .foregroundColor(.red)
                            .padding(.top, 6)
                    }
                }
                .padding()
            }
            .navigationTitle("IP 自动定位与全局时区助手")
            .onAppear {
                engine.refreshHookStatus()
                engine.loadInstalledAppsAndWhitelist()
            }
        }
        .navigationViewStyle(StackNavigationViewStyle())
    }
}

@main
struct AutoIPLocApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}
