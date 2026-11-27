import SwiftUI
import UIKit
import CoreLocation
import Network
import Darwin

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
}

final class LocationEngine: NSObject, ObservableObject, CLLocationManagerDelegate {
    static let shared = LocationEngine()

    @Published var isSimulating = false
    @Published var isSyncing = false
    @Published var statusError: String? = nil
    @Published var exitIP = "未获取 [--]"
    @Published var timezoneName = "- (待同步)"
    @Published var coordText = "- (0.0000, 0.0000)"
    @Published var streetAddress = "等待同步解析附近精确街道地址..."
    @Published var zipCode = "--"
    @Published var hookStatusText = "正在检测插件状态..."
    @Published var hookIsActive = false
    @Published var autoSyncOnNetworkChange = true
    @Published var lockSessionGeo = true
    @Published var wifiList: [[String: String]] = []

    private let geoPlistPaths = [
        "/var/mobile/Library/Preferences/com.autoiploc.geo.plist",
        "/var/tmp/com.autoiploc.geo.plist"
    ]
    private let wifiPlistPaths = [
        "/var/mobile/Library/Preferences/com.autoiploc.wifi.plist",
        "/var/tmp/com.autoiploc.wifi.plist"
    ]
    private let hookStatusPaths = [
        "/var/mobile/Library/Preferences/com.autoiploc.hookstatus.plist",
        "/var/tmp/com.autoiploc.hookstatus.plist"
    ]

    private let locationManager = CLLocationManager()
    private lazy var simManager = CLSimulationManager()
    private let pathMonitor = NWPathMonitor()
    private let monitorQueue = DispatchQueue(label: "com.autoiploc.netmonitor")
    private var lastPathStatus: NWPath.Status?
    private var lockedProfile: GeoProfile?

    override init() {
        super.init()
        locationManager.delegate = self
        locationManager.requestAlwaysAuthorization()
        loadSavedState()
        refreshHookStatus()
        startNetworkMonitor()
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

    private func findInstalledHookDylib() -> String? {
        let fm = FileManager.default
        let baseDir = "/var/containers/Bundle/Application"
        if let items = try? fm.contentsOfDirectory(atPath: baseDir) {
            for item in items where item.hasPrefix(".jbroot-") {
                let candidate = "\(baseDir)/\(item)/Library/MobileSubstrate/DynamicLibraries/AutoIPLocHook.dylib"
                if fm.fileExists(atPath: candidate) {
                    return candidate
                }
            }
        }
        let fallback = "/var/jb/Library/MobileSubstrate/DynamicLibraries/AutoIPLocHook.dylib"
        return fm.fileExists(atPath: fallback) ? fallback : nil
    }

    func refreshHookStatus() {
        let now = Date().timeIntervalSince1970
        for path in hookStatusPaths {
            if let dict = NSDictionary(contentsOfFile: path) as? [String: Any],
               let active = dict["active"] as? Bool, active {
                let ver = dict["version"] as? String ?? "4.4.0"
                let proc = dict["lastProc"] as? String ?? "目标应用"
                let hookOk = (dict["cHookReady"] as? Bool) ?? false
                let ts = (dict["timestamp"] as? Double) ?? 0
                let ageSec = Int(max(0, now - ts))

                if ts > 0 && ageSec <= 300 && hookOk {
                    self.hookIsActive = true
                    self.hookStatusText = "已实时激活 v\(ver) · arm64e就绪（\(proc) · \(ageSec)秒前）"
                    return
                } else if ts > 0 && ageSec > 300 {
                    self.hookIsActive = false
                    self.hookStatusText = "上次注入已过 \(ageSec / 60) 分钟（请确认 Dopamine 插件注入已开启并重开目标 App）"
                    return
                }
            }
        }

        if let dylibPath = findInstalledHookDylib() {
            if let handle = dlopen(dylibPath, RTLD_NOW) {
                dlclose(handle)
                self.hookIsActive = false
                self.hookStatusText = "插件就绪（请开启 Dopamine 插件注入并重开检测 App）"
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
        if let dict = readSharedPlist(paths: geoPlistPaths),
           let enabled = dict["enabled"] as? Bool, enabled,
           let ip = dict["ip"] as? String,
           let cc = dict["countryCode"] as? String,
           let tz = dict["timezone"] as? String,
           let lat = dict["lat"] as? Double,
           let lon = dict["lon"] as? Double {
            let street = dict["street"] as? String ?? "742 Evergreen Terrace"
            let zip = dict["zip"] as? String ?? "10001"
            let city = dict["city"] as? String ?? ""
            let region = dict["region"] as? String ?? ""
            let isp = dict["isp"] as? String ?? ""
            let profile = GeoProfile(
                ip: ip, countryCode: cc, region: region, city: city,
                timezone: tz, latitude: lat, longitude: lon,
                street: street, zip: zip, isp: isp
            )
            self.lockedProfile = profile
            self.isSimulating = true
            self.exitIP = "\(ip) [\(cc)]"
            self.timezoneName = tz
            self.coordText = String(format: "%.5f, %.5f", lat, lon)
            self.streetAddress = street
            self.zipCode = zip
        }
        if let wDict = readSharedPlist(paths: wifiPlistPaths),
           let nets = wDict["networks"] as? [[String: String]] {
            self.wifiList = nets
        }
    }

    func syncEnvironment(forceReanchor: Bool = true) {
        refreshHookStatus()
        guard !isSyncing else { return }
        isSyncing = true
        statusError = nil

        let endpoints = [
            "http://ip-api.com/json/?fields=status,countryCode,regionName,city,zip,lat,lon,timezone,isp,query",
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
            street: "", zip: zip, isp: isp
        )
    }

    private func applyDetectedProfile(_ raw: GeoProfile, forceReanchor: Bool) {
        if lockSessionGeo, isSimulating, let locked = lockedProfile,
           locked.countryCode == raw.countryCode, locked.timezone == raw.timezone, !forceReanchor {
            self.exitIP = "\(raw.ip) [\(raw.countryCode)]"
            self.isSyncing = false
            return
        }

        let jitterLat = raw.latitude + Double.random(in: -0.0065...0.0065)
        let jitterLon = raw.longitude + Double.random(in: -0.0065...0.0065)
        let loc = CLLocation(latitude: jitterLat, longitude: jitterLon)

        let fallbackStreet = "\(Int.random(in: 112...4890)) Oakridge Ave, \(raw.city.isEmpty ? "Austin" : raw.city), \(raw.region.isEmpty ? "TX" : raw.region)"
        let fallbackZip = raw.zip.isEmpty ? String(Int.random(in: 10001...98199)) : raw.zip

        let finalized = GeoProfile(
            ip: raw.ip, countryCode: raw.countryCode, region: raw.region,
            city: raw.city, timezone: raw.timezone,
            latitude: jitterLat, longitude: jitterLon,
            street: fallbackStreet, zip: fallbackZip, isp: raw.isp
        )
        self.commitSimulation(finalized)

        CLGeocoder().reverseGeocodeLocation(loc) { [weak self] placemarks, _ in
            guard let self = self, let pm = placemarks?.first else { return }
            let num = pm.subThoroughfare ?? "\(Int.random(in: 105...3980))"
            let road = pm.thoroughfare ?? "Maple Creek Dr"
            let c = pm.locality ?? (raw.city.isEmpty ? "Dallas" : raw.city)
            let st = pm.administrativeArea ?? (raw.region.isEmpty ? "TX" : raw.region)
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
        let geoDict: [String: Any] = [
            "enabled": true,
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
        writeSharedPlist(geoDict, paths: geoPlistPaths)
    }

    private func commitSimulation(_ profile: GeoProfile) {
        self.lockedProfile = profile
        self.isSimulating = true
        self.isSyncing = false
        self.statusError = nil
        self.exitIP = "\(profile.ip) [\(profile.countryCode)]"
        self.timezoneName = profile.timezone
        self.coordText = String(format: "%.5f, %.5f", profile.latitude, profile.longitude)
        self.streetAddress = profile.street
        self.zipCode = profile.zip

        if self.wifiList.isEmpty {
            regenerateWiFiList(save: false)
        }

        writeGeoPlist(profile)
        saveWiFiPlist(enabled: true)

        let simLocation = CLLocation(
            coordinate: CLLocationCoordinate2D(latitude: profile.latitude, longitude: profile.longitude),
            altitude: Double.random(in: 18.0...145.0),
            horizontalAccuracy: 5.0,
            verticalAccuracy: 8.0,
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

    func regenerateWiFiList(save: Bool = true) {
        let prefixes = [
            "Xfinity", "SpectrumSetup", "ATT-FIBER", "Fios",
            "MySpectrumWiFi", "NETGEAR", "Linksys", "HOME-WIFI"
        ]
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

    func resetAppleMapsCache() {
        let fm = FileManager.default
        let paths = [
            "/var/mobile/Library/Caches/com.apple.Maps",
            "/var/mobile/Library/Caches/GeoServices",
            "/var/mobile/Library/Preferences/com.apple.GEO.plist"
        ]
        for p in paths {
            try? fm.removeItem(atPath: p)
        }
    }

    func stopSimulation() {
        simManager.stopLocationSimulation()
        simManager.clearSimulatedLocations()
        simManager.flush()

        isSimulating = false
        lockedProfile = nil
        exitIP = "未获取 [--]"
        timezoneName = "- (待同步)"
        coordText = "- (0.0000, 0.0000)"
        streetAddress = "等待同步解析附近精确街道地址..."
        zipCode = "--"
        statusError = nil

        let geoDict: [String: Any] = ["enabled": false]
        writeSharedPlist(geoDict, paths: geoPlistPaths)
        saveWiFiPlist(enabled: false)
    }
}

struct ContentView: View {
    @ObservedObject private var engine = LocationEngine.shared

    var body: some View {
        NavigationView {
            ScrollView {
                VStack(spacing: 14) {
                    if let err = engine.statusError {
                        Text("⚠️ \(err)")
                            .font(.footnote.bold())
                            .foregroundColor(.white)
                            .padding(10)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(Color.red)
                            .cornerRadius(10)
                    }

                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Image(systemName: engine.isSimulating ? "checkmark.circle.fill" : "stop.circle.fill")
                                .foregroundColor(engine.isSimulating ? .green : .gray)
                            Text(engine.isSimulating ? "正在模拟海外住宅环境" : "已停止模拟")
                                .font(.headline)
                        }
                        Text("出口 IP: \(engine.exitIP)")
                            .font(.subheadline.monospaced())
                        Text("全局时区: \(engine.timezoneName)")
                            .font(.subheadline)
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

                    VStack(spacing: 10) {
                        Toggle("网络与代理切换自动同步 IP + 时区 + Wi-Fi", isOn: $engine.autoSyncOnNetworkChange)
                            .font(.subheadline)
                        Toggle("防旋转 IP 跳变锁定（同会话固定坐标与时区）", isOn: $engine.lockSessionGeo)
                            .font(.subheadline)
                    }
                    .padding()
                    .background(Color(.secondarySystemBackground))
                    .cornerRadius(14)

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

                    Button(action: { engine.resetAppleMapsCache() }) {
                        Text("重置并恢复苹果国际原生地图（清除高德缓存）")
                            .font(.subheadline.bold())
                            .foregroundColor(.blue)
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 12)
                            .background(Color.blue.opacity(0.12))
                            .cornerRadius(12)
                    }

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
            }
        }
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
