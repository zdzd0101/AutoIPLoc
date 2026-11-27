import SwiftUI
import UIKit
import CoreLocation
import Network
import AVFoundation
import Darwin
import ObjectiveC

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
    @Published var streetAddress = "等待获取 IP 附近的地理编码结果..."
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
    private let pathMonitor = NWPathMonitor()
    private let monitorQueue = DispatchQueue(label: "com.autoiploc.netmonitor")
    private let syncStateLock = NSLock()
    private var lastPathStatus: NWPath.Status?
    private var lockedProfile: GeoProfile?
    private var activeGeocodeRequestID = UUID()
    private var activeSyncRequestID = UUID()
    private var activeURLSession: URLSession?

    override init() {
        super.init()
        locationManager.delegate = self
        locationManager.requestAlwaysAuthorization()
        loadSavedState()
        refreshHookStatus()
        startNetworkMonitor()
    }

    private func readSharedPlist(paths: [String]) -> [String: Any]? {
        for path in paths {
            let url = URL(fileURLWithPath: path)
            guard let data = try? Data(contentsOf: url),
                  let value = try? PropertyListSerialization.propertyList(
                    from: data,
                    options: [],
                    format: nil
                  ),
                  let dictionary = value as? [String: Any] else {
                continue
            }
            return dictionary
        }
        return nil
    }

    private func writeSharedPlist(_ dict: [String: Any], paths: [String]) {
        let nsDict = dict as NSDictionary
        var successfulWrites = 0
        var failedPaths: [String] = []

        for path in paths {
            guard nsDict.write(toFile: path, atomically: true) else {
                failedPaths.append(path)
                continue
            }

            guard Darwin.chmod(path, 0o600) == 0 else {
                failedPaths.append(path)
                continue
            }
            successfulWrites += 1
        }

        if successfulWrites == 0 {
            statusError = "共享配置写入失败，所有配置路径均不可写：\(failedPaths.joined(separator: ", "))"
        } else if !failedPaths.isEmpty {
            statusError = "共享配置仅写入 \(successfulWrites) 个位置；部分备用路径不可写。"
        }
    }

    private func makeSimulationManager(requiredSelectors: [String]) -> CLSimulationManager? {
        guard let managerClass = NSClassFromString("CLSimulationManager") else {
            statusError = "当前系统未提供 CLSimulationManager，无法确认定位模拟已启动。"
            return nil
        }

        for name in requiredSelectors {
            let selector = NSSelectorFromString(name)
            guard class_getInstanceMethod(managerClass, selector) != nil else {
                statusError = "当前系统的 CLSimulationManager 缺少接口：\(name)"
                return nil
            }
        }
        return CLSimulationManager()
    }

    private func startLocationSimulation(for profile: GeoProfile) -> Bool {
        let required = [
            "stopLocationSimulation",
            "clearSimulatedLocations",
            "appendSimulatedLocation:",
            "flush",
            "startLocationSimulation"
        ]
        guard let manager = makeSimulationManager(requiredSelectors: required) else {
            return false
        }

        let location = CLLocation(
            coordinate: CLLocationCoordinate2D(
                latitude: profile.latitude,
                longitude: profile.longitude
            ),
            altitude: Double.random(in: 18.0...145.0),
            horizontalAccuracy: 5.0,
            verticalAccuracy: 8.0,
            course: -1,
            speed: 0,
            timestamp: Date()
        )
        manager.stopLocationSimulation()
        manager.clearSimulatedLocations()
        manager.appendSimulatedLocation(location)
        manager.flush()
        manager.startLocationSimulation()
        return true
    }

    private func stopLocationSimulation() -> Bool {
        let required = [
            "stopLocationSimulation",
            "clearSimulatedLocations",
            "flush"
        ]
        guard let manager = makeSimulationManager(requiredSelectors: required) else {
            return false
        }
        manager.stopLocationSimulation()
        manager.clearSimulatedLocations()
        manager.flush()
        return true
    }

    private func findInstalledHookDylib() -> String? {
        let fm = FileManager.default
        let baseDir = "/var/containers/Bundle/Application"
        var roots: [String] = []

        if let savedRootList = try? String(
            contentsOfFile: "/var/tmp/com.autoiploc.jbroot.txt",
            encoding: .utf8
        ) {
            roots.append(contentsOf: savedRootList.components(separatedBy: .newlines))
        }

        if let items = try? fm.contentsOfDirectory(atPath: baseDir) {
            roots.append(contentsOf: items
                .filter { $0.hasPrefix(".jbroot-") }
                .sorted()
                .map { "\(baseDir)/\($0)" })
        }

        var visitedRoots = Set<String>()
        for rawRoot in roots {
            let root = rawRoot.trimmingCharacters(in: .whitespacesAndNewlines)
            guard root.hasPrefix("\(baseDir)/.jbroot-"),
                  visitedRoots.insert(root).inserted else {
                continue
            }

            let candidate = "\(root)/Library/MobileSubstrate/DynamicLibraries/AutoIPLocHook.dylib"
            if fm.fileExists(atPath: candidate) {
                return candidate
            }
        }

        let fallback = "/var/jb/Library/MobileSubstrate/DynamicLibraries/AutoIPLocHook.dylib"
        return fm.fileExists(atPath: fallback) ? fallback : nil
    }

    func refreshHookStatus() {
        let now = Date().timeIntervalSince1970
        for path in hookStatusPaths {
            if let dict = readSharedPlist(paths: [path]),
               let active = dict["active"] as? Bool, active {
                let ver = dict["version"] as? String ?? "未知版本"
                let proc = dict["lastProc"] as? String ?? "未知进程"
                let hookOk = (dict["cHookReady"] as? Bool) ?? false
                let ts = (dict["timestamp"] as? Double) ?? 0
                let ageSec = Int(max(0, now - ts))

                self.hookIsActive = false
                if ts > 0 && ageSec <= 300 && hookOk {
                    self.hookStatusText = "检测到近期加载报告 v\(ver)（\(proc) · \(ageSec)秒前）；函数入口可用不代表全部 Hook 已生效"
                    return
                } else if ts > 0 && ageSec > 300 {
                    self.hookStatusText = "最近一次加载报告已过 \(ageSec / 60) 分钟；尚未验证当前目标进程状态"
                    return
                } else {
                    self.hookStatusText = "检测到加载报告，但报告字段不完整，无法确认实际功能状态"
                    return
                }
            }
        }

        if let dylibPath = findInstalledHookDylib() {
            if let handle = dlopen(dylibPath, RTLD_NOW) {
                dlclose(handle)
                self.hookIsActive = false
                self.hookStatusText = "动态库可由当前主程序加载；这不证明目标 App 已安装或执行 Hook"
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
            let street = dict["street"] as? String ?? "未提供街道地址"
            let zip = dict["zip"] as? String ?? "--"
            let city = dict["city"] as? String ?? ""
            let region = dict["region"] as? String ?? ""
            let isp = dict["isp"] as? String ?? ""
            let profile = GeoProfile(
                ip: ip, countryCode: cc, region: region, city: city,
                timezone: tz, latitude: lat, longitude: lon,
                street: street, zip: zip, isp: isp
            )
            self.lockedProfile = profile
            self.isSimulating = startLocationSimulation(for: profile)
            self.exitIP = "\(ip) [\(cc)]"
            self.timezoneName = tz
            self.coordText = String(format: "%.5f, %.5f", lat, lon)
            self.streetAddress = street
            self.zipCode = zip
            if !self.isSimulating && self.statusError == nil {
                self.statusError = "已加载保存的定位配置，但系统未确认定位模拟已启动。"
            }
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

        let requestID = UUID()
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

        var requests: [URLRequest] = []
        for urlStr in endpoints {
            guard let url = URL(string: urlStr) else { continue }
            var req = URLRequest(
                url: url,
                cachePolicy: .reloadIgnoringLocalAndRemoteCacheData,
                timeoutInterval: 15.0
            )
            req.setValue(
                "Mozilla/5.0 (iPhone; CPU iPhone OS 16_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.2 Mobile/15E148 Safari/604.1",
                forHTTPHeaderField: "User-Agent"
            )
            req.setValue("application/json", forHTTPHeaderField: "Accept")
            requests.append(req)
        }

        guard !requests.isEmpty else {
            isSyncing = false
            statusError = "没有可用的 IP 探测接口地址。"
            return
        }

        syncStateLock.lock()
        activeSyncRequestID = requestID
        activeURLSession = session
        syncStateLock.unlock()

        var settled = false
        var completedCount = 0
        var lastErrorMsg = "超时"
        let expectedCount = requests.count

        for request in requests {
            session.dataTask(with: request) { [weak self] data, response, error in
                guard let self = self else { return }

                var parsedProfile: GeoProfile? = nil
                if let http = response as? HTTPURLResponse,
                   (200...299).contains(http.statusCode),
                   let data = data {
                    parsedProfile = self.parseGeoJSON(data: data)
                }

                self.syncStateLock.lock()
                guard self.activeSyncRequestID == requestID else {
                    self.syncStateLock.unlock()
                    return
                }
                if settled {
                    self.syncStateLock.unlock()
                    return
                }

                if let valid = parsedProfile {
                    settled = true
                    self.activeURLSession = nil
                    self.syncStateLock.unlock()
                    session.invalidateAndCancel()

                    DispatchQueue.main.async {
                        self.syncStateLock.lock()
                        let stillCurrent = self.activeSyncRequestID == requestID
                        self.syncStateLock.unlock()
                        guard stillCurrent else { return }
                        self.applyDetectedProfile(valid, forceReanchor: forceReanchor)
                    }
                    return
                }

                completedCount += 1
                let code = (response as? HTTPURLResponse)?.statusCode
                    ?? (error as NSError?)?.code
                    ?? -1
                lastErrorMsg = "code:\(code)"
                let allFailed = completedCount >= expectedCount
                if allFailed {
                    settled = true
                    self.activeURLSession = nil
                }
                self.syncStateLock.unlock()

                if allFailed {
                    session.finishTasksAndInvalidate()
                    DispatchQueue.main.async {
                        self.syncStateLock.lock()
                        let stillCurrent = self.activeSyncRequestID == requestID
                        self.syncStateLock.unlock()
                        guard stillCurrent else { return }
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

        let rawCountryCode = (json["countryCode"] as? String)
            ?? (json["country_code"] as? String)
            ?? (json["country"] as? String)
            ?? ""
        let cc = rawCountryCode.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
        guard cc.utf8.count == 2,
              cc.utf8.allSatisfy({ (65...90).contains(Int($0)) }) else { return nil }
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
            ?? "Unknown"
        let zip = (json["zip"] as? String)
            ?? (json["postal"] as? String)
            ?? (json["zipCode"] as? String)
            ?? ""

        var tz: String?
        if let tzDict = json["timezone"] as? [String: Any],
           let tzId = tzDict["id"] as? String, !tzId.isEmpty {
            tz = tzId
        } else if let tzStr = json["timezone"] as? String, !tzStr.isEmpty {
            tz = tzStr
        } else if let tzArr = json["timeZones"] as? [String],
                  let firstTz = tzArr.first, !firstTz.isEmpty {
            tz = firstTz
        }
        guard let timezone = tz,
              TimeZone(identifier: timezone) != nil else { return nil }

        var lat = (json["lat"] as? Double)
            ?? (json["latitude"] as? Double)
            ?? 0.0
        var lon = (json["lon"] as? Double)
            ?? (json["longitude"] as? Double)
            ?? 0.0
        if (json["lat"] == nil || json["latitude"] == nil ||
            json["lon"] == nil || json["longitude"] == nil),
           let locStr = json["loc"] as? String {
            let parts = locStr.split(separator: ",")
            if parts.count == 2, let la = Double(parts[0]), let lo = Double(parts[1]) {
                lat = la
                lon = lo
            }
        }
        guard lat.isFinite, lon.isFinite,
              (-90.0...90.0).contains(lat),
              (-180.0...180.0).contains(lon) else { return nil }

        return GeoProfile(
            ip: ip, countryCode: cc, region: region, city: city,
            timezone: timezone, latitude: lat, longitude: lon,
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

        let fallbackStreet = "IP 定位坐标附近；街道地址尚未由地理编码服务确认"
        let fallbackZip = raw.zip

        let finalized = GeoProfile(
            ip: raw.ip, countryCode: raw.countryCode, region: raw.region,
            city: raw.city, timezone: raw.timezone,
            latitude: jitterLat, longitude: jitterLon,
            street: fallbackStreet, zip: fallbackZip, isp: raw.isp
        )
        self.commitSimulation(finalized)

        let requestID = UUID()
        self.activeGeocodeRequestID = requestID
        CLGeocoder().reverseGeocodeLocation(loc) { [weak self] placemarks, _ in
            guard let self = self, let pm = placemarks?.first else { return }
            let addressParts = [
                pm.subThoroughfare,
                pm.thoroughfare,
                pm.locality,
                pm.administrativeArea,
                pm.postalCode
            ].compactMap { value -> String? in
                guard let value = value?.trimmingCharacters(in: .whitespacesAndNewlines),
                      !value.isEmpty else { return nil }
                return value
            }
            let resolvedStreet = addressParts.isEmpty
                ? "地理编码服务未返回街道地址"
                : addressParts.joined(separator: ", ")
            let resolvedZip = (pm.postalCode?.isEmpty == false) ? pm.postalCode! : fallbackZip

            DispatchQueue.main.async {
                guard self.activeGeocodeRequestID == requestID,
                      self.isSimulating else { return }

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

    private func writeGeoPlist(_ profile: GeoProfile, enabled: Bool = true) {
        let geoDict: [String: Any] = [
            "enabled": enabled,
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
        self.isSimulating = false
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

        let simulationStarted = startLocationSimulation(for: profile)
        self.isSimulating = simulationStarted
        writeGeoPlist(profile, enabled: simulationStarted)
        saveWiFiPlist(enabled: simulationStarted)
        if !simulationStarted && self.statusError == nil {
            self.statusError = "定位配置已保存，但系统定位模拟未启动。"
        }
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
        var failures: [String] = []
        for path in paths where fm.fileExists(atPath: path) {
            do {
                try fm.removeItem(atPath: path)
            } catch {
                failures.append("\(path): \(error.localizedDescription)")
            }
        }
        if !failures.isEmpty {
            statusError = "部分 Apple Maps 缓存未能清理：\(failures.joined(separator: "；"))"
        }
    }

    func stopSimulation() {
        activeGeocodeRequestID = UUID()

        syncStateLock.lock()
        activeSyncRequestID = UUID()
        let sessionToCancel = activeURLSession
        activeURLSession = nil
        syncStateLock.unlock()
        sessionToCancel?.invalidateAndCancel()
        isSyncing = false

        guard stopLocationSimulation() else { return }

        isSimulating = false
        lockedProfile = nil
        exitIP = "未获取 [--]"
        timezoneName = "- (待同步)"
        coordText = "- (0.0000, 0.0000)"
        streetAddress = "等待获取 IP 附近的地理编码结果..."
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
                            Text(engine.isSimulating ? "正在模拟已解析的定位环境" : "已停止模拟")
                                .font(.headline)
                        }
                        Text("出口 IP: \(engine.exitIP)")
                            .font(.subheadline.monospaced())
                        Text("目标时区配置: \(engine.timezoneName)")
                            .font(.subheadline)
                        Text("模拟坐标: \(engine.coordText)")
                            .font(.caption.monospaced())
                            .foregroundColor(.secondary)
                        Divider()
                        HStack {
                            Circle()
                                .fill(engine.hookIsActive ? Color.green : Color.orange)
                                .frame(width: 8, height: 8)
                            Text("Hook 状态报告: \(engine.hookStatusText)")
                                .font(.caption.bold())
                                .foregroundColor(engine.hookIsActive ? .green : .orange)
                            Spacer()
                            Button("刷新") {
                                engine.refreshHookStatus()
                            }
                            .font(.caption)
                        }
                        Divider()
                        Text("IP 坐标附近的反向地理编码结果（不保证为住宅地址）")
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
                            Text(engine.isSyncing ? "正在探测当前美国出口 IP..." : "立即同步当前 IP 定位与全局环境")
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
                        Text("清理 Apple Maps / GeoServices 本地缓存")
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
