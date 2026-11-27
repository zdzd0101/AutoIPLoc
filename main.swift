import SwiftUI
import UIKit
import CoreLocation
import Network
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
    @Published var ipGeoInfo: IPGeoDisplayInfo? = nil
    @Published var ipGeoAddress = "等待查询 IP 坐标附近的地理位置..."
    @Published var ipGeoStatusText = "尚未查询 IP 地理信息"
    @Published var ipGeoUpdatedAt: Date? = nil

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
    private let ipDisplayStateLock = NSLock()
    private var lastPathSignature: String?
    private var activeIPDisplayRequestID = UUID()
    private var activeIPDisplaySession: URLSession?
    private var pendingIPDisplayRefresh = false
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
        let serialized: Data
        do {
            serialized = try PropertyListSerialization.data(
                fromPropertyList: dict,
                format: .xml,
                options: 0
            )
        } catch {
            statusError = "共享配置序列化失败：\(error.localizedDescription)"
            return
        }

        var successfulWrites = 0
        var failedPaths: [String] = []
        let fileManager = FileManager.default

        for path in paths {
            let url = URL(fileURLWithPath: path)
            do {
                try fileManager.createDirectory(
                    at: url.deletingLastPathComponent(),
                    withIntermediateDirectories: true
                )
                try serialized.write(to: url, options: .atomic)
                guard path.withCString({ Darwin.chmod($0, 0o600) }) == 0 else {
                    throw NSError(
                        domain: NSPOSIXErrorDomain,
                        code: Int(errno),
                        userInfo: [NSLocalizedDescriptionKey: String(cString: strerror(errno))]
                    )
                }

                let readBack = try Data(contentsOf: url)
                let decoded = try PropertyListSerialization.propertyList(
                    from: readBack,
                    options: [],
                    format: nil
                )
                guard decoded is [String: Any] else {
                    throw NSError(
                        domain: "AutoIPLoc.Configuration",
                        code: 1,
                        userInfo: [NSLocalizedDescriptionKey: "写入后配置格式验证失败"]
                    )
                }
                successfulWrites += 1
            } catch {
                failedPaths.append("\(path): \(error.localizedDescription)")
            }
        }

        if successfulWrites == 0 {
            statusError = "共享配置写入失败，所有配置路径均不可写：\(failedPaths.joined(separator: "；"))"
        } else if !failedPaths.isEmpty {
            statusError = "共享配置仅写入\(successfulWrites)个位置；失败路径：\(failedPaths.joined(separator: "；"))"
        }
    }

    private func isValidIPAddress(_ rawValue: String) -> Bool {
        let value = rawValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty else { return false }

        var ipv4 = in_addr()
        if value.withCString({ inet_pton(AF_INET, $0, &ipv4) == 1 }) {
            return true
        }

        var ipv6 = in6_addr()
        return value.withCString({ inet_pton(AF_INET6, $0, &ipv6) == 1 })
    }

    private func isValidGeoProfile(_ profile: GeoProfile) -> Bool {
        let country = profile.countryCode.uppercased()
        return isValidIPAddress(profile.ip) &&
            country.utf8.count == 2 &&
            country.utf8.allSatisfy { (65...90).contains(Int($0)) } &&
            TimeZone(identifier: profile.timezone) != nil &&
            profile.latitude.isFinite &&
            profile.longitude.isFinite &&
            (-90.0...90.0).contains(profile.latitude) &&
            (-180.0...180.0).contains(profile.longitude)
    }

    private func methodTypeCode(_ rawType: UnsafeMutablePointer<CChar>?) -> CChar? {
        guard let rawType else { return nil }
        defer { free(UnsafeMutableRawPointer(rawType)) }

        let qualifiers: Set<CChar> = [114, 110, 78, 111, 79, 82, 86] // r, n, N, o, O, R, V
        var cursor = rawType
        while qualifiers.contains(cursor.pointee) {
            cursor = cursor.advanced(by: 1)
        }
        return cursor.pointee
    }

    private func methodMatchesSignature(_ method: Method, explicitArgumentTypes: [CChar]) -> Bool {
        guard method_getNumberOfArguments(method) == UInt32(explicitArgumentTypes.count + 2),
              methodTypeCode(method_copyReturnType(method)) == 118 else { // void
            return false
        }

        let selfType = methodTypeCode(method_copyArgumentType(method, 0))
        let selectorType = methodTypeCode(method_copyArgumentType(method, 1))
        guard selfType == 64 || selfType == 35, selectorType == 58 else { // @/# and :
            return false
        }

        for (index, expectedType) in explicitArgumentTypes.enumerated() {
            guard methodTypeCode(method_copyArgumentType(method, UInt32(index + 2))) == expectedType else {
                return false
            }
        }
        return true
    }

    private func makeSimulationManager(requiredSelectors: [String]) -> CLSimulationManager? {
        guard let managerClass = NSClassFromString("CLSimulationManager") else {
            statusError = "当前系统未提供 CLSimulationManager，无法确认定位模拟已启动。"
            return nil
        }

        for name in requiredSelectors {
            let selector = NSSelectorFromString(name)
            guard let method = class_getInstanceMethod(managerClass, selector) else {
                statusError = "当前系统的 CLSimulationManager 缺少接口：\(name)"
                return nil
            }

            let expectedArguments: [CChar]
            switch name {
            case "appendSimulatedLocation:":
                expectedArguments = [64] // CLLocation * (Objective-C object)
            case "stopLocationSimulation", "clearSimulatedLocations", "flush", "startLocationSimulation":
                expectedArguments = []
            default:
                statusError = "未登记 CLSimulationManager 接口签名：\(name)"
                return nil
            }

            guard methodMatchesSignature(method, explicitArgumentTypes: expectedArguments) else {
                statusError = "当前系统的 CLSimulationManager 接口签名不兼容：\(name)"
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
        let reports = hookStatusPaths.compactMap { readSharedPlist(paths: [$0]) }
        let activeReports = reports.filter { ($0["active"] as? Bool) == true }

        if let dict = activeReports.max(by: {
            ($0["timestamp"] as? Double ?? 0) < ($1["timestamp"] as? Double ?? 0)
        }) {
            let ver = dict["version"] as? String ?? "未知版本"
            let proc = dict["lastProc"] as? String ?? "未知进程"
            let hookOk = (dict["cHookReady"] as? Bool) ?? false
            let cCount = dict["cHookCount"] as? Int ?? 0
            let objcCount = dict["objcHookCount"] as? Int ?? 0
            let ts = (dict["timestamp"] as? Double) ?? 0
            let ageSec = Int(max(0, now - ts))

            hookIsActive = false
            if ts > 0 && ageSec <= 300 && hookOk {
                hookStatusText = "\(proc) 在 \(ageSec) 秒前写入 v\(ver) 加载报告（C \(cCount) / ObjC \(objcCount)）；仅能证明该进程写入报告，其他目标进程仍未验证"
                return
            } else if ts > 0 && ageSec > 300 {
                hookStatusText = "最近报告来自 \(proc)，已过 \(ageSec / 60) 分钟（C \(cCount) / ObjC \(objcCount)）；当前目标进程状态未验证"
                return
            } else {
                hookStatusText = "检测到加载报告，但关键字段不完整，无法确认实际功能状态"
                return
            }
        }

        if findInstalledHookDylib() != nil {
            hookIsActive = false
            hookStatusText = "已找到 Hook 动态库文件；未验证目标进程加载或实际执行"
        } else {
            hookIsActive = false
            hookStatusText = "未找到 AutoIPLocHook.dylib（请检查 RootHide 安装路径）"
        }
    }

    private func networkPathSignature(_ path: NWPath) -> String {
        var interfaces: [String] = []
        if path.usesInterfaceType(.wifi) { interfaces.append("wifi") }
        if path.usesInterfaceType(.cellular) { interfaces.append("cellular") }
        if path.usesInterfaceType(.wiredEthernet) { interfaces.append("ethernet") }
        if path.usesInterfaceType(.loopback) { interfaces.append("loopback") }
        if path.usesInterfaceType(.other) { interfaces.append("other") }
        return "\(path.status)|\(interfaces.sorted().joined(separator: ","))|expensive:\(path.isExpensive)|constrained:\(path.isConstrained)"
    }

    private func startNetworkMonitor() {
        pathMonitor.pathUpdateHandler = { [weak self] path in
            guard let self = self else { return }
            let signature = self.networkPathSignature(path)
            let changed = signature != self.lastPathSignature
            self.lastPathSignature = signature
            guard changed, path.status == .satisfied else { return }

            DispatchQueue.main.async {
                guard self.autoSyncOnNetworkChange else { return }
                if self.isSyncing {
                    self.pendingIPDisplayRefresh = true
                } else {
                    self.refreshIPGeoInfo()
                }
            }
        }
        pathMonitor.start(queue: monitorQueue)
    }

    private func loadSavedState() {
        if let dict = readSharedPlist(paths: geoPlistPaths),
           (dict["enabled"] as? Bool) == true {
            if let ip = dict["ip"] as? String,
               let cc = dict["countryCode"] as? String,
               let tz = dict["timezone"] as? String,
               let lat = dict["lat"] as? Double,
               let lon = dict["lon"] as? Double {
                let profile = GeoProfile(
                    ip: ip,
                    countryCode: cc,
                    region: dict["region"] as? String ?? "",
                    city: dict["city"] as? String ?? "",
                    timezone: tz,
                    latitude: lat,
                    longitude: lon,
                    street: dict["street"] as? String ?? "未提供街道地址",
                    zip: dict["zip"] as? String ?? "--",
                    isp: dict["isp"] as? String ?? ""
                )

                if isValidGeoProfile(profile) {
                    lockedProfile = profile
                    isSimulating = startLocationSimulation(for: profile)
                    exitIP = "\(ip) [\(cc)]"
                    timezoneName = tz
                    coordText = String(format: "%.5f, %.5f", lat, lon)
                    streetAddress = profile.street
                    zipCode = profile.zip
                    if !isSimulating {
                        lockedProfile = nil
                        if statusError == nil {
                            statusError = "已加载保存的定位配置，但系统未确认定位模拟已启动。"
                        }
                    }
                } else {
                    lockedProfile = nil
                    isSimulating = false
                    statusError = "已保存的定位配置包含无效 IP、国家码、时区或坐标，未启动模拟。"
                }
            } else {
                lockedProfile = nil
                isSimulating = false
                statusError = "已保存的定位配置字段不完整，未启动模拟。"
            }
        }

        if let wDict = readSharedPlist(paths: wifiPlistPaths) {
            if let validatedNetworks = WiFiConfigValidator.validatedNetworks(wDict["networks"]) {
                wifiList = validatedNetworks
            } else {
                wifiList = []
                statusError = statusError ?? "已保存的 Wi-Fi 配置格式无效；未加载不完整的网络条目。"
            }
        }
    }

    func refreshIPGeoInfo() {
        guard !isSyncing else { return }
        isSyncing = true
        statusError = nil
        ipGeoStatusText = "正在查询当前出口 IP 的归属信息..."

        let requestID = UUID()
        let endpoints = [
            "https://ipwho.is/",
            "https://free.freeipapi.com/api/v1/json",
            "https://ipinfo.io/json",
            "https://api.ip.sb/geoip"
        ]

        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 12.0
        configuration.timeoutIntervalForResource = 18.0
        configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        let session = URLSession(configuration: configuration)

        var requests: [URLRequest] = []
        for endpoint in endpoints {
            guard let url = URL(string: endpoint) else { continue }
            var request = URLRequest(
                url: url,
                cachePolicy: .reloadIgnoringLocalAndRemoteCacheData,
                timeoutInterval: 12.0
            )
            request.setValue("application/json", forHTTPHeaderField: "Accept")
            requests.append(request)
        }

        guard !requests.isEmpty else {
            finishIPGeoRefresh(error: "没有可用的 IP 地理信息服务地址。")
            return
        }

        ipDisplayStateLock.lock()
        activeIPDisplayRequestID = requestID
        activeIPDisplaySession = session
        ipDisplayStateLock.unlock()

        var settled = false
        var completedCount = 0
        var lastFailure = "未收到有效响应"
        let expectedCount = requests.count

        for request in requests {
            session.dataTask(with: request) { [weak self] data, response, error in
                guard let self = self else { return }

                let http = response as? HTTPURLResponse
                let parsedInfo: IPGeoDisplayInfo?
                if let http, (200...299).contains(http.statusCode), let data {
                    parsedInfo = IPGeoDisplayInfo.parse(
                        data: data,
                        provider: request.url?.host ?? "unknown"
                    )
                } else {
                    parsedInfo = nil
                }

                self.ipDisplayStateLock.lock()
                guard self.activeIPDisplayRequestID == requestID, !settled else {
                    self.ipDisplayStateLock.unlock()
                    return
                }

                if let info = parsedInfo {
                    settled = true
                    self.activeIPDisplaySession = nil
                    self.ipDisplayStateLock.unlock()
                    session.invalidateAndCancel()

                    DispatchQueue.main.async {
                        self.ipDisplayStateLock.lock()
                        let stillCurrent = self.activeIPDisplayRequestID == requestID
                        self.ipDisplayStateLock.unlock()
                        guard stillCurrent else { return }
                        self.applyIPGeoDisplay(info)
                    }
                    return
                }

                completedCount += 1
                if let http {
                    lastFailure = "HTTP \(http.statusCode)（\(request.url?.host ?? "unknown")）"
                } else if let error {
                    lastFailure = "\((error as NSError).localizedDescription)（\(request.url?.host ?? "unknown")）"
                } else {
                    lastFailure = "响应字段不包含可验证的 IP 和有效坐标（\(request.url?.host ?? "unknown")）"
                }

                let allFailed = completedCount >= expectedCount
                if allFailed {
                    settled = true
                    self.activeIPDisplaySession = nil
                }
                self.ipDisplayStateLock.unlock()

                if allFailed {
                    session.finishTasksAndInvalidate()
                    DispatchQueue.main.async {
                        self.ipDisplayStateLock.lock()
                        let stillCurrent = self.activeIPDisplayRequestID == requestID
                        self.ipDisplayStateLock.unlock()
                        guard stillCurrent else { return }
                        self.finishIPGeoRefresh(
                            error: "未取得有效的 IP 地理坐标：\(lastFailure)"
                        )
                    }
                }
            }.resume()
        }
    }

    private func applyIPGeoDisplay(_ info: IPGeoDisplayInfo) {
        ipGeoInfo = info
        ipGeoUpdatedAt = Date()
        ipGeoStatusText = "已取得 IP 数据库估算结果（\(info.provider)）；不是 GPS 精确位置"
        statusError = nil
        reverseGeocodeIPDisplay(info)
        finishIPGeoRefresh(error: nil)
    }

    private func finishIPGeoRefresh(error: String?) {
        isSyncing = false
        if let error {
            ipGeoStatusText = error
            statusError = error
        }

        if pendingIPDisplayRefresh {
            pendingIPDisplayRefresh = false
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.75) { [weak self] in
                self?.refreshIPGeoInfo()
            }
        }
    }

    private func reverseGeocodeIPDisplay(_ info: IPGeoDisplayInfo) {
        let requestID = UUID()
        activeGeocodeRequestID = requestID
        ipGeoAddress = "正在查询 IP 估算坐标附近的行政区信息..."

        let location = CLLocation(latitude: info.latitude, longitude: info.longitude)
        CLGeocoder().reverseGeocodeLocation(location) { [weak self] placemarks, error in
            guard let self = self else { return }
            DispatchQueue.main.async {
                guard self.activeGeocodeRequestID == requestID else { return }

                guard let placemark = placemarks?.first else {
                    self.ipGeoAddress = error == nil
                        ? "反向地理编码未返回地点名称；保留 IP 数据库坐标估算"
                        : "反向地理编码暂不可用；保留 IP 数据库坐标估算"
                    return
                }

                let parts = [
                    placemark.locality,
                    placemark.subAdministrativeArea,
                    placemark.administrativeArea,
                    placemark.country,
                    placemark.postalCode
                ].compactMap { value -> String? in
                    guard let trimmed = value?.trimmingCharacters(in: .whitespacesAndNewlines),
                          !trimmed.isEmpty else { return nil }
                    return trimmed
                }
                self.ipGeoAddress = parts.isEmpty
                    ? "反向地理编码未返回可显示的行政区名称"
                    : parts.joined(separator: ", ")
            }
        }
    }

    func syncEnvironment(forceReanchor: Bool = true) {
        refreshHookStatus()
        guard !isSyncing else { return }
        isSyncing = true
        statusError = nil

        let requestID = UUID()
        let endpoints = [
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

        let rawIP = (json["query"] as? String)
            ?? (json["ip"] as? String)
            ?? (json["ipAddress"] as? String)
            ?? ""
        let ip = rawIP.trimmingCharacters(in: .whitespacesAndNewlines)
        guard isValidIPAddress(ip) else { return nil }

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

        var coordinates: (Double, Double)?
        if let lat = (json["lat"] as? Double) ?? (json["latitude"] as? Double),
           let lon = (json["lon"] as? Double) ?? (json["longitude"] as? Double) {
            coordinates = (lat, lon)
        } else if let locStr = json["loc"] as? String {
            let parts = locStr.split(separator: ",")
            if parts.count == 2,
               let lat = Double(parts[0].trimmingCharacters(in: .whitespaces)),
               let lon = Double(parts[1].trimmingCharacters(in: .whitespaces)) {
                coordinates = (lat, lon)
            }
        }
        guard let resolvedCoordinates = coordinates else { return nil }
        let lat = resolvedCoordinates.0
        let lon = resolvedCoordinates.1
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

        let jitterLat = min(90.0, max(-90.0, raw.latitude + Double.random(in: -0.0065...0.0065)))
        let unwrappedLongitude = raw.longitude + Double.random(in: -0.0065...0.0065)
        let jitterLon = ((unwrappedLongitude + 180.0)
            .truncatingRemainder(dividingBy: 360.0) + 360.0)
            .truncatingRemainder(dividingBy: 360.0) - 180.0
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
                guard self.activeGeocodeRequestID == requestID else { return }

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
        if !simulationStarted {
            self.lockedProfile = nil
        }
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
        guard let validatedNetworks = WiFiConfigValidator.validatedNetworks(wifiList) else {
            statusError = "Wi-Fi 配置未保存：SSID 必须为 1–32 个 UTF-8 字节，BSSID 必须为六组十六进制字节。"
            return
        }
        let dict: [String: Any] = [
            "enabled": enabled,
            "networks": validatedNetworks
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

        ipDisplayStateLock.lock()
        activeIPDisplayRequestID = UUID()
        let displaySessionToCancel = activeIPDisplaySession
        activeIPDisplaySession = nil
        ipDisplayStateLock.unlock()
        displaySessionToCancel?.invalidateAndCancel()
        pendingIPDisplayRefresh = false
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
                        Text("当前保存的模拟坐标: \(engine.coordText)")
                            .font(.caption.monospaced())
                            .foregroundColor(.secondary)
                        Divider()
                        HStack(alignment: .top) {
                            Circle()
                                .fill(Color.orange)
                                .frame(width: 8, height: 8)
                                .padding(.top, 4)
                            VStack(alignment: .leading, spacing: 4) {
                                Text("最近一次 Hook 加载报告")
                                    .font(.caption.bold())
                                Text(engine.hookStatusText)
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                                Text("单个进程的报告不代表所有目标进程都已加载。")
                                    .font(.caption2)
                                    .foregroundColor(.secondary)
                            }
                            Spacer(minLength: 8)
                            Button("刷新") {
                                engine.refreshHookStatus()
                            }
                            .font(.caption)
                        }
                        Divider()
                        VStack(alignment: .leading, spacing: 5) {
                            Text("出口 IP 地理信息（数据库估算）")
                                .font(.subheadline.bold())
                            Text(engine.ipGeoStatusText)
                                .font(.caption)
                                .foregroundColor(.secondary)
                            if let info = engine.ipGeoInfo {
                                Text("出口 IP：\(info.ip)")
                                    .font(.caption.monospaced())
                                Text("归属区域：\(info.areaDescription)")
                                    .font(.subheadline)
                                Text(String(format: "IP 估算坐标：%.5f, %.5f", info.latitude, info.longitude))
                                    .font(.caption.monospaced())
                                Text("IP 数据库时区：\(info.timeZoneIdentifier ?? "未提供唯一时区")")
                                    .font(.caption)
                                Text("iPhone 当前系统时区：\(TimeZone.autoupdatingCurrent.identifier)")
                                    .font(.caption)
                                if let ipTimeZone = info.timeZoneIdentifier {
                                    Text(ipTimeZone == TimeZone.autoupdatingCurrent.identifier
                                         ? "IP 时区与设备时区标识一致"
                                         : "IP 时区与设备时区不同；此处只报告差异，不更改系统时区")
                                        .font(.caption2)
                                        .foregroundColor(.secondary)
                                } else {
                                    Text("服务未提供唯一时区，未从多个时区中猜测。")
                                        .font(.caption2)
                                        .foregroundColor(.secondary)
                                }
                                Text("附近行政区：\(engine.ipGeoAddress)")
                                    .font(.caption)
                                if let updated = engine.ipGeoUpdatedAt {
                                    Text("查询时间：\(updated.formatted(date: .abbreviated, time: .shortened)) · 来源：\(info.provider)")
                                        .font(.caption2)
                                        .foregroundColor(.secondary)
                                }
                            }
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
                        Toggle("网络接口变化时自动刷新出口 IP 地理信息", isOn: $engine.autoSyncOnNetworkChange)
                            .font(.subheadline)
                        Text("自动刷新只更新 IP 信息展示，不会更改 iPhone 系统定位或系统时区。")
                            .font(.caption2)
                            .foregroundColor(.secondary)
                    }
                    .padding()
                    .background(Color(.secondarySystemBackground))
                    .cornerRadius(14)

                    Button(action: { engine.refreshIPGeoInfo() }) {
                        HStack(spacing: 8) {
                            if engine.isSyncing {
                                ProgressView()
                                    .progressViewStyle(CircularProgressViewStyle(tint: .white))
                            }
                            Text(engine.isSyncing ? "正在查询当前出口 IP..." : "查询当前出口 IP 地理信息")
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
