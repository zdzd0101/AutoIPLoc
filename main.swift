import SwiftUI
import UIKit
import CoreLocation
import Network
import AVFoundation

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
    @Published var statusError: String? = nil
    @Published var exitIP = "未获取 [--]"
    @Published var timezoneName = "- (待同步)"
    @Published var coordText = "- (0.0000, 0.0000)"
    @Published var streetAddress = "等待同步解析附近精确街道地址..."
    @Published var zipCode = "--"
    @Published var autoSyncOnNetworkChange = true
    @Published var lockSessionGeo = true
    @Published var wifiList: [[String: String]] = []

    private let geoPlistPath = "/var/mobile/Library/Preferences/com.autoiploc.geo.plist"
    private let wifiPlistPath = "/var/mobile/Library/Preferences/com.autoiploc.wifi.plist"
    private let locationManager = CLLocationManager()
    private let pathMonitor = NWPathMonitor()
    private let monitorQueue = DispatchQueue(label: "com.autoiploc.netmonitor")
    private var lastPathStatus: NWPath.Status?
    private var isFetching = false
    private var lockedProfile: GeoProfile?

    override init() {
        super.init()
        locationManager.delegate = self
        locationManager.requestAlwaysAuthorization()
        loadSavedState()
        startNetworkMonitor()
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
        if let dict = NSDictionary(contentsOfFile: geoPlistPath) as? [String: Any],
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
        if let wDict = NSDictionary(contentsOfFile: wifiPlistPath) as? [String: Any],
           let nets = wDict["networks"] as? [[String: String]] {
            self.wifiList = nets
        }
    }

    func syncEnvironment(forceReanchor: Bool = true) {
        guard !isFetching else { return }
        isFetching = true
        statusError = nil

        let endpoints = [
            "https://ipwho.is/",
            "https://ipapi.co/json/",
            "https://ipinfo.io/json",
            "https://api.ip.sb/geoip"
        ]

        probeSequentialHTTPS(urls: endpoints, index: 0, forceReanchor: forceReanchor)
    }

    private func probeSequentialHTTPS(urls: [String], index: Int, forceReanchor: Bool) {
        guard index < urls.count else {
            DispatchQueue.main.async {
                self.isFetching = false
                self.statusError = "当前节点无法连接 IP 探测接口，请切换可用海外节点后再同步。"
            }
            return
        }

        guard let url = URL(string: urls[index]) else {
            probeSequentialHTTPS(urls: urls, index: index + 1, forceReanchor: forceReanchor)
            return
        }

        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 6.0
        config.timeoutIntervalForResource = 8.0
        config.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        config.httpAdditionalHeaders = [
            "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.2 Mobile/15E148 Safari/604.1",
            "Accept": "application/json",
            "Connection": "close"
        ]

        let session = URLSession(configuration: config)
        session.dataTask(with: url) { [weak self] data, response, error in
            guard let self = self else { return }
            defer { session.finishTasksAndInvalidate() }

            if let http = response as? HTTPURLResponse, (200...299).contains(http.statusCode),
               let data = data, let parsed = self.parseGeoJSON(data: data) {
                DispatchQueue.main.async {
                    self.applyDetectedProfile(parsed, forceReanchor: forceReanchor)
                }
            } else {
                self.probeSequentialHTTPS(urls: urls, index: index + 1, forceReanchor: forceReanchor)
            }
        }.resume()
    }

    private func parseGeoJSON(data: Data) -> GeoProfile? {
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
        if let success = json["success"] as? Bool, !success { return nil }

        guard let ip = json["ip"] as? String, !ip.isEmpty else { return nil }
        let cc = ((json["country_code"] as? String) ?? (json["country"] as? String) ?? "US").uppercased()
        if cc == "CN" || cc == "HK" || cc == "MO" { return nil }

        let region = (json["region"] as? String) ?? (json["regionName"] as? String) ?? ""
        let city = (json["city"] as? String) ?? ""
        let isp = ((json["connection"] as? [String: Any])?["isp"] as? String)
            ?? (json["isp"] as? String)
            ?? (json["org"] as? String)
            ?? "Residential Broadband"
        let zip = (json["postal"] as? String) ?? (json["postal_code"] as? String) ?? (json["zip"] as? String) ?? ""

        var tz = "America/New_York"
        if let tzDict = json["timezone"] as? [String: Any], let tzId = tzDict["id"] as? String, !tzId.isEmpty {
            tz = tzId
        } else if let tzStr = json["timezone"] as? String, !tzStr.isEmpty {
            tz = tzStr
        }

        var lat = (json["latitude"] as? Double) ?? (json["lat"] as? Double) ?? 0.0
        var lon = (json["longitude"] as? Double) ?? (json["lon"] as? Double) ?? 0.0
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
        // 防旋转 IP 跳变：如果已开启会话锁定且同属一个国家与时区，则仅刷新出口 IP 显示，保持原街道坐标与 Wi-Fi 不跳变
        if lockSessionGeo, isSimulating, let locked = lockedProfile,
           locked.countryCode == raw.countryCode, locked.timezone == raw.timezone, !forceReanchor {
            self.exitIP = "\(raw.ip) [\(raw.countryCode)]"
            self.isFetching = false
            return
        }

        // 在 IP 中心点 300~900 米范围内生成真实住宅微偏坐标
        let jitterLat = raw.latitude + Double.random(in: -0.0065...0.0065)
        let jitterLon = raw.longitude + Double.random(in: -0.0065...0.0065)
        let loc = CLLocation(latitude: jitterLat, longitude: jitterLon)

        let fallbackStreet = "\(Int.random(in: 112...4890)) Oakridge Ave, \(raw.city.isEmpty ? "Austin" : raw.city), \(raw.region.isEmpty ? "TX" : raw.region)"
        let fallbackZip = raw.zip.isEmpty ? String(Int.random(in: 10001...98199)) : raw.zip

        CLGeocoder().reverseGeocodeLocation(loc) { [weak self] placemarks, _ in
            guard let self = self else { return }
            var finalStreet = fallbackStreet
            var finalZip = fallbackZip

            if let pm = placemarks?.first {
                let num = pm.subThoroughfare ?? "\(Int.random(in: 105...3980))"
                let road = pm.thoroughfare ?? "Maple Creek Dr"
                let c = pm.locality ?? (raw.city.isEmpty ? "Dallas" : raw.city)
                let st = pm.administrativeArea ?? (raw.region.isEmpty ? "TX" : raw.region)
                finalStreet = "\(num) \(road), \(c), \(st)"
                if let pZip = pm.postalCode, !pZip.isEmpty {
                    finalZip = pZip
                }
            }

            let finalized = GeoProfile(
                ip: raw.ip, countryCode: raw.countryCode, region: raw.region,
                city: raw.city, timezone: raw.timezone,
                latitude: jitterLat, longitude: jitterLon,
                street: finalStreet, zip: finalZip, isp: raw.isp
            )

            DispatchQueue.main.async {
                self.commitSimulation(finalized)
            }
        }
    }

    private func commitSimulation(_ profile: GeoProfile) {
        self.lockedProfile = profile
        self.isSimulating = true
        self.isFetching = false
        self.statusError = nil
        self.exitIP = "\(profile.ip) [\(profile.countryCode)]"
        self.timezoneName = profile.timezone
        self.coordText = String(format: "%.5f, %.5f", profile.latitude, profile.longitude)
        self.streetAddress = profile.street
        self.zipCode = profile.zip

        if self.wifiList.isEmpty {
            regenerateWiFiList(save: false)
        }

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
        (geoDict as NSDictionary).write(toFile: geoPlistPath, atomically: true)
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
        let simManager = CLSimulationManager()
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
        (dict as NSDictionary).write(toFile: wifiPlistPath, atomically: true)
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
        let simManager = CLSimulationManager()
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
        (geoDict as NSDictionary).write(toFile: geoPlistPath, atomically: true)
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
                            Text(engine.isSimulating ? "正在模拟美国住宅环境" : "已停止模拟")
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
                        Text("立即同步当前 IP 定位与全局环境")
                            .font(.headline)
                            .foregroundColor(.white)
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 14)
                            .background(Color.blue)
                            .cornerRadius(12)
                    }

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
