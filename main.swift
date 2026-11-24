import UIKit
import CoreLocation
import Network
import AVFoundation

// MARK: - 1. 声明系统私有定位模拟接口 (CLSimulationManager)
@objc protocol CLSimulationManagerProtocol {
    func clearSimulatedLocations()
    func appendSimulatedLocation(_ location: CLLocation)
    func flush()
    func startLocationSimulation()
    func stopLocationSimulation()
}

// MARK: - 2. 周边 Wi-Fi 节点模型
struct SimulatedWiFiNode: Codable {
    let ssid: String
    let bssid: String
    let rssi: Int
    let channel: Int
    let band: String

    func toPlistDict() -> [String: Any] {
        return [
            "SSID": ssid,
            "BSSID": bssid,
            "RSSI": rssi,
            "CHANNEL": channel,
            "BAND": band
        ]
    }
}

// MARK: - 3. 系统底层 Root 提权执行器（兼容 TrollStore + 无根越狱 /var/jb）
class RootSystemHelper {
    @_silgen_name("posix_spawnattr_set_persona_np")
    private static func posix_spawnattr_set_persona_np(_ attr: UnsafeMutablePointer<posix_spawnattr_t?>, _ persona_id: uid_t, _ flags: UInt32) -> Int32

    @_silgen_name("posix_spawnattr_set_persona_uid_np")
    private static func posix_spawnattr_set_persona_uid_np(_ attr: UnsafeMutablePointer<posix_spawnattr_t?>, _ uid: uid_t) -> Int32

    @_silgen_name("posix_spawnattr_set_persona_gid_np")
    private static func posix_spawnattr_set_persona_gid_np(_ attr: UnsafeMutablePointer<posix_spawnattr_t?>, _ gid: gid_t) -> Int32

    @discardableResult
    static func runAsRoot(_ command: String) -> Bool {
        let shellCandidates = ["/var/jb/bin/sh", "/var/jb/usr/bin/sh", "/bin/sh"]
        guard let shellPath = shellCandidates.first(where: { FileManager.default.isExecutableFile(atPath: $0) }) else {
            return false
        }

        let fullCmd = "export PATH=/var/jb/usr/bin:/var/jb/bin:/usr/bin:/bin:/usr/sbin:/sbin; \(command)"

        var attr: posix_spawnattr_t?
        posix_spawnattr_init(&attr)
        _ = posix_spawnattr_set_persona_np(&attr, 99, 1) // POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE
        _ = posix_spawnattr_set_persona_uid_np(&attr, 0)
        _ = posix_spawnattr_set_persona_gid_np(&attr, 0)

        var pid: pid_t = 0
        let argv: [UnsafeMutablePointer<CChar>?] = [
            strdup(shellPath),
            strdup("-c"),
            strdup(fullCmd),
            nil
        ]
        defer {
            for ptr in argv where ptr != nil { free(ptr) }
            posix_spawnattr_destroy(&attr)
        }

        let status = posix_spawn(&pid, shellPath, nil, &attr, argv, environ)
        if status == 0 {
            var exitCode: Int32 = 0
            waitpid(pid, &exitCode, 0)
            return exitCode == 0
        }
        return false
    }

    // 修改系统全局时区
    static func applyTimeZone(_ tzIdentifier: String) -> Bool {
        let zoneCandidates = [
            "/var/db/timezone/zoneinfo/\(tzIdentifier)",
            "/usr/share/zoneinfo/\(tzIdentifier)"
        ]
        guard !tzIdentifier.isEmpty,
              let zonePath = zoneCandidates.first(where: { FileManager.default.fileExists(atPath: $0) }) else {
            return false
        }

        let dtDomain = "com.apple.preferences.datetime" as CFString
        CFPreferencesSetValue("AutomaticTimeZoneEnabled" as CFString, kCFBooleanFalse, dtDomain, kCFPreferencesCurrentUser, kCFPreferencesAnyHost)
        CFPreferencesSetValue("timezone" as CFString, tzIdentifier as CFString, dtDomain, kCFPreferencesCurrentUser, kCFPreferencesAnyHost)
        CFPreferencesSynchronize(dtDomain, kCFPreferencesCurrentUser, kCFPreferencesAnyHost)

        let cmd = """
        mkdir -p /var/db/timezone && \
        rm -f /var/db/timezone/localtime /private/var/db/timezone/localtime && \
        ln -sf "\(zonePath)" /var/db/timezone/localtime && \
        chmod -h 755 /var/db/timezone/localtime && \
        defaults write /var/mobile/Library/Preferences/com.apple.preferences.datetime AutomaticTimeZoneEnabled -bool false 2>/dev/null || true; \
        defaults write /var/mobile/Library/Preferences/com.apple.preferences.datetime timezone -string "\(tzIdentifier)" 2>/dev/null || true; \
        chown 501:501 /var/mobile/Library/Preferences/com.apple.preferences.datetime.plist 2>/dev/null || true; \
        killall -HUP timed 2>/dev/null || true
        """
        let ok = runAsRoot(cmd)

        setenv("TZ", tzIdentifier, 1)
        tzset()
        NSTimeZone.resetSystemTimeZone()

        let center = CFNotificationCenterGetDarwinNotifyCenter()
        CFNotificationCenterPostNotification(center, CFNotificationName("NSSystemTimeZoneDidChangeNotification" as CFString), nil, nil, true)
        CFNotificationCenterPostNotification(center, CFNotificationName("SignificantTimeChangeNotification" as CFString), nil, nil, true)

        return ok
    }

    // 清除高德地图缓存并强制切换苹果国际原生地图
    static func forceAppleInternationalMaps(countryCode: String) {
        let cc = countryCode.isEmpty ? "US" : countryCode.uppercased()
        let geoDict: NSDictionary = [
            "countryCode": cc,
            "forceAppleMaps": true,
            "updatedAt": Date().timeIntervalSince1970
        ]

        let tmpGeo = "/tmp/autoiploc_geo.plist"
        geoDict.write(toFile: tmpGeo, atomically: true)

        let cmd = """
        for p in /var/mobile/Library/Preferences/com.apple.GEO.plist /var/mobile/Library/Preferences/com.apple.Maps.plist; do
            defaults write "$p" CountryCode -string "\(cc)" 2>/dev/null || true
            defaults write "$p" GEOCountryCode -string "\(cc)" 2>/dev/null || true
            defaults write "$p" LastKnownCountryCode -string "\(cc)" 2>/dev/null || true
            defaults delete "$p" AutoNavi 2>/dev/null || true
            chown 501:501 "$p" 2>/dev/null || true
            chmod 644 "$p" 2>/dev/null || true
        done
        cp -f \(tmpGeo) /var/mobile/Library/Preferences/com.autoiploc.geo.plist
        chown 501:501 /var/mobile/Library/Preferences/com.autoiploc.geo.plist
        chmod 644 /var/mobile/Library/Preferences/com.autoiploc.geo.plist
        if [ -d /var/jb/var/mobile/Library/Preferences ]; then
            cp -f \(tmpGeo) /var/jb/var/mobile/Library/Preferences/com.autoiploc.geo.plist
            chown 501:501 /var/jb/var/mobile/Library/Preferences/com.autoiploc.geo.plist
            chmod 644 /var/jb/var/mobile/Library/Preferences/com.autoiploc.geo.plist
        fi
        rm -f \(tmpGeo)
        killall -9 geod 2>/dev/null || true
        killall -9 Maps 2>/dev/null || true
        """
        runAsRoot(cmd)

        let center = CFNotificationCenterGetDarwinNotifyCenter()
        CFNotificationCenterPostNotification(center, CFNotificationName("com.autoiploc.geo.updated" as CFString), nil, nil, true)
    }

    // 注入 12~15 个动态周边 Wi-Fi 列表到系统共享配置
    static func injectWiFiList(_ nodes: [SimulatedWiFiNode], countryCode: String) {
        let payload: NSDictionary = [
            "enabled": true,
            "countryCode": countryCode,
            "updatedAt": Date().timeIntervalSince1970,
            "networks": nodes.map { $0.toPlistDict() }
        ]
        let tmpWifi = "/tmp/autoiploc_wifi.plist"
        payload.write(toFile: tmpWifi, atomically: true)

        let cmd = """
        cp -f \(tmpWifi) /var/mobile/Library/Preferences/com.autoiploc.wifi.plist
        chown 501:501 /var/mobile/Library/Preferences/com.autoiploc.wifi.plist
        chmod 644 /var/mobile/Library/Preferences/com.autoiploc.wifi.plist
        if [ -d /var/jb/var/mobile/Library/Preferences ]; then
            cp -f \(tmpWifi) /var/jb/var/mobile/Library/Preferences/com.autoiploc.wifi.plist
            chown 501:501 /var/jb/var/mobile/Library/Preferences/com.autoiploc.wifi.plist
            chmod 644 /var/jb/var/mobile/Library/Preferences/com.autoiploc.wifi.plist
        fi
        rm -f \(tmpWifi)
        """
        runAsRoot(cmd)

        let center = CFNotificationCenterGetDarwinNotifyCenter()
        CFNotificationCenterPostNotification(center, CFNotificationName("com.autoiploc.wifi.updated" as CFString), nil, nil, true)
    }

    static func clearWiFiInjection() {
        let cmd = """
        rm -f /var/mobile/Library/Preferences/com.autoiploc.wifi.plist /var/jb/var/mobile/Library/Preferences/com.autoiploc.wifi.plist
        """
        runAsRoot(cmd)
        let center = CFNotificationCenterGetDarwinNotifyCenter()
        CFNotificationCenterPostNotification(center, CFNotificationName("com.autoiploc.wifi.updated" as CFString), nil, nil, true)
    }
}

// MARK: - 4. 核心防泄漏定位、地址解析与 Wi-Fi 同步引擎
class LocationSyncEngine: NSObject {
    static let shared = LocationSyncEngine()

    private var simManager: AnyObject?
    private let pathMonitor = NWPathMonitor()
    private let monitorQueue = DispatchQueue(label: "com.autoiploc.netmonitor")
    private var audioPlayer: AVAudioPlayer?
    private var heartbeatTimer: Timer?
    private var debounceWorkItem: DispatchWorkItem?

    private(set) var isSimulating = false
    private(set) var baseLat: Double = 0
    private(set) var baseLon: Double = 0
    private(set) var currentIP: String = "未获取"
    private(set) var currentCountryCode: String = "--"
    private(set) var currentCity: String = "-"
    private(set) var currentISP: String = "-"
    private(set) var currentTZ: String = "-"
    private(set) var tzSyncedSuccess: Bool = false
    private(set) var exactAddress: String = "等待同步解析附近精确街道地址..."
    private(set) var exactZipCode: String = "--"
    private(set) var nearbyWiFis: [SimulatedWiFiNode] = []
    private(set) var leakAlertMessage: String? = nil

    var autoSyncOnNetworkChange: Bool {
        get { UserDefaults.standard.object(forKey: "autoSyncOnNet") as? Bool ?? true }
        set { UserDefaults.standard.set(newValue, forKey: "autoSyncOnNet") }
    }

    var onStatusUpdated: (() -> Void)?

    override init() {
        super.init()
        if let cls = NSClassFromString("CLSimulationManager") as? NSObject.Type {
            simManager = cls.init()
        }
        setupNetworkMonitor()
    }

    private func setupNetworkMonitor() {
        var lastSatisfied = false
        pathMonitor.pathUpdateHandler = { [weak self] path in
            guard let self = self else { return }
            let isNowSatisfied = (path.status == .satisfied)
            if isNowSatisfied && !lastSatisfied && self.autoSyncOnNetworkChange {
                self.debounceWorkItem?.cancel()
                let work = DispatchWorkItem { [weak self] in
                    self?.syncWithCurrentIP()
                }
                self.debounceWorkItem = work
                DispatchQueue.main.asyncAfter(deadline: .now() + 2.5, execute: work)
            }
            lastSatisfied = isNowSatisfied
        }
        pathMonitor.start(queue: monitorQueue)
    }

    func syncWithCurrentIP() {
        guard let url = URL(string: "http://ip-api.com/json/?fields=status,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,query") else { return }
        var req = URLRequest(url: url, timeoutInterval: 8.0)
        req.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData

        URLSession.shared.dataTask(with: req) { [weak self] data, _, error in
            guard let self = self, let data = data, error == nil,
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  (json["status"] as? String) == "success",
                  let rawLat = json["lat"] as? Double,
                  let rawLon = json["lon"] as? Double else {
                DispatchQueue.main.async { self?.onStatusUpdated?() }
                return
            }

            let ip = json["query"] as? String ?? "Unknown"
            let cc = (json["countryCode"] as? String ?? "US").uppercased()
            let country = json["country"] as? String ?? ""
            let region = json["regionName"] as? String ?? ""
            let city = json["city"] as? String ?? ""
            let apiZip = json["zip"] as? String ?? ""
            let tz = json["timezone"] as? String ?? ""
            let isp = json["isp"] as? String ?? "Residential ISP"

            // 防泄漏门禁：如果出口 IP 为国内 CN，立即阻断同步，避免暴露真实国内归属地
            if cc == "CN" {
                DispatchQueue.main.async {
                    self.currentIP = ip
                    self.currentCountryCode = cc
                    self.currentCity = "\(country) · \(city)"
                    self.leakAlertMessage = "⚠️ 检测到国内出口 IP (\(ip))，已自动阻断同步以防位置与 IP 关联泄漏！"
                    self.onStatusUpdated?()
                }
                return
            }

            // 对 IP 中心坐标加入 180m~450m 随机住宅街道偏移（避免落在湖泊或机房正中心）
            let residentialLat = rawLat + Double.random(in: -0.0036...0.0036)
            let residentialLon = rawLon + Double.random(in: -0.0036...0.0036)

            // 使用 en_US 区域逆向地理编码解析精确门牌街道地址与 ZIP
            self.reverseGeocodeExactAddress(
                lat: residentialLat,
                lon: residentialLon,
                fallbackCity: city,
                fallbackRegion: region,
                fallbackCountry: country,
                fallbackZip: apiZip
            ) { resolvedAddress, resolvedZip in
                DispatchQueue.main.async {
                    self.leakAlertMessage = nil
                    self.currentIP = ip
                    self.currentCountryCode = cc
                    self.currentCity = "\(country) · \(city)"
                    self.currentISP = isp
                    self.currentTZ = tz
                    self.baseLat = residentialLat
                    self.baseLon = residentialLon
                    self.exactAddress = resolvedAddress
                    self.exactZipCode = resolvedZip

                    // 1. 同步系统全局时区
                    self.tzSyncedSuccess = RootSystemHelper.applyTimeZone(tz)

                    // 2. 动态生成并注入 12~15 个当地周边 Wi-Fi SSID + BSSID
                    let generatedWiFis = self.generateDynamicWiFis(isp: isp)
                    self.nearbyWiFis = generatedWiFis
                    RootSystemHelper.injectWiFiList(generatedWiFis, countryCode: cc)

                    // 3. 清除高德 GeoServices 缓存并强制切换苹果原生国际地图
                    RootSystemHelper.forceAppleInternationalMaps(countryCode: cc)

                    // 4. 注入底层 GPS 坐标并启动 4 秒心跳保活与静音后台保活
                    self.pushSimulatedLocation(lat: residentialLat, lon: residentialLon)
                    self.startHeartbeat()
                    self.startSilentBackgroundAudio()
                    self.isSimulating = true
                    self.onStatusUpdated?()
                }
            }
        }.resume()
    }

    func regenerateWiFiAndInject() {
        let list = generateDynamicWiFis(isp: currentISP)
        nearbyWiFis = list
        RootSystemHelper.injectWiFiList(list, countryCode: currentCountryCode == "--" ? "US" : currentCountryCode)
        onStatusUpdated?()
    }

    private func reverseGeocodeExactAddress(
        lat: Double,
        lon: Double,
        fallbackCity: String,
        fallbackRegion: String,
        fallbackCountry: String,
        fallbackZip: String,
        completion: @escaping (String, String) -> Void
    ) {
        let geocoder = CLGeocoder()
        let location = CLLocation(latitude: lat, longitude: lon)
        let enLocale = Locale(identifier: "en_US")

        geocoder.reverseGeocodeLocation(location, preferredLocale: enLocale) { placemarks, _ in
            if let pm = placemarks?.first {
                let streetNum = pm.subThoroughfare ?? "\(Int.random(in: 112...4680))"
                let street = pm.thoroughfare ?? "W Maple Ave"
                let city = pm.locality ?? fallbackCity
                let state = pm.administrativeArea ?? fallbackRegion
                let zip = (pm.postalCode?.isEmpty == false) ? pm.postalCode! : (fallbackZip.isEmpty ? "80219" : fallbackZip)
                let country = pm.country ?? fallbackCountry
                let fullAddress = "\(streetNum) \(street), \(city), \(state) \(zip), \(country)"
                completion(fullAddress, zip)
            } else {
                let safeZip = fallbackZip.isEmpty ? "80219" : fallbackZip
                let fallbackAddr = "\(Int.random(in: 120...3890)) Oakridge Dr, \(fallbackCity), \(fallbackRegion) \(safeZip), \(fallbackCountry)"
                completion(fallbackAddr, safeZip)
            }
        }
    }

    private func generateDynamicWiFis(isp: String) -> [SimulatedWiFiNode] {
        let count = Int.random(in: 12...15)
        let lowerISP = isp.lowercased()

        // 主流路由厂商真实 IEEE MAC OUI 前缀
        let ouis = [
            "20:4E:7F", "44:94:FC", "B0:BE:76", "A4:2B:B0", "C8:D7:19",
            "14:91:82", "78:8A:20", "E4:F0:42", "3C:37:86", "94:A6:7E",
            "D8:47:32", "00:26:F2", "AC:84:C6", "00:1E:58", "88:DC:96"
        ]

        var ispGenerators: [() -> String] = []
        if lowerISP.contains("centurylink") || lowerISP.contains("lumen") || lowerISP.contains("qwest") {
            ispGenerators.append { "CenturyLink\(Int.random(in: 1000...9999))" }
            ispGenerators.append { "CenturyLink\(Int.random(in: 1000...9999))-5G" }
            ispGenerators.append { "QuantumFiber-\(self.randHex(4))" }
        } else if lowerISP.contains("comcast") || lowerISP.contains("xfinity") {
            ispGenerators.append { "XFSETUP-\(self.randHex(4))" }
            ispGenerators.append { "xfinitywifi" }
            ispGenerators.append { "HOME-\(self.randHex(4))-5G" }
        } else if lowerISP.contains("charter") || lowerISP.contains("spectrum") {
            ispGenerators.append { "SpectrumSetup-\(self.randHex(2))" }
            ispGenerators.append { "MySpectrumWiFi\(self.randHex(2))-5G" }
            ispGenerators.append { "MySpectrumWiFi\(self.randHex(2))-2G" }
        } else if lowerISP.contains("att") || lowerISP.contains("at&t") {
            ispGenerators.append { "ATT\(self.randAlphaNum(7))" }
            ispGenerators.append { "ATT-FIBER-\(self.randAlphaNum(4))" }
        } else if lowerISP.contains("verizon") {
            ispGenerators.append { "Verizon_\(self.randAlphaNum(6))" }
            ispGenerators.append { "Fios-\(self.randAlphaNum(5))-5G" }
        } else {
            ispGenerators.append { "Xfinity-\(self.randHex(4))-5G" }
            ispGenerators.append { "SpectrumSetup-\(self.randHex(2))" }
            ispGenerators.append { "ATT\(self.randAlphaNum(6))" }
        }

        let neighborPool = [
            "NETGEAR\(Int.random(in: 10...99))-5G",
            "NETGEAR\(Int.random(in: 10...99))",
            "ASUS_\(randHex(2))_5G",
            "TP-Link_\(randHex(4))_5G",
            "TP-Link_\(randHex(4))",
            "Linksys\(Int.random(in: 10000...99999))",
            "eero-Home-\(randHex(3))",
            "Orbi\(Int.random(in: 10...99))",
            "GoogleFiber-\(randHex(4))",
            "Miller_Family_5G",
            "SmithHomeWiFi",
            "Johnson_5G",
            "Davis-Guest",
            "HomeSweetHome_5G",
            "DIRECT-\(randHex(2))-HP OfficeJet",
            "Ring-Setup-\(randHex(2))",
            "Roku-Streaming-\(randHex(3))",
            "Starlink-\(randAlphaNum(6))"
        ]

        var used = Set<String>()
        var result: [SimulatedWiFiNode] = []
        let ch5G = [36, 40, 44, 48, 149, 153, 157, 161]
        let ch2G = [1, 6, 11]

        while result.count < count {
            let ssid: String
            if result.count < 5, let gen = ispGenerators.randomElement() {
                ssid = gen()
            } else {
                ssid = neighborPool.randomElement() ?? "HomeWiFi-\(randHex(4))"
            }
            if used.contains(ssid) { continue }
            used.insert(ssid)

            let oui = ouis.randomElement() ?? "20:4E:7F"
            let bssid = "\(oui):\(randHex(2)):\(randHex(2)):\(randHex(2))"
            let is5G = ssid.contains("5G") || Bool.random()
            let ch = is5G ? (ch5G.randomElement() ?? 149) : (ch2G.randomElement() ?? 6)
            let rssi = Int.random(in: -84 ... -46)

            result.append(SimulatedWiFiNode(
                ssid: ssid,
                bssid: bssid,
                rssi: rssi,
                channel: ch,
                band: is5G ? "5G" : "2.4G"
            ))
        }

        return result.sorted { $0.rssi > $1.rssi }
    }

    private func randHex(_ len: Int) -> String {
        let chars = Array("0123456789ABCDEF")
        return String((0..<len).map { _ in chars.randomElement()! })
    }

    private func randAlphaNum(_ len: Int) -> String {
        let chars = Array("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        return String((0..<len).map { _ in chars.randomElement()! })
    }

    private func pushSimulatedLocation(lat: Double, lon: Double) {
        guard let mgr = simManager else { return }
        let jitterLat = lat + Double.random(in: -0.00008...0.00008)
        let jitterLon = lon + Double.random(in: -0.00008...0.00008)
        let coord = CLLocationCoordinate2D(latitude: jitterLat, longitude: jitterLon)
        let loc = CLLocation(coordinate: coord, altitude: 24.5, horizontalAccuracy: 5.0, verticalAccuracy: 5.0, timestamp: Date())

        _ = mgr.perform(NSSelectorFromString("stopLocationSimulation"))
        _ = mgr.perform(NSSelectorFromString("clearSimulatedLocations"))
        _ = mgr.perform(NSSelectorFromString("appendSimulatedLocation:"), with: loc)
        _ = mgr.perform(NSSelectorFromString("flush"))
        _ = mgr.perform(NSSelectorFromString("startLocationSimulation"))
    }

    private func startHeartbeat() {
        heartbeatTimer?.invalidate()
        heartbeatTimer = Timer.scheduledTimer(withTimeInterval: 4.0, repeats: true) { [weak self] _ in
            guard let self = self, self.isSimulating else { return }
            self.pushSimulatedLocation(lat: self.baseLat, lon: self.baseLon)
        }
    }

    func stopSimulation() {
        heartbeatTimer?.invalidate()
        heartbeatTimer = nil
        if let mgr = simManager {
            _ = mgr.perform(NSSelectorFromString("stopLocationSimulation"))
            _ = mgr.perform(NSSelectorFromString("clearSimulatedLocations"))
            _ = mgr.perform(NSSelectorFromString("flush"))
        }
        RootSystemHelper.clearWiFiInjection()
        audioPlayer?.stop()
        isSimulating = false
        leakAlertMessage = nil
        onStatusUpdated?()
    }

    private func startSilentBackgroundAudio() {
        if audioPlayer?.isPlaying == true { return }
        try? AVAudioSession.sharedInstance().setCategory(.playback, options: .mixWithOthers)
        try? AVAudioSession.sharedInstance().setActive(true)
        var wav = Data([0x52,0x49,0x46,0x46,0x24,0x08,0x00,0x00,0x57,0x41,0x56,0x45,0x66,0x6d,0x74,0x20,
                        0x10,0x00,0x00,0x00,0x01,0x00,0x01,0x00,0x44,0xac,0x00,0x00,0x88,0x58,0x01,0x00,
                        0x02,0x00,0x10,0x00,0x64,0x61,0x74,0x61,0x00,0x08,0x00,0x00])
        wav.append(Data(count: 2048))
        audioPlayer = try? AVAudioPlayer(data: wav)
        audioPlayer?.numberOfLoops = -1
        audioPlayer?.volume = 0.0
        audioPlayer?.play()
    }
}

// MARK: - 5. 主界面 UIViewController（支持滚动、一键复制地址/ZIP、Wi-Fi 列表展示）
class MainViewController: UIViewController {
    private let scrollView = UIScrollView()
    private let contentStack = UIStackView()

    private let leakBanner = UILabel()
    private let statusLabel = UILabel()
    private let ipLabel = UILabel()
    private let tzLabel = UILabel()
    private let coordLabel = UILabel()
    private let addressValueLabel = UILabel()
    private let zipValueLabel = UILabel()
    private let autoSwitch = UISwitch()
    private let wifiHeaderLabel = UILabel()
    private let wifiListLabel = UILabel()

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .systemGroupedBackground
        setupUI()
        LocationSyncEngine.shared.onStatusUpdated = { [weak self] in
            self?.refreshUI()
        }
        refreshUI()
    }

    private func setupUI() {
        scrollView.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(scrollView)

        contentStack.axis = .vertical
        contentStack.spacing = 14
        contentStack.translatesAutoresizingMaskIntoConstraints = false
        scrollView.addSubview(contentStack)

        NSLayoutConstraint.activate([
            scrollView.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor),
            scrollView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            scrollView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            scrollView.bottomAnchor.constraint(equalTo: view.bottomAnchor),

            contentStack.topAnchor.constraint(equalTo: scrollView.topAnchor, constant: 16),
            contentStack.leadingAnchor.constraint(equalTo: scrollView.leadingAnchor, constant: 16),
            contentStack.trailingAnchor.constraint(equalTo: scrollView.trailingAnchor, constant: -16),
            contentStack.bottomAnchor.constraint(equalTo: scrollView.bottomAnchor, constant: -32),
            contentStack.widthAnchor.constraint(equalTo: scrollView.widthAnchor, constant: -32)
        ])

        let titleLbl = UILabel()
        titleLbl.text = "IP 自动定位与全局时区助手"
        titleLbl.font = .systemFont(ofSize: 23, weight: .bold)
        contentStack.addArrangedSubview(titleLbl)

        // 防泄漏警报横幅
        leakBanner.backgroundColor = .systemRed
        leakBanner.textColor = .white
        leakBanner.font = .systemFont(ofSize: 13, weight: .semibold)
        leakBanner.numberOfLines = 0
        leakBanner.layer.cornerRadius = 10
        leakBanner.clipsToBounds = true
        leakBanner.isHidden = true
        contentStack.addArrangedSubview(leakBanner)

        // 状态与坐标卡片
        let infoCard = makeCard()
        statusLabel.font = .systemFont(ofSize: 16, weight: .semibold)
        ipLabel.font = .monospacedSystemFont(ofSize: 14, weight: .regular)
        tzLabel.font = .monospacedSystemFont(ofSize: 14, weight: .medium)
        coordLabel.font = .systemFont(ofSize: 13, weight: .regular)
        coordLabel.textColor = .secondaryLabel
        coordLabel.numberOfLines = 2

        let sep = UIView()
        sep.backgroundColor = .separator
        sep.heightAnchor.constraint(equalToConstant: 0.5).isActive = true

        let addrTitle = UILabel()
        addrTitle.text = "IP 附近精确住宅街道地址"
        addrTitle.font = .systemFont(ofSize: 12, weight: .semibold)
        addrTitle.textColor = .secondaryLabel

        addressValueLabel.font = .systemFont(ofSize: 14, weight: .medium)
        addressValueLabel.numberOfLines = 0

        let copyRow = UIStackView()
        copyRow.axis = .horizontal
        copyRow.spacing = 8
        copyRow.alignment = .center

        zipValueLabel.font = .monospacedSystemFont(ofSize: 13, weight: .bold)
        zipValueLabel.textColor = .label

        let copyZipBtn = makePillButton(title: "复制 ZIP", bgColor: .systemBlue.withAlphaComponent(0.15), textColor: .systemBlue, action: #selector(tapCopyZip))
        let copyAddrBtn = makePillButton(title: "复制地址", bgColor: .systemGreen.withAlphaComponent(0.15), textColor: .systemGreen, action: #selector(tapCopyAddress))

        copyRow.addArrangedSubview(zipValueLabel)
        copyRow.addArrangedSubview(UIView())
        copyRow.addArrangedSubview(copyZipBtn)
        copyRow.addArrangedSubview(copyAddrBtn)

        let cardStack = UIStackView(arrangedSubviews: [statusLabel, ipLabel, tzLabel, coordLabel, sep, addrTitle, addressValueLabel, copyRow])
        cardStack.axis = .vertical
        cardStack.spacing = 8
        embed(cardStack, in: infoCard)
        contentStack.addArrangedSubview(infoCard)

        // 飞行模式自动同步开关
        let switchCard = makeCard()
        let swTitle = UILabel()
        swTitle.text = "开关飞行模式自动同步 IP + 时区 + Wi-Fi"
        swTitle.font = .systemFont(ofSize: 14, weight: .medium)
        autoSwitch.isOn = LocationSyncEngine.shared.autoSyncOnNetworkChange
        autoSwitch.addTarget(self, action: #selector(toggleAutoSync), for: .valueChanged)

        let swRow = UIStackView(arrangedSubviews: [swTitle, autoSwitch])
        swRow.axis = .horizontal
        swRow.alignment = .center
        embed(swRow, in: switchCard)
        contentStack.addArrangedSubview(switchCard)

        // 主同步按钮
        let syncBtn = UIButton(type: .system)
        syncBtn.setTitle("立即同步当前 IP 定位与全局环境", for: .normal)
        syncBtn.titleLabel?.font = .systemFont(ofSize: 17, weight: .semibold)
        syncBtn.backgroundColor = .systemBlue
        syncBtn.setTitleColor(.white, for: .normal)
        syncBtn.layer.cornerRadius = 12
        syncBtn.heightAnchor.constraint(equalToConstant: 50).isActive = true
        syncBtn.addTarget(self, action: #selector(tapSyncNow), for: .touchUpInside)
        contentStack.addArrangedSubview(syncBtn)

        // 强制重置苹果国际地图按钮
        let forceMapBtn = UIButton(type: .system)
        forceMapBtn.setTitle("强制切换苹果国际原生地图（清除高德水印）", for: .normal)
        forceMapBtn.titleLabel?.font = .systemFont(ofSize: 14, weight: .semibold)
        forceMapBtn.backgroundColor = .systemBlue.withAlphaComponent(0.12)
        forceMapBtn.setTitleColor(.systemBlue, for: .normal)
        forceMapBtn.layer.cornerRadius = 11
        forceMapBtn.heightAnchor.constraint(equalToConstant: 42).isActive = true
        forceMapBtn.addTarget(self, action: #selector(tapForceAppleMaps), for: .touchUpInside)
        contentStack.addArrangedSubview(forceMapBtn)

        // 周边 12~15 个 Wi-Fi SSID 注入展示卡片
        let wifiCard = makeCard()
        let wifiTopRow = UIStackView()
        wifiTopRow.axis = .horizontal
        wifiTopRow.alignment = .center

        wifiHeaderLabel.font = .systemFont(ofSize: 14, weight: .bold)
        let refreshWiFiBtn = makePillButton(title: "换一批 Wi-Fi", bgColor: .systemBlue.withAlphaComponent(0.15), textColor: .systemBlue, action: #selector(tapRefreshWiFi))

        wifiTopRow.addArrangedSubview(wifiHeaderLabel)
        wifiTopRow.addArrangedSubview(UIView())
        wifiTopRow.addArrangedSubview(refreshWiFiBtn)

        wifiListLabel.font = .monospacedSystemFont(ofSize: 11.5, weight: .regular)
        wifiListLabel.textColor = .secondaryLabel
        wifiListLabel.numberOfLines = 0

        let wifiStack = UIStackView(arrangedSubviews: [wifiTopRow, wifiListLabel])
        wifiStack.axis = .vertical
        wifiStack.spacing = 8
        embed(wifiStack, in: wifiCard)
        contentStack.addArrangedSubview(wifiCard)

        // 停止模拟按钮
        let stopBtn = UIButton(type: .system)
        stopBtn.setTitle("一键停止模拟并恢复真实定位", for: .normal)
        stopBtn.titleLabel?.font = .systemFont(ofSize: 15, weight: .medium)
        stopBtn.setTitleColor(.systemRed, for: .normal)
        stopBtn.heightAnchor.constraint(equalToConstant: 36).isActive = true
        stopBtn.addTarget(self, action: #selector(tapStop), for: .touchUpInside)
        contentStack.addArrangedSubview(stopBtn)
    }

    private func makeCard() -> UIView {
        let v = UIView()
        v.backgroundColor = .secondarySystemGroupedBackground
        v.layer.cornerRadius = 14
        return v
    }

    private func embed(_ sub: UIView, in container: UIView) {
        sub.translatesAutoresizingMaskIntoConstraints = false
        container.addSubview(sub)
        NSLayoutConstraint.activate([
            sub.topAnchor.constraint(equalTo: container.topAnchor, constant: 14),
            sub.bottomAnchor.constraint(equalTo: container.bottomAnchor, constant: -14),
            sub.leadingAnchor.constraint(equalTo: container.leadingAnchor, constant: 14),
            sub.trailingAnchor.constraint(equalTo: container.trailingAnchor, constant: -14)
        ])
    }

    private func makePillButton(title: String, bgColor: UIColor, textColor: UIColor, action: Selector) -> UIButton {
        let btn = UIButton(type: .system)
        btn.setTitle("  \(title)  ", for: .normal)
        btn.titleLabel?.font = .systemFont(ofSize: 12, weight: .bold)
        btn.backgroundColor = bgColor
        btn.setTitleColor(textColor, for: .normal)
        btn.layer.cornerRadius = 7
        btn.heightAnchor.constraint(equalToConstant: 28).isActive = true
        btn.addTarget(self, action: action, for: .touchUpInside)
        return btn
    }

    private func refreshUI() {
        let eng = LocationSyncEngine.shared
        if let leak = eng.leakAlertMessage {
            leakBanner.text = "  \(leak)  "
            leakBanner.isHidden = false
        } else {
            leakBanner.isHidden = true
        }

        statusLabel.text = eng.isSimulating ? "✅ 正在同步定位、时区与周边 Wi-Fi" : "⏹ 已停止模拟"
        ipLabel.text = "出口 IP: \(eng.currentIP) [\(eng.currentCountryCode)]"
        let tzTag = eng.tzSyncedSuccess ? "(系统全局已生效)" : "(待同步)"
        tzLabel.text = "全局时区: \(eng.currentTZ) \(tzTag)"
        coordLabel.text = "模拟坐标: \(eng.currentCity) (\(String(format: "%.4f", eng.baseLat)), \(String(format: "%.4f", eng.baseLon)))"
        addressValueLabel.text = eng.exactAddress
        zipValueLabel.text = "ZIP 邮编: \(eng.exactZipCode)"

        wifiHeaderLabel.text = "已注入周边 Wi-Fi（\(eng.nearbyWiFis.count) 个）"
        if eng.nearbyWiFis.isEmpty {
            wifiListLabel.text = "点击“立即同步”自动生成 12~15 个当地周边 Wi-Fi SSID"
        } else {
            wifiListLabel.text = eng.nearbyWiFis.enumerated().map { idx, ap in
                String(format: "%02d. %-22@ | %@ | %ddBm", idx + 1, ap.ssid as NSString, ap.bssid, ap.rssi)
            }.joined(separator: "\n")
        }
    }

    private func showToast(_ text: String) {
        let lbl = UILabel()
        lbl.text = "  \(text)  "
        lbl.backgroundColor = UIColor.black.withAlphaComponent(0.82)
        lbl.textColor = .white
        lbl.font = .systemFont(ofSize: 13, weight: .semibold)
        lbl.textAlignment = .center
        lbl.layer.cornerRadius = 16
        lbl.clipsToBounds = true
        lbl.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(lbl)
        NSLayoutConstraint.activate([
            lbl.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            lbl.bottomAnchor.constraint(equalTo: view.safeAreaLayoutGuide.bottomAnchor, constant: -24),
            lbl.heightAnchor.constraint(equalToConstant: 34)
        ])
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.8) {
            lbl.removeFromSuperview()
        }
    }

    @objc private func toggleAutoSync() {
        LocationSyncEngine.shared.autoSyncOnNetworkChange = autoSwitch.isOn
    }

    @objc private func tapSyncNow() {
        statusLabel.text = "⏳ 正在防泄漏探测并同步全套环境..."
        LocationSyncEngine.shared.syncWithCurrentIP()
    }

    @objc private func tapForceAppleMaps() {
        let cc = LocationSyncEngine.shared.currentCountryCode
        RootSystemHelper.forceAppleInternationalMaps(countryCode: cc == "--" ? "US" : cc)
        showToast("已清理高德缓存并切换苹果国际地图")
    }

    @objc private func tapRefreshWiFi() {
        LocationSyncEngine.shared.regenerateWiFiAndInject()
        showToast("已重新生成并注入 \(LocationSyncEngine.shared.nearbyWiFis.count) 个 Wi-Fi")
    }

    @objc private func tapCopyZip() {
        let zip = LocationSyncEngine.shared.exactZipCode
        UIPasteboard.general.string = zip
        showToast("已复制邮编: \(zip)")
    }

    @objc private func tapCopyAddress() {
        let addr = LocationSyncEngine.shared.exactAddress
        UIPasteboard.general.string = addr
        showToast("已复制精确街道地址")
    }

    @objc private func tapStop() {
        LocationSyncEngine.shared.stopSimulation()
        showToast("已恢复硬件真实定位")
    }
}

// MARK: - 6. AppDelegate 入口（兼容 -parse-as-library 编译模式）
@main
class AppDelegate: UIResponder, UIApplicationDelegate {
    var window: UIWindow?
    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        window = UIWindow(frame: UIScreen.main.bounds)
        window?.rootViewController = MainViewController()
        window?.makeKeyAndVisible()
        return true
    }
}
