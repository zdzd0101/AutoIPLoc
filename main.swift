import UIKit
import CoreLocation
import Network
import AVFoundation
import Darwin

@objc protocol CLSimulationManagerProtocol {
    func clearSimulatedLocations()
    func appendSimulatedLocation(_ location: CLLocation)
    func flush()
    func startLocationSimulation()
    func stopLocationSimulation()
}

@_silgen_name("proc_listpids")
private func proc_listpids(_ type: UInt32, _ typeinfo: UInt32, _ buffer: UnsafeMutableRawPointer?, _ buffersize: Int32) -> Int32

@_silgen_name("proc_name")
private func proc_name(_ pid: Int32, _ buffer: UnsafeMutableRawPointer?, _ buffersize: UInt32) -> Int32

@_silgen_name("posix_spawnattr_set_persona_np")
private func posix_spawnattr_set_persona_np(_ attr: UnsafeMutablePointer<posix_spawnattr_t?>, _ persona_id: uid_t, _ flags: UInt32) -> Int32

@_silgen_name("posix_spawnattr_set_persona_uid_np")
private func posix_spawnattr_set_persona_uid_np(_ attr: UnsafeMutablePointer<posix_spawnattr_t?>, _ uid: uid_t) -> Int32

@_silgen_name("posix_spawnattr_set_persona_gid_np")
private func posix_spawnattr_set_persona_gid_np(_ attr: UnsafeMutablePointer<posix_spawnattr_t?>, _ gid: gid_t) -> Int32

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

struct EgressIPResult {
    let ip: String
    let countryCode: String
    let country: String
    let region: String
    let city: String
    let zip: String
    let lat: Double
    let lon: Double
    let timezone: String
    let isp: String
}

class NativeSystemController {
    static let geoSharedPath = "/var/mobile/Library/Preferences/com.autoiploc.geo.plist"
    static let wifiSharedPath = "/var/mobile/Library/Preferences/com.autoiploc.wifi.plist"

    @discardableResult
    static func runSelfAsRoot(args: [String]) -> Bool {
        guard let execPath = Bundle.main.executablePath else { return false }
        var attr: posix_spawnattr_t?
        posix_spawnattr_init(&attr)
        _ = posix_spawnattr_set_persona_np(&attr, 99, 1)
        _ = posix_spawnattr_set_persona_uid_np(&attr, 0)
        _ = posix_spawnattr_set_persona_gid_np(&attr, 0)

        var cArgs: [UnsafeMutablePointer<CChar>?] = [strdup(execPath), strdup("--root-worker")]
        for a in args { cArgs.append(strdup(a)) }
        cArgs.append(nil)

        defer {
            for ptr in cArgs where ptr != nil { free(ptr) }
            posix_spawnattr_destroy(&attr)
        }

        var pid: pid_t = 0
        let status = posix_spawn(&pid, execPath, nil, &attr, cArgs, environ)
        if status == 0 {
            var exitCode: Int32 = 0
            waitpid(pid, &exitCode, 0)
            return exitCode == 0
        }
        return false
    }

    static func handleRootWorkerIfNeeded() {
        let args = CommandLine.arguments
        guard let idx = args.firstIndex(of: "--root-worker"), idx + 1 < args.count else { return }
        let action = args[idx + 1]

        if action == "timezone", idx + 2 < args.count {
            let tz = args[idx + 2]

            // 1. 调用 CoreTime 私有接口关闭自动时区并下发目标时区到 timed 守护进程
            if let handle = dlopen("/System/Library/PrivateFrameworks/CoreTime.framework/CoreTime", RTLD_LAZY) {
                typealias SetAutoTZFn = @convention(c) (Bool) -> Void
                typealias SetManualTZFn = @convention(c) (CFString) -> Void
                if let symAuto = dlsym(handle, "TMSetAutomaticTimeZoneEnabled") {
                    unsafeBitCast(symAuto, to: SetAutoTZFn.self)(false)
                }
                if let symManual = dlsym(handle, "TMSetManualTimeZone") {
                    unsafeBitCast(symManual, to: SetManualTZFn.self)(tz as CFString)
                }
            }

            // 2. 同步写入系统级与用户级时间配置表
            let plistTargets = [
                ("/var/mobile/Library/Preferences/com.apple.preferences.datetime.plist", uid_t(501)),
                ("/var/preferences/com.apple.preferences.datetime.plist", uid_t(0)),
                ("/var/preferences/com.apple.timed.plist", uid_t(0))
            ]
            for (path, owner) in plistTargets {
                let dict = NSMutableDictionary(contentsOfFile: path) ?? NSMutableDictionary()
                dict["AutomaticTimeZoneEnabled"] = false
                dict["TMAutomaticTimeZoneEnabled"] = false
                dict["timezone"] = tz
                dict.write(toFile: path, atomically: true)
                chown(path, owner, owner)
                chmod(path, 0o644)
            }

            // 等待 350ms 让 timed 完成 XPC 事务与状态栏时钟刷新，切勿立即强杀
            usleep(350_000)
            exit(0)
        } else if action == "clear-geo" {
            let paths = [
                "/var/mobile/Library/GeoServices",
                "/var/mobile/Library/Caches/GeoServices",
                "/var/mobile/Library/Caches/com.apple.Maps",
                "/var/mobile/Library/Caches/com.apple.geod"
            ]
            for p in paths {
                try? FileManager.default.removeItem(atPath: p)
            }
            restartProcessesNative(["geod", "Maps"])
            exit(0)
        } else if action == "kill", idx + 2 < args.count {
            let names = args[idx + 2].components(separatedBy: ",")
            restartProcessesNative(names)
            exit(0)
        }
        exit(0)
    }

    static func restartProcessesNative(_ targetNames: [String]) {
        let byteSize = proc_listpids(1, 0, nil, 0)
        guard byteSize > 0 else { return }
        let count = Int(byteSize) / MemoryLayout<pid_t>.size
        var pids = [pid_t](repeating: 0, count: count)
        let actualBytes = proc_listpids(1, 0, &pids, byteSize)
        let actualCount = Int(actualBytes) / MemoryLayout<pid_t>.size

        var nameBuffer = [CChar](repeating: 0, count: 256)
        for i in 0..<actualCount {
            let pid = pids[i]
            if pid <= 0 { continue }
            memset(&nameBuffer, 0, 256)
            if proc_name(pid, &nameBuffer, 256) > 0 {
                let procName = String(cString: nameBuffer)
                if targetNames.contains(procName) {
                    kill(pid, SIGKILL)
                }
            }
        }
    }

    static func updateGeoSharedConfig(countryCode: String, timezone: String?) {
        let cc = (countryCode.isEmpty || countryCode == "--") ? "US" : countryCode.uppercased()
        let dict = NSMutableDictionary(contentsOfFile: geoSharedPath) ?? NSMutableDictionary()
        dict["countryCode"] = cc
        dict["forceAppleMaps"] = true
        if let tz = timezone, !tz.isEmpty, tz != "-" {
            dict["timezone"] = tz
        }
        dict["updatedAt"] = Date().timeIntervalSince1970
        dict.write(toFile: geoSharedPath, atomically: true)
        chmod(geoSharedPath, 0o644)
    }

    static func applyTimeZone(_ tzIdentifier: String, countryCode: String) -> Bool {
        guard !tzIdentifier.isEmpty else { return false }

        updateGeoSharedConfig(countryCode: countryCode, timezone: tzIdentifier)

        let dtDomain = "com.apple.preferences.datetime" as CFString
        CFPreferencesSetValue("AutomaticTimeZoneEnabled" as CFString, kCFBooleanFalse, dtDomain, kCFPreferencesCurrentUser, kCFPreferencesAnyHost)
        CFPreferencesSetValue("timezone" as CFString, tzIdentifier as CFString, dtDomain, kCFPreferencesCurrentUser, kCFPreferencesAnyHost)
        CFPreferencesSynchronize(dtDomain, kCFPreferencesCurrentUser, kCFPreferencesAnyHost)

        _ = runSelfAsRoot(args: ["timezone", tzIdentifier])

        setenv("TZ", tzIdentifier, 1)
        tzset()
        NSTimeZone.resetSystemTimeZone()

        let center = CFNotificationCenterGetDarwinNotifyCenter()
        CFNotificationCenterPostNotification(center, CFNotificationName("NSSystemTimeZoneDidChangeNotification" as CFString), nil, nil, true)
        CFNotificationCenterPostNotification(center, CFNotificationName("SignificantTimeChangeNotification" as CFString), nil, nil, true)

        return TimeZone(identifier: tzIdentifier) != nil
    }

    static func forceAppleInternationalMaps(countryCode: String) {
        let cc = (countryCode.isEmpty || countryCode == "--") ? "US" : countryCode.uppercased()
        updateGeoSharedConfig(countryCode: cc, timezone: nil)

        let prefFiles = [
            "/var/mobile/Library/Preferences/com.apple.GEO.plist",
            "/var/mobile/Library/Preferences/com.apple.Maps.plist"
        ]
        for path in prefFiles {
            let dict = NSMutableDictionary(contentsOfFile: path) ?? NSMutableDictionary()
            dict["CountryCode"] = cc
            dict["GEOCountryCode"] = cc
            dict["LastKnownCountryCode"] = cc
            dict.removeObject(forKey: "AutoNavi")
            dict.removeObject(forKey: "CN_Config")
            dict.write(toFile: path, atomically: true)
            chmod(path, 0o644)
        }

        let center = CFNotificationCenterGetDarwinNotifyCenter()
        CFNotificationCenterPostNotification(center, CFNotificationName("com.autoiploc.geo.updated" as CFString), nil, nil, true)
        _ = runSelfAsRoot(args: ["clear-geo"])
    }

    static func injectWiFiList(_ nodes: [SimulatedWiFiNode], countryCode: String) {
        let payload: NSDictionary = [
            "enabled": true,
            "countryCode": countryCode,
            "updatedAt": Date().timeIntervalSince1970,
            "networks": nodes.map { $0.toPlistDict() }
        ]
        payload.write(toFile: wifiSharedPath, atomically: true)
        chmod(wifiSharedPath, 0o644)

        let center = CFNotificationCenterGetDarwinNotifyCenter()
        CFNotificationCenterPostNotification(center, CFNotificationName("com.autoiploc.wifi.updated" as CFString), nil, nil, true)
    }

    static func clearWiFiInjection() {
        unlink(wifiSharedPath)
        let center = CFNotificationCenterGetDarwinNotifyCenter()
        CFNotificationCenterPostNotification(center, CFNotificationName("com.autoiploc.wifi.updated" as CFString), nil, nil, true)
    }
}

class LocationSyncEngine: NSObject {
    static let shared = LocationSyncEngine()

    private var simManager: AnyObject?
    private let pathMonitor = NWPathMonitor()
    private let monitorQueue = DispatchQueue(label: "com.autoiploc.netmonitor")
    private var audioPlayer: AVAudioPlayer?
    private var heartbeatTimer: Timer?
    private var debounceWorkItem: DispatchWorkItem?

    private(set) var isSimulating = false
    private(set) var isSyncing = false
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
    private(set) var alertMessage: String? = nil

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

    // 监听 Wi-Fi / 蜂窝流量 / 代理隧道(other) 任意通道变化并自动同步时区与定位
    private func setupNetworkMonitor() {
        var lastSignature = ""
        pathMonitor.pathUpdateHandler = { [weak self] path in
            guard let self = self else { return }
            let sig = "\(path.status == .satisfied)|w:\(path.usesInterfaceType(.wifi))|c:\(path.usesInterfaceType(.cellular))|o:\(path.usesInterfaceType(.other))"
            if path.status == .satisfied && sig != lastSignature && self.autoSyncOnNetworkChange {
                self.debounceWorkItem?.cancel()
                let work = DispatchWorkItem { [weak self] in
                    self?.syncWithCurrentIP()
                }
                self.debounceWorkItem = work
                DispatchQueue.main.asyncAfter(deadline: .now() + 2.5, execute: work)
            }
            lastSignature = sig
        }
        pathMonitor.start(queue: monitorQueue)
    }

    private func fetchEgressIPWithFallback(completion: @escaping (EgressIPResult?) -> Void) {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 6.0
        config.timeoutIntervalForResource = 8.0
        config.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        let session = URLSession(configuration: config)

        func trySource1() {
            guard let url = URL(string: "https://ipwho.is/") else { trySource2(); return }
            session.dataTask(with: url) { data, _, _ in
                if let data = data,
                   let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                   (json["success"] as? Bool) == true,
                   let ip = json["ip"] as? String,
                   let cc = json["country_code"] as? String,
                   let lat = json["latitude"] as? Double,
                   let lon = json["longitude"] as? Double {
                    let tzDict = json["timezone"] as? [String: Any]
                    let connDict = json["connection"] as? [String: Any]
                    completion(EgressIPResult(
                        ip: ip,
                        countryCode: cc.uppercased(),
                        country: json["country"] as? String ?? cc,
                        region: json["region"] as? String ?? "",
                        city: json["city"] as? String ?? "",
                        zip: json["postal"] as? String ?? "",
                        lat: lat,
                        lon: lon,
                        timezone: tzDict?["id"] as? String ?? "America/Los_Angeles",
                        isp: connDict?["isp"] as? String ?? "Residential ISP"
                    ))
                } else {
                    trySource2()
                }
            }.resume()
        }

        func trySource2() {
            guard let url = URL(string: "http://ip-api.com/json/?fields=status,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,query") else { trySource3(); return }
            session.dataTask(with: url) { data, _, _ in
                if let data = data,
                   let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                   (json["status"] as? String) == "success",
                   let ip = json["query"] as? String,
                   let cc = json["countryCode"] as? String,
                   let lat = json["lat"] as? Double,
                   let lon = json["lon"] as? Double {
                    completion(EgressIPResult(
                        ip: ip,
                        countryCode: cc.uppercased(),
                        country: json["country"] as? String ?? cc,
                        region: json["regionName"] as? String ?? "",
                        city: json["city"] as? String ?? "",
                        zip: json["zip"] as? String ?? "",
                        lat: lat,
                        lon: lon,
                        timezone: json["timezone"] as? String ?? "America/Los_Angeles",
                        isp: json["isp"] as? String ?? "Residential ISP"
                    ))
                } else {
                    trySource3()
                }
            }.resume()
        }

        func trySource3() {
            guard let url = URL(string: "https://ipapi.co/json/") else { completion(nil); return }
            var req = URLRequest(url: url)
            req.setValue("Mozilla/5.0 (iPhone; CPU iPhone OS 16_2 like Mac OS X)", forHTTPHeaderField: "User-Agent")
            session.dataTask(with: req) { data, _, _ in
                if let data = data,
                   let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                   let ip = json["ip"] as? String,
                   let cc = json["country_code"] as? String,
                   let lat = json["latitude"] as? Double,
                   let lon = json["longitude"] as? Double {
                    completion(EgressIPResult(
                        ip: ip,
                        countryCode: cc.uppercased(),
                        country: json["country_name"] as? String ?? cc,
                        region: json["region"] as? String ?? "",
                        city: json["city"] as? String ?? "",
                        zip: json["postal"] as? String ?? "",
                        lat: lat,
                        lon: lon,
                        timezone: json["timezone"] as? String ?? "America/Los_Angeles",
                        isp: json["org"] as? String ?? "Residential ISP"
                    ))
                } else {
                    completion(nil)
                }
            }.resume()
        }

        trySource1()
    }

    func syncWithCurrentIP() {
        guard !isSyncing else { return }
        isSyncing = true
        alertMessage = nil
        onStatusUpdated?()

        fetchEgressIPWithFallback { [weak self] info in
            guard let self = self else { return }
            guard let info = info else {
                DispatchQueue.main.async {
                    self.isSyncing = false
                    self.alertMessage = "⚠️ 当前节点无法连接 IP 探测接口，请切换可用海外节点后再同步。"
                    self.onStatusUpdated?()
                }
                return
            }

            if info.countryCode == "CN" {
                DispatchQueue.main.async {
                    self.isSyncing = false
                    self.currentIP = info.ip
                    self.currentCountryCode = "CN"
                    self.alertMessage = "⚠️ 检测到国内出口 IP (\(info.ip))，已阻断同步以防位置暴露！请连接海外节点后再同步。"
                    self.onStatusUpdated?()
                }
                return
            }

            let residentialLat = info.lat + Double.random(in: -0.0014...0.0014)
            let residentialLon = info.lon + Double.random(in: -0.0014...0.0014)

            self.reverseGeocodeExactAddress(
                lat: residentialLat,
                lon: residentialLon,
                fallbackCity: info.city,
                fallbackRegion: info.region,
                fallbackCountry: info.country,
                fallbackZip: info.zip
            ) { resolvedAddress, resolvedZip in
                DispatchQueue.main.async {
                    self.isSyncing = false
                    self.alertMessage = nil
                    self.currentIP = info.ip
                    self.currentCountryCode = info.countryCode
                    self.currentCity = "\(info.country) · \(info.city)"
                    self.currentISP = info.isp
                    self.currentTZ = info.timezone
                    self.baseLat = residentialLat
                    self.baseLon = residentialLon
                    self.exactAddress = resolvedAddress
                    self.exactZipCode = resolvedZip

                    // 1. 同步系统时区与状态栏时钟
                    self.tzSyncedSuccess = NativeSystemController.applyTimeZone(info.timezone, countryCode: info.countryCode)

                    // 2. 动态生成并注入 12~15 个当地周边 Wi-Fi
                    let generatedWiFis = self.generateDynamicWiFis(isp: info.isp)
                    self.nearbyWiFis = generatedWiFis
                    NativeSystemController.injectWiFiList(generatedWiFis, countryCode: info.countryCode)

                    // 3. 切换苹果国际原生地图并清除高德缓存
                    NativeSystemController.forceAppleInternationalMaps(countryCode: info.countryCode)

                    // 4. 注入底层 GPS 坐标并启动心跳保活
                    self.pushSimulatedLocation(lat: residentialLat, lon: residentialLon)
                    self.startHeartbeat()
                    self.startSilentBackgroundAudio()
                    self.isSimulating = true
                    self.onStatusUpdated?()
                }
            }
        }
    }

    func regenerateWiFiAndInject() {
        let list = generateDynamicWiFis(isp: currentISP)
        nearbyWiFis = list
        NativeSystemController.injectWiFiList(list, countryCode: currentCountryCode == "--" ? "US" : currentCountryCode)
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
        let safeZip = fallbackZip.isEmpty ? "90001" : fallbackZip
        let fallbackAddr = "\(Int.random(in: 120...3890)) Oakridge Dr, \(fallbackCity), \(fallbackRegion) \(safeZip), \(fallbackCountry)"

        var finished = false
        let lock = NSLock()

        let timeoutWork = DispatchWorkItem {
            lock.lock()
            let shouldComplete = !finished
            finished = true
            lock.unlock()
            if shouldComplete {
                geocoder.cancelGeocode()
                completion(fallbackAddr, safeZip)
            }
        }
        DispatchQueue.global().asyncAfter(deadline: .now() + 5.0, execute: timeoutWork)

        geocoder.reverseGeocodeLocation(location, preferredLocale: enLocale) { placemarks, _ in
            lock.lock()
            let shouldComplete = !finished
            finished = true
            lock.unlock()
            timeoutWork.cancel()
            guard shouldComplete else { return }

            if let pm = placemarks?.first {
                let streetNum = pm.subThoroughfare ?? "\(Int.random(in: 112...4680))"
                let street = pm.thoroughfare ?? "W Maple Ave"
                let city = pm.locality ?? fallbackCity
                let state = pm.administrativeArea ?? fallbackRegion
                let zip = (pm.postalCode?.isEmpty == false) ? pm.postalCode! : safeZip
                let country = pm.country ?? fallbackCountry
                completion("\(streetNum) \(street), \(city), \(state) \(zip), \(country)", zip)
            } else {
                completion(fallbackAddr, safeZip)
            }
        }
    }

    private func generateDynamicWiFis(isp: String) -> [SimulatedWiFiNode] {
        let count = Int.random(in: 12...15)
        let lowerISP = isp.lowercased()

        let ouis = [
            "20:4E:7F", "44:94:FC", "B0:BE:76", "A4:2B:B0", "C8:D7:19",
            "14:91:82", "78:8A:20", "E4:F0:42", "3C:37:86", "94:A6:7E",
            "D8:47:32", "00:26:F2", "AC:84:C6", "00:1E:58", "88:DC:96"
        ]

        var ispGenerators: [() -> String] = []
        if lowerISP.contains("t-mobile") {
            ispGenerators.append { "TMOBILE-\(self.randHex(4))" }
            ispGenerators.append { "TMOBILE-5G-\(self.randHex(4))" }
            ispGenerators.append { "T-Mobile_Home_\(self.randAlphaNum(4))" }
        } else if lowerISP.contains("centurylink") || lowerISP.contains("lumen") {
            ispGenerators.append { "CenturyLink\(Int.random(in: 1000...9999))" }
            ispGenerators.append { "CenturyLink\(Int.random(in: 1000...9999))-5G" }
        } else if lowerISP.contains("comcast") || lowerISP.contains("xfinity") {
            ispGenerators.append { "XFSETUP-\(self.randHex(4))" }
            ispGenerators.append { "xfinitywifi" }
            ispGenerators.append { "HOME-\(self.randHex(4))-5G" }
        } else if lowerISP.contains("charter") || lowerISP.contains("spectrum") {
            ispGenerators.append { "SpectrumSetup-\(self.randHex(2))" }
            ispGenerators.append { "MySpectrumWiFi\(self.randHex(2))-5G" }
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
        let jitterLat = lat + Double.random(in: -0.00006...0.00006)
        let jitterLon = lon + Double.random(in: -0.00006...0.00006)
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
        NativeSystemController.clearWiFiInjection()
        _ = NativeSystemController.runSelfAsRoot(args: ["kill", "locationd,geod"])
        audioPlayer?.stop()
        isSimulating = false
        alertMessage = nil
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

class MainViewController: UIViewController {
    private let scrollView = UIScrollView()
    private let contentStack = UIStackView()

    private let alertBanner = UILabel()
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

        alertBanner.backgroundColor = .systemRed
        alertBanner.textColor = .white
        alertBanner.font = .systemFont(ofSize: 13, weight: .semibold)
        alertBanner.numberOfLines = 0
        alertBanner.layer.cornerRadius = 10
        alertBanner.clipsToBounds = true
        alertBanner.isHidden = true
        contentStack.addArrangedSubview(alertBanner)

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

        let switchCard = makeCard()
        let swTitle = UILabel()
        swTitle.text = "网络与代理切换自动同步 IP + 时区 + Wi-Fi"
        swTitle.font = .systemFont(ofSize: 14, weight: .medium)
        autoSwitch.isOn = LocationSyncEngine.shared.autoSyncOnNetworkChange
        autoSwitch.addTarget(self, action: #selector(toggleAutoSync), for: .valueChanged)

        let swRow = UIStackView(arrangedSubviews: [swTitle, autoSwitch])
        swRow.axis = .horizontal
        swRow.alignment = .center
        embed(swRow, in: switchCard)
        contentStack.addArrangedSubview(switchCard)

        let syncBtn = UIButton(type: .system)
        syncBtn.setTitle("立即同步当前 IP 定位与全局环境", for: .normal)
        syncBtn.titleLabel?.font = .systemFont(ofSize: 17, weight: .semibold)
        syncBtn.backgroundColor = .systemBlue
        syncBtn.setTitleColor(.white, for: .normal)
        syncBtn.layer.cornerRadius = 12
        syncBtn.heightAnchor.constraint(equalToConstant: 50).isActive = true
        syncBtn.addTarget(self, action: #selector(tapSyncNow), for: .touchUpInside)
        contentStack.addArrangedSubview(syncBtn)

        let forceMapBtn = UIButton(type: .system)
        forceMapBtn.setTitle("强制切换苹果国际原生地图（清除高德水印）", for: .normal)
        forceMapBtn.titleLabel?.font = .systemFont(ofSize: 14, weight: .semibold)
        forceMapBtn.backgroundColor = .systemBlue.withAlphaComponent(0.12)
        forceMapBtn.setTitleColor(.systemBlue, for: .normal)
        forceMapBtn.layer.cornerRadius = 11
        forceMapBtn.heightAnchor.constraint(equalToConstant: 42).isActive = true
        forceMapBtn.addTarget(self, action: #selector(tapForceAppleMaps), for: .touchUpInside)
        contentStack.addArrangedSubview(forceMapBtn)

        let wifiCard = makeCard()
        let wifiTopRow = UIStackView()
        wifiTopRow.axis = .horizontal
        wifiTopRow.spacing = 6
        wifiTopRow.alignment = .center

        wifiHeaderLabel.font = .systemFont(ofSize: 14, weight: .bold)
        let copyWiFiBtn = makePillButton(title: "复制参数", bgColor: .systemGreen.withAlphaComponent(0.15), textColor: .systemGreen, action: #selector(tapCopyWiFi))
        let refreshWiFiBtn = makePillButton(title: "换一批", bgColor: .systemBlue.withAlphaComponent(0.15), textColor: .systemBlue, action: #selector(tapRefreshWiFi))

        wifiTopRow.addArrangedSubview(wifiHeaderLabel)
        wifiTopRow.addArrangedSubview(UIView())
        wifiTopRow.addArrangedSubview(copyWiFiBtn)
        wifiTopRow.addArrangedSubview(refreshWiFiBtn)

        wifiListLabel.font = .monospacedSystemFont(ofSize: 11.5, weight: .regular)
        wifiListLabel.textColor = .secondaryLabel
        wifiListLabel.numberOfLines = 0

        let wifiStack = UIStackView(arrangedSubviews: [wifiTopRow, wifiListLabel])
        wifiStack.axis = .vertical
        wifiStack.spacing = 8
        embed(wifiStack, in: wifiCard)
        contentStack.addArrangedSubview(wifiCard)

        let stopBtn = UIButton(type: .system)
        stopBtn.setTitle("一键停止模拟并立即恢复真实定位", for: .normal)
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
        if let msg = eng.alertMessage {
            alertBanner.text = "  \(msg)  "
            alertBanner.isHidden = false
        } else {
            alertBanner.isHidden = true
        }

        if eng.isSyncing {
            statusLabel.text = "⏳ 正在防泄漏探测并同步全套环境..."
        } else {
            statusLabel.text = eng.isSimulating ? "✅ 正在同步定位、时区与周边 Wi-Fi" : "⏹ 已停止模拟"
        }

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
                String(format: "%02d. %@ | %@ | CH%d | %ddBm", idx + 1, ap.ssid, ap.bssid, ap.channel, ap.rssi)
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
        LocationSyncEngine.shared.syncWithCurrentIP()
    }

    @objc private func tapForceAppleMaps() {
        let cc = LocationSyncEngine.shared.currentCountryCode
        NativeSystemController.forceAppleInternationalMaps(countryCode: cc)
        showToast("已清理高德配置并重载苹果国际地图")
    }

    @objc private func tapRefreshWiFi() {
        LocationSyncEngine.shared.regenerateWiFiAndInject()
        showToast("已重新生成并注入 \(LocationSyncEngine.shared.nearbyWiFis.count) 个 Wi-Fi")
    }

    @objc private func tapCopyWiFi() {
        let text = LocationSyncEngine.shared.nearbyWiFis.map { "\($0.ssid) | \($0.bssid) | CH\($0.channel) | \($0.rssi)dBm" }.joined(separator: "\n")
        UIPasteboard.general.string = text
        showToast("已复制全部 \(LocationSyncEngine.shared.nearbyWiFis.count) 个 Wi-Fi 参数")
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
        showToast("已重载定位服务，恢复硬件真实定位")
    }
}

class AppDelegate: UIResponder, UIApplicationDelegate {
    var window: UIWindow?
    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        window = UIWindow(frame: UIScreen.main.bounds)
        window?.rootViewController = MainViewController()
        window?.makeKeyAndVisible()
        return true
    }
}

@main
struct AutoIPLocMain {
    static func main() {
        NativeSystemController.handleRootWorkerIfNeeded()
        UIApplicationMain(
            CommandLine.argc,
            CommandLine.unsafeArgv,
            nil,
            NSStringFromClass(AppDelegate.self)
        )
    }
}
