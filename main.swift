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

// MARK: - 2. 封装系统全局时区修改器 (Root 提权修改底层 localtime + 通知系统刷新)
@_silgen_name("posix_spawnattr_set_persona_np")
func posix_spawnattr_set_persona_np(_ attr: UnsafeMutablePointer<posix_spawnattr_t?>, _ persona_id: uid_t, _ flags: UInt32) -> Int32
@_silgen_name("posix_spawnattr_set_persona_uid_np")
func posix_spawnattr_set_persona_uid_np(_ attr: UnsafeMutablePointer<posix_spawnattr_t?>, _ uid: uid_t) -> Int32
@_silgen_name("posix_spawnattr_set_persona_gid_np")
func posix_spawnattr_set_persona_gid_np(_ attr: UnsafeMutablePointer<posix_spawnattr_t?>, _ gid: gid_t) -> Int32

class SystemTimeZoneUpdater {
    static func applyTimeZone(_ tzIdentifier: String) -> Bool {
        let zonePath = "/usr/share/zoneinfo/\(tzIdentifier)"
        guard !tzIdentifier.isEmpty, FileManager.default.fileExists(atPath: zonePath) else {
            return false
        }

        // 1. 先关闭自动时区偏好设置
        let dtDomain = "com.apple.preferences.datetime" as CFString
        CFPreferencesSetValue("AutomaticTimeZoneEnabled" as CFString, kCFBooleanFalse, dtDomain, kCFPreferencesCurrentUser, kCFPreferencesAnyHost)
        CFPreferencesSetValue("timezone" as CFString, tzIdentifier as CFString, dtDomain, kCFPreferencesCurrentUser, kCFPreferencesAnyHost)
        CFPreferencesSynchronize(dtDomain, kCFPreferencesCurrentUser, kCFPreferencesAnyHost)

        // 2. 以 root (uid 0) 身份重写 /var/db/timezone/localtime 软链接
        let cmd = "rm -f /var/db/timezone/localtime && ln -sf \(zonePath) /var/db/timezone/localtime && chmod 755 /var/db/timezone/localtime && killall -HUP timed 2>/dev/null || true"
        let ok = runAsRoot(cmd)

        // 3. 发送系统全局时区变更广播，触发状态栏与 Safari 实时刷新
        let center = CFNotificationCenterGetDarwinNotifyCenter()
        CFNotificationCenterPostNotification(center, CFNotificationName("NSSystemTimeZoneDidChangeNotification" as CFString), nil, nil, true)
        CFNotificationCenterPostNotification(center, CFNotificationName("SignificantTimeChangeNotification" as CFString), nil, nil, true)

        return ok
    }

    private static func runAsRoot(_ command: String) -> Bool {
        var attr: posix_spawnattr_t?
        posix_spawnattr_init(&attr)
        posix_spawnattr_set_persona_np(&attr, 99, 1) // POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE
        posix_spawnattr_set_persona_uid_np(&attr, 0)
        posix_spawnattr_set_persona_gid_np(&attr, 0)

        var pid: pid_t = 0
        let argv: [UnsafeMutablePointer<CChar>?] = [
            strdup("/bin/sh"),
            strdup("-c"),
            strdup(command),
            nil
        ]
        defer {
            for ptr in argv where ptr != nil { free(ptr) }
            posix_spawnattr_destroy(&attr)
        }

        let status = posix_spawn(&pid, "/bin/sh", nil, &attr, argv, environ)
        if status == 0 {
            var exitCode: Int32 = 0
            waitpid(pid, &exitCode, 0)
            return exitCode == 0
        }
        return false
    }
}

// MARK: - 3. 核心定位与网络监听器
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
    private(set) var currentCity: String = "-"
    private(set) var currentTZ: String = "-"
    private(set) var tzSyncedSuccess: Bool = false

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
            // 检测到从断网（飞行模式）恢复联网时触发防抖同步
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
        guard let url = URL(string: "http://ip-api.com/json/?fields=status,country,regionName,city,lat,lon,timezone,query") else { return }
        var req = URLRequest(url: url, timeoutInterval: 8.0)
        req.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData

        URLSession.shared.dataTask(with: req) { [weak self] data, _, error in
            guard let self = self, let data = data, error == nil,
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  (json["status"] as? String) == "success",
                  let lat = json["lat"] as? Double,
                  let lon = json["lon"] as? Double else {
                DispatchQueue.main.async { self?.onStatusUpdated?() }
                return
            }

            let ip = json["query"] as? String ?? "Unknown"
            let country = json["country"] as? String ?? ""
            let city = json["city"] as? String ?? ""
            let tz = json["timezone"] as? String ?? ""

            DispatchQueue.main.async {
                self.currentIP = ip
                self.currentCity = "\(country) · \(city)"
                self.currentTZ = tz
                self.baseLat = lat
                self.baseLon = lon

                // 1. 同步修改系统全局时区
                self.tzSyncedSuccess = SystemTimeZoneUpdater.applyTimeZone(tz)

                // 2. 注入模拟 GPS 坐标并启动心跳保活
                self.pushSimulatedLocation(lat: lat, lon: lon)
                self.startHeartbeat()
                self.startSilentBackgroundAudio()
                self.isSimulating = true
                self.onStatusUpdated?()
            }
        }.resume()
    }

    private func pushSimulatedLocation(lat: Double, lon: Double) {
        guard let mgr = simManager else { return }
        // 添加约 5~12 米的微扰，模拟真人手持呼吸漂移
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
        audioPlayer?.stop()
        isSimulating = false
        onStatusUpdated?()
    }

    private func startSilentBackgroundAudio() {
        if audioPlayer?.isPlaying == true { return }
        try? AVAudioSession.sharedInstance().setCategory(.playback, options: .mixWithOthers)
        try? AVAudioSession.sharedInstance().setActive(true)
        // 生成 1 秒静音 WAV 数据用于后台保活
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

// MARK: - 4. 主界面 UIViewController
class MainViewController: UIViewController {
    private let statusLabel = UILabel()
    private let ipLabel = UILabel()
    private let tzLabel = UILabel()
    private let coordLabel = UILabel()
    private let autoSwitch = UISwitch()

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
        let titleLbl = UILabel()
        titleLbl.text = "IP 自动定位与全局时区助手"
        titleLbl.font = .systemFont(ofSize: 24, weight: .bold)
        titleLbl.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(titleLbl)

        let card = UIView()
        card.backgroundColor = .secondarySystemGroupedBackground
        card.layer.cornerRadius = 14
        card.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(card)

        statusLabel.font = .systemFont(ofSize: 16, weight: .semibold)
        ipLabel.font = .monospacedSystemFont(ofSize: 14, weight: .regular)
        tzLabel.font = .monospacedSystemFont(ofSize: 14, weight: .medium)
        coordLabel.font = .systemFont(ofSize: 13, weight: .regular)
        coordLabel.textColor = .secondaryLabel
        coordLabel.numberOfLines = 2

        let stack = UIStackView(arrangedSubviews: [statusLabel, ipLabel, tzLabel, coordLabel])
        stack.axis = .vertical
        stack.spacing = 10
        stack.translatesAutoresizingMaskIntoConstraints = false
        card.addSubview(stack)

        let switchRow = UIView()
        switchRow.backgroundColor = .secondarySystemGroupedBackground
        switchRow.layer.cornerRadius = 14
        switchRow.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(switchRow)

        let swTitle = UILabel()
        swTitle.text = "开关飞行模式自动同步 IP + 时区"
        swTitle.font = .systemFont(ofSize: 15, weight: .medium)
        swTitle.translatesAutoresizingMaskIntoConstraints = false
        autoSwitch.isOn = LocationSyncEngine.shared.autoSyncOnNetworkChange
        autoSwitch.addTarget(self, action: #selector(toggleAutoSync), for: .valueChanged)
        autoSwitch.translatesAutoresizingMaskIntoConstraints = false
        switchRow.addSubview(swTitle)
        switchRow.addSubview(autoSwitch)

        let syncBtn = UIButton(type: .system)
        syncBtn.setTitle("立即同步当前 IP 定位与全局时区", for: .normal)
        syncBtn.titleLabel?.font = .systemFont(ofSize: 17, weight: .semibold)
        syncBtn.backgroundColor = .systemBlue
        syncBtn.setTitleColor(.white, for: .normal)
        syncBtn.layer.cornerRadius = 12
        syncBtn.addTarget(self, action: #selector(tapSyncNow), for: .touchUpInside)
        syncBtn.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(syncBtn)

        let stopBtn = UIButton(type: .system)
        stopBtn.setTitle("一键停止模拟并恢复真实定位", for: .normal)
        stopBtn.titleLabel?.font = .systemFont(ofSize: 15, weight: .medium)
        stopBtn.setTitleColor(.systemRed, for: .normal)
        stopBtn.addTarget(self, action: #selector(tapStop), for: .touchUpInside)
        stopBtn.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(stopBtn)

        NSLayoutConstraint.activate([
            titleLbl.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 20),
            titleLbl.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 20),

            card.topAnchor.constraint(equalTo: titleLbl.bottomAnchor, constant: 18),
            card.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 16),
            card.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -16),

            stack.topAnchor.constraint(equalTo: card.topAnchor, constant: 16),
            stack.bottomAnchor.constraint(equalTo: card.bottomAnchor, constant: -16),
            stack.leadingAnchor.constraint(equalTo: card.leadingAnchor, constant: 16),
            stack.trailingAnchor.constraint(equalTo: card.trailingAnchor, constant: -16),

            switchRow.topAnchor.constraint(equalTo: card.bottomAnchor, constant: 16),
            switchRow.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 16),
            switchRow.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -16),
            switchRow.heightAnchor.constraint(equalToConstant: 54),

            swTitle.centerYAnchor.constraint(equalTo: switchRow.centerYAnchor),
            swTitle.leadingAnchor.constraint(equalTo: switchRow.leadingAnchor, constant: 16),
            autoSwitch.centerYAnchor.constraint(equalTo: switchRow.centerYAnchor),
            autoSwitch.trailingAnchor.constraint(equalTo: switchRow.trailingAnchor, constant: -16),

            syncBtn.topAnchor.constraint(equalTo: switchRow.bottomAnchor, constant: 24),
            syncBtn.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 16),
            syncBtn.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -16),
            syncBtn.heightAnchor.constraint(equalToConstant: 50),

            stopBtn.topAnchor.constraint(equalTo: syncBtn.bottomAnchor, constant: 14),
            stopBtn.centerXAnchor.constraint(equalTo: view.centerXAnchor)
        ])
    }

    private func refreshUI() {
        let eng = LocationSyncEngine.shared
        statusLabel.text = eng.isSimulating ? "✅ 正在同步定位与系统全局时区" : "⏹ 已停止模拟"
        ipLabel.text = "出口 IP: \(eng.currentIP)"
        let tzTag = eng.tzSyncedSuccess ? "(系统全局已生效)" : "(待同步)"
        tzLabel.text = "全局时区: \(eng.currentTZ) \(tzTag)"
        coordLabel.text = "模拟坐标: \(eng.currentCity) (\(String(format: "%.4f", eng.baseLat)), \(String(format: "%.4f", eng.baseLon)))"
    }

    @objc private func toggleAutoSync() {
        LocationSyncEngine.shared.autoSyncOnNetworkChange = autoSwitch.isOn
    }

    @objc private func tapSyncNow() {
        statusLabel.text = "⏳ 正在查询 IP 并同步时区..."
        LocationSyncEngine.shared.syncWithCurrentIP()
    }

    @objc private func tapStop() {
        LocationSyncEngine.shared.stopSimulation()
    }
}

// MARK: - 5. AppDelegate 入口（兼容 -parse-as-library 编译模式）
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
