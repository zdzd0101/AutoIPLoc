import SwiftUI
import CoreLocation
import Network
import AVFoundation

class LocationService: ObservableObject {
    @Published var statusText = "未启动定位模拟"
    @Published var currentIP = "-"
    @Published var locationDetail = "-"
    @Published var currentTimezone = "-"
    @Published var isAutoMode = true
    @Published var isSimulating = false
    
    private let sim = CLSimulationManager()
    private let monitor = NWPathMonitor()
    private let netQueue = DispatchQueue(label: "ip.loc.monitor")
    private var audioPlayer: AVAudioPlayer?
    private var lastIP = ""
    
    init() {
        setupBackgroundAudio()
        startNetworkWatcher()
    }
    
    private func setupBackgroundAudio() {
        try? AVAudioSession.sharedInstance().setCategory(.playback, mode: .default, options: .mixWithOthers)
        try? AVAudioSession.sharedInstance().setActive(true)
        
        var header = Data([
            0x52,0x49,0x46,0x46, 0x24,0x08,0x00,0x00, 0x57,0x41,0x56,0x45, 0x66,0x6d,0x74,0x20,
            0x10,0x00,0x00,0x00, 0x01,0x00, 0x01,0x00, 0x44,0xac,0x00,0x00, 0x88,0x58,0x01,0x00,
            0x02,0x00, 0x10,0x00, 0x64,0x61,0x74,0x61, 0x00,0x08,0x00,0x00
        ])
        header.append(Data(count: 2048))
        
        audioPlayer = try? AVAudioPlayer(data: header)
        audioPlayer?.volume = 0.0
        audioPlayer?.numberOfLoops = -1
        audioPlayer?.play()
    }
    
    private func startNetworkWatcher() {
        monitor.pathUpdateHandler = { [weak self] path in
            guard let self = self, self.isAutoMode else { return }
            if path.status == .satisfied {
                DispatchQueue.main.async { self.statusText = "检测到网络恢复，4秒后同步IP与时区..." }
                DispatchQueue.main.asyncAfter(deadline: .now() + 4.0) {
                    self.syncNow(force: false)
                }
            }
        }
        monitor.start(queue: netQueue)
    }
    
    func syncNow(force: Bool = true) {
        guard let url = URL(string: "http://ip-api.com/json/?fields=status,country,city,lat,lon,timezone,query") else { return }
        DispatchQueue.main.async { self.statusText = "正在查询当前出口 IP..." }
        
        URLSession.shared.dataTask(with: url) { [weak self] data, _, err in
            guard let self = self, let data = data, err == nil,
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  (json["status"] as? String) == "success",
                  let ip = json["query"] as? String,
                  let lat = json["lat"] as? Double,
                  let lon = json["lon"] as? Double else {
                DispatchQueue.main.async { self?.statusText = "IP 查询失败，请检查网络" }
                return
            }
            
            if !force && ip == self.lastIP && self.isSimulating {
                DispatchQueue.main.async { self.statusText = "IP 未变化，保持当前模拟定位" }
                return
            }
            
            let finalLat = lat + Double.random(in: -0.001...0.001)
            let finalLon = lon + Double.random(in: -0.001...0.001)
            
            let loc = CLLocation(
                coordinate: CLLocationCoordinate2D(latitude: finalLat, longitude: finalLon),
                altitude: Double.random(in: 10...40),
                horizontalAccuracy: 5.0,
                verticalAccuracy: 5.0,
                timestamp: Date()
            )
            
            self.sim.stopLocationSimulation()
            self.sim.clearSimulatedLocations()
            self.sim.appendSimulatedLocation(loc)
            self.sim.flush()
            self.sim.startLocationSimulation()
            
            // 自动同步系统全局时区
            let tzName = (json["timezone"] as? String) ?? "America/Los_Angeles"
            if let tz = TimeZone(identifier: tzName) {
                CFTimeZoneSetDefault(tz as CFTimeZone)
                NSTimeZone.default = tz
            }
            
            DispatchQueue.main.async {
                self.lastIP = ip
                self.currentIP = ip
                self.currentTimezone = tzName
                self.locationDetail = "\(json["country"] ?? "") · \(json["city"] ?? "") (\(String(format: "%.4f", finalLat)), \(String(format: "%.4f", finalLon)))"
                self.isSimulating = true
                self.statusText = "✅ 已同步 IP 定位与系统时区"
            }
        }.resume()
    }
    
    func stopNow() {
        sim.stopLocationSimulation()
        sim.clearSimulatedLocations()
        sim.flush()
        lastIP = ""
        DispatchQueue.main.async {
            self.isSimulating = false
            self.statusText = "⏹ 已停止模拟，恢复真实 GPS"
        }
    }
}

struct ContentView: View {
    @StateObject private var service = LocationService()
    
    var body: some View {
        NavigationView {
            Form {
                Section(header: Text("当前状态")) {
                    Text(service.statusText).font(.headline)
                    HStack { Text("出口 IP"); Spacer(); Text(service.currentIP).foregroundColor(.secondary) }
                    HStack { Text("同步时区"); Spacer(); Text(service.currentTimezone).foregroundColor(.secondary) }
                    HStack { Text("模拟坐标"); Spacer(); Text(service.locationDetail).font(.caption).foregroundColor(.secondary) }
                }
                
                Section(header: Text("自动化控制")) {
                    Toggle("开关飞行模式自动同步 IP 定位", isOn: $service.isAutoMode)
                }
                
                Section {
                    Button(action: { service.syncNow(force: true) }) {
                        HStack { Spacer(); Text("立即同步当前 IP 定位").bold(); Spacer() }
                    }
                    Button(action: { service.stopNow() }) {
                        HStack { Spacer(); Text("一键停止并恢复真实定位").foregroundColor(.red); Spacer() }
                    }
                }
            }
            .navigationTitle("IP 自动定位助手")
        }
    }
}

@main
struct AutoIPLocApp: App {
    var body: some Scene {
        WindowGroup { ContentView() }
    }
}
