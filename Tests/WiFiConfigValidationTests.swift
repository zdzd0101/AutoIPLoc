import Foundation

@main
struct WiFiConfigValidationTests {
    static func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
        guard condition() else {
            fatalError("Wi-Fi validation test failed: \(message)")
        }
    }

    static func main() {
        let valid = [
            ["SSID": "Home WiFi", "BSSID": "20:4E:7F:67:BC:7F"],
            ["SSID": "网络", "BSSID": "00:26:f2:01:02:03"]
        ]
        expect(WiFiConfigValidator.validatedNetworks(valid) == valid,
               "valid ASCII and UTF-8 SSIDs should pass")
        expect(WiFiConfigValidator.validatedNetworks([[String: String]]()) == [],
               "an empty network list should be accepted")

        expect(WiFiConfigValidator.validatedNetworks([
            ["SSID": "", "BSSID": "20:4E:7F:67:BC:7F"]
        ]) == nil, "empty SSID must be rejected")
        expect(WiFiConfigValidator.validatedNetworks([
            ["SSID": String(repeating: "A", count: 33), "BSSID": "20:4E:7F:67:BC:7F"]
        ]) == nil, "SSID longer than 32 UTF-8 bytes must be rejected")
        expect(WiFiConfigValidator.validatedNetworks([
            ["SSID": "Valid", "BSSID": "20:4E:7F:67:BC"]
        ]) == nil, "BSSID with fewer than six octets must be rejected")
        expect(WiFiConfigValidator.validatedNetworks([
            ["SSID": "Valid", "BSSID": "20:4E:7F:67:BC:GG"]
        ]) == nil, "non-hex BSSID octet must be rejected")
        expect(WiFiConfigValidator.validatedNetworks([
            ["SSID": "Valid"]
        ]) == nil, "missing BSSID must be rejected")
        expect(WiFiConfigValidator.validatedNetworks([
            ["SSID": 123, "BSSID": "20:4E:7F:67:BC:7F"]
        ]) == nil, "wrong field type must be rejected")
        expect(WiFiConfigValidator.validatedNetworks(["not-a-dictionary"]) == nil,
               "non-dictionary network entry must be rejected")

        let tooMany = Array(repeating: valid[0], count: 65)
        expect(WiFiConfigValidator.validatedNetworks(tooMany) == nil,
               "more than 64 entries must be rejected")
        expect(WiFiConfigValidator.isValidBSSID("AA:bb:00:01:FE:ff"),
               "lowercase and uppercase hexadecimal octets should pass")
        expect(!WiFiConfigValidator.isValidBSSID("A:bb:00:01:FE:ff"),
               "one-character octet must be rejected")

        print("Wi-Fi configuration validation tests: PASS")
    }
}
