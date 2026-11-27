import Foundation

/// Strictly validates the on-disk Wi-Fi configuration schema without generating,
/// rewriting, or normalizing network identifiers.
enum WiFiConfigValidator {
    static let maximumNetworkCount = 64
    static let maximumSSIDUTF8Length = 32

    static func validatedNetworks(_ rawValue: Any?) -> [[String: String]]? {
        guard let rawNetworks = rawValue as? [Any],
              rawNetworks.count <= maximumNetworkCount else {
            return nil
        }

        var validated: [[String: String]] = []
        validated.reserveCapacity(rawNetworks.count)

        for item in rawNetworks {
            guard let entry = item as? [String: Any],
                  let ssid = entry["SSID"] as? String,
                  let bssid = entry["BSSID"] as? String,
                  isValidSSID(ssid),
                  isValidBSSID(bssid) else {
                return nil
            }
            validated.append(["SSID": ssid, "BSSID": bssid])
        }
        return validated
    }

    static func isValidSSID(_ ssid: String) -> Bool {
        let byteCount = ssid.utf8.count
        return byteCount > 0 && byteCount <= maximumSSIDUTF8Length
    }

    static func isValidBSSID(_ bssid: String) -> Bool {
        let octets = bssid.split(separator: ":", omittingEmptySubsequences: false)
        guard octets.count == 6 else { return false }

        return octets.allSatisfy { octet in
            octet.utf8.count == 2 &&
                octet.utf8.allSatisfy { byte in
                    (48...57).contains(byte) ||
                        (65...70).contains(byte) ||
                        (97...102).contains(byte)
                }
        }
    }
}
