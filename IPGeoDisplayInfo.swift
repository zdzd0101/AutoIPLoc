import Foundation
import Darwin

/// Read-only IP geolocation data for UI display. This type is separate from
/// GeoProfile and is never passed to the private location manager.
struct IPGeoDisplayInfo: Equatable {
    let ip: String
    let countryName: String?
    let countryCode: String?
    let region: String?
    let city: String?
    let latitude: Double
    let longitude: Double
    let timeZoneIdentifier: String?
    let postalCode: String?
    let provider: String

    var areaDescription: String {
        [city, region, countryName ?? countryCode]
            .compactMap { value -> String? in
                guard let value, !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                    return nil
                }
                return value
            }
            .joined(separator: ", ")
    }

    static func parse(data: Data, provider: String) -> IPGeoDisplayInfo? {
        guard let root = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
            return nil
        }
        if let success = root["success"] as? Bool, !success { return nil }
        if let status = root["status"] as? String, status.lowercased() == "fail" { return nil }
        if let valid = root["is_valid"] as? Bool, !valid { return nil }

        let payload = (root["data"] as? [String: Any]) ?? root
        let geo = (payload["geoLocation"] as? [String: Any]) ?? payload

        func string(_ keys: [String], in dictionaries: [[String: Any]]) -> String? {
            for dictionary in dictionaries {
                for key in keys {
                    if let value = dictionary[key] as? String {
                        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
                        if !trimmed.isEmpty && trimmed.lowercased() != "unknown" {
                            return trimmed
                        }
                    }
                }
            }
            return nil
        }

        let dictionaries = [geo, payload, root]
        guard let rawIP = string(["ip", "query", "ipAddress", "ip_address"], in: dictionaries),
              isIPAddress(rawIP) else {
            return nil
        }

        let rawCountryCode = string(["countryCode", "country_code"], in: dictionaries)
        let countryCode: String?
        if let rawCountryCode {
            let value = rawCountryCode.uppercased()
            if value.utf8.count == 2 &&
                value.utf8.allSatisfy({ (65...90).contains(Int($0)) }) {
                countryCode = value
            } else {
                countryCode = nil
            }
        } else {
            countryCode = nil
        }
        let countryCandidate = string(["countryName", "country_name", "country"], in: dictionaries)
        let countryName: String?
        if let countryCandidate, countryCandidate.utf8.count != 2 {
            countryName = countryCandidate
        } else {
            countryName = nil
        }

        let region = string(["regionName", "region", "region_name"], in: dictionaries)
        let city = string(["city", "cityName", "city_name"], in: dictionaries)
        let postalCode = string(["postal", "postal_code", "postal_Code", "zip", "zipCode"], in: dictionaries)

        func number(_ keys: [String]) -> Double? {
            for dictionary in dictionaries {
                for key in keys {
                    if let value = dictionary[key] as? NSNumber {
                        return value.doubleValue
                    }
                    if let value = dictionary[key] as? Double {
                        return value
                    }
                }
            }
            return nil
        }

        var coordinates: (Double, Double)?
        if let latitude = number(["latitude", "lat"]),
           let longitude = number(["longitude", "lon", "lng"]) {
            coordinates = (latitude, longitude)
        } else if let locationString = string(["loc"], in: dictionaries) {
            let parts = locationString.split(separator: ",", omittingEmptySubsequences: false)
            if parts.count == 2,
               let latitude = Double(parts[0].trimmingCharacters(in: .whitespacesAndNewlines)),
               let longitude = Double(parts[1].trimmingCharacters(in: .whitespacesAndNewlines)) {
                coordinates = (latitude, longitude)
            }
        }

        guard let (latitude, longitude) = coordinates,
              latitude.isFinite, longitude.isFinite,
              (-90.0...90.0).contains(latitude),
              (-180.0...180.0).contains(longitude) else {
            return nil
        }

        let timezoneDictionary = (payload["timezone"] as? [String: Any])
            ?? (root["timezone"] as? [String: Any])
        var rawTimezone = string(
            ["id", "time_zone", "timeZone", "timezone_id"],
            in: [timezoneDictionary ?? [:]]
        )
        if rawTimezone == nil {
            rawTimezone = string(["timezone", "time_zone", "timeZone"], in: dictionaries)
        }
        if rawTimezone == nil {
            let timezones = (payload["timeZones"] as? [String])
                ?? (payload["time_zones"] as? [String])
                ?? (root["timeZones"] as? [String])
            // Country-level APIs may list several zones. Never guess one.
            if timezones?.count == 1 {
                rawTimezone = timezones?.first
            }
        }
        let timezone = rawTimezone.flatMap { TimeZone(identifier: $0) == nil ? nil : $0 }

        return IPGeoDisplayInfo(
            ip: rawIP,
            countryName: countryName,
            countryCode: countryCode,
            region: region,
            city: city,
            latitude: latitude,
            longitude: longitude,
            timeZoneIdentifier: timezone,
            postalCode: postalCode,
            provider: provider
        )
    }

    private static func isIPAddress(_ value: String) -> Bool {
        var ipv4 = in_addr()
        if value.withCString({ inet_pton(AF_INET, $0, &ipv4) == 1 }) {
            return true
        }
        var ipv6 = in6_addr()
        return value.withCString({ inet_pton(AF_INET6, $0, &ipv6) == 1 })
    }
}
