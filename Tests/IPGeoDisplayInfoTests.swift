import Foundation

@main
struct IPGeoDisplayInfoTests {
    static func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
        guard condition() else {
            fatalError("IP geodata test failed: \(message)")
        }
    }

    static func parse(_ json: String, provider: String = "fixture.example") -> IPGeoDisplayInfo? {
        IPGeoDisplayInfo.parse(data: Data(json.utf8), provider: provider)
    }

    static func main() {
        let ipWho = parse("""
        {
          "ip":"8.8.8.8","success":true,"country":"United States","country_code":"US",
          "region":"California","city":"San Jose","latitude":37.336,"longitude":-121.89,
          "timezone":{"id":"America/Los_Angeles"}
        }
        """)
        expect(ipWho?.city == "San Jose", "ipwho.is city and region fields")
        expect(ipWho?.timeZoneIdentifier == "America/Los_Angeles", "nested timezone id")
        expect(ipWho?.areaDescription == "San Jose, California, United States",
               "human-readable area string")

        let ipInfo = parse("""
        {
          "ip":"1.1.1.1","country":"AU","region":"New South Wales","city":"Sydney",
          "loc":"-33.8688,151.2090","timezone":"Australia/Sydney","org":"Cloudflare"
        }
        """)
        expect(ipInfo?.latitude == -33.8688, "ipinfo loc coordinates")
        expect(ipInfo?.timeZoneIdentifier == "Australia/Sydney", "ipinfo timezone string")

        let ipSB = parse("""
        {
          "ip":"203.0.113.1","country_code":"US","country":"United States",
          "region":"California","city":"Los Angeles","latitude":34.05,"longitude":-118.24,
          "timezone":"America/Los_Angeles"
        }
        """)
        expect(ipSB?.provider == "fixture.example", "provider provenance")
        expect(ipSB?.city == "Los Angeles", "ip.sb city")
        expect(ipSB != nil, "valid IPv4 display data")

        let freeIPAPI = parse("""
        {
          "ipAddress":"1.1.1.1","countryName":"Australia","countryCode":"AU",
          "regionName":"New South Wales","cityName":"Sydney","latitude":-33.8688,
          "longitude":151.209,"timeZones":["Australia/Sydney","Australia/Perth"]
        }
        """)
        expect(freeIPAPI?.city == "Sydney", "camelCase FreeIPAPI fields")
        expect(freeIPAPI?.timeZoneIdentifier == nil,
               "multiple possible timezones must not be arbitrarily selected")

        expect(parse("""
        {"ip":"8.8.8.8","success":false}
        """) == nil, "failed provider response rejected")
        expect(parse("""
        {"ip":"not-an-ip","latitude":1,"longitude":2}
        """) == nil, "invalid IP rejected")
        expect(parse("""
        {"ip":"8.8.8.8","latitude":91,"longitude":2}
        """) == nil, "out-of-range latitude rejected")
        expect(parse("""
        {"ip":"8.8.8.8","latitude":1,"longitude":181}
        """) == nil, "out-of-range longitude rejected")

        let noUniqueZone = parse("""
        {"ip":"8.8.8.8","latitude":1,"longitude":2,
         "timeZones":["America/New_York","America/Chicago"]}
        """)
        expect(noUniqueZone?.timeZoneIdentifier == nil,
               "ambiguous timezone collection must remain unset")

        print("IP geolocation display parser tests: PASS")
    }
}
