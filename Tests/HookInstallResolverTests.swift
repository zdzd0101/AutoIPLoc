import Foundation

@main
struct HookInstallResolverTests {
    static func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
        guard condition() else {
            fatalError("Hook install resolver test failed: \(message)")
        }
    }

    static func main() {
        let base = "/var/containers/Bundle/Application"
        let relative = "Library/MobileSubstrate/DynamicLibraries/AutoIPLocHook.dylib"
        let legacy = "/var/jb/Library/MobileSubstrate/DynamicLibraries/AutoIPLocHook.dylib"

        let none = HookInstallResolver.candidatePaths(
            savedRootList: nil,
            discoveredRootNames: [],
            baseDirectory: base,
            hookRelativePath: relative,
            legacyPath: legacy,
            legacyPathExists: false
        )
        expect(none.isEmpty, "no root or legacy file produces no candidates")

        let one = HookInstallResolver.candidatePaths(
            savedRootList: "\(base)/.jbroot-current\n",
            discoveredRootNames: [".jbroot-current"],
            baseDirectory: base,
            hookRelativePath: relative,
            legacyPath: legacy,
            legacyPathExists: false
        )
        expect(one == ["\(base)/.jbroot-current/\(relative)"],
               "saved and discovered same root are deduplicated")

        let multiple = HookInstallResolver.candidatePaths(
            savedRootList: "\(base)/.jbroot-old\n",
            discoveredRootNames: [".jbroot-old", ".jbroot-current"],
            baseDirectory: base,
            hookRelativePath: relative,
            legacyPath: legacy,
            legacyPathExists: false
        )
        expect(multiple.count == 2,
               "multiple RootHide roots are returned as ambiguous candidates")
        expect(multiple == multiple.sorted(), "candidate order is deterministic")

        let traversal = HookInstallResolver.candidatePaths(
            savedRootList: "\(base)/.jbroot-current/../outside\n",
            discoveredRootNames: ["../../outside", ".jbroot-valid"],
            baseDirectory: base,
            hookRelativePath: relative,
            legacyPath: legacy,
            legacyPathExists: false
        )
        expect(traversal.count == 1 && traversal[0].contains(".jbroot-valid"),
               "path traversal and non-root names are ignored")

        let legacyOnly = HookInstallResolver.candidatePaths(
            savedRootList: nil,
            discoveredRootNames: [],
            baseDirectory: base,
            hookRelativePath: relative,
            legacyPath: legacy,
            legacyPathExists: true
        )
        expect(legacyOnly == [legacy], "legacy root path is included only when it exists")

        let mixed = HookInstallResolver.candidatePaths(
            savedRootList: "\(base)/.jbroot-current\n",
            discoveredRootNames: [".jbroot-current"],
            baseDirectory: base,
            hookRelativePath: relative,
            legacyPath: legacy,
            legacyPathExists: true
        )
        expect(mixed.count == 2,
               "simultaneous rootless and legacy copies are reported as ambiguous")

        print("Hook install path resolver tests: PASS")
    }
}
