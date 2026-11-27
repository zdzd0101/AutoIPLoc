import Foundation

/// Builds candidate Hook file paths without assuming that the first .jbroot
/// directory is the active RootHide root. Existing files are checked by caller.
enum HookInstallResolver {
    static func candidatePaths(
        savedRootList: String?,
        discoveredRootNames: [String],
        baseDirectory: String,
        hookRelativePath: String,
        legacyPath: String,
        legacyPathExists: Bool
    ) -> [String] {
        let normalizedBase = baseDirectory.hasSuffix("/")
            ? String(baseDirectory.dropLast())
            : baseDirectory
        let rootPrefix = normalizedBase + "/"
        var roots = Set<String>()

        func addRootPath(_ rawPath: String) {
            let path = rawPath.trimmingCharacters(in: .whitespacesAndNewlines)
            guard path.hasPrefix(rootPrefix) else { return }
            let component = String(path.dropFirst(rootPrefix.count))
            guard component.hasPrefix(".jbroot-"),
                  component.count > ".jbroot-".count,
                  !component.contains("/"),
                  component != "." && component != ".." else {
                return
            }
            roots.insert(rootPrefix + component)
        }

        if let savedRootList {
            for rawPath in savedRootList.split(whereSeparator: \.isNewline) {
                addRootPath(String(rawPath))
            }
        }

        for name in discoveredRootNames where name.hasPrefix(".jbroot-") {
            addRootPath(rootPrefix + name)
        }

        let relative = hookRelativePath.hasPrefix("/")
            ? hookRelativePath
            : "/" + hookRelativePath
        var candidates = roots.map { $0 + relative }

        if legacyPathExists {
            candidates.append(legacyPath)
        }

        return Array(Set(candidates)).sorted()
    }
}
