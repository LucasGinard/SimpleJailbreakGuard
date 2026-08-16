import Foundation

struct JailbreakScanner: Sendable {
    let configuration: JailbreakGuardConfiguration
    let environment: any JailbreakRuntimeEnvironment

    func scan() async -> JailbreakReport {
        let checks = JailbreakCheck.allCases.filter(configuration.enabledChecks.contains)

        if environment.isSimulator && configuration.simulatorPolicy == .skip {
            return JailbreakReport(results: checks.map {
                JailbreakCheckResult(
                    check: $0,
                    status: .skipped,
                    notes: ["Simulator evaluation is disabled by configuration."]
                )
            })
        }

        var results: [JailbreakCheckResult] = []
        for check in checks {
            switch check {
            case .privilegeEscalation:
                results.append(privilegeEscalationResult())
            case .frida:
                results.append(await fridaResult())
            case .suspiciousStores:
                results.append(await suspiciousStoresResult())
            case .filesystemArtifacts:
                results.append(filesystemArtifactsResult())
            case .injectedLibraries:
                results.append(injectedLibrariesResult())
            case .sandboxEscape:
                results.append(sandboxEscapeResult())
            }
        }

        return JailbreakReport(results: results)
    }

    private func privilegeEscalationResult() -> JailbreakCheckResult {
        let paths = Indicators.privilegeEscalationPaths + configuration.additionalPaths[.privilegeEscalation, default: []]
        let findings = unique(paths).compactMap { path -> JailbreakFinding? in
            guard environment.isExecutable(atPath: path) || environment.pathExists(path) else { return nil }
            return JailbreakFinding(check: .privilegeEscalation, kind: .executable, indicator: path)
        }
        return result(for: .privilegeEscalation, findings: findings)
    }

    private func fridaResult() async -> JailbreakCheckResult {
        var findings = unique(Indicators.fridaPaths + configuration.additionalPaths[.frida, default: []]).compactMap {
            environment.pathExists($0)
                ? JailbreakFinding(check: .frida, kind: .file, indicator: $0)
                : nil
        }

        findings += matchingLoadedLibraries(
            check: .frida,
            markers: Indicators.fridaLibraryMarkers
        )

        for key in Indicators.fridaEnvironmentKeys where environment.environmentValue(forKey: key) != nil {
            findings.append(
                JailbreakFinding(check: .frida, kind: .environmentVariable, indicator: key)
            )
        }

        for port in configuration.fridaPorts.sorted() {
            if await environment.isLocalPortOpen(port, timeoutMilliseconds: 150) {
                findings.append(
                    JailbreakFinding(check: .frida, kind: .openPort, indicator: "127.0.0.1:\(port)")
                )
            }
        }

        return result(for: .frida, findings: findings)
    }

    private func suspiciousStoresResult() async -> JailbreakCheckResult {
        var findings = unique(Indicators.suspiciousStorePaths + configuration.additionalPaths[.suspiciousStores, default: []]).compactMap {
            environment.pathExists($0)
                ? JailbreakFinding(check: .suspiciousStores, kind: .file, indicator: $0)
                : nil
        }

        let schemes = unique(Indicators.suspiciousStoreSchemes + configuration.additionalStoreSchemes)
        var declaredSchemeCount = 0
        var undeclaredSchemes: [String] = []

        for scheme in schemes {
            switch await environment.probeURLScheme(scheme) {
            case .available:
                declaredSchemeCount += 1
                findings.append(
                    JailbreakFinding(check: .suspiciousStores, kind: .urlScheme, indicator: scheme)
                )
            case .notAvailable:
                declaredSchemeCount += 1
            case .notDeclared:
                undeclaredSchemes.append(scheme)
            }
        }

        if !findings.isEmpty {
            return result(for: .suspiciousStores, findings: findings)
        }
        if declaredSchemeCount == 0 && !schemes.isEmpty {
            return JailbreakCheckResult(
                check: .suspiciousStores,
                status: .unavailable,
                notes: ["Declare the URL schemes in LSApplicationQueriesSchemes: \(undeclaredSchemes.joined(separator: ", "))."]
            )
        }

        let notes = undeclaredSchemes.isEmpty
            ? []
            : ["Some URL schemes were not declared: \(undeclaredSchemes.joined(separator: ", "))."]
        return JailbreakCheckResult(check: .suspiciousStores, status: .clean, notes: notes)
    }

    private func filesystemArtifactsResult() -> JailbreakCheckResult {
        let findings = unique(Indicators.filesystemArtifactPaths + configuration.additionalPaths[.filesystemArtifacts, default: []]).compactMap {
            environment.pathExists($0)
                ? JailbreakFinding(check: .filesystemArtifacts, kind: .file, indicator: $0)
                : nil
        }
        return result(for: .filesystemArtifacts, findings: findings)
    }

    private func injectedLibrariesResult() -> JailbreakCheckResult {
        var findings = matchingLoadedLibraries(
            check: .injectedLibraries,
            markers: Indicators.injectedLibraryMarkers
        )

        if environment.environmentValue(forKey: "DYLD_INSERT_LIBRARIES") != nil {
            findings.append(
                JailbreakFinding(
                    check: .injectedLibraries,
                    kind: .environmentVariable,
                    indicator: "DYLD_INSERT_LIBRARIES"
                )
            )
        }

        return result(for: .injectedLibraries, findings: findings)
    }

    private func sandboxEscapeResult() -> JailbreakCheckResult {
        let escaped = environment.canWriteOutsideSandbox()
        let findings = escaped
            ? [JailbreakFinding(
                check: .sandboxEscape,
                kind: .sandboxViolation,
                indicator: "/private"
            )]
            : []
        return result(for: .sandboxEscape, findings: findings)
    }

    private func matchingLoadedLibraries(
        check: JailbreakCheck,
        markers: [String]
    ) -> [JailbreakFinding] {
        let normalizedMarkers = markers.map { $0.lowercased() }
        return environment.loadedImageNames().compactMap { image in
            let normalizedImage = image.lowercased()
            guard normalizedMarkers.contains(where: normalizedImage.contains) else { return nil }
            return JailbreakFinding(check: check, kind: .loadedLibrary, indicator: image)
        }
    }

    private func result(
        for check: JailbreakCheck,
        findings: [JailbreakFinding]
    ) -> JailbreakCheckResult {
        JailbreakCheckResult(
            check: check,
            status: findings.isEmpty ? .clean : .detected,
            findings: findings
        )
    }

    private func unique(_ values: [String]) -> [String] {
        var seen = Set<String>()
        return values.filter { seen.insert($0).inserted }
    }
}

private enum Indicators {
    static let privilegeEscalationPaths = [
        "/bin/su",
        "/usr/bin/su",
        "/usr/bin/sudo",
        "/usr/local/bin/sudo",
        "/var/jb/usr/bin/su",
        "/var/jb/usr/bin/sudo",
        "/var/jb/bin/bash",
        "/var/jb/bin/zsh"
    ]

    static let fridaPaths = [
        "/usr/sbin/frida-server",
        "/usr/bin/frida-server",
        "/usr/local/bin/frida-server",
        "/var/jb/usr/sbin/frida-server",
        "/var/jb/usr/bin/frida-server",
        "/Library/LaunchDaemons/re.frida.server.plist",
        "/var/jb/Library/LaunchDaemons/re.frida.server.plist",
        "/usr/lib/frida/frida-agent.dylib"
    ]

    static let fridaLibraryMarkers = [
        "fridagadget",
        "frida-agent",
        "libfrida",
        "gadget.dylib"
    ]

    static let fridaEnvironmentKeys = [
        "FRIDA_LD_PRELOAD",
        "FRIDA_GADGET_CONFIG",
        "FRIDA_SCRIPT_RUNTIME"
    ]

    static let suspiciousStorePaths = [
        "/Applications/Cydia.app",
        "/Applications/Sileo.app",
        "/Applications/Zebra.app",
        "/Applications/Installer.app",
        "/Applications/Saily.app",
        "/var/jb/Applications/Sileo.app",
        "/var/jb/Applications/Zebra.app"
    ]

    static let suspiciousStoreSchemes = [
        "cydia",
        "sileo",
        "zbra",
        "installer",
        "saily"
    ]

    static let filesystemArtifactPaths = [
        "/var/jb",
        "/.installed_unc0ver",
        "/.bootstrapped_electra",
        "/private/var/lib/apt",
        "/private/var/lib/dpkg",
        "/private/var/stash",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/usr/lib/libsubstitute.dylib",
        "/usr/lib/libhooker.dylib",
        "/usr/libexec/ssh-keysign",
        "/usr/sbin/sshd",
        "/etc/apt",
        "/var/lib/dpkg/status"
    ]

    static let injectedLibraryMarkers = [
        "mobilesubstrate",
        "substrateloader",
        "substitute",
        "libhooker",
        "ellekit",
        "tweakinject"
    ]
}
