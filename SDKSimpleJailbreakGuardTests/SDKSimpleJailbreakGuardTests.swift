import Testing
@testable import SDKSimpleJailbreakGuard

struct SDKSimpleJailbreakGuardTests {
    @Test func fridaProfileRunsOnlyFridaChecks() async {
        let environment = MockRuntimeEnvironment(
            paths: ["/Applications/Cydia.app"],
            openPorts: [27042]
        )
        let report = await JailbreakGuard(
            configuration: .fridaOnly,
            environment: environment
        ).scan()

        #expect(report.results.count == 1)
        #expect(report.results.first?.check == .frida)
        #expect(report.results.first?.status == .detected)
        #expect(report.findings.contains {
            $0.kind == .openPort && $0.indicator == "127.0.0.1:27042"
        })
        #expect(report.isJailbroken)
    }

    @Test func privilegeEscalationDetectsSudoAndSu() async {
        let environment = MockRuntimeEnvironment(
            paths: ["/usr/bin/sudo", "/var/jb/usr/bin/su"],
            executables: ["/usr/bin/sudo", "/var/jb/usr/bin/su"]
        )
        let configuration = JailbreakGuardConfiguration(
            enabledChecks: [.privilegeEscalation],
            simulatorPolicy: .evaluate
        )
        let report = await JailbreakGuard(
            configuration: configuration,
            environment: environment
        ).scan()

        #expect(report.results.first?.status == .detected)
        #expect(Set(report.findings.map(\.indicator)) == ["/usr/bin/sudo", "/var/jb/usr/bin/su"])
    }

    @Test func suspiciousStoresUsesDeclaredSchemes() async {
        let environment = MockRuntimeEnvironment(
            schemes: ["cydia": .available, "sileo": .notAvailable]
        )
        let report = await JailbreakGuard(
            configuration: .suspiciousStoresOnly,
            environment: environment
        ).scan()

        #expect(report.results.first?.status == .detected)
        #expect(report.findings == [
            JailbreakFinding(check: .suspiciousStores, kind: .urlScheme, indicator: "cydia")
        ])
    }

    @Test func storeCheckIsUnavailableWithoutDeclaredSchemes() async {
        let report = await JailbreakGuard(
            configuration: .suspiciousStoresOnly,
            environment: MockRuntimeEnvironment()
        ).scan()

        #expect(report.results.first?.status == .unavailable)
        #expect(report.results.first?.notes.isEmpty == false)
        #expect(report.isJailbroken == false)
    }

    @Test func simulatorSkipsEnabledChecksByDefault() async {
        let environment = MockRuntimeEnvironment(
            isSimulator: true,
            paths: ["/usr/bin/sudo"]
        )
        let configuration = JailbreakGuardConfiguration(enabledChecks: [.frida, .privilegeEscalation])
        let report = await JailbreakGuard(
            configuration: configuration,
            environment: environment
        ).scan()

        #expect(report.results.count == 2)
        #expect(report.results.allSatisfy { $0.status == .skipped })
        #expect(report.isJailbroken == false)
    }

    @Test func simulatorCanBeEvaluatedExplicitly() async {
        let environment = MockRuntimeEnvironment(
            isSimulator: true,
            paths: ["/usr/sbin/frida-server"]
        )
        var configuration = JailbreakGuardConfiguration.fridaOnly
        configuration.simulatorPolicy = .evaluate
        let report = await JailbreakGuard(
            configuration: configuration,
            environment: environment
        ).scan()

        #expect(report.results.first?.status == .detected)
    }

    @Test func detectsInjectedLibrariesAndEnvironment() async {
        let environment = MockRuntimeEnvironment(
            images: ["/usr/lib/ellekit/loader.dylib"],
            environment: ["DYLD_INSERT_LIBRARIES": "/tmp/injected.dylib"]
        )
        let configuration = JailbreakGuardConfiguration(
            enabledChecks: [.injectedLibraries],
            simulatorPolicy: .evaluate
        )
        let report = await JailbreakGuard(
            configuration: configuration,
            environment: environment
        ).scan()

        #expect(report.findings.count == 2)
        #expect(report.results.first?.status == .detected)
    }

    @Test func customPathsAreScopedToTheirCheck() async {
        let customPath = "/custom/frida-server"
        let environment = MockRuntimeEnvironment(paths: [customPath])
        let configuration = JailbreakGuardConfiguration(
            enabledChecks: [.frida, .filesystemArtifacts],
            simulatorPolicy: .evaluate,
            additionalPaths: [.frida: [customPath]],
            fridaPorts: []
        )
        let report = await JailbreakGuard(
            configuration: configuration,
            environment: environment
        ).scan()

        #expect(report.results.first(where: { $0.check == .frida })?.status == .detected)
        #expect(report.results.first(where: { $0.check == .filesystemArtifacts })?.status == .clean)
    }

    @Test func sandboxEscapeContributesToAggregateResult() async {
        let environment = MockRuntimeEnvironment(canEscapeSandbox: true)
        let configuration = JailbreakGuardConfiguration(
            enabledChecks: [.sandboxEscape],
            simulatorPolicy: .evaluate
        )
        let report = await JailbreakGuard(
            configuration: configuration,
            environment: environment
        ).scan()

        #expect(report.results.first?.status == .detected)
        #expect(report.isJailbroken)
    }
}

private struct MockRuntimeEnvironment: JailbreakRuntimeEnvironment {
    var isSimulator = false
    var paths: Set<String> = []
    var executables: Set<String> = []
    var images: [String] = []
    var environment: [String: String] = [:]
    var schemes: [String: URLSchemeProbe] = [:]
    var openPorts: Set<UInt16> = []
    var canEscapeSandbox = false

    func pathExists(_ path: String) -> Bool {
        paths.contains(path)
    }

    func isExecutable(atPath path: String) -> Bool {
        executables.contains(path)
    }

    func loadedImageNames() -> [String] {
        images
    }

    func environmentValue(forKey key: String) -> String? {
        environment[key]
    }

    func probeURLScheme(_ scheme: String) async -> URLSchemeProbe {
        schemes[scheme] ?? .notDeclared
    }

    func isLocalPortOpen(_ port: UInt16, timeoutMilliseconds: Int32) async -> Bool {
        openPorts.contains(port)
    }

    func canWriteOutsideSandbox() -> Bool {
        canEscapeSandbox
    }
}
