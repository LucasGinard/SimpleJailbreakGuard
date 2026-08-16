import Foundation

/// Independent signals that can be enabled for a jailbreak scan.
public enum JailbreakCheck: String, CaseIterable, Codable, Sendable {
    case privilegeEscalation
    case frida
    case suspiciousStores
    case filesystemArtifacts
    case injectedLibraries
    case sandboxEscape
}

/// Defines whether checks should run inside an iOS Simulator.
public enum SimulatorPolicy: String, Codable, Sendable {
    /// Avoids the false positives caused by files and services on the host Mac.
    case skip
    /// Runs the same checks as a physical device. Intended only for development.
    case evaluate
}

/// Configuration used by ``JailbreakGuard``.
public struct JailbreakGuardConfiguration: Sendable {
    public var enabledChecks: Set<JailbreakCheck>
    public var simulatorPolicy: SimulatorPolicy
    public var additionalPaths: [JailbreakCheck: [String]]
    public var additionalStoreSchemes: [String]
    public var fridaPorts: Set<UInt16>

    public init(
        enabledChecks: Set<JailbreakCheck> = Set(JailbreakCheck.allCases),
        simulatorPolicy: SimulatorPolicy = .skip,
        additionalPaths: [JailbreakCheck: [String]] = [:],
        additionalStoreSchemes: [String] = [],
        fridaPorts: Set<UInt16> = [27042, 27043]
    ) {
        self.enabledChecks = enabledChecks
        self.simulatorPolicy = simulatorPolicy
        self.additionalPaths = additionalPaths
        self.additionalStoreSchemes = additionalStoreSchemes
        self.fridaPorts = fridaPorts
    }

    public static var all: Self { Self() }

    public static var fridaOnly: Self {
        Self(enabledChecks: [.frida])
    }

    public static var suspiciousStoresOnly: Self {
        Self(enabledChecks: [.suspiciousStores])
    }
}

public enum JailbreakCheckStatus: String, Codable, Sendable {
    case detected
    case clean
    case skipped
    case unavailable
}

public enum JailbreakFindingKind: String, Codable, Sendable {
    case file
    case executable
    case urlScheme
    case loadedLibrary
    case environmentVariable
    case openPort
    case sandboxViolation
}

/// A concrete signal found during a scan.
public struct JailbreakFinding: Hashable, Codable, Sendable {
    public let check: JailbreakCheck
    public let kind: JailbreakFindingKind
    public let indicator: String

    public init(check: JailbreakCheck, kind: JailbreakFindingKind, indicator: String) {
        self.check = check
        self.kind = kind
        self.indicator = indicator
    }
}

/// Result for one enabled category.
public struct JailbreakCheckResult: Equatable, Codable, Sendable {
    public let check: JailbreakCheck
    public let status: JailbreakCheckStatus
    public let findings: [JailbreakFinding]
    public let notes: [String]

    public init(
        check: JailbreakCheck,
        status: JailbreakCheckStatus,
        findings: [JailbreakFinding] = [],
        notes: [String] = []
    ) {
        self.check = check
        self.status = status
        self.findings = findings
        self.notes = notes
    }
}

/// Complete, auditable output of a jailbreak scan.
public struct JailbreakReport: Equatable, Codable, Sendable {
    public let results: [JailbreakCheckResult]

    public init(results: [JailbreakCheckResult]) {
        self.results = results
    }

    public var findings: [JailbreakFinding] {
        results.flatMap(\.findings)
    }

    public var isJailbroken: Bool {
        results.contains { $0.status == .detected }
    }
}

/// Performs an offline, best-effort scan for jailbreak signals.
public struct JailbreakGuard: Sendable {
    public let configuration: JailbreakGuardConfiguration
    private let environment: any JailbreakRuntimeEnvironment

    public init(configuration: JailbreakGuardConfiguration = .all) {
        self.configuration = configuration
        self.environment = SystemJailbreakRuntimeEnvironment()
    }

    init(
        configuration: JailbreakGuardConfiguration,
        environment: any JailbreakRuntimeEnvironment
    ) {
        self.configuration = configuration
        self.environment = environment
    }

    public func scan() async -> JailbreakReport {
        await JailbreakScanner(configuration: configuration, environment: environment).scan()
    }
}
