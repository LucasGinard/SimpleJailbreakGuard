import Darwin
import Foundation
import MachO
import UIKit

enum URLSchemeProbe: Sendable {
    case available
    case notAvailable
    case notDeclared
}

protocol JailbreakRuntimeEnvironment: Sendable {
    var isSimulator: Bool { get }
    func pathExists(_ path: String) -> Bool
    func isExecutable(atPath path: String) -> Bool
    func loadedImageNames() -> [String]
    func environmentValue(forKey key: String) -> String?
    func probeURLScheme(_ scheme: String) async -> URLSchemeProbe
    func isLocalPortOpen(_ port: UInt16, timeoutMilliseconds: Int32) async -> Bool
    func canWriteOutsideSandbox() -> Bool
}

struct SystemJailbreakRuntimeEnvironment: JailbreakRuntimeEnvironment {
    var isSimulator: Bool {
        #if targetEnvironment(simulator)
        true
        #else
        false
        #endif
    }

    func pathExists(_ path: String) -> Bool {
        FileManager.default.fileExists(atPath: path) || path.withCString { access($0, F_OK) == 0 }
    }

    func isExecutable(atPath path: String) -> Bool {
        path.withCString { access($0, X_OK) == 0 }
    }

    func loadedImageNames() -> [String] {
        (0..<_dyld_image_count()).compactMap { index in
            guard let name = _dyld_get_image_name(index) else { return nil }
            return String(cString: name)
        }
    }

    func environmentValue(forKey key: String) -> String? {
        ProcessInfo.processInfo.environment[key]
    }

    func probeURLScheme(_ scheme: String) async -> URLSchemeProbe {
        let declaredSchemes = Bundle.main.object(forInfoDictionaryKey: "LSApplicationQueriesSchemes") as? [String] ?? []
        guard declaredSchemes.contains(where: { $0.caseInsensitiveCompare(scheme) == .orderedSame }) else {
            return .notDeclared
        }
        guard let url = URL(string: "\(scheme)://") else { return .notAvailable }

        let canOpen = await MainActor.run {
            UIApplication.shared.canOpenURL(url)
        }
        return canOpen ? .available : .notAvailable
    }

    func isLocalPortOpen(_ port: UInt16, timeoutMilliseconds: Int32) async -> Bool {
        await Task.detached(priority: .utility) {
            Self.probeLocalPort(port, timeoutMilliseconds: timeoutMilliseconds)
        }.value
    }

    func canWriteOutsideSandbox() -> Bool {
        let path = "/private/sdk-simple-jailbreak-guard-\(UUID().uuidString)"
        let fileManager = FileManager.default
        let created = fileManager.createFile(atPath: path, contents: Data(), attributes: nil)
        guard created else { return false }
        try? fileManager.removeItem(atPath: path)
        return true
    }

    private static func probeLocalPort(_ port: UInt16, timeoutMilliseconds: Int32) -> Bool {
        let descriptor = socket(AF_INET, SOCK_STREAM, 0)
        guard descriptor >= 0 else { return false }
        defer { close(descriptor) }

        let currentFlags = fcntl(descriptor, F_GETFL, 0)
        guard currentFlags >= 0, fcntl(descriptor, F_SETFL, currentFlags | O_NONBLOCK) >= 0 else {
            return false
        }

        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = port.bigEndian
        address.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))

        let connectionResult = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }

        if connectionResult == 0 { return true }
        guard errno == EINPROGRESS else { return false }

        var pollDescriptor = pollfd(fd: descriptor, events: Int16(POLLOUT), revents: 0)
        guard poll(&pollDescriptor, 1, timeoutMilliseconds) > 0 else { return false }

        var socketError: Int32 = 0
        var socketErrorLength = socklen_t(MemoryLayout<Int32>.size)
        guard getsockopt(descriptor, SOL_SOCKET, SO_ERROR, &socketError, &socketErrorLength) == 0 else {
            return false
        }
        return socketError == 0
    }
}
