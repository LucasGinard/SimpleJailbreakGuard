import SDKSimpleJailbreakGuard
import SwiftUI

struct ContentView: View {
    @State private var selectedProfile: ScanProfile = .all
    @State private var evaluateSimulator = false
    @State private var report: JailbreakReport?
    @State private var isScanning = false

    var body: some View {
        NavigationView {
            Form {
                Section("Configuración") {
                    Picker("Perfil", selection: $selectedProfile) {
                        ForEach(ScanProfile.allCases) { profile in
                            Text(profile.title).tag(profile)
                        }
                    }

                    Toggle("Evaluar en Simulator", isOn: $evaluateSimulator)

                    Button(isScanning ? "Analizando…" : "Ejecutar análisis") {
                        scan()
                    }
                    .disabled(isScanning)
                }

                if let report {
                    Section("Resultado") {
                        Label(
                            report.isJailbroken ? "Se detectaron indicios" : "Sin indicios detectados",
                            systemImage: report.isJailbroken ? "exclamationmark.shield.fill" : "checkmark.shield.fill"
                        )
                        .foregroundColor(report.isJailbroken ? .red : .green)
                    }

                    ForEach(report.results, id: \.check) { result in
                        Section(result.check.title) {
                            HStack {
                                Text("Estado")
                                Spacer()
                                Text(result.status.title)
                                    .foregroundColor(result.status.color)
                            }

                            ForEach(result.findings, id: \.self) { finding in
                                VStack(alignment: .leading, spacing: 4) {
                                    Text(finding.kind.title)
                                        .font(.caption)
                                        .foregroundColor(.secondary)
                                    Text(finding.indicator)
                                        .font(.system(.footnote, design: .monospaced))
                                }
                            }

                            ForEach(result.notes, id: \.self) { note in
                                Text(note)
                                    .font(.footnote)
                                    .foregroundColor(.secondary)
                            }
                        }
                    }
                }
            }
            .navigationTitle("Jailbreak Guard")
        }
        .navigationViewStyle(.stack)
    }

    private func scan() {
        isScanning = true
        report = nil

        Task {
            var configuration = selectedProfile.configuration
            configuration.simulatorPolicy = evaluateSimulator ? .evaluate : .skip
            report = await JailbreakGuard(configuration: configuration).scan()
            isScanning = false
        }
    }
}

private enum ScanProfile: String, CaseIterable, Identifiable {
    case all
    case frida
    case stores

    var id: Self { self }

    var title: String {
        switch self {
        case .all: "Todos"
        case .frida: "Solo Frida"
        case .stores: "Solo tiendas"
        }
    }

    var configuration: JailbreakGuardConfiguration {
        switch self {
        case .all: .all
        case .frida: .fridaOnly
        case .stores: .suspiciousStoresOnly
        }
    }
}

private extension JailbreakCheck {
    var title: String {
        switch self {
        case .privilegeEscalation: "Escalada de privilegios"
        case .frida: "Frida"
        case .suspiciousStores: "Tiendas sospechosas"
        case .filesystemArtifacts: "Artefactos del sistema"
        case .injectedLibraries: "Librerías inyectadas"
        case .sandboxEscape: "Integridad del sandbox"
        @unknown default: "Otro check"
        }
    }
}

private extension JailbreakCheckStatus {
    var title: String {
        switch self {
        case .detected: "Detectado"
        case .clean: "Limpio"
        case .skipped: "Omitido"
        case .unavailable: "No disponible"
        @unknown default: "Desconocido"
        }
    }

    var color: Color {
        switch self {
        case .detected: .red
        case .clean: .green
        case .skipped, .unavailable: .orange
        @unknown default: .secondary
        }
    }
}

private extension JailbreakFindingKind {
    var title: String {
        switch self {
        case .file: "Archivo"
        case .executable: "Ejecutable"
        case .urlScheme: "URL scheme"
        case .loadedLibrary: "Librería cargada"
        case .environmentVariable: "Variable de entorno"
        case .openPort: "Puerto local"
        case .sandboxViolation: "Escritura fuera del sandbox"
        @unknown default: "Otro indicio"
        }
    }
}
