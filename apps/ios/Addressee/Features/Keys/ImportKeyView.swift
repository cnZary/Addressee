import SwiftUI
import UniformTypeIdentifiers

struct ImportKeyView: View {
    enum ImportMode: String, CaseIterable, Identifiable {
        case publicKey
        case privateKey

        var id: String { rawValue }
        var title: LocalizedStringKey {
            switch self {
            case .publicKey: "keys.import.public"
            case .privateKey: "keys.import.private"
            }
        }
    }

    @Environment(\.dismiss) private var dismiss
    @ObservedObject var model: OpenPgpApplicationModel

    @State private var mode: ImportMode = .publicKey
    @State private var armoredInput = ""
    @State private var selectedFile: URL?
    @State private var fileData: Data?
    @State private var showFileImporter = false
    @State private var currentPassword = ""
    @State private var newPassword = ""
    @State private var allowExport = false

    var body: some View {
        Form {
            Section("keys.import.source") {
                Picker("keys.import.mode", selection: $mode) {
                    ForEach(ImportMode.allCases) { mode in
                        Text(mode.title).tag(mode)
                    }
                }
                .pickerStyle(.segmented)
                .accessibilityIdentifier("field.keys.importMode")
                Button("keys.import.file") {
                    showFileImporter = true
                }
                .buttonStyle(.bordered)
                .accessibilityIdentifier("action.keys.import.file")
                if let selectedFile {
                    Text(selectedFile.lastPathComponent)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
                LongTextEditor(
                    text: $armoredInput,
                    identifier: "field.keys.importArmored",
                    minHeight: 180
                )
            }

            if mode == .privateKey {
                Section("keys.import.privateProtection") {
                    SecureField("keys.import.currentPassword", text: $currentPassword)
                        .textContentType(.password)
                        .accessibilityIdentifier("field.keys.importCurrentPassword")
                    SecureField("keys.import.newPassword", text: $newPassword)
                        .textContentType(.password)
                        .accessibilityIdentifier("field.keys.importNewPassword")
                    Toggle("generation.allowPrivateExport", isOn: $allowExport)
                        .accessibilityIdentifier("field.keys.importAllowExport")
                    Text("keys.import.protectionNote")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }

            Section {
                Button("action.keys.import") {
                    Task { await performImport() }
                }
                .buttonStyle(.borderedProminent)
                .disabled(!canImport || model.isBusy)
                .accessibilityIdentifier("action.keys.import.confirm")
            }
            if model.isBusy {
                ProgressView("operation.inProgress")
            }
            if let errorMessage = model.errorMessage {
                Text(errorMessage)
                    .foregroundStyle(.red)
            }
        }
        .navigationTitle("keys.import.title")
        .navigationBarTitleDisplayMode(.inline)
        .accessibilityIdentifier("screen.keys.import")
        .dismissKeyboard()
        .onChange(of: armoredInput) { _ in
            selectedFile = nil
            fileData = nil
        }
        .onAppear {
            allowExport = model.allowsSoftwareExportByDefault
        }
        .fileImporter(
            isPresented: $showFileImporter,
            allowedContentTypes: [.data, .text],
            allowsMultipleSelection: false
        ) { result in
            switch result {
            case .success(let urls):
                guard let url = urls.first else { return }
                selectedFile = url
                Task { await loadFile(url) }
            case .failure(let error):
                model.errorMessage = ErrorPresenter.message(for: error)
            }
        }
    }

    private var canImport: Bool {
        (fileData != nil || !armoredInput.isEmpty)
            && (mode == .publicKey || !newPassword.isEmpty)
    }

    private func loadFile(_ url: URL) async {
        do {
            fileData = try await FileInput.readData(from: url)
        } catch {
            model.errorMessage = ErrorPresenter.message(for: error)
        }
    }

    private func performImport() async {
        do {
            let input = fileData ?? Data(armoredInput.utf8)
            if mode == .publicKey {
                _ = try await model.importPublic(input)
            } else {
                _ = try await model.importPrivate(
                    input,
                    currentPassword: currentPassword.isEmpty ? nil : currentPassword,
                    newPassword: newPassword,
                    exportPolicy: allowExport ? .allowed : .disabled
                )
            }
            dismiss()
        } catch {}
    }
}
