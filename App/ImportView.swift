// ImportView.swift - another manager's export onto the KEY, in VAULT mode
// (KEY 11bf, firmware issue #36, 16 Nov 2026). The reading is in
// Shared/VaultImport.swift, the KEY's window in AccountsModel.runImport.
//
// One sheet, four steps: choose the export (a CSV file, or the iOS 26
// hand-over from Apple Passwords), see what goes on and what is skipped and
// why, type the passkey PIN on the KEY, watch the count. Nothing is written
// on the phone: the file is read into memory and dropped when the sheet goes.

import SwiftUI
import UniformTypeIdentifiers

struct ImportFlowView: View {
    @ObservedObject var model: AccountsModel
    /// Rows already in hand (the iOS 26 hand-over); nil: choose a file.
    var preset: (source: String, rows: [VaultImport.Row])?
    var onClose: () -> Void

    @State private var rows: [VaultImport.Row] = []
    @State private var source = ""
    @State private var plan: VaultImport.Plan?
    @State private var picking = false
    @State private var readError = ""
    @State private var listReady = false
    @State private var showSkipped = false
    @State private var showFailed = true

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                switch model.importPhase {
                case .idle: chooseOrPlan
                case .pin: pinCard
                case .sending(let done, let of): sendingCard(done, of)
                case .finished(let saved, let failed, let note): finishedCard(saved, failed, note)
                case .failed(let why): failedCard(why)
                }
            }
            .padding(20)
        }
        .background(Brand.bg.ignoresSafeArea())
        .fileImporter(isPresented: $picking, allowedContentTypes: [.commaSeparatedText, .plainText, .text, .data]) { r in read(r) }
        .onAppear {
            model.importPhase = .idle
            if let p = preset { source = p.source; rows = p.rows }
            if model.entries.isEmpty && model.busy.isEmpty { model.load() } else if model.busy.isEmpty { listReady = true }
            replan()
        }
        .onChange(of: model.busy) { _, b in if b.isEmpty && !listReady { listReady = true; replan() } }
        .onDisappear { rows = []; plan = nil; if !isRunning { model.importPhase = .idle } }
    }

    private var isRunning: Bool {
        switch model.importPhase { case .pin, .sending: return true; default: return false }
    }

    // MARK: Steps

    @ViewBuilder private var chooseOrPlan: some View {
        Text("Import from another manager").font(Brand.font(20, .semibold)).foregroundStyle(Brand.ink)
        if rows.isEmpty {
            card {
                Text("Choose the export file").font(Brand.font(17, .semibold)).foregroundStyle(Brand.ink)
                Text("A CSV export from 1Password, Bitwarden, Apple Passwords, Chrome, Edge, Firefox or KeePassXC. One-time codes in it (otpauth) come across too.")
                    .font(Brand.small).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true)
                BrandButton(title: "CHOOSE FILE") { picking = true }
                if !readError.isEmpty { Text(readError).font(Brand.small).foregroundStyle(Brand.danger).fixedSize(horizontal: false, vertical: true) }
                Text("The file is read into this app's memory only. Delete the export from Files when the import is done: it holds every password in plain text.")
                    .font(Brand.small).foregroundStyle(Brand.faint).fixedSize(horizontal: false, vertical: true)
            }
        } else if !listReady {
            card {
                Text("Reading what's on the KEY…").font(Brand.font(17, .semibold)).foregroundStyle(Brand.ink)
                Text("So nothing already there is added twice.").font(Brand.small).foregroundStyle(Brand.grey)
                ProgressView().tint(Brand.brass)
            }
        } else if model.entries.isEmpty && !model.status.isEmpty {
            card {
                Text("Import works in VAULT mode").font(Brand.font(17, .semibold)).foregroundStyle(Brand.ink)
                Text(model.status).font(Brand.small).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true)
                BrandButton(title: "TRY AGAIN", filled: false) { listReady = false; model.load() }
            }
        } else if let p = plan {
            planCards(p)
        }
    }

    @ViewBuilder private func planCards(_ p: VaultImport.Plan) -> some View {
        card {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Text("\(p.items.count)").font(Brand.font(34, .bold)).monospacedDigit().foregroundStyle(Brand.ink)
                Text("to import").font(Brand.body).foregroundStyle(Brand.grey)
            }
            Text("\(p.passwords) password\(p.passwords == 1 ? "" : "s"), \(p.codes) one-time code\(p.codes == 1 ? "" : "s"), from \(p.source)")
                .font(Brand.small).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true)
            if p.cutNotes > 0 {
                Text("\(p.cutNotes) note\(p.cutNotes == 1 ? " was" : "s were") shortened to fit the KEY.").font(Brand.small).foregroundStyle(Brand.faint)
            }
        }
        if !p.skipped.isEmpty {
            card {
                Button { showSkipped.toggle() } label: {
                    HStack {
                        Text("\(p.skipped.count) skipped").font(Brand.font(17, .semibold)).foregroundStyle(Brand.ink)
                        Spacer()
                        Image(systemName: showSkipped ? "chevron.up" : "chevron.down").font(.system(size: 13, weight: .semibold)).foregroundStyle(Brand.grey)
                    }
                }
                Text(reasonSummary(p.skipped)).font(Brand.small).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true)
                if showSkipped { itemList(p.skipped) }
            }
        }
        if p.items.isEmpty {
            BrandButton(title: "CHOOSE ANOTHER FILE", filled: false) { rows = []; plan = nil; picking = true }
        } else {
            VStack(alignment: .leading, spacing: 10) {
                BrandButton(title: "IMPORT \(p.items.count) ON THE KEY") { start(p) }
                    .disabled(!model.busy.isEmpty)
                Text("The KEY asks for your passkey PIN once, then saves each one with no press, marked imported. The KEY allows one import each time it's switched on.")
                    .font(Brand.small).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private var pinCard: some View {
        card {
            Text("Type your passkey PIN on the KEY").font(Brand.font(20, .semibold)).foregroundStyle(Brand.ink)
            Text("The KEY shows IMPORT PIN. BACK on the KEY cancels.").font(Brand.small).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true)
            ProgressView().tint(Brand.brass)
        }
    }

    private func sendingCard(_ done: Int, _ of: Int) -> some View {
        card {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Text("\(done)").font(Brand.font(34, .bold)).monospacedDigit().foregroundStyle(Brand.ink)
                Text("of \(of)").font(Brand.body).foregroundStyle(Brand.grey)
            }
            ProgressView(value: Double(done), total: Double(max(of, 1))).tint(Brand.brass)
            Text("Keep the app open and the KEY near. BACK on the KEY stops it; what's saved stays.")
                .font(Brand.small).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true)
        }
    }

    @ViewBuilder private func finishedCard(_ saved: Int, _ failed: [VaultImport.Skipped], _ note: String) -> some View {
        card {
            Text("\(saved) imported" + (failed.isEmpty ? "" : ", \(failed.count) not")).font(Brand.font(20, .semibold)).foregroundStyle(Brand.ink)
            if !note.isEmpty { Text(note).font(Brand.small).foregroundStyle(Brand.ink).fixedSize(horizontal: false, vertical: true) }
            if !failed.isEmpty { itemList(failed) }
            Text("Delete the export file from Files now: it holds your passwords in plain text.")
                .font(Brand.small).foregroundStyle(Brand.faint).fixedSize(horizontal: false, vertical: true)
        }
        BrandButton(title: "DONE") { model.importPhase = .idle; onClose() }
    }

    @ViewBuilder private func failedCard(_ why: String) -> some View {
        card {
            Text("Nothing was imported").font(Brand.font(17, .semibold)).foregroundStyle(Brand.ink)
            Text(why).font(Brand.small).foregroundStyle(Brand.ink).fixedSize(horizontal: false, vertical: true)
        }
        if plan.map({ !$0.items.isEmpty }) == true {
            BrandButton(title: "TRY AGAIN", filled: false) { model.importPhase = .idle }
        }
        BrandButton(title: "CLOSE", filled: false) { model.importPhase = .idle; onClose() }
    }

    // MARK: Pieces

    private func itemList(_ list: [VaultImport.Skipped]) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            ForEach(Array(list.prefix(200).enumerated()), id: \.offset) { _, s in
                VStack(alignment: .leading, spacing: 1) {
                    Text(s.label).font(Brand.small).foregroundStyle(Brand.ink).lineLimit(1)
                    Text(s.why).font(Brand.small).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true)
                }
            }
            if list.count > 200 { Text("and \(list.count - 200) more").font(Brand.small).foregroundStyle(Brand.faint) }
        }
    }

    private func reasonSummary(_ list: [VaultImport.Skipped]) -> String {
        var counts: [(String, Int)] = []
        for s in list {
            if let i = counts.firstIndex(where: { $0.0 == s.why }) { counts[i].1 += 1 } else { counts.append((s.why, 1)) }
        }
        return counts.map { "\($0.1) \($0.0)" }.joined(separator: ", ")
    }

    private func card<C: View>(@ViewBuilder _ c: () -> C) -> some View {
        VStack(alignment: .leading, spacing: 12) { c() }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(16)
            .background(Brand.card)
            .clipShape(RoundedRectangle(cornerRadius: 14))
    }

    // MARK: Actions

    private func read(_ r: Result<URL, Error>) {
        readError = ""
        guard case .success(let url) = r else { if case .failure(let e) = r { readError = e.localizedDescription }; return }
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        guard let d = try? Data(contentsOf: url) else { readError = "The file couldn't be opened."; return }
        let text = String(data: d, encoding: .utf8) ?? String(data: d, encoding: .utf16) ?? String(data: d, encoding: .isoLatin1) ?? ""
        guard let got = VaultImport.rows(csv: text) else {
            readError = "That doesn't look like a password export: no password column. Export as CSV from the other manager and choose that file."
            return
        }
        guard !got.rows.isEmpty else { readError = "The file has no logins in it."; return }
        source = got.source
        rows = got.rows
        replan()
    }

    private func replan() {
        guard !rows.isEmpty, listReady else { return }
        plan = VaultImport.plan(rows, source: source, onKey: VaultImport.OnKey(model.entries))
    }

    private func start(_ p: VaultImport.Plan) {
        Task {
            await model.runImport(p)
            rows = []   // the passwords are on the KEY or reported; drop the copy
        }
    }
}

/// The page's own sheet around the flow.
struct ImportSheet: View {
    @ObservedObject var model: AccountsModel
    var preset: (source: String, rows: [VaultImport.Row])? = nil
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            ImportFlowView(model: model, preset: preset) { dismiss() }
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Close") { dismiss() }.font(Brand.button).foregroundStyle(Brand.brass).disabled(running)
                    }
                }
        }
        .preferredColorScheme(.dark)
        .interactiveDismissDisabled(running)
    }

    private var running: Bool {
        switch model.importPhase { case .pin, .sending: return true; default: return false }
    }
}
