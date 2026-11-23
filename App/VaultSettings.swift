// VaultSettings.swift - the vault courier's app side: the KEY's asks on a nudge,
// the buttons, the card in Settings > This iPhone (10 Nov 2026).

import Foundation
import SwiftUI
import UIKit

/// One background task, ended once whichever comes first: the run's end or iOS's expiry.
@MainActor
final class BackgroundHold {
    var id = UIBackgroundTaskIdentifier.invalid
    func end() {
        guard id != .invalid else { return }
        UIApplication.shared.endBackgroundTask(id); id = .invalid
    }
}

@MainActor
final class VaultService: ObservableObject {
    static let shared = VaultService()
    @Published private(set) var info: Vault.Info?
    @Published private(set) var busy = ""        // what's running, or empty
    @Published private(set) var status = ""
    /// The running step, for the page (issue #59). nil when nothing runs.
    @Published private(set) var step: Vault.Step?
    /// The run that is showing: a backup or a restore.
    @Published private(set) var runIsBackup = true
    /// A good result shows for a moment, then the steps close by themselves; a failure stays.
    @Published private(set) var doneOK = false
    @Published private(set) var log: [String] = []
    private var lastAsk: (UInt8, Date)?

    private func note(_ s: String) {
        log.insert(ISO8601DateFormatter().string(from: Date()) + " " + s, at: 0)
        if log.count > 40 { log.removeLast() }
        Bunker.log("vault: " + s)
    }

    /// The KEY asked on a nudge (bit0 back up, bit1 restore). The same ask repeats
    /// every 5 s while the KEY waits; one run per ask.
    func asked(_ bits: UInt8) {
        guard busy.isEmpty else { return }
        if let (b, at) = lastAsk, b == bits, Date().timeIntervalSince(at) < 120 { return }
        lastAsk = (bits, Date())
        if bits & 1 != 0 { run(backup: true, why: "the KEY asked") } else if bits & 2 != 0 { run(backup: false, why: "the KEY asked") }
    }

    func refresh() {
        guard busy.isEmpty, Credentials.isPaired, KeyRoute.current == .bluetooth else { return }
        Task {
            do { info = try await Vault.info(NostrLink.shared) ; status = "" } catch { status = "\(error)" }
        }
    }

    func run(backup: Bool, why: String) {
        guard busy.isEmpty else { return }
        guard Credentials.isPaired, KeyRoute.current == .bluetooth else { status = "Choose Bluetooth above and pair the app first."; return }
        busy = backup ? "Backing up…" : "Restoring…"
        status = ""
        runIsBackup = backup; doneOK = false; step = .checking(0)
        // Issue #35: say whether iOS had the app in front; a KEY-started run
        // usually finds it in the background, woken by the nudge.
        let where_ = UIApplication.shared.applicationState == .active ? "foreground" : "background"
        note((backup ? "backup" : "restore") + " started (\(why), app in the \(where_))")
        // Held from the KEY's ask until VAULT_DONE is sent (or the restore ends),
        // so iOS doesn't suspend the app between VAULT_GET and VAULT_DONE.
        let bg = BackgroundHold()
        bg.id = UIApplication.shared.beginBackgroundTask(withName: "vault") { [weak self] in
            MainActor.assumeIsolated {      // iOS calls this on the main thread
                self?.note("iOS ended the background time before the \(backup ? "backup" : "restore") finished")
                bg.end()
            }
        }
        if where_ == "background" { note(String(format: "background time left: %.0f s", UIApplication.shared.backgroundTimeRemaining)) }
        Task {
            defer { busy = ""; bg.end() }
            let log: (String) -> Void = { [weak self] s in Task { @MainActor in self?.note(s) } }
            let at: (Vault.Step) -> Void = { [weak self] s in Task { @MainActor in if self?.busy.isEmpty == false { self?.step = s } } }
            let out = backup ? await Vault.backup(NostrLink.shared, log: log, step: at)
                             : await Vault.restoreOnly(NostrLink.shared, log: log, step: at)
            step = nil
            if case .failed = out {} else {
                doneOK = true
                Task { try? await Task.sleep(nanoseconds: 1_500_000_000); if self.busy.isEmpty { self.doneOK = false } }
            }
            switch out {
            case .backedUp(let i):
                info = i ?? info
                status = "Backed up to \(i?.host ?? info?.host ?? "the vault relay")."
                note("backed up")
            case .restored(let added, let removed, let result):
                status = result == 0 ? "Restored: \(added) added, \(removed) removed." : Vault.words(result)
                note("restored: result \(result), \(added) added, \(removed) removed")
                refresh()
            case .failed(let why):
                status = why
                note("failed: \(why)")
            }
        }
    }
}

