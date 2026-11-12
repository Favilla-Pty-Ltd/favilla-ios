// VaultSettings.swift - the vault courier's app side: the KEY's asks on a nudge,
// the buttons, the card in Settings > This iPhone (10 Nov 2026).

import Foundation
import SwiftUI
import UIKit

@MainActor
final class VaultService: ObservableObject {
    static let shared = VaultService()
    @Published private(set) var info: Vault.Info?
    @Published private(set) var busy = ""        // what's running, or empty
    @Published private(set) var status = ""
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
        note((backup ? "backup" : "restore") + " started (\(why))")
        let bg = UIApplication.shared.beginBackgroundTask(withName: "vault") {}
        Task {
            defer { busy = ""; UIApplication.shared.endBackgroundTask(bg) }
            let out = backup ? await Vault.backup(NostrLink.shared, log: { [weak self] s in Task { @MainActor in self?.note(s) } })
                             : await Vault.restoreOnly(NostrLink.shared, log: { [weak self] s in Task { @MainActor in self?.note(s) } })
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

