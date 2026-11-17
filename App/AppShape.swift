// AppShape.swift - the app takes the shape of the KEY's mode (17 Nov 2026).
//
// NOSTR Bluetooth (or the Wi-Fi route): home is the Nostr client. VAULT: home
// is Accounts, and the Nostr client isn't loaded. Not known yet (KEY off, not
// paired): one card that says what to do. The mode comes from the KEY's HELLO
// (KeyLife), else the last mode seen, kept across launches. Settings shows
// only what the current mode can use, with one line for the other.

import SwiftUI

enum AppMode: Equatable {
    case nostr, vault, unknown

    static func of(route: KeyRoute, paired: Bool, life: UInt8?) -> AppMode {
        if route == .wifi { return .nostr }            // VAULT mode has no Wi-Fi
        guard paired else { return .unknown }
        switch life {
        case 3: return .nostr
        case 1, 2: return .vault
        default: return .unknown
        }
    }

    var name: String {
        switch self {
        case .nostr: return "NOSTR mode"
        case .vault: return "VAULT mode"
        case .unknown: return "mode not known yet"
        }
    }

    /// One line for Settings: what the other mode adds.
    static let nostrAdds = "In NOSTR mode: the Nostr client, Route, Sign for other apps, and the vault backup."
    static let vaultAdds = "In VAULT mode: Accounts (passwords, codes, the breach check, import) and the AutoFill account list."
}

/// Home while the KEY's mode isn't known: not paired, or never seen.
struct StartHome: View {
    @ObservedObject var link: KeyLink
    var onSettings: () -> Void
    @ObservedObject private var life = KeyLife.shared
    @State private var appPaired = KeyLink.appPaired
    @Environment(\.scenePhase) private var phase

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 24) {
                    if appPaired {
                        VStack(alignment: .leading, spacing: 12) {
                            Text("Turn on your KEY").font(Brand.headline).foregroundStyle(Brand.ink)
                            Text("On the KEY, choose NOSTR or VAULT and enter that PIN. Favilla opens on the Nostr client in NOSTR Bluetooth mode, and on your accounts in VAULT mode.")
                                .font(Brand.body).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true)
                        }
                        .padding(.horizontal, 4)
                    }
                    KeyCard(link: link, appPaired: $appPaired)
                }
                .padding(20)
            }
            .background(Brand.bg.ignoresSafeArea())
            .navigationBarTitleDisplayMode(.inline)
            .toolbarBackground(Brand.bg, for: .navigationBar)
            .toolbar {
                ToolbarItem(placement: .principal) { Lockup(mark: 22, word: 15) }
                ToolbarItem(placement: .cancellationAction) {
                    Button(action: onSettings) { Image(systemName: "gearshape").font(.system(size: 17, weight: .regular)) }
                        .foregroundStyle(Brand.brass).accessibilityLabel("Settings")
                }
            }
        }
        .preferredColorScheme(.dark)
        .tint(Brand.brass)
        // Ask the KEY which mode it's in: one HELLO (FIND MY KEY) on open and on return.
        .onAppear { probe() }
        .onChange(of: phase) { _, p in if p == .active { probe() } }
        .onReceive(NotificationCenter.default.publisher(for: PairIdentity.cleared)) { _ in appPaired = false }
        .onReceive(link.$outcome) { _ in appPaired = KeyLink.appPaired }
    }

    private func probe() {
        appPaired = KeyLink.appPaired
        guard Demo.mode == nil, appPaired, life.life == nil, !link.busy else { return }
        link.probe()
    }
}
