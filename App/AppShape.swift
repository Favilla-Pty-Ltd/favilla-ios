// AppShape.swift - the app's shape: a home page of modes (19 Nov 2026; before
// that, 17 Nov, the KEY's mode picked the screen).
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

// MARK: - The mode home (19 Nov 2026)
//
// The app opens on a home page with a door per mode: NOSTR, VAULT, and
// BITCOIN later. The owner picks; the KEY's mode (KeyLife) marks which door the
// KEY is behind and finishes a hand-over, but no longer picks the screen. A
// door the KEY isn't behind opens a page of what to do on the KEY, which moves
// on by itself when the KEY arrives. Inside a mode, a switcher across the top
// goes straight to the others.

enum Door: String, Equatable {
    case nostr, vault
    var title: String { self == .nostr ? "NOSTR" : "VAULT" }
}

/// NOSTR | VAULT | BITCOIN across the top of a mode.
struct ModeSwitcher: View {
    let here: Door
    let go: (Door) -> Void

    var body: some View {
        HStack(spacing: 4) {
            segment(.nostr)
            segment(.vault)
            Text("BITCOIN").font(Brand.font(12, .semibold)).tracking(1.5).foregroundStyle(Brand.faint)
                .frame(maxWidth: .infinity, minHeight: 40)
                .accessibilityLabel("Bitcoin, later")
        }
        .padding(4)
        .background(Brand.card)
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }

    private func segment(_ d: Door) -> some View {
        Button { if d != here { go(d) } } label: {
            Text(d.title).font(Brand.font(12, d == here ? .bold : .semibold)).tracking(1.5)
                .foregroundStyle(d == here ? Brand.bg : Brand.grey)
                .frame(maxWidth: .infinity, minHeight: 40)
                .background(d == here ? Brand.brass : Color.clear)
                .clipShape(RoundedRectangle(cornerRadius: 9))
                .contentShape(Rectangle())
        }
        .accessibilityAddTraits(d == here ? .isSelected : [])
    }
}

/// Where the KEY is, for the home page and the hand-over.
enum KeyWhere {
    static func live(_ life: KeyLife) -> UInt8? { Demo.mode != nil ? Demo.life : life.life }
    static func last(_ life: KeyLife) -> UInt8? { Demo.mode != nil ? Demo.life : life.shape }
    static func isHere(_ d: Door, _ l: UInt8?) -> Bool { d == .vault ? (l == 1 || l == 2) : l == 3 }
}

/// Home: a door per mode.
struct ModeHome: View {
    @ObservedObject var link: KeyLink
    var route: KeyRoute
    var onSettings: () -> Void
    var open: (Door) -> Void
    @ObservedObject private var life = KeyLife.shared
    @State private var appPaired = KeyLink.appPaired
    @Environment(\.scenePhase) private var phase

    private var statusLine: String {
        guard appPaired else { return "Your KEY isn't paired with this iPhone yet" }
        if let l = KeyWhere.live(life) { return "Your KEY is in " + KeyLife.name(l) }
        if let l = life.lastSeen { return "KEY not connected · last seen in " + KeyLife.name(l) }
        return "KEY not found yet"
    }

    private func tag(_ d: Door) -> (String, Bool)? {
        let l = KeyWhere.live(life)
        if KeyWhere.isHere(d, l) { return ("KEY IS HERE", true) }
        if l == 1 || l == 2 || l == 3 { return ("SWITCH THE KEY", false) }   // VAULT mode has no Wi-Fi
        if d == .nostr, route == .wifi { return ("OVER WI-FI", false) }
        return nil
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Where to?").font(Brand.headline).foregroundStyle(Brand.ink)
                        HStack(spacing: 8) {
                            Circle().fill(KeyWhere.live(life) != nil ? Brand.brass : Brand.faint).frame(width: 8, height: 8)
                            Text(statusLine).font(Brand.small).foregroundStyle(Brand.grey)
                        }
                    }
                    .padding(.horizontal, 4)
                    VStack(spacing: 12) {
                        card(.vault, "Passwords, passkeys and one-time codes. Sign in to sites and apps with a press on the KEY.")
                        card(.nostr, "Notes, messages and secure chat, signed by the KEY. Sign for other Nostr apps too.")
                        VStack(alignment: .leading, spacing: 10) {
                            HStack {
                                Text("BITCOIN").font(Brand.font(19, .bold)).tracking(2).foregroundStyle(Brand.grey)
                                Spacer()
                                Text("LATER").font(Brand.label).tracking(2).foregroundStyle(Brand.grey)
                            }
                            Text("A wallet on the phone that the KEY signs for. Not built yet.")
                                .font(Brand.body).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true)
                        }
                        .padding(18)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .overlay(RoundedRectangle(cornerRadius: 14).stroke(Brand.line, style: StrokeStyle(lineWidth: 1, dash: [5, 4])))
                    }
                    KeyCard(link: link, appPaired: $appPaired, compact: true)
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
        // Ask the KEY which mode it's in: one HELLO on open and on return.
        .onAppear { probe() }
        .onChange(of: phase) { _, p in if p == .active { probe() } }
        .onReceive(NotificationCenter.default.publisher(for: PairIdentity.cleared)) { _ in appPaired = false }
        .onReceive(link.$outcome) { _ in appPaired = KeyLink.appPaired }
    }

    private func card(_ d: Door, _ text: String) -> some View {
        let t = tag(d)
        return Button { open(d) } label: {
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Text(d.title).font(Brand.font(19, .bold)).tracking(2).foregroundStyle(Brand.ink)
                    Spacer()
                    if let t {
                        if t.1 {
                            Text(t.0).font(Brand.label).tracking(2).foregroundStyle(Brand.bg)
                                .padding(.horizontal, 10).padding(.vertical, 4).background(Brand.brass).clipShape(Capsule())
                        } else {
                            Text(t.0).font(Brand.label).tracking(2).foregroundStyle(Brand.grey)
                        }
                    }
                }
                Text(text).font(Brand.body).foregroundStyle(Brand.grey).multilineTextAlignment(.leading).fixedSize(horizontal: false, vertical: true)
            }
            .padding(18)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Brand.card)
            .clipShape(RoundedRectangle(cornerRadius: 14))
            .overlay(RoundedRectangle(cornerRadius: 14).stroke(t?.1 == true ? Brand.brass : Brand.line, lineWidth: 1))
        }
        .buttonStyle(.plain)
    }

    private func probe() {
        appPaired = KeyLink.appPaired
        guard Demo.mode == nil, appPaired, life.life == nil, !link.busy else { return }
        link.probe()
    }
}

/// A door the KEY isn't behind: what to do on the KEY. It asks the KEY every
/// few seconds and RootView opens the mode when it arrives.
struct SwitchPage: View {
    let target: Door
    var route: KeyRoute = .bluetooth
    @ObservedObject var link: KeyLink
    var onHome: () -> Void
    var onSettings: () -> Void
    @ObservedObject private var life = KeyLife.shared
    @State private var appPaired = KeyLink.appPaired
    @State private var asked = 0

    private var from: UInt8? { KeyWhere.live(life) }
    private var steps: [String] {
        target == .vault
            ? ["Restart the KEY", "Choose VAULT", "Enter the VAULT PIN and leave it on its home screen"]
            : route == .wifi
                ? ["Restart the KEY", "Choose NOSTR and enter the NOSTR PIN"]
                : ["Restart the KEY", "Choose NOSTR and enter the NOSTR PIN", "If it isn't on Bluetooth: Settings > Network > Change mode > Bluetooth"]
    }
    private var waiting: String {
        if let l = from { return "It says " + KeyLife.name(l) + "." }
        return link.busy ? "Looking for the KEY." : "KEY not found yet."
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    VStack(alignment: .leading, spacing: 8) {
                        Text(from != nil ? "Switch your KEY to \(target.title)" : "Open \(target.title) on your KEY").font(Brand.headline).foregroundStyle(Brand.ink)
                        Text("The KEY opens one mode at a time, each behind its own PIN. Nothing to do on the phone: this page moves on by itself.")
                            .font(Brand.body).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true)
                    }
                    .padding(.horizontal, 4)
                    if appPaired {
                        VStack(alignment: .leading, spacing: 16) {
                            Text("ON THE KEY").font(Brand.label).tracking(2).foregroundStyle(Brand.brass)
                            ForEach(Array(steps.enumerated()), id: \.offset) { i, s in
                                HStack(alignment: .top, spacing: 12) {
                                    Text("\(i + 1)").font(Brand.font(13, .bold)).foregroundStyle(i == 0 ? Brand.bg : Brand.ink)
                                        .frame(width: 26, height: 26)
                                        .background(i == 0 ? Brand.brass : Color.clear).clipShape(Circle())
                                        .overlay(Circle().stroke(i == 0 ? Color.clear : Brand.grey, lineWidth: 1))
                                    Text(s).font(Brand.body).foregroundStyle(Brand.ink).fixedSize(horizontal: false, vertical: true).padding(.top, 3)
                                }
                            }
                        }
                        .padding(20)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(Brand.card)
                        .clipShape(RoundedRectangle(cornerRadius: 14))
                        HStack(spacing: 12) {
                            ProgressView().tint(Brand.brass)
                            VStack(alignment: .leading, spacing: 2) {
                                Text("Waiting for the KEY in \(target.title) mode").font(Brand.font(15, .semibold)).foregroundStyle(Brand.ink)
                                Text(waiting).font(Brand.small).foregroundStyle(Brand.grey)
                            }
                        }
                        .padding(.horizontal, 4)
                    } else {
                        KeyCard(link: link, appPaired: $appPaired)
                    }
                    BrandButton(title: "HOME", filled: false, action: onHome)
                }
                .padding(20)
            }
            .background(Brand.bg.ignoresSafeArea())
            .navigationBarTitleDisplayMode(.inline)
            .toolbarBackground(Brand.bg, for: .navigationBar)
            .toolbar {
                ToolbarItem(placement: .principal) { Button(action: onHome) { Lockup(mark: 22, word: 15) }.accessibilityLabel("Home") }
                ToolbarItem(placement: .cancellationAction) {
                    Button(action: onSettings) { Image(systemName: "gearshape").font(.system(size: 17, weight: .regular)) }
                        .foregroundStyle(Brand.brass).accessibilityLabel("Settings")
                }
            }
        }
        .preferredColorScheme(.dark)
        .tint(Brand.brass)
        .task {
            // One HELLO every 10 s while this page shows; the answer carries the mode.
            while !Task.isCancelled {
                appPaired = KeyLink.appPaired
                if Demo.mode == nil, appPaired, !link.busy { link.probe(); asked += 1 }
                try? await Task.sleep(nanoseconds: 10_000_000_000)
            }
        }
        .onReceive(NotificationCenter.default.publisher(for: PairIdentity.cleared)) { _ in appPaired = false }
        .onReceive(link.$outcome) { _ in appPaired = KeyLink.appPaired }
    }
}

extension Demo {
    static var door: Door? { doorName.flatMap(Door.init(rawValue:)) }
}
