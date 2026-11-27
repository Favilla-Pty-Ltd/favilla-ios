// SettingsPages.swift - Settings > This iPhone, laid out as a settings screen
// (12 Nov 2026). One scrolling page: the KEY card, then grouped rows that
// open a page each, so nothing is crammed and each feature has room to
// explain itself where it is used.
//
//   YOUR KEY      the pairing state (KeyCard)
//   NOSTR         Route (Bluetooth or Wi-Fi), Sign for other apps (the bunker)
//   VAULT         Accounts, Keyboard bar, Backup
//   DIAGNOSTICS   Last sign-in, Bluetooth log, Bunker and calls log, Push test
//
// Type scale as Brand.swift: rows at body 15 with a 13 subtitle, section
// labels 11 tracked brass, page titles in the navigation bar.

import SwiftUI
import UIKit

// MARK: - Building blocks

/// One row: an icon on a brass tile, a title, a subtitle, a chevron.
struct SettingsRow: View {
    let icon: String
    let title: String
    var subtitle: String? = nil
    var tint: Color = Brand.brass

    var body: some View {
        HStack(spacing: 14) {
            Image(systemName: icon)
                .font(.system(size: 15, weight: .semibold))
                .foregroundStyle(tint)
                .frame(width: 32, height: 32)
                .background(tint.opacity(0.14))
                .clipShape(RoundedRectangle(cornerRadius: 8))
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(Brand.body).foregroundStyle(Brand.ink)
                if let s = subtitle, !s.isEmpty {
                    Text(s).font(Brand.small).foregroundStyle(Brand.grey).lineLimit(2)
                }
            }
            .multilineTextAlignment(.leading)
            .frame(maxWidth: .infinity, alignment: .leading)
            Spacer(minLength: 8)
            Image(systemName: "chevron.right").font(.system(size: 13, weight: .semibold)).foregroundStyle(Brand.faint)
        }
        .padding(.horizontal, 16).padding(.vertical, 12)
        .contentShape(Rectangle())
    }
}

/// A labelled card of rows with hairlines between them.
struct SettingsGroup<Content: View>: View {
    let title: String
    @ViewBuilder let content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(title).font(Brand.label).tracking(2).foregroundStyle(Brand.brass).padding(.leading, 4)
            VStack(spacing: 0) { content }
                .background(Brand.card)
                .clipShape(RoundedRectangle(cornerRadius: 14))
        }
    }
}

/// The hairline between two rows, inset past the icon.
struct RowLine: View {
    var body: some View { Divider().overlay(Brand.line).padding(.leading, 62) }
}

/// A page's chrome: the brand background, the title, 20 pt gutters.
struct SettingsPage<Content: View>: View {
    let title: String
    @ViewBuilder let content: Content

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) { content }.padding(20)
        }
        .background(Brand.bg.ignoresSafeArea())
        .navigationTitle(title)
        .navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(Brand.bg, for: .navigationBar)
    }
}

/// A card of explanation and controls on a page.
struct SettingsCard<Content: View>: View {
    @ViewBuilder let content: Content
    var body: some View {
        VStack(alignment: .leading, spacing: 12) { content }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(16)
            .background(Brand.card)
            .clipShape(RoundedRectangle(cornerRadius: 14))
    }
}

/// Explanatory copy under a card.
struct Footnote: View {
    let text: String
    init(_ t: String) { text = t }
    var body: some View {
        Text(text).font(Brand.small).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true).padding(.horizontal, 4)
    }
}

// MARK: - Pages

/// Where the Settings sheet opens (the page's "Activity log" goes straight to
/// the log), and the way back to the page's Connect apps (27 Nov: one page
/// for the bunker).
enum SettingsStart {
    static var next: SettingsDest?
    static let openConnect = Notification.Name("FavillaOpenConnectApps")
}

enum SettingsDest: Hashable {
    case route, bunker, accounts, keyboard, backup, lastRequest, bluetoothLog, bunkerLog, chatLog, pushTest
}

/// NOSTR > Route: how this iPhone reaches the KEY for the Nostr client.
struct RoutePage: View {
    @Binding var route: KeyRoute
    @ObservedObject private var nostr = NostrLink.shared
    @ObservedObject private var life = KeyLife.shared
    @State private var host = UserDefaults.standard.string(forKey: WifiTransport.hostKey) ?? ""

    var body: some View {
        SettingsPage(title: "Route") {
            SettingsCard {
                Picker("Route", selection: $route) {
                    ForEach(KeyRoute.allCases, id: \.self) { Text($0.title).tag($0) }
                }
                .pickerStyle(.segmented)
                if route == .bluetooth {
                    Text(btStatus).font(Brand.small).foregroundStyle(btStatusColour).fixedSize(horizontal: false, vertical: true)
                } else {
                    TextField("favilla-xxxxxxxx.local or 192.168.x.x", text: $host)
                        .font(Brand.body).foregroundStyle(Brand.ink)
                        .textInputAutocapitalization(.never).autocorrectionDisabled().keyboardType(.URL)
                        .padding(12).background(Brand.bg).clipShape(RoundedRectangle(cornerRadius: 10))
                        .onSubmit(saveHost)
                    if !host.isEmpty && !WifiTransport.isLocal(host) {
                        Text("That isn't a local address. Use the KEY's .local name or its 192.168 / 10. address.")
                            .font(Brand.small).foregroundStyle(Brand.danger).fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
            if route == .bluetooth {
                Footnote("On the KEY, choose NOSTR, then Settings > Network > Change mode > Bluetooth, and enter the NOSTR PIN. The KEY never starts Wi-Fi: the app reaches it over the paired Bluetooth link and reaches relays over this iPhone's own internet.")
            } else {
                Footnote("Choose NOSTR on the KEY's Select Mode screen, on the same Wi-Fi as this iPhone. The address is filled in when you pair the KEY, or type it here.")
            }
        }
        .onDisappear(perform: saveHost)
    }

    private var btStatus: String {
        guard KeyLink.appPaired else { return "Pair the app with the KEY first (the card at the top of This iPhone)." }
        if life.isVault { return NostrLink.vaultMode }
        switch nostr.state {
        case .ready: return "Connected to your KEY over Bluetooth."
        case .connecting: return "Connecting to your KEY…"
        case .failed(let why):
            if why == NostrLink.vaultWait, let w = nostr.otherLifeWait { return why + " It tries the KEY again in \(w) s." }
            return why
        case .idle: return "App paired. The link opens when the Nostr client next calls the KEY."
        }
    }

    private var btStatusColour: Color {
        if life.isVault { return Brand.grey }
        if case .failed = nostr.state { return Brand.danger }
        return KeyLink.appPaired ? Brand.brass : Brand.grey
    }

    private func saveHost() {
        let h = host.trimmingCharacters(in: .whitespaces)
        if h.isEmpty || WifiTransport.isLocal(h) { UserDefaults.standard.set(h, forKey: WifiTransport.hostKey) }
    }
}

/// NOSTR > Sign for other apps: the Bluetooth bunker.
struct BunkerPage: View {
    @ObservedObject private var b = BunkerService.shared
    @State private var showAll = false

    var body: some View {
        SettingsPage(title: "Sign for other apps") {
            SettingsCard {
                Toggle(isOn: Binding(get: { b.on }, set: { $0 ? b.turnOn() : b.turnOff() })) {
                    Text("Sign for other apps").font(Brand.body).foregroundStyle(Brand.ink)
                }
                .tint(Brand.brass)
                .disabled(b.busy)
                if !b.status.isEmpty {
                    Text(b.status).font(Brand.small).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true)
                }
                if b.on, let i = b.info {
                    Text("Relays: " + i.relays.map { $0.replacingOccurrences(of: "wss://", with: "") }.joined(separator: ", "))
                        .font(Brand.small).foregroundStyle(Brand.ink).fixedSize(horizontal: false, vertical: true)
                    Text(b.listening > 0 ? "Listening on \(b.listening) relay\(b.listening == 1 ? "" : "s") while Favilla is open." : "Favilla is closed or in the background: the push bridge wakes this iPhone.")
                        .font(Brand.small).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true)
                }
            }
            Footnote("Lets Nostr apps like Amethyst, Primal and Coracle sign with your KEY while it is in Bluetooth mode. This iPhone passes each request to the KEY over Bluetooth and sends the answer back, even with Favilla closed. Make each app's bunker link in the Nostr client: Settings > Connect apps.")
            if !b.log.isEmpty {
                BunkerLogCard(showAll: $showAll)
            }
        }
        .onAppear { b.reloadLog() }
    }
}

/// The bunker and calls log: the KEY's bunker traffic, calls, the client's own lines.
struct BunkerLogCard: View {
    @ObservedObject private var b = BunkerService.shared
    @Binding var showAll: Bool
    @State private var copied = false

    var body: some View {
        SettingsCard {
            HStack(spacing: 12) {
                Text("Log (\(b.log.count))").font(Brand.button).foregroundStyle(Brand.ink)
                Spacer()
                Button("Refresh") { b.reloadLog() }.font(Brand.button).foregroundStyle(Brand.brass)
                Button(copied ? "Copied" : "Copy") {
                    UIPasteboard.general.string = b.log.joined(separator: "\n")
                    copied = true
                    DispatchQueue.main.asyncAfter(deadline: .now() + 2) { copied = false }
                }.font(Brand.button).foregroundStyle(Brand.brass)
            }
            Text(b.log.prefix(showAll ? 120 : 8).joined(separator: "\n"))
                .font(.system(size: 11, design: .monospaced)).foregroundStyle(Brand.ink)
                .textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                .padding(10).frame(maxWidth: .infinity, alignment: .leading)
                .background(Brand.bg).clipShape(RoundedRectangle(cornerRadius: 10))
            if b.log.count > 8 {
                Button(showAll ? "Show fewer" : "Show all") { showAll.toggle() }.font(Brand.button).foregroundStyle(Brand.grey)
            }
        }
    }
}

/// VAULT > Keyboard bar: the opt-in account list iOS keeps.
struct KeyboardListPage: View {
    @ObservedObject var link: KeyLink
    @State private var listOn = AccountList.isOn
    @State private var count = AccountList.entries.count
    @State private var listNote: String?
    private var appPaired: Bool { KeyLink.appPaired }

    var body: some View {
        SettingsPage(title: "Keyboard bar") {
            SettingsCard {
                Toggle(isOn: Binding(get: { listOn }, set: { on in
                    listOn = on
                    AccountList.setOn(on) { _ in count = AccountList.entries.count }
                })) {
                    Text("Show my accounts in the keyboard bar").font(Brand.body).foregroundStyle(Brand.ink)
                }
                .tint(Brand.brass)
                if listOn {
                    Divider().overlay(Brand.line)
                    HStack {
                        Text("Accounts listed").font(Brand.body).foregroundStyle(Brand.ink)
                        Spacer()
                        Text("\(count)").font(Brand.body).foregroundStyle(Brand.grey)
                    }
                }
            }
            Footnote("iOS keeps a list of the site names and usernames you use through Favilla, so it can offer them the moment you tap a login field, and offer Favilla on a code field for sites with a one-time code on the KEY. Passwords, codes and passkeys stay on the KEY until you approve one there. Off: Favilla is one entry under the key icon, and iOS holds no account names.")
            if listOn {
                if appPaired {
                    BrandButton(title: link.busy && link.mode == .list ? "CANCEL" : "FILL THE LIST FROM MY KEY", filled: false) {
                        link.busy ? link.cancel() : link.list()
                    }
                    Footnote(listNote ?? "Only site names and usernames come over, never passwords. The list also fills as you sign in through Favilla.")
                }
                Button {
                    AccountList.setOn(false) { _ in AccountList.setOn(true) { _ in count = AccountList.entries.count } }
                } label: {
                    Text("Remove the list from this iPhone").font(Brand.body).foregroundStyle(Brand.danger)
                        .frame(maxWidth: .infinity, minHeight: 48)
                        .background(Brand.card).clipShape(RoundedRectangle(cornerRadius: 14))
                }
            }
        }
        .onReceive(link.$outcome) { o in
            switch o {
            case .list(let l)?:
                AccountList.replace(with: l) { n in
                    count = AccountList.entries.count
                    listNote = n == l.count ? "\(n) accounts from your KEY." : "\(n) of the KEY's \(l.count) accounts listed. iOS lists websites only; left out: \(AccountList.leftOutText())."
                }
            case .failed(let why)? where link.mode == .list:
                listNote = why
            default: break
            }
        }
    }
}

/// VAULT > Backup.
struct VaultPage: View {
    @ObservedObject private var v = VaultService.shared
    @State private var showLog = false
    private static let when: DateFormatter = { let f = DateFormatter(); f.dateStyle = .medium; f.timeStyle = .short; return f }()

    var body: some View {
        SettingsPage(title: "Backup") {
            SettingsCard {
                if let i = v.info {
                    Text("Last backup: " + (i.lastBackup.map { Self.when.string(from: $0) } ?? "never"))
                        .font(Brand.body).foregroundStyle(Brand.ink)
                    Text("\(i.records) record\(i.records == 1 ? "" : "s")" + (i.dirty ? " · changes since the last backup" : "") + " · relay \(i.host)")
                        .font(Brand.small).foregroundStyle(i.dirty ? Brand.brass : Brand.grey).fixedSize(horizontal: false, vertical: true)
                    if i.status != 0 { Text(Vault.words(i.status)).font(Brand.small).foregroundStyle(Brand.brass).fixedSize(horizontal: false, vertical: true) }
                } else {
                    Text("Ask the KEY for its backup state: Refresh, with the KEY in Bluetooth mode.").font(Brand.small).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true)
                }
                if !v.status.isEmpty {
                    Text(v.status).font(Brand.small).foregroundStyle(Brand.ink).fixedSize(horizontal: false, vertical: true)
                }
            }
            if v.step != nil || v.doneOK { VaultSteps(step: v.step, backup: v.runIsBackup) }
            BrandButton(title: v.busy.isEmpty ? "BACK UP NOW" : v.busy.uppercased()) { v.run(backup: true, why: "the button") }
                .disabled(!v.busy.isEmpty)
            HStack(spacing: 12) {
                BrandButton(title: "RESTORE", filled: false) { v.run(backup: false, why: "the button") }.disabled(!v.busy.isEmpty)
                BrandButton(title: "REFRESH", filled: false) { v.refresh() }.disabled(!v.busy.isEmpty)
            }
            Footnote("In Bluetooth mode the KEY backs up its passkeys and passwords through this iPhone. The KEY signs the backup and checks a restore; this iPhone only carries it to the vault relay and sees ciphertext.")
            if !v.log.isEmpty {
                Button(showLog ? "Hide log" : "Log (\(v.log.count))") { showLog.toggle() }.font(Brand.button).foregroundStyle(Brand.grey).padding(.horizontal, 4)
                if showLog { LogBox(lines: Array(v.log.prefix(40)), maxHeight: 260) }
            }
        }
        .onAppear { v.refresh() }
    }
}

/// The steps of a backup or restore, the same ones the KEY's screen shows
/// (issue #59). `step` nil = all done.
struct VaultSteps: View {
    let step: Vault.Step?
    let backup: Bool

    /// (index of the running row, its fraction when there is one)
    private var at: (Int, Double?) {
        guard let step else { return (99, nil) }
        if backup {
            switch step {
            case .checking(let f): return (0, f)
            case .merging: return (0, nil)
            case .sealing(let f): return (1, f)
            case .relay: return (2, nil)
            }
        }
        switch step {
        case .checking(let f): return (0, f)
        default: return (1, nil)
        }
    }

    private var rows: [String] {
        backup ? ["Checking the relay", "Sealed and sent", "Relay keeps it"] : ["Fetching the backup", "Checked and merged"]
    }

    var body: some View {
        let (now, part) = at
        SettingsCard {
            VStack(alignment: .leading, spacing: 14) {
                ForEach(Array(rows.enumerated()), id: \.offset) { i, text in
                    VStack(alignment: .leading, spacing: 8) {
                        StepRow(text: i == now && part != nil ? "\(text) \(Int((part! * 100).rounded()))%" : text,
                                state: i < now ? 2 : (i == now ? 1 : 0))
                        if i == now, let part { WaitBar(fraction: part).padding(.leading, 34) }
                    }
                }
            }
        }
    }
}

/// DIAGNOSTICS > Last sign-in.
struct LastRequestPage: View {
    var body: some View {
        SettingsPage(title: "Last sign-in") {
            LogBox(lines: (LastRequest.load() ?? "No request yet.").components(separatedBy: "\n"), maxHeight: 520)
                .textSelection(.enabled)
            Footnote("The steps of the last AutoFill request: what was asked, how the KEY was reached, and what it answered. Lengths and reasons only, never a password.")
        }
    }
}

/// DIAGNOSTICS > Bluetooth log.
struct BluetoothLogPage: View {
    @ObservedObject private var log = LinkLog.shared
    @State private var copied = false

    var body: some View {
        SettingsPage(title: "Bluetooth log") {
            HStack(spacing: 14) {
                BrandButton(title: copied ? "COPIED" : "COPY LOG") {
                    UIPasteboard.general.string = log.text
                    copied = true
                    DispatchQueue.main.asyncAfter(deadline: .now() + 2) { copied = false }
                }.disabled(log.lines.isEmpty)
                BrandButton(title: "CLEAR", filled: false) { log.clear() }.disabled(log.lines.isEmpty)
            }
            ScrollView([.horizontal, .vertical]) {
                Text(log.lines.suffix(400).joined(separator: "\n"))
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(Brand.ink)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: true, vertical: true)
                    .padding(12)
            }
            .frame(maxWidth: .infinity, minHeight: 200, maxHeight: 520)
            .background(Brand.card).clipShape(RoundedRectangle(cornerRadius: 14))
            Footnote("What the app's Bluetooth links did: pairing and FIND MY KEY (lines starting key:), and the Nostr client's link: connects, requests, notifications, answers and why any failed (\(log.lines.count) lines kept). No keys or message contents.")
        }
    }
}

/// DIAGNOSTICS > Bunker and calls log (the same log as on the bunker page).
struct BunkerLogPage: View {
    @State private var showAll = true
    var body: some View {
        SettingsPage(title: "Bunker and calls") {
            BunkerLogCard(showAll: $showAll)
            Footnote("Signing for other apps, incoming calls, pairing resets, and the client's own call, secure-chat and DM lines (120 kept).")
        }
        .onAppear { BunkerService.shared.reloadLog() }
    }
}

/// DIAGNOSTICS > Secure chat log: the page's own [mmx] lines, newest first.
struct ChatLogPage: View {
    @State private var lines: [String] = []
    @State private var copied = false
    private func load() { lines = (Bunker.store.stringArray(forKey: "chatLog") ?? []).reversed() }

    var body: some View {
        SettingsPage(title: "Secure chat") {
            SettingsCard {
                HStack(spacing: 12) {
                    Text("Log (\(lines.count))").font(Brand.button).foregroundStyle(Brand.ink)
                    Spacer()
                    Button("Refresh") { load() }.font(Brand.button).foregroundStyle(Brand.brass)
                    Button(copied ? "Copied" : "Copy") {
                        UIPasteboard.general.string = lines.joined(separator: "\n")
                        copied = true
                        DispatchQueue.main.asyncAfter(deadline: .now() + 2) { copied = false }
                    }.font(Brand.button).foregroundStyle(Brand.brass)
                }
                Text(lines.isEmpty ? "Nothing yet. Open NOSTR and a secure chat, then come back." : lines.joined(separator: "\n"))
                    .font(.system(size: 11, design: .monospaced)).foregroundStyle(Brand.ink)
                    .textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                    .padding(10).frame(maxWidth: .infinity, alignment: .leading)
                    .background(Brand.bg).clipShape(RoundedRectangle(cornerRadius: 10))
            }
            Footnote("What the client page says about secure chat as it runs (newest first, 120 kept). No message text; it can hold the first characters of public keys.")
        }
        .onAppear { load() }
    }
}

/// DIAGNOSTICS > Push test.
struct PushTestPage: View {
    var body: some View {
        SettingsPage(title: "Push test") { PushTestSection(titled: false) }
    }
}

// MARK: - The screen

/// Settings > This iPhone.
struct ThisPhoneView: View {
    @ObservedObject var link: KeyLink
    @Binding var route: KeyRoute
    /// The app's shape (AppShape.swift): only what this mode can use is shown.
    var mode: AppMode = .unknown
    /// The door the settings were opened from (nil: the home page), and the way
    /// to another: a second route to Home and the other mode, should the
    /// client's own NOSTR chip ever be missing.
    var door: Door? = nil
    var go: ((Door?) -> Void)? = nil
    @ObservedObject private var nostr = NostrLink.shared
    @ObservedObject private var bunker = BunkerService.shared
    @ObservedObject private var vault = VaultService.shared
    @State private var appPaired = KeyLink.appPaired
    @State private var listOn = AccountList.isOn
    @State private var listCount = AccountList.entries.count
    @Environment(\.scenePhase) private var phase
    @Environment(\.dismiss) private var dismiss
    @State private var path: [SettingsDest] = []

    var body: some View {
        NavigationStack(path: $path) {
            ScrollView {
                VStack(alignment: .leading, spacing: 24) {
                    KeyCard(link: link, appPaired: $appPaired)

                    if let door, let go {
                        let other: Door = door == .nostr ? .vault : .nostr
                        SettingsGroup(title: "MODE") {
                            Button { dismiss(); go(nil) } label: {
                                SettingsRow(icon: "square.grid.2x2", title: "Home", subtitle: "Choose NOSTR or VAULT")
                            }
                            RowLine()
                            Button { dismiss(); go(other) } label: {
                                SettingsRow(icon: "arrow.left.arrow.right", title: "Go to \(other.title)", subtitle: "You're in \(door.title) now")
                            }
                        }
                    }

                    if mode != .vault {
                        SettingsGroup(title: "NOSTR") {
                            NavigationLink(value: SettingsDest.route) {
                                SettingsRow(icon: route == .bluetooth ? "dot.radiowaves.left.and.right" : "wifi", title: "Route", subtitle: routeSubtitle)
                            }
                            if mode == .nostr {
                                RowLine()
                                // One page for the bunker: the client's Connect apps
                                // (its switch, the apps, the links). This row goes there.
                                Button {
                                    dismiss(); go?(.nostr)
                                    DispatchQueue.main.asyncAfter(deadline: .now() + 0.7) { NotificationCenter.default.post(name: SettingsStart.openConnect, object: nil) }
                                } label: {
                                    SettingsRow(icon: "signature", title: "Connect apps", subtitle: bunkerSubtitle)
                                }
                                RowLine()
                                NavigationLink(value: SettingsDest.backup) {
                                    SettingsRow(icon: "externaldrive.badge.timemachine", title: "Vault backup", subtitle: backupSubtitle)
                                }
                            }
                        }
                    }

                    if mode == .vault {
                        SettingsGroup(title: "AUTOFILL") {
                            Button {
                                if let u = URL(string: UIApplication.openSettingsURLString) { UIApplication.shared.open(u) }
                            } label: {
                                SettingsRow(icon: "key.horizontal", title: "Turn on AutoFill", subtitle: "iOS Settings > General > AutoFill & Passwords > Favilla")
                            }
                            RowLine()
                            NavigationLink(value: SettingsDest.keyboard) {
                                SettingsRow(icon: "keyboard", title: "Keyboard bar", subtitle: listOn ? "On · \(listCount) account\(listCount == 1 ? "" : "s") listed" : "Off · Favilla is one entry under the key icon")
                            }
                        }
                    }

                    SettingsGroup(title: "DIAGNOSTICS") {
                        if mode != .nostr {
                            NavigationLink(value: SettingsDest.lastRequest) {
                                SettingsRow(icon: "clock.arrow.circlepath", title: "Last sign-in", subtitle: "The steps of the last AutoFill request", tint: Brand.grey)
                            }
                            RowLine()
                        }
                        NavigationLink(value: SettingsDest.bluetoothLog) {
                            SettingsRow(icon: "list.bullet.rectangle", title: "Bluetooth log", subtitle: "\(LinkLog.shared.lines.count) lines", tint: Brand.grey)
                        }
                        if mode != .vault {
                            RowLine()
                            NavigationLink(value: SettingsDest.bunkerLog) {
                                SettingsRow(icon: "text.alignleft", title: "Bunker and calls log", subtitle: "\(bunker.log.count) lines, with the client's own", tint: Brand.grey)
                            }
                            RowLine()
                            NavigationLink(value: SettingsDest.chatLog) {
                                SettingsRow(icon: "lock.doc", title: "Secure chat log", subtitle: "The client's own secure-chat lines, last 120", tint: Brand.grey)
                            }
                            RowLine()
                            NavigationLink(value: SettingsDest.pushTest) {
                                SettingsRow(icon: "bell.badge", title: "Push test", subtitle: "Can a notification reach the KEY with Favilla closed?", tint: Brand.grey)
                            }
                        }
                    }

                    VStack(alignment: .leading, spacing: 8) {
                        switch mode {
                        case .nostr: Text(AppMode.vaultAdds).font(Brand.small).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true)
                        case .vault:
                            Text(AppMode.nostrAdds).font(Brand.small).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true)
                            Text("Back up the vault from NOSTR mode: it goes to your relay over the NOSTR Bluetooth link.").font(Brand.small).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true)
                        case .unknown:
                            Text("Turn on your KEY and choose a mode: Settings then shows what that mode can do.").font(Brand.small).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true)
                        }
                    }
                    .padding(.horizontal, 4)

                    Text("Favilla \(ThisPhoneView.version)").font(Brand.small).foregroundStyle(Brand.faint).padding(.horizontal, 4)
                }
                .padding(20)
            }
            .background(Brand.bg.ignoresSafeArea())
            .onAppear { if let s = SettingsStart.next { SettingsStart.next = nil; path = [s] } }
            .navigationDestination(for: SettingsDest.self) { d in
                switch d {
                case .route: RoutePage(route: $route)
                case .bunker: BunkerPage()
                case .accounts: AccountsView(pushed: true)
                case .keyboard: KeyboardListPage(link: link)
                case .backup: VaultPage()
                case .lastRequest: LastRequestPage()
                case .bluetoothLog: BluetoothLogPage()
                case .bunkerLog: BunkerLogPage()
                case .chatLog: ChatLogPage()
                case .pushTest: PushTestPage()
                }
            }
            .toolbar {
                ToolbarItem(placement: .principal) { Lockup(mark: 22, word: 15) }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }.font(Brand.button).foregroundStyle(Brand.brass)
                }
            }
            .toolbarBackground(Brand.bg, for: .navigationBar)
            .tint(Brand.brass)
            .onChange(of: route) { _, r in
                KeyRoute.current = r
                if r == .wifi { nostr.disconnect() }
                BunkerService.shared.refresh()
            }
            .onChange(of: phase) { _, p in if p == .active { refreshCounts() } }
            .onAppear(perform: refreshCounts)
            .onReceive(NotificationCenter.default.publisher(for: PairIdentity.cleared)) { _ in appPaired = false }
            .onReceive(link.$outcome) { _ in refreshCounts() }
        }
        .preferredColorScheme(.dark)
    }

    private func refreshCounts() {
        appPaired = KeyLink.appPaired
        listOn = AccountList.isOn
        listCount = AccountList.entries.count
    }

    private var routeSubtitle: String {
        if route == .wifi { return LinkSettingsView.routeText(.wifi) }
        switch nostr.state {
        case .ready: return "Bluetooth · connected"
        case .connecting: return "Bluetooth · connecting…"
        case .failed(let why): return "Bluetooth · " + why
        case .idle: return "Bluetooth"
        }
    }

    private var bunkerSubtitle: String {
        guard bunker.on else { return "Off" }
        if bunker.listening > 0 { return "On · listening on \(bunker.listening) relay\(bunker.listening == 1 ? "" : "s")" }
        return "On · the push bridge wakes this iPhone"
    }

    private var backupSubtitle: String {
        guard let i = vault.info else { return "Passkeys and passwords, through this iPhone to the vault relay" }
        let f = DateFormatter(); f.dateStyle = .medium; f.timeStyle = .short
        return (i.lastBackup.map { "Last backup " + f.string(from: $0) } ?? "Never backed up") + (i.dirty ? " · changes since" : "")
    }

    static var version: String {
        let v = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? ""
        let b = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? ""
        return "\(v) (\(b))"
    }
}
