// FavillaApp.swift - the Favilla app. It opens on the Nostr client (the KEY's
// own PWA, NostrClientView, 7 Nov 2026). Its Settings has a "This iPhone" row
// that opens the app's own screen (LinkSettingsView): how the phone reaches the
// KEY, the KEY's pairing, the opt-in account list, and the last AutoFill
// request (ThisPhoneView in SettingsPages.swift, 12 Nov 2026). The sign-in itself happens in the
// AutoFill sheet (CredentialProviderViewController).

import SwiftUI

@main
struct FavillaApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate   // push token (PushTest.swift)
    @StateObject private var link = KeyLink()
    @Environment(\.scenePhase) private var phase

    var body: some Scene {
        WindowGroup {
            RootView(link: link)
        }
        // The Bluetooth bunker listens to the relays itself while the app is open (BunkerService).
        .onChange(of: phase) { _, p in BunkerService.shared.appActive(p == .active) }
    }
}

struct RootView: View {
    @ObservedObject var link: KeyLink
    @State private var showSettings = false
    @State private var route = KeyRoute.current
    @State private var routeText = LinkSettingsView.routeText(KeyRoute.current)
    @State private var pageColour = UIColor.black
    @State private var paired = KeyLink.appPaired
    @ObservedObject private var life = KeyLife.shared
    @ObservedObject private var importer = CredentialImport.shared   // Apple Passwords > Export to another app (issue #16)
    @State private var showImport = false
    /// The door the owner picked on the home page; nil is the home page.
    @State private var door: Door? = Demo.door

    /// The KEY is behind this door (or, for NOSTR, the Wi-Fi route needs no mode).
    private func ready(_ d: Door) -> Bool {
        if Demo.mode != nil { return KeyWhere.isHere(d, Demo.life) }
        // Wi-Fi needs no mode from the KEY, unless the KEY just said VAULT (which has no Wi-Fi).
        if d == .nostr { return route == .wifi ? !life.isVault : (paired && life.shape == 3) }
        // VAULT: also when the mode isn't known yet; Accounts asks the KEY and its answer says.
        return paired && (life.shape == nil || life.shape == 1 || life.shape == 2)
    }
    private func go(_ d: Door?) { Bunker.log("app: door \(door?.rawValue ?? "home") -> \(d?.rawValue ?? "home")"); door = d }
    private var settingsMode: AppMode { door == .vault ? .vault : door == .nostr ? .nostr : mode }

    /// The app's shape follows the KEY's mode (AppShape.swift).
    private var mode: AppMode {
        if Demo.mode != nil { return AppMode.of(route: .bluetooth, paired: true, life: Demo.life) }
        return AppMode.of(route: route, paired: paired, life: life.shape)
    }

    var body: some View {
        ZStack {
            if let d = door {
                if !ready(d) {
                    SwitchPage(target: d, route: route, link: link, onHome: { go(nil) }, onSettings: { showSettings = true }).transition(.opacity)
                } else if d == .nostr {
                    nostrHome.transition(.opacity)
                } else {
                    AccountsView(home: true, onSettings: { showSettings = true }, onHome: { go(nil) },
                                 switcher: AnyView(ModeSwitcher(here: .vault, go: { go($0) }))).transition(.opacity)
                }
            } else {
                ModeHome(link: link, route: route, onSettings: { showSettings = true }, open: { go($0) }).transition(.opacity)
            }
        }
        .animation(.easeInOut(duration: 0.3), value: door)
        .animation(.easeInOut(duration: 0.3), value: door.map(ready))
        .sheet(isPresented: $showSettings, onDismiss: { routeText = LinkSettingsView.routeText(route); paired = KeyLink.appPaired }) {
            ThisPhoneView(link: link, route: $route, mode: settingsMode)
        }
        // iOS opens the app with this activity when the owner picks Favilla in
        // another password manager's export (CredentialImport.swift).
        .onContinueUserActivity(CredentialImport.activityType) { activity in
            importer.handle(activity)
            if showSettings {
                showSettings = false   // one sheet at a time: let Settings go first
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.7) { showImport = true }
            } else {
                showImport = true
            }
        }
        .sheet(isPresented: $showImport, onDismiss: { if !importer.busy { importer.discard() } }) {
            CredentialImportSheet()
        }
        .onReceive(NotificationCenter.default.publisher(for: PairIdentity.cleared)) { _ in paired = false }
        .onReceive(link.$outcome) { _ in paired = KeyLink.appPaired }
        .onChange(of: mode) { old, new in Bunker.log("app: \(old.name) -> \(new.name)") }
        .onAppear { if Demo.settings { DispatchQueue.main.asyncAfter(deadline: .now() + 1) { showSettings = true } } }
    }

    /// The Nostr client, as before: the page starts below the status bar, as the
    /// home-screen PWA does (its header has no top safe-area padding) and runs to
    /// the bottom edge with no safe-area inset, so the bottom bar sits where the
    /// home-screen PWA's does. The strip behind the status bar takes the page's
    /// background, and the status bar text follows its brightness.
    private var nostrHome: some View {
        VStack(spacing: 0) {
            // Home (the mark) and the other modes, above the client (19 Nov).
            HStack(spacing: 6) {
                Button { go(nil) } label: { EmberMark(size: 22).frame(width: 44, height: 44) }.accessibilityLabel("Home")
                ModeSwitcher(here: .nostr, go: { go($0) })
            }
            .padding(.leading, 8).padding(.trailing, 12).padding(.vertical, 6)
            .background(Brand.bg)
            NostrClientView(onOpenSettings: { showSettings = true }, onPageColour: { pageColour = $0 }, routeText: $routeText)
                .ignoresSafeArea(.container, edges: .bottom)
                .ignoresSafeArea(.keyboard)
                .background(Color(uiColor: pageColour).ignoresSafeArea(edges: .bottom))
        }
        .background(Brand.bg.ignoresSafeArea())
        .preferredColorScheme(.dark)
    }

    static func isLight(_ c: UIColor) -> Bool {
        var r: CGFloat = 0, g: CGFloat = 0, b: CGFloat = 0, a: CGFloat = 0
        c.getRed(&r, green: &g, blue: &b, alpha: &a)
        return 0.299 * r + 0.587 * g + 0.114 * b > 0.6
    }
}

/// The card at the top of This iPhone: the KEY's pairing state. Not paired
/// (fresh install, a wiped KEY, a pairing the KEY forgot): one page, one
/// instruction (issue #22 ruling, 11 Nov). Paired: the status and FIND MY KEY.
struct KeyCard: View {
    @ObservedObject var link: KeyLink
    @Binding var appPaired: Bool
    @ObservedObject private var life = KeyLife.shared

    var body: some View {
        BrandSection(title: "YOUR KEY") {
            if !appPaired {
                VStack(alignment: .leading, spacing: 12) {
                    Text("Your KEY isn't paired with this iPhone.").font(Brand.font(17, .semibold)).foregroundStyle(Brand.ink)
                    Text("On the KEY: Settings > Network > Pair a phone, then tap Pair. If iPhone asks for a number, type the one the KEY shows.")
                        .font(Brand.small).foregroundStyle(Brand.ink).fixedSize(horizontal: false, vertical: true)
                    if let code = link.appCode {
                        Text(code).font(Brand.font(30, .bold)).monospacedDigit().foregroundStyle(Brand.brass).accessibilityLabel("Code \(code)")
                        Text("On the KEY: if PAIR THE APP shows the same number, press ENTER.")
                            .font(Brand.small).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true)
                    } else if let d = KeyStatus.detail(link), link.busy || link.result != nil {
                        Text(d).font(Brand.small).foregroundStyle(link.pairing ? Brand.brass : Brand.grey).fixedSize(horizontal: false, vertical: true)
                    }
                    BrandButton(title: link.busy ? "CANCEL" : "PAIR", filled: !link.busy) {
                        link.busy ? link.cancel() : link.pairApp()
                    }
                }
                .padding(16)
                .background(Brand.card)
                .clipShape(RoundedRectangle(cornerRadius: 14))
            } else {
                VStack(alignment: .leading, spacing: 12) {
                    HStack(alignment: .firstTextBaseline) {
                        Text(KeyStatus.headline(link)).font(Brand.font(17, .semibold)).foregroundStyle(Brand.ink)
                        Spacer()
                        Text(life.life != nil ? "Paired · " + KeyLife.name(life.life) : life.lastSeen != nil ? "Paired · last seen in " + KeyLife.name(life.lastSeen) : "Paired").font(Brand.small).foregroundStyle(Brand.brass)
                    }
                    if let d = KeyStatus.detail(link) {
                        Text(d).font(Brand.small).foregroundStyle(link.pairing ? Brand.brass : Brand.grey).fixedSize(horizontal: false, vertical: true)
                    }
                    BrandButton(title: link.busy ? "CANCEL" : "FIND MY KEY", filled: false) {
                        link.busy ? link.cancel() : link.probe()
                    }
                    Text("Passwords, passkeys, one-time codes and the account list go over the app's own locked channel. Other apps on this iPhone can't ask the KEY for anything.")
                        .font(Brand.small).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true)
                    Button {
                        link.forgetApp(); appPaired = false
                    } label: {
                        Text("Forget the app's pairing").font(Brand.body).foregroundStyle(Brand.danger).frame(minHeight: 44)
                    }
                }
                .padding(16)
                .background(Brand.card)
                .clipShape(RoundedRectangle(cornerRadius: 14))
            }
        }
        .onReceive(link.$outcome) { _ in appPaired = KeyLink.appPaired }   // also catches a pairing the KEY forgot (0x08)
    }
}

private struct BrandSection<Content: View>: View {
    let title: String
    @ViewBuilder let content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(title).font(Brand.label).tracking(2).foregroundStyle(Brand.brass)
            content
        }
    }
}
