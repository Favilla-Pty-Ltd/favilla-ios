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
    /// VAULT's way to the other modes: the wordmark is a menu (no banner).
    private var vaultMenu: some View {
        Menu {
            Button("NOSTR") { go(.nostr) }
            Button("Home") { go(nil) }
            Button("BITCOIN (later)") {}.disabled(true)
        } label: {
            HStack(spacing: 7) {
                Lockup(mark: 22, word: 15)
                Image(systemName: "chevron.down").font(.system(size: 10, weight: .bold)).foregroundStyle(Brand.brass)
            }
            .frame(minHeight: 44).contentShape(Rectangle())
        }
        .accessibilityLabel("Favilla KEY, VAULT mode. Switch mode")
    }
    @State private var showModes = false
    @State private var nativeChip = false       // bridge.js found no place for its chip in the page

    // The Nostr client keeps running under Home and VAULT once it has been
    // opened (21 Nov): going Home and back no longer loads the page again
    // (every load redials each relay and decrypts the messages afresh). It is
    // started anew if the KEY went to VAULT mode meanwhile, and let go after
    // ten minutes out of sight.
    @State private var clientAlive = false
    @State private var clientRun = 0            // a new number is a new web view
    @State private var clientStale = false      // the KEY was seen in VAULT mode since the client started
    @State private var clientHiddenAt: Date?
    private var showClient: Bool { door == .nostr && ready(.nostr) }
    private func go(_ d: Door?) {
        Bunker.log("app: door \(door?.rawValue ?? "home") -> \(d?.rawValue ?? "home")")
        if let d { UserDefaults.standard.set(d.rawValue, forKey: "lastDoor") }
        door = d
    }
    private var settingsMode: AppMode { door == .vault ? .vault : door == .nostr ? .nostr : mode }

    /// The app's shape follows the KEY's mode (AppShape.swift).
    private var mode: AppMode {
        if Demo.mode != nil { return AppMode.of(route: .bluetooth, paired: true, life: Demo.life) }
        return AppMode.of(route: route, paired: paired, life: life.shape)
    }

    var body: some View {
        #if targetEnvironment(simulator)
        if let sheet = DemoGallery.wanted { DemoGallery(name: sheet) } else { app }
        #else
        app
        #endif
    }

    private var app: some View {
        ZStack {
            if clientAlive || showClient {
                nostrHome
                    .id(clientRun)
                    .opacity(showClient ? 1 : 0)
                    .allowsHitTesting(showClient)
                    .accessibilityHidden(!showClient)
            }
            if let d = door {
                if !ready(d) {
                    SwitchPage(target: d, route: route, link: link, onHome: { go(nil) }, onSettings: { showSettings = true }).transition(.opacity)
                } else if d == .vault {
                    AccountsView(home: true, onSettings: { showSettings = true }, modeMenu: AnyView(vaultMenu)).transition(.opacity)
                }
                // .nostr and ready: the client, above.
            } else {
                ModeHome(link: link, route: route, onSettings: { showSettings = true }, open: { go($0) }).transition(.opacity)
            }
        }
        .animation(.easeInOut(duration: 0.3), value: door)
        .animation(.easeInOut(duration: 0.3), value: door.map(ready))
        .onAppear {
            if showClient { clientAlive = true }
            // Opened on Home, NOSTR was the last door used and the KEY is where
            // NOSTR needs it: the client starts loading now, under the home page,
            // so it is there when NOSTR is tapped.
            else if door == nil, Demo.mode == nil, UserDefaults.standard.string(forKey: "lastDoor") == Door.nostr.rawValue, ready(.nostr) {
                clientAlive = true
                clientHiddenAt = Date()
                Bunker.log("app: the Nostr client loads under the home page (NOSTR was the last door)")
            }
        }
        .onChange(of: showClient) { _, on in
            if on {
                if clientStale { clientStale = false; clientRun += 1; Bunker.log("app: the Nostr client starts anew (the KEY was in VAULT mode meanwhile)") }
                clientAlive = true
                clientHiddenAt = nil
            } else {
                clientHiddenAt = Date()
                // A text box in the page must not keep the keyboard up under another page.
                UIApplication.shared.sendAction(#selector(UIResponder.resignFirstResponder), to: nil, from: nil, for: nil)
            }
        }
        .onChange(of: life.isVault) { _, vault in if vault, clientAlive { clientStale = true } }
        .task(id: clientHiddenAt) {
            guard clientHiddenAt != nil else { return }
            try? await Task.sleep(nanoseconds: 600_000_000_000)
            if !Task.isCancelled, !showClient, clientAlive { clientAlive = false; clientStale = false; Bunker.log("app: the Nostr client let go after ten minutes out of sight") }
        }
        .sheet(isPresented: $showSettings, onDismiss: { routeText = LinkSettingsView.routeText(route); paired = KeyLink.appPaired }) {
            ThisPhoneView(link: link, route: $route, mode: settingsMode, door: door, go: { go($0) })
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
        // The way to the other modes is a small NOSTR chip that bridge.js puts
        // beside the client's own wordmark (no banner): it opens the menu below.
        NostrClientView(onOpenSettings: { showSettings = true }, onOpenModes: { showModes = true }, onChipMissing: { nativeChip = true },
                        onPageColour: { pageColour = $0 }, routeText: $routeText)
            .ignoresSafeArea(.container, edges: .bottom)
            .ignoresSafeArea(.keyboard)
            .overlay(alignment: .top) {
                // Only if a newer page's header gave bridge.js no place for its chip.
                if nativeChip {
                    Button { showModes = true } label: {
                        HStack(spacing: 6) {
                            Text("NOSTR").font(Brand.font(11, .semibold)).tracking(2)
                            Image(systemName: "chevron.down").font(.system(size: 9, weight: .bold))
                        }
                        .foregroundStyle(Brand.brass)
                        .padding(.horizontal, 12).frame(minHeight: 32)
                        .background(Brand.bg.opacity(0.9))
                        .clipShape(Capsule())
                        .overlay(Capsule().stroke(Brand.brass, lineWidth: 1))
                        .frame(minHeight: 44)
                    }
                    .accessibilityLabel("NOSTR mode. Switch mode")
                }
            }
            .background(Color(uiColor: pageColour).ignoresSafeArea())
            .preferredColorScheme(showClient ? (RootView.isLight(pageColour) ? .light : .dark) : nil)
            .confirmationDialog("Go to", isPresented: $showModes, titleVisibility: .visible) {
                Button("VAULT") { go(.vault) }
                Button("Home") { go(nil) }
                Button("Cancel", role: .cancel) {}
            }
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
    /// The home page's version: the link's state and FIND MY KEY on one card.
    /// The explanation and Forget the app's pairing stay in Settings.
    var compact = false
    @ObservedObject private var life = KeyLife.shared
    @State private var forgot = false

    private var pairedLine: String {
        life.life != nil ? "Paired · " + KeyLife.name(life.life) : life.lastSeen != nil ? "Paired · last seen in " + KeyLife.name(life.lastSeen) : "Paired"
    }
    /// The compact card says the state, not what to do: the button says that.
    private var compactTitle: String {
        if link.busy || link.pairing || link.appCode != nil { return KeyStatus.headline(link) }
        if case .failed? = link.outcome { return KeyStatus.headline(link) }
        return "Paired with this iPhone"
    }
    private var compactLine: String {
        if let l = KeyWhere.live(life) { return "In " + KeyLife.name(l) }
        return life.lastSeen != nil ? "Last seen in " + KeyLife.name(life.lastSeen) : "Not found yet"
    }

    /// Issue #83: the paired KEY is silent and another KEY is in range. If the
    /// owner's KEY was reset or restored it is that other one, at a new
    /// address. One tap forgets the old pairing and starts a new one.
    private var pairAgain: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Your KEY may have been reset or restored.").font(Brand.font(15, .semibold)).foregroundStyle(Brand.ink)
                .fixedSize(horizontal: false, vertical: true)
            Text("If so, pair it again. On the KEY: Settings > Network > Pair a phone, then tap here.")
                .font(Brand.small).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true)
            BrandButton(title: "PAIR AGAIN", filled: true) {
                appPaired = false
                link.pairAgain()
            }
        }
        .padding(.top, 4)
    }

    /// Clears everything this iPhone keeps for a KEY. In Settings always: when
    /// the app shows Not paired there can still be a KEY remembered (issue #83).
    private var forget: some View {
        Button {
            link.cancel()
            link.forgetApp(); appPaired = false
            forgot = true
            DispatchQueue.main.asyncAfter(deadline: .now() + 3) { forgot = false }
        } label: {
            Text(forgot ? "Forgotten" : "Forget the app's pairing").font(Brand.body).foregroundStyle(Brand.danger).frame(minHeight: 44)
        }
        .disabled(forgot)
    }

    var body: some View {
        BrandSection(title: "YOUR KEY") {
            if appPaired, compact {
                VStack(alignment: .leading, spacing: 10) {
                    HStack(spacing: 12) {
                        VStack(alignment: .leading, spacing: 3) {
                            Text(compactTitle).font(Brand.font(15, .semibold)).foregroundStyle(Brand.ink)
                                .lineLimit(2).fixedSize(horizontal: false, vertical: true)
                            Text(compactLine).font(Brand.small).foregroundStyle(Brand.brass).lineLimit(2).fixedSize(horizontal: false, vertical: true)
                        }
                        Spacer(minLength: 8)
                        Button { link.busy ? link.cancel() : link.probe() } label: {
                            Text(link.busy ? "CANCEL" : "FIND MY KEY").font(Brand.font(12, .semibold)).tracking(1.5).foregroundStyle(Brand.ink)
                                .padding(.horizontal, 14).frame(minHeight: 44)
                                .overlay(RoundedRectangle(cornerRadius: 10).stroke(Brand.line, lineWidth: 1))
                        }
                    }
                    if let d = KeyStatus.detail(link), link.busy || link.result != nil {
                        Text(d).font(Brand.small).foregroundStyle(link.pairing ? Brand.brass : Brand.grey).fixedSize(horizontal: false, vertical: true)
                    }
                    if link.maybeReset { pairAgain }
                }
                .padding(16)
                .background(Brand.card)
                .clipShape(RoundedRectangle(cornerRadius: 14))
            } else if !appPaired {
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
                    // Issue #83: reachable in Settings whatever state the pairing is in.
                    if !compact { forget }
                }
                .padding(16)
                .background(Brand.card)
                .clipShape(RoundedRectangle(cornerRadius: 14))
            } else {
                VStack(alignment: .leading, spacing: 12) {
                    HStack(alignment: .firstTextBaseline) {
                        Text(KeyStatus.headline(link)).font(Brand.font(17, .semibold)).foregroundStyle(Brand.ink)
                        Spacer()
                        Text(pairedLine).font(Brand.small).foregroundStyle(Brand.brass)
                    }
                    if let d = KeyStatus.detail(link) {
                        Text(d).font(Brand.small).foregroundStyle(link.pairing ? Brand.brass : Brand.grey).fixedSize(horizontal: false, vertical: true)
                    }
                    BrandButton(title: link.busy ? "CANCEL" : "FIND MY KEY", filled: false) {
                        link.busy ? link.cancel() : link.probe()
                    }
                    if link.maybeReset { pairAgain }
                    Text("Passwords, passkeys, one-time codes and the account list go over the app's own locked channel. Other apps on this iPhone can't ask the KEY for anything.")
                        .font(Brand.small).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true)
                    forget
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
            Text(title).font(Brand.label).tracking(2).foregroundStyle(Brand.brass).padding(.leading, 4)
            content
        }
    }
}
