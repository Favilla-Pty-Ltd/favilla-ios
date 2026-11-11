// FavillaApp.swift - the Favilla app. It opens on the Nostr client (the KEY's
// own PWA, NostrClientView, 7 Nov 2026). Its Settings has a "This iPhone" row
// that opens the app's own screen (LinkSettingsView): how the phone reaches the
// KEY, the KEY's pairing, the opt-in account list, and the last AutoFill
// request (HomeBody, mockup 1d, 6 Nov 2026). The sign-in itself happens in the
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
    @ObservedObject private var importer = CredentialImport.shared   // Apple Passwords > Export to another app (issue #16)

    var body: some View {
        // The page starts below the status bar, as the home-screen PWA does (its
        // header has no top safe-area padding) and runs to the bottom edge with no
        // safe-area inset, so the bottom bar sits where the home-screen PWA's does. The strip behind the status bar takes
        // the page's background, and the status bar text follows its brightness.
        NostrClientView(onOpenSettings: { showSettings = true }, onPageColour: { pageColour = $0 }, routeText: $routeText)
            .ignoresSafeArea(.container, edges: .bottom)
            .ignoresSafeArea(.keyboard)
            .background(Color(uiColor: pageColour).ignoresSafeArea())
            .preferredColorScheme(RootView.isLight(pageColour) ? .light : .dark)
            .sheet(isPresented: $showSettings, onDismiss: { routeText = LinkSettingsView.routeText(route) }) {
                LinkSettingsView(link: link, route: $route)
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
    }
    @State private var showImport = false

    static func isLight(_ c: UIColor) -> Bool {
        var r: CGFloat = 0, g: CGFloat = 0, b: CGFloat = 0, a: CGFloat = 0
        c.getRed(&r, green: &g, blue: &b, alpha: &a)
        return 0.299 * r + 0.587 * g + 0.114 * b > 0.6
    }
}

struct HomeBody: View {
    @ObservedObject var link: KeyLink
    @State private var listOn = AccountList.isOn
    @State private var count = AccountList.entries.count
    @State private var showLast = false
    @State private var appPaired = KeyLink.appPaired
    @State private var listNote: String?
    @State private var showAccounts = false
    @Environment(\.scenePhase) private var phase

    var body: some View {
        VStack(alignment: .leading, spacing: 22) {
            // YOUR KEY. Not paired (fresh install, a wiped KEY, a pairing the KEY
            // forgot): one page, one instruction (issue #22 ruling, 11 Nov).
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
                        Text(KeyStatus.headline(link)).font(Brand.font(17, .semibold)).foregroundStyle(Brand.ink)
                        if let d = KeyStatus.detail(link) {
                            Text(d).font(Brand.small).foregroundStyle(link.pairing ? Brand.brass : Brand.grey).fixedSize(horizontal: false, vertical: true)
                        }
                        BrandButton(title: link.busy ? "CANCEL" : "FIND MY KEY", filled: !link.busy) {
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

            // ACCOUNTS (11s): every password on the KEY, its health, the breach check
            if appPaired {
                BrandSection(title: "ACCOUNTS") {
                    VStack(alignment: .leading, spacing: 12) {
                        Text("Every account on the KEY, with its health: weak, reused, seen in a breach, made on the KEY. The breach check never sends a password.")
                            .font(Brand.small).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true)
                        BrandButton(title: "OPEN ACCOUNTS", filled: false) { showAccounts = true }
                    }
                    .padding(16)
                    .background(Brand.card)
                    .clipShape(RoundedRectangle(cornerRadius: 14))
                }
                .sheet(isPresented: $showAccounts) { AccountsView() }
            }

            // SIGNING IN
            BrandSection(title: "SIGNING IN") {
                VStack(alignment: .leading, spacing: 12) {
                    Toggle(isOn: Binding(get: { listOn }, set: { on in
                        listOn = on
                        AccountList.setOn(on) { _ in count = AccountList.entries.count }
                    })) {
                        Text("Show my accounts in the keyboard bar").font(Brand.font(17, .semibold)).foregroundStyle(Brand.ink)
                    }
                    .tint(Brand.brass)
                    Text("iOS keeps a list of the site names and usernames you use through Favilla, so it can offer them the moment you tap a login field, and offer Favilla on a code field for sites with a one-time code on the KEY. Passwords, codes and passkeys stay on the KEY until you approve one there.")
                        .font(Brand.small).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true)
                }
                .padding(16)
                .background(Brand.card)
                .clipShape(RoundedRectangle(cornerRadius: 14))

                if listOn {
                    VStack(spacing: 0) {
                        HStack {
                            Text("Accounts listed").font(Brand.body).foregroundStyle(Brand.ink)
                            Spacer()
                            Text("\(count)").font(Brand.body).foregroundStyle(Brand.grey)
                        }
                        .padding(16)
                        Divider().overlay(Brand.line)
                        Button {
                            AccountList.setOn(false) { _ in AccountList.setOn(true) { _ in count = AccountList.entries.count } }
                        } label: {
                            Text("Remove the list from this iPhone").font(Brand.body).foregroundStyle(Brand.danger)
                                .frame(maxWidth: .infinity, minHeight: 48, alignment: .leading).padding(.horizontal, 16)
                        }
                    }
                    .background(Brand.card)
                    .clipShape(RoundedRectangle(cornerRadius: 14))
                    if appPaired {
                        BrandButton(title: link.busy && link.mode == .list ? "CANCEL" : "FILL THE LIST FROM MY KEY", filled: false) {
                            link.busy ? link.cancel() : link.list()
                        }
                        Text(listNote ?? "The KEY asks first (Share list?): press ENTER on the KEY. Only site names and usernames come over, never passwords.")
                            .font(Brand.small).foregroundStyle(listNote == nil ? Brand.grey : Brand.ink).fixedSize(horizontal: false, vertical: true)
                    }
                    Text("It fills as you sign in through Favilla. Off: Favilla is one entry under the key icon, and iOS holds no account names.")
                        .font(Brand.small).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true)
                } else {
                    Text("Off: Favilla is one entry under the key icon, and iOS holds no account names.")
                        .font(Brand.small).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true)
                }
                Text("Turn on Favilla in Settings > General > AutoFill & Passwords.")
                    .font(Brand.small).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true)
            }

            // LAST REQUEST (bench)
            BrandSection(title: "LAST REQUEST") {
                Button(showLast ? "Hide" : "Show the last sign-in's steps") { showLast.toggle() }
                    .font(Brand.body).foregroundStyle(Brand.brass).frame(minHeight: 44)
                if showLast {
                    LogBox(lines: (LastRequest.load() ?? "No request yet.").components(separatedBy: "\n"), maxHeight: 260)
                        .textSelection(.enabled)
                }
            }
        }
        .onChange(of: phase) { _, p in
            if p == .active { listOn = AccountList.isOn; count = AccountList.entries.count; appPaired = KeyLink.appPaired }
        }
        .onReceive(NotificationCenter.default.publisher(for: PairIdentity.cleared)) { _ in
            appPaired = false
        }
        .onReceive(link.$outcome) { o in
            appPaired = KeyLink.appPaired   // also catches a pairing the KEY forgot (0x08)
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
