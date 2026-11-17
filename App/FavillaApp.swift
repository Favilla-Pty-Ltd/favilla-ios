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
                ThisPhoneView(link: link, route: $route)
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
                        Text(life.life == nil ? "Paired" : "Paired · " + KeyLife.name(life.life)).font(Brand.small).foregroundStyle(Brand.brass)
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
