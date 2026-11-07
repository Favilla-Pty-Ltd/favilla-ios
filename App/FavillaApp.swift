// FavillaApp.swift - the Favilla app. It opens on the Nostr client (the KEY's
// own PWA, NostrClientView, 7 Nov 2026). Its Settings has a "This iPhone" row
// that opens the app's own screen (LinkSettingsView): how the phone reaches the
// KEY, the KEY's pairing, the opt-in account list, and the last AutoFill
// request (HomeBody, mockup 1d, 6 Nov 2026). The sign-in itself happens in the
// AutoFill sheet (CredentialProviderViewController).

import SwiftUI

@main
struct FavillaApp: App {
    @StateObject private var link = KeyLink()

    var body: some Scene {
        WindowGroup {
            RootView(link: link)
        }
    }
}

struct RootView: View {
    @ObservedObject var link: KeyLink
    @State private var showSettings = false
    @State private var route = KeyRoute.current
    @State private var routeText = LinkSettingsView.routeText(KeyRoute.current)
    @State private var pageColour = UIColor.black

    var body: some View {
        // The page starts below the status bar, as the home-screen PWA does (its
        // header has no top safe-area padding); it runs to the bottom edge and
        // clears the home indicator itself. The strip behind the status bar takes
        // the page's background, and the status bar text follows its brightness.
        NostrClientView(onOpenSettings: { showSettings = true }, onPageColour: { pageColour = $0 }, routeText: $routeText)
            .ignoresSafeArea(.container, edges: .bottom)
            .ignoresSafeArea(.keyboard)
            .background(Color(uiColor: pageColour).ignoresSafeArea())
            .preferredColorScheme(RootView.isLight(pageColour) ? .light : .dark)
            .sheet(isPresented: $showSettings, onDismiss: { routeText = LinkSettingsView.routeText(route) }) {
                LinkSettingsView(link: link, route: $route)
            }
    }

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
    @Environment(\.scenePhase) private var phase

    var body: some View {
        VStack(alignment: .leading, spacing: 22) {
            // YOUR KEY
            BrandSection(title: "YOUR KEY") {
                VStack(alignment: .leading, spacing: 12) {
                    Text(KeyStatus.headline(link)).font(Brand.font(17, .semibold)).foregroundStyle(Brand.ink)
                    if let d = KeyStatus.detail(link) {
                        Text(d).font(Brand.small).foregroundStyle(link.pairing ? Brand.brass : Brand.grey).fixedSize(horizontal: false, vertical: true)
                    }
                    BrandButton(title: link.busy ? "CANCEL" : "FIND MY KEY", filled: !link.busy) {
                        link.busy ? link.cancel() : link.probe()
                    }
                    Text("To pair a KEY: open PAIR A PHONE on the KEY, tap FIND MY KEY, check the code matches, tap Pair, then press ENTER on the KEY.")
                        .font(Brand.small).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true)
                }
                .padding(16)
                .background(Brand.card)
                .clipShape(RoundedRectangle(cornerRadius: 14))
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
                    Text("iOS keeps a list of the site names and usernames you use through Favilla, so it can offer them the moment you tap a login field. Passwords and passkeys stay on the KEY until you approve one there.")
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
            if p == .active { listOn = AccountList.isOn; count = AccountList.entries.count }
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
