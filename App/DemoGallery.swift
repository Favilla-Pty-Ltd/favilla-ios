// DemoGallery.swift - the AutoFill extension's sheets, shown in the app for
// their screenshots (simulator sample runs only; compiled out of device builds).
//
// The sheets live in an extension the CI simulator can't open, so their layout
// was shipped unseen. `-FavillaDemo x-<name>` shows one of them here, in a
// given state, with sample data and no KEY.

import SwiftUI

#if targetEnvironment(simulator)
struct DemoGallery: View {
    let name: String
    @StateObject private var link = KeyLink()

    static var wanted: String? {
        guard let m = Demo.mode, m.hasPrefix("x-") else { return nil }
        return m
    }

    @MainActor private func change(_ phase: ChangeJob.Phase, matches: Int, pick: Int = 0) -> ChangeJob {
        let j = ChangeJob(site: "www.example-shop.com")
        j.matches = Array(Demo.accounts.prefix(matches)).map { var e = $0; e.site = "example-shop.com"; return e }
        j.suggestions = ["you@example.com", "you"]
        j.pick = pick
        j.phase = phase
        return j
    }
    @MainActor private func save(_ phase: SaveJob.Phase, user: String) -> SaveJob {
        let j = SaveJob(site: "www.example-shop.com", user: user, pass: "x")
        j.suggestions = ["you@example.com", "you"]
        j.phase = phase
        return j
    }

    var body: some View {
        Group {
            switch name {
            case "x-signin":
                SignInView(link: link, purpose: .password, onNewPassword: {}, onClose: {})
                    .onAppear { link.site = "www.example-shop.com" }
            case "x-newpw-choose": NewPasswordView(job: change(.choose, matches: 2), onCancel: {})
            case "x-newpw-new": NewPasswordView(job: change(.choose, matches: 0), onCancel: {})
            case "x-newpw-asking": NewPasswordView(job: change(.asking(change: true), matches: 1), onCancel: {})
            case "x-newpw-done": NewPasswordView(job: change(.done(change: true), matches: 1), onCancel: {})
            case "x-save-user": SaveToKeyView(job: save(.needUser, user: ""), onDone: {}, onCancel: {})
            case "x-save-asking": SaveToKeyView(job: save(.asking(change: true), user: "you@example.com"), onDone: {}, onCancel: {})
            case "x-pair-search", "x-pair-none":
                ScrollView {
                    KeyCard(link: link, appPaired: .constant(false))
                        .padding(20)
                }
                .onAppear {
                    link.demoSearch(name == "x-pair-none" ? [] : [
                        KeyLink.Found(id: UUID(), name: "Favilla KEY 9EF1", rssi: -48),
                        KeyLink.Found(id: UUID(), name: "Favilla KEY 27C0", rssi: -81),
                    ])
                }
            case "x-wait-key":
                SignInView(link: link, purpose: .password, onNewPassword: {}, onClose: {})
                    .onAppear { link.site = "www.example-shop.com"; link.demoWaiting() }
            case "x-waits":
                // The waiting pieces of the Accounts and Backup pages (issue #59).
                VStack(alignment: .leading, spacing: 16) {
                    WaitCard(title: "Reading the KEY's list", detail: "48 of 131")
                    WaitBar(fraction: 48.0 / 131)
                    WaitCard(title: "Check your KEY", detail: "It shows DELETE ENTRY for example-shop.com as you@example.com. Hold ENTER there to delete it, or BACK to keep it.")
                    VaultSteps(step: .sealing(0.4), backup: true)
                    VaultSteps(step: .merging, backup: false)
                    VaultSteps(step: nil, backup: true)
                    Spacer()
                }
                .padding(20)
            default: Text("No sample sheet named \(name)").foregroundStyle(Brand.ink)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Brand.bg.ignoresSafeArea())
        .preferredColorScheme(.dark)
    }
}
#endif
