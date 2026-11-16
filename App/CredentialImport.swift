// CredentialImport.swift - passwords handed over by Apple Passwords and other
// managers (iOS 26 credential exchange, FIDO CXF 1.0; firmware issue #16,
// 10 Nov 2026).
//
// Apple Passwords > Export Data to Another App lists every app whose AutoFill
// extension declares SupportsCredentialExchange (project.yml). When the owner
// picks Favilla, iOS opens the app with an NSUserActivity carrying an import
// token; ASCredentialImportManager turns the token into the exported data,
// decrypted by iOS, in this process's memory.
//
// What happens to it: only the password logins go on, through the KEY's
// import window over the app channel in VAULT mode (KEY 11bf, issue #36;
// ImportFlowView): duplicates of what the KEY lists are skipped, the KEY asks
// for the passkey PIN once and seals each one, marked "imported". Nothing is
// written on the phone; the logins are dropped when the sheet goes.
//
// Not imported, and said so on the summary: passkeys (CXF carries the private
// key; the KEY's passkeys are derived in its G0 from the words, and there is
// no path to load a foreign key), one-time codes (no KEY endpoint yet; the KEY
// takes them from the site's setup QR), and everything else (cards, notes,
// Wi-Fi, identities).

import AuthenticationServices
import Foundation
import SwiftUI

@MainActor
final class CredentialImport: ObservableObject {
    static let shared = CredentialImport()

    /// The activity type iOS launches the app with. Apple's docs call the
    /// constant ASCredentialExchangeActivityType; its value is this string,
    /// and both spellings are in NSUserActivityTypes (project.yml).
    static let activityType = "ASCredentialExchangeActivity"
    static let tokenKey = "ASCredentialImportToken"
    /// Posted with the logins (JSON) when the owner taps IMPORT: NostrClientView
    /// hands them to bridge.js (`__favillaImport`).
    static let handoff = Notification.Name("CredentialImport.handoff")

    struct Login: Encodable {
        var title: String
        var url: String
        var user: String
        var pass: String
        var note: String
    }

    struct Summary {
        var from: String             // the exporting app's name
        var logins: Int
        var noPassword: Int          // password items with an empty password
        var passkeys: Int
        var codes: Int               // TOTP
        var other: Int               // cards, notes, Wi-Fi, identities...
        var error: String?
    }

    @Published var summary: Summary?
    @Published private(set) var busy = false
    private var logins: [Login] = []

    /// The launch activity: fetch the export and summarise it for the sheet.
    func handle(_ activity: NSUserActivity) {
        guard activity.activityType == CredentialImport.activityType else { return }
        guard let token = activity.userInfo?[CredentialImport.tokenKey] as? UUID else {
            summary = Summary(from: "", logins: 0, noPassword: 0, passkeys: 0, codes: 0, other: 0, error: "The hand-over from the other app had no import token. Try the export again.")
            return
        }
        guard #available(iOS 26, *) else {
            summary = Summary(from: "", logins: 0, noPassword: 0, passkeys: 0, codes: 0, other: 0, error: "Importing from another app needs iOS 26 or later.")
            return
        }
        busy = true
        discard()
        Task {
            defer { busy = false }
            do {
                let data = try await ASCredentialImportManager().importCredentials(token: token)
                let (list, s) = CredentialImport.convert(data)
                logins = list
                summary = s
                Bunker.log("import: \(s.logins) logins from \(s.from), \(s.passkeys) passkeys, \(s.codes) codes, \(s.other) other not imported")
            } catch {
                summary = Summary(from: "", logins: 0, noPassword: 0, passkeys: 0, codes: 0, other: 0, error: "The other app's export couldn't be read: \(error.localizedDescription)")
                Bunker.log("import: failed: \(error.localizedDescription)")
            }
        }
    }

    /// CXF accounts > items > credentials. One login per item that has a
    /// basic-auth credential with a password; the item's title and first URL
    /// name the site (the PWA's normSite picks the host), its note credentials
    /// go in the note.
    @available(iOS 26, *)
    static func convert(_ data: ASExportedCredentialData) -> ([Login], Summary) {
        var out: [Login] = []
        var s = Summary(from: data.exporterDisplayName, logins: 0, noPassword: 0, passkeys: 0, codes: 0, other: 0)
        for account in data.accounts {
            for item in account.items {
                var user = "", pass = "", notes: [String] = []
                var hasAuth = false, hasOther = false
                for c in item.credentials {
                    switch c {
                    case .basicAuthentication(let a):
                        hasAuth = true
                        if user.isEmpty, let u = a.userName?.value { user = u }
                        if pass.isEmpty, let p = a.password?.value { pass = p }
                    case .passkey: s.passkeys += 1
                    case .totp: s.codes += 1
                    case .note(let n):
                        let t = n.content.value.trimmingCharacters(in: .whitespacesAndNewlines)
                        if !t.isEmpty { notes.append(t) }
                    default: hasOther = true
                    }
                }
                if hasAuth {
                    if pass.isEmpty { s.noPassword += 1; continue }
                    if let sub = item.subtitle?.trimmingCharacters(in: .whitespacesAndNewlines), !sub.isEmpty, sub != user { notes.insert(sub, at: 0) }
                    out.append(Login(title: item.title, url: item.scope?.urls.first?.absoluteString ?? "", user: user, pass: pass, note: notes.joined(separator: "\n")))
                    s.logins += 1
                } else if hasOther || notes.count == item.credentials.count {
                    s.other += 1     // a card, a secure note, Wi-Fi...: no login here
                }
            }
        }
        return (out, s)
    }

    /// The logins as import rows (VaultImport), for the KEY's window.
    func rows() -> (source: String, rows: [VaultImport.Row]) {
        (summary?.from.isEmpty == false ? summary!.from : "another app",
         logins.map { VaultImport.Row(url: $0.url, name: $0.title, user: $0.user, pass: $0.pass, note: $0.note) })
    }

    /// IMPORT: the logins go to the Nostr client's Passwords page, and this
    /// side forgets them. (Before KEY 11bf; kept for the Wi-Fi route.)
    func send() {
        guard !logins.isEmpty, let d = try? JSONEncoder().encode(logins), let json = String(data: d, encoding: .utf8) else { discard(); return }
        let from = summary?.from ?? ""
        let note = CredentialImport.leftOut(summary)
        discard()
        NotificationCenter.default.post(name: CredentialImport.handoff, object: nil, userInfo: ["json": json, "from": from, "note": note])
    }

    /// Drop the copy held here. (Swift strings are values: this releases the
    /// buffers; nothing was written to disk.)
    func discard() {
        logins.removeAll(keepingCapacity: false)
        summary = nil
    }

    /// One line for the page's status: what the hand-over had that the KEY won't take.
    static func leftOut(_ s: Summary?) -> String {
        guard let s else { return "" }
        var parts: [String] = []
        if s.passkeys > 0 { parts.append("\(s.passkeys) passkey\(s.passkeys == 1 ? "" : "s") not imported: create new ones on those sites with your KEY") }
        if s.codes > 0 { parts.append("\(s.codes) one-time code\(s.codes == 1 ? "" : "s") not imported from this hand-over: a CSV export from that manager brings codes, or add them on the KEY from each site's setup QR") }
        if s.noPassword > 0 { parts.append("\(s.noPassword) with no password skipped") }
        if s.other > 0 { parts.append("\(s.other) other item\(s.other == 1 ? "" : "s") (cards, notes, Wi-Fi) not imported") }
        return parts.joined(separator: ". ")
    }
}

// MARK: - The summary sheet

struct CredentialImportSheet: View {
    @ObservedObject var model = CredentialImport.shared
    @StateObject private var accounts = AccountsModel()
    @State private var flow: (source: String, rows: [VaultImport.Row])?
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            if let f = flow {
                ImportFlowView(model: accounts, preset: f) { flow = nil; accounts.close(); dismiss() }
                    .navigationTitle("Import passwords")
                    .navigationBarTitleDisplayMode(.inline)
                    .toolbarBackground(Brand.bg, for: .navigationBar)
            } else {
                summaryPage
            }
        }
        .preferredColorScheme(.dark)
        .interactiveDismissDisabled(model.busy || accounts.importPhase != .idle)
        .onDisappear { flow = nil; accounts.close() }
    }

    private var summaryPage: some View {
            ScrollView {
                VStack(alignment: .leading, spacing: 22) {
                    if let s = model.summary {
                        if let e = s.error {
                            card {
                                Text("Nothing to import").font(Brand.font(17, .semibold)).foregroundStyle(Brand.ink)
                                Text(e).font(Brand.small).foregroundStyle(Brand.danger).fixedSize(horizontal: false, vertical: true)
                            }
                            BrandButton(title: "CLOSE", filled: false) { model.discard(); dismiss() }
                        } else {
                            card {
                                HStack(alignment: .firstTextBaseline, spacing: 8) {
                                    Text("\(s.logins)").font(Brand.font(34, .bold)).monospacedDigit().foregroundStyle(Brand.ink)
                                    Text(s.logins == 1 ? "login" : "logins").font(Brand.body).foregroundStyle(Brand.grey)
                                }
                                Text("from " + (s.from.isEmpty ? "another app" : s.from) + ", held in Favilla's memory only")
                                    .font(Brand.small).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true)
                            }
                            let left = CredentialImport.leftOut(s)
                            if !left.isEmpty {
                                card {
                                    Text("Not imported").font(Brand.font(17, .semibold)).foregroundStyle(Brand.ink)
                                    ForEach(left.components(separatedBy: ". "), id: \.self) { line in
                                        Text("• " + line).font(Brand.small).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true)
                                    }
                                    Text("Passkeys made on the KEY are derived from its words, so they are restorable; one brought in from another manager would not be. Create new ones on those sites once the password is on the KEY.")
                                        .font(Brand.small).foregroundStyle(Brand.faint).fixedSize(horizontal: false, vertical: true)
                                }
                            }
                            if s.logins > 0 {
                                VStack(alignment: .leading, spacing: 12) {
                                    BrandButton(title: "NEXT") { flow = model.rows(); model.discard() }
                                    Text("Next: the KEY's list is read so nothing is added twice, then the KEY asks for your passkey PIN and saves each one, marked imported. The KEY must be in VAULT mode. Nothing is written on this iPhone.")
                                        .font(Brand.small).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true)
                                }
                            }
                            BrandButton(title: "DISCARD", filled: false) { model.discard(); dismiss() }
                        }
                    } else if model.busy {
                        card {
                            Text("Reading the hand-over…").font(Brand.font(17, .semibold)).foregroundStyle(Brand.ink)
                            ProgressView().tint(Brand.brass)
                        }
                    }
                }
                .padding(20)
            }
            .background(Brand.bg.ignoresSafeArea())
            .navigationTitle("Import passwords")
            .navigationBarTitleDisplayMode(.inline)
            .toolbarBackground(Brand.bg, for: .navigationBar)
    }

    private func card<C: View>(@ViewBuilder _ c: () -> C) -> some View {
        VStack(alignment: .leading, spacing: 12) { c() }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(16)
            .background(Brand.card)
            .clipShape(RoundedRectangle(cornerRadius: 14))
    }
}
