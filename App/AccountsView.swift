// AccountsView.swift - the accounts page: every password entry on the KEY with
// its health, a breach check that never sends a password, and tap-to-fix
// (KEY 11s, firmware issue #15, 10 Nov 2026).
//
// The KEY scores each password when it holds it anyway (seal, sign-in, a slow
// backfill on a quiet screen) and keeps one health byte per entry in the clear.
// The breach check is k-anonymity against Have I Been Pwned: the KEY hands out
// 5-hex-digit SHA-1 prefixes with no account attached, this iPhone fetches the
// buckets (padded), the KEY matches. Neither a password nor its full hash
// leaves the KEY.
//
// Transport: a KeySession on the app channel (the KEY in VAULT mode with the
// PIN in). LIST with the flags byte, SHOW 0x43, HEALTH 0x44.

import SafariServices
import SwiftUI
import UniformTypeIdentifiers
import UIKit

@MainActor
final class AccountsModel: ObservableObject {
    @Published private(set) var entries: [AppChannel.ListEntry] = []
    @Published private(set) var busy = ""
    @Published private(set) var status = ""
    @Published private(set) var oldFirmware = false
    @Published private(set) var log: [String] = []
    private var session: KeySession?

    private func note(_ s: String) {
        log.insert(s, at: 0)
        if log.count > 30 { log.removeLast() }
    }

    private func open() async throws -> KeySession {
        if let s = session { return s }
        guard let c = Credentials.load() else { throw KeySession.Failure("Pair the app with the KEY first (PAIR THE APP on the home screen).") }
        let s = KeySession(c)
        try await s.open()
        session = s
        return s
    }

    func close() { session?.close(); session = nil }

    /// LIST, SHOW and HEALTH are VAULT-side commands: the KEY's NOSTR Bluetooth
    /// life answers them 0x04 (not here), which the bunker wording would read
    /// backwards.
    static func refusal(_ st: UInt8) -> String {
        if st == 0x04 { return "Your KEY is in NOSTR Bluetooth mode. Accounts need its VAULT side: on the KEY choose VAULT, enter the VAULT PIN, and leave it on its home screen." }
        return KeySession.refusal(st)
    }

    /// LIST with health, all pages.
    func load() {
        guard busy.isEmpty else { return }
        busy = "Reading the KEY's list…"
        status = ""
        Task {
            defer { busy = "" }
            do {
                let s = try await open()
                var got: [AppChannel.ListEntry] = [], start = 0
                while true {
                    let a = try await s.request(AppChannel.cList, AppChannel.listBody(start: start, health: true), timeout: 35)
                    if a.rsp == AppChannel.rErr { throw KeySession.Failure(AccountsModel.refusal(a.body.first ?? 0xFF)) }
                    guard a.rsp == AppChannel.rList else { throw KeySession.Failure("The KEY answered the list with type \(String(format: "%02x", a.rsp)).") }
                    let page: AppChannel.ListPage
                    do { page = try AppChannel.parseList(a.body) } catch AppChannel.BodyFailure.status(let st) { throw KeySession.Failure(KeyLink.listMessage(st)) }
                    got += page.entries
                    if !page.more || page.entries.isEmpty || got.count >= 2000 { break }
                    start += page.entries.count
                }
                entries = got.filter { !$0.passkey }
                oldFirmware = !entries.isEmpty && entries.allSatisfy { $0.health == nil }
                note("list: \(entries.count) accounts" + (oldFirmware ? " (no health: KEY before 11s)" : ""))
            } catch {
                status = "\(error)"
                note("list failed: \(error)")
            }
        }
    }

    /// The breach check: prefixes from the KEY, buckets from HIBP, back to the KEY.
    func checkBreaches() {
        guard busy.isEmpty else { return }
        busy = "Checking breaches…"
        status = ""
        Task {
            defer { busy = "" }
            do {
                let s = try await open()
                var buckets = 0, rounds = 0, lastPending = -1
                while rounds < 40 {
                    rounds += 1
                    let page = try await health(s, body: Data())
                    if page.prefixes.isEmpty {
                        status = page.pending == 0 ? "Checked \(buckets) bucket\(buckets == 1 ? "" : "s"). Every password the KEY has seen this sitting is checked."
                            : "Checked \(buckets) bucket\(buckets == 1 ? "" : "s"). \(page.pending) account\(page.pending == 1 ? "" : "s") still pending: the KEY hasn't held \(page.pending == 1 ? "that password" : "those passwords") since the PIN. Sign in with them, or leave the KEY on its home screen a while, then check again."
                        break
                    }
                    if page.pending == lastPending, page.prefixes.isEmpty { break }
                    lastPending = page.pending
                    for prefix in page.prefixes {
                        let suffixes = try await hibp(prefix)
                        buckets += 1
                        var sent = 0
                        repeat {
                            let slice = Array(suffixes[sent..<min(sent + 1200, suffixes.count)])
                            guard let body = AppChannel.healthBody(prefix: prefix, suffixes: slice) else { throw KeySession.Failure("A breach bucket couldn't be packed.") }
                            _ = try await health(s, body: body)
                            sent += slice.count
                        } while sent < suffixes.count
                        note("bucket \(prefix): \(suffixes.count) hashes to the KEY")
                    }
                }
                load()
            } catch {
                status = "\(error)"
                note("breach check failed: \(error)")
            }
        }
    }

    private func health(_ s: KeySession, body: Data) async throws -> AppChannel.HealthPage {
        let a = try await s.request(AppChannel.cHealth, body, timeout: 20)
        if a.rsp == AppChannel.rErr { throw KeySession.Failure(AccountsModel.refusal(a.body.first ?? 0xFF)) }
        guard a.rsp == AppChannel.rHealth else { throw KeySession.Failure("This KEY doesn't have the breach check yet (firmware 11s).") }
        do { return try AppChannel.parseHealth(a.body) } catch AppChannel.BodyFailure.status(let st) { throw KeySession.Failure(AccountsModel.refusal(st)) }
    }

    /// The HIBP range bucket for a 5-hex-digit prefix: the suffixes seen at least once.
    static func hibp(_ prefix: String) async throws -> [String] {
        var q = URLRequest(url: URL(string: "https://api.pwnedpasswords.com/range/\(prefix)")!, timeoutInterval: 15)
        q.setValue("true", forHTTPHeaderField: "Add-Padding")
        q.setValue("Favilla iOS", forHTTPHeaderField: "User-Agent")
        let (d, r) = try await URLSession.shared.data(for: q)
        guard (r as? HTTPURLResponse)?.statusCode == 200, let text = String(data: d, encoding: .utf8) else {
            throw KeySession.Failure("Have I Been Pwned didn't answer (bucket \(prefix)).")
        }
        return text.split(whereSeparator: { $0 == "\n" || $0 == "\r" }).compactMap { line in
            let parts = line.split(separator: ":")
            guard parts.count == 2, let n = Int(parts[1].trimmingCharacters(in: .whitespaces)), n > 0 else { return nil }
            let sfx = String(parts[0]).uppercased()
            return sfx.count == 35 ? sfx : nil
        }
    }
    private func hibp(_ prefix: String) async throws -> [String] { try await AccountsModel.hibp(prefix) }

    /// OTP (11v): the code linked to this entry. The KEY shows that code alone
    /// when the ask comes within 60 s of a FILL it answered for the entry;
    /// otherwise the owner picks it on the KEY. ENTER on the KEY sends it.
    func code(_ e: AppChannel.ListEntry) async -> Result<String, KeySession.Failure> {
        guard let site = KeyLink.siteBytes(site: e.site, appName: false) else { return .failure(KeySession.Failure("That site name is too long for the KEY.")) }
        do {
            let s = try await open()
            let a = try await s.request(AppChannel.cOtp, AppChannel.otpBody(site: site), timeout: 40)
            if a.rsp == AppChannel.rErr { return .failure(KeySession.Failure(AccountsModel.refusal(a.body.first ?? 0xFF))) }
            guard a.rsp == AppChannel.rOtp else { return .failure(KeySession.Failure("The KEY answered with type \(String(format: "%02x", a.rsp)).")) }
            do { return .success(try AppChannel.parseOtp(a.body)) }
            catch AppChannel.BodyFailure.status(let st) { return .failure(KeySession.Failure(KeyLink.otpMessage(st))) }
            catch { return .failure(KeySession.Failure("The KEY's code couldn't be read.")) }
        } catch let f as KeySession.Failure { return .failure(f) }
        catch { return .failure(KeySession.Failure("\(error)")) }
    }

    /// SHOW: the entry's PASSWORD screen on the KEY, so the sign-in that follows is one press.
    func show(_ e: AppChannel.ListEntry) async -> String? {
        guard let id = e.id else { return "This KEY can't put an entry on its screen yet (firmware 11s)." }
        do {
            let s = try await open()
            let a = try await s.request(AppChannel.cShow, id, timeout: 8)
            if a.rsp == AppChannel.rErr { return AccountsModel.refusal(a.body.first ?? 0xFF) }
            guard a.rsp == AppChannel.rAck, let st = a.body.first else { return "The KEY's answer couldn't be read." }
            switch st {
            case 0x00: return nil
            case 0x03: return "The KEY has no entry with that id any more. Refresh the list."
            case 0x05: return "Your KEY is locked. Enter the VAULT PIN on the KEY."
            default: return AppChannel.statusText(st)
            }
        } catch { return "\(error)" }
    }
}

// MARK: - The page

struct AccountsView: View {
    @StateObject private var m = AccountsModel()
    @State private var picked: PickedAccount?
    @State private var filter = ""
    @State private var qr: SetupKeyQR.Prefill?
    @Environment(\.dismiss) private var dismiss

    private var shown: [AppChannel.ListEntry] {
        let f = filter.trimmingCharacters(in: .whitespaces).lowercased()
        let list = f.isEmpty ? m.entries : m.entries.filter { $0.site.lowercased().contains(f) || $0.user.lowercased().contains(f) }
        // Trouble first: breached, then reused, then weak; the rest by site.
        return list.sorted { a, b in
            let ra = rank(a.health), rb = rank(b.health)
            return ra != rb ? ra < rb : a.site.lowercased() < b.site.lowercased()
        }
    }
    private func rank(_ h: AppChannel.Health?) -> Int {
        guard let h else { return 4 }
        if h.breached { return 0 }
        if h.reused { return 1 }
        if h.strength == 1 { return 2 }
        return 3
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    summary
                    if !m.status.isEmpty {
                        Text(m.status).font(Brand.small).foregroundStyle(Brand.ink).fixedSize(horizontal: false, vertical: true).padding(.horizontal, 16)
                    }
                    if m.entries.count > 8 {
                        TextField("Search", text: $filter).textInputAutocapitalization(.never).autocorrectionDisabled()
                            .font(Brand.body).foregroundStyle(Brand.ink).padding(12).background(Brand.card).clipShape(RoundedRectangle(cornerRadius: 10)).padding(.horizontal, 16)
                    }
                    LazyVStack(spacing: 0) {
                        ForEach(Array(shown.enumerated()), id: \.offset) { _, e in
                            Button { picked = PickedAccount(e: e) } label: { AccountRow(e: e) }
                            Divider().overlay(Brand.line).padding(.leading, 16)
                        }
                    }
                    .background(Brand.card)
                    .clipShape(RoundedRectangle(cornerRadius: 14))
                    .padding(.horizontal, 16)
                    if m.oldFirmware {
                        Text("Health badges need KEY firmware 11s or later.").font(Brand.small).foregroundStyle(Brand.grey).padding(.horizontal, 16)
                    }
                    Text("Health is scored on the KEY each time it holds a password: at a sign-in, when an entry is saved, and a few entries at a time while it sits on its home screen. The breach check sends Have I Been Pwned the first 5 characters of a password's hash and nothing else; the KEY does the matching.")
                        .font(Brand.small).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true).padding(.horizontal, 16)
                    if !m.log.isEmpty {
                        LogBox(lines: m.log, maxHeight: 160).padding(.horizontal, 16)
                    }
                }
                .padding(.vertical, 16)
            }
            .background(Brand.bg.ignoresSafeArea())
            .navigationTitle("Accounts")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Done") { m.close(); dismiss() }.font(Brand.button).foregroundStyle(Brand.brass) }
            }
            .sheet(item: $picked) { p in AccountSheet(e: p.e, model: m) }
            .sheet(item: $qr) { p in SetupKeyQR(prefill: p) }
            .onAppear { if m.entries.isEmpty { m.load() } }
            .onDisappear { m.close() }
        }
        .preferredColorScheme(.dark)
    }

    private var summary: some View {
        let hs = m.entries.compactMap { $0.health }
        let breached = hs.filter { $0.breached }.count, reused = hs.filter { $0.reused }.count
        let weak = hs.filter { $0.strength == 1 }.count, pending = hs.filter { !$0.checked }.count
        return VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .firstTextBaseline) {
                Text("\(m.entries.count)").font(Brand.font(28, .semibold)).foregroundStyle(Brand.ink)
                Text("accounts on the KEY").font(Brand.body).foregroundStyle(Brand.grey)
                Spacer()
            }
            if !hs.isEmpty {
                HStack(spacing: 8) {
                    Pill("\(breached) breached", tone: breached > 0 ? .bad : .quiet)
                    Pill("\(reused) reused", tone: reused > 0 ? .warn : .quiet)
                    Pill("\(weak) weak", tone: weak > 0 ? .warn : .quiet)
                    if pending > 0 { Pill("\(pending) unchecked", tone: .quiet) }
                    let codes = hs.filter { $0.hasCode }.count
                    if codes > 0 { Pill("\(codes) with 2FA", tone: .good) }
                }
            }
            HStack(spacing: 12) {
                BrandButton(title: m.busy.isEmpty ? "CHECK BREACHES" : m.busy.uppercased(), filled: m.busy.isEmpty) { m.checkBreaches() }
                    .disabled(!m.busy.isEmpty)
                Button("Refresh") { m.load() }.font(Brand.button).foregroundStyle(Brand.brass).disabled(!m.busy.isEmpty)
            }
            Button { qr = SetupKeyQR.Prefill(site: "", account: "") } label: {
                HStack(spacing: 6) { Image(systemName: "qrcode"); Text("Setup key to QR, for the KEY to scan") }
                    .font(Brand.small).foregroundStyle(Brand.brass)
            }
        }
        .padding(16)
        .background(Brand.card)
        .clipShape(RoundedRectangle(cornerRadius: 14))
        .padding(.horizontal, 16)
    }
}

struct PickedAccount: Identifiable {
    let e: AppChannel.ListEntry
    var id: String { e.id.map { $0.map { String(format: "%02x", $0) }.joined() } ?? (e.site + "|" + e.user) }
}

private struct AccountRow: View {
    let e: AppChannel.ListEntry
    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .firstTextBaseline) {
                Text(e.site).font(Brand.font(16, .semibold)).foregroundStyle(Brand.ink).lineLimit(1)
                Spacer()
                Image(systemName: "chevron.right").font(.system(size: 13, weight: .semibold)).foregroundStyle(Brand.grey)
            }
            Text(e.user).font(Brand.small).foregroundStyle(Brand.grey).lineLimit(1)
            if let h = e.health {
                HStack(spacing: 6) {
                    if h.breached { Pill("Seen in a breach", tone: .bad) }
                    if h.reused { Pill("Reused", tone: .warn) }
                    switch h.strength {
                    case 1: Pill("Weak", tone: .warn)
                    case 2: Pill("Fair", tone: .quiet)
                    case 3: Pill("Strong", tone: .good)
                    default: EmptyView()
                    }
                    switch h.origin {
                    case 1: Pill("✓ Made on KEY", tone: .good)
                    case 3: Pill("Imported", tone: .quiet)
                    default: EmptyView()
                    }
                    if h.hasCode { Pill("2FA", tone: .good) }
                    if !h.checked { Pill("Breach check pending", tone: .quiet) }
                }
                .padding(.top, 2)
            }
        }
        .padding(.horizontal, 16).padding(.vertical, 12)
        .contentShape(Rectangle())
    }
}

private struct Pill: View {
    enum Tone { case bad, warn, good, quiet }
    let text: String
    let tone: Tone
    init(_ t: String, tone: Tone) { text = t; self.tone = tone }
    var body: some View {
        let c: Color = { switch tone { case .bad: return Brand.danger; case .warn: return Brand.brass; case .good: return Color(red: 0.55, green: 0.78, blue: 0.56); case .quiet: return Brand.grey } }()
        Text(text).font(Brand.font(11, .semibold)).foregroundStyle(c)
            .padding(.horizontal, 8).padding(.vertical, 3)
            .background(c.opacity(0.14)).clipShape(Capsule())
    }
}

// MARK: - One account: tap-to-fix

private struct AccountSheet: View {
    let e: AppChannel.ListEntry
    @ObservedObject var model: AccountsModel
    @Environment(\.dismiss) private var dismiss
    @State private var status = ""
    @State private var working = false
    @State private var codeWorking = false
    @State private var code = ""
    @State private var codeNote = ""
    @State private var qr: SetupKeyQR.Prefill?

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    VStack(alignment: .leading, spacing: 4) {
                        Text(e.site).font(Brand.font(20, .semibold)).foregroundStyle(Brand.ink)
                        Text(e.user).font(Brand.body).foregroundStyle(Brand.grey)
                    }
                    if let h = e.health {
                        VStack(alignment: .leading, spacing: 8) {
                            if h.breached { Line("Seen in a breach", "This password appears in a known data breach. Change it on the site, then make the new one on the KEY.", bad: true) }
                            if h.reused { Line("Reused", "The same password is on another account on the KEY. Each site should have its own.", bad: true) }
                            if h.strength == 1 { Line("Weak", "Short or guessable. A password made on the KEY is long and random.", bad: true) }
                            if h.strength == 3 && !h.breached && !h.reused { Line("Strong", "Long and random. Nothing to do here.", bad: false) }
                            if h.origin == 1 { Line("Made on KEY", "The KEY generated this one; it was never typed anywhere.", bad: false) }
                            if h.origin == 3 { Line("Imported", "Came in through the Nostr client's import. The KEY has scored it like any other.", bad: false) }
                            if h.hasCode { Line("2FA", "A one-time code on the KEY is linked to this account. At a sign-in, the code is one press on the KEY after the password.", bad: false) }
                            if !h.checked { Line("Breach check pending", "The KEY hasn't held this password since the PIN. Sign in with it once, or leave the KEY on its home screen a while, then check breaches.", bad: false) }
                        }
                    }
                    BrandButton(title: working ? "ASKING THE KEY…" : "SIGN IN ON THE SITE", filled: !working) { signIn() }
                        .disabled(working)
                    Text("Puts this account on the KEY's screen and opens the site. Tap the password field, choose Favilla in the keyboard bar, and the sign-in is one press on the KEY.")
                        .font(Brand.small).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true)
                    if !status.isEmpty { Text(status).font(Brand.small).foregroundStyle(Brand.ink).fixedSize(horizontal: false, vertical: true) }

                    if e.health?.hasCode == true {
                        BrandButton(title: codeWorking ? "ASKING THE KEY…" : "GET CODE", filled: false) { getCode() }
                            .disabled(codeWorking || working)
                        if !code.isEmpty {
                            HStack(spacing: 14) {
                                Text(code.count == 6 ? code.prefix(3) + " " + code.suffix(3) : code)
                                    .font(.system(size: 34, weight: .semibold, design: .monospaced)).foregroundStyle(Brand.ink)
                                Spacer()
                                Button("Copy") {
                                    UIPasteboard.general.setItems([[UTType.plainText.identifier: code]], options: [.expirationDate: Date().addingTimeInterval(60)])
                                    codeNote = "Copied. The clipboard forgets it in a minute."
                                }.font(Brand.button).foregroundStyle(Brand.brass)
                            }
                            .padding(16).background(Brand.card).clipShape(RoundedRectangle(cornerRadius: 14))
                        }
                        if !codeNote.isEmpty { Text(codeNote).font(Brand.small).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true) }
                        Text("Press ENTER on the KEY when it shows the code. Codes change every 30 seconds; the sign-in sheet usually fills them for you without this.")
                            .font(Brand.small).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true)
                    }
                    Button { qr = SetupKeyQR.Prefill(site: e.site, account: e.user) } label: {
                        HStack(spacing: 6) { Image(systemName: "qrcode"); Text("Site gave you a setup key instead of a QR? Make the QR here") }
                            .font(Brand.small).foregroundStyle(Brand.brass).multilineTextAlignment(.leading)
                    }

                    Text("FIX IT").font(Brand.label).tracking(2).foregroundStyle(Brand.brass).padding(.top, 6)
                    VStack(alignment: .leading, spacing: 0) {
                        Step(n: 1, title: "Change the password", text: "Sign in on the site, go to its password settings, and make the new password on the KEY: NEW PASSWORD on the KEY, then fill it from the keyboard bar. The KEY saves it and scores it.")
                        Divider().overlay(Brand.line)
                        Step(n: 2, title: "Add two-factor", text: "Turn on an authenticator app on the site. When it shows the QR code, on the KEY open VAULT > Codes > ADD BY QR and point the KEY at it. The code then comes from the KEY at each sign-in.")
                        Divider().overlay(Brand.line)
                        Step(n: 3, title: "Add a passkey", text: "If the site offers passkeys, add one and choose Favilla when iOS asks where to save it. The KEY keeps it; the password stops mattering.")
                    }
                    .background(Brand.card)
                    .clipShape(RoundedRectangle(cornerRadius: 14))
                }
                .padding(16)
            }
            .background(Brand.bg.ignoresSafeArea())
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Close") { dismiss() }.font(Brand.button).foregroundStyle(Brand.brass) } }
            .sheet(item: $qr) { p in SetupKeyQR(prefill: p) }
        }
        .preferredColorScheme(.dark)
        .onDisappear { code = "" }
    }

    private func getCode() {
        codeWorking = true
        code = ""; codeNote = ""
        Task {
            switch await model.code(e) {
            case .success(let c): code = c; codeNote = ""
            case .failure(let f): codeNote = f.description
            }
            codeWorking = false
        }
    }

    private func signIn() {
        working = true
        status = ""
        Task {
            let why = await model.show(e)
            working = false
            if let why { status = why; return }
            status = "On the KEY's screen. Opening \(e.site)…"
            guard let url = URL(string: e.site.hasPrefix("http") ? e.site : "https://\(e.site)"),
                  let top = UIApplication.shared.connectedScenes.compactMap({ ($0 as? UIWindowScene)?.keyWindow?.rootViewController }).first else { return }
            var t = top
            while let p = t.presentedViewController { t = p }
            let sf = SFSafariViewController(url: url)
            sf.preferredBarTintColor = UIColor(red: 0x11 / 255, green: 0x11 / 255, blue: 0x11 / 255, alpha: 1)
            sf.preferredControlTintColor = UIColor(red: 0xC9 / 255, green: 0xA4 / 255, blue: 0x5C / 255, alpha: 1)
            t.present(sf, animated: true)
        }
    }

    private struct Line: View {
        let title: String, text: String, bad: Bool
        init(_ t: String, _ x: String, bad: Bool) { title = t; text = x; self.bad = bad }
        var body: some View {
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(Brand.font(14, .semibold)).foregroundStyle(bad ? Brand.danger : Brand.ink)
                Text(text).font(Brand.small).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true)
            }
        }
    }
    private struct Step: View {
        let n: Int, title: String, text: String
        var body: some View {
            HStack(alignment: .top, spacing: 12) {
                Text("\(n)").font(Brand.font(14, .semibold)).foregroundStyle(Brand.brass).frame(width: 22, height: 22).background(Brand.brass.opacity(0.14)).clipShape(Circle())
                VStack(alignment: .leading, spacing: 3) {
                    Text(title).font(Brand.font(15, .semibold)).foregroundStyle(Brand.ink)
                    Text(text).font(Brand.small).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true)
                }
            }
            .padding(14)
        }
    }
}
