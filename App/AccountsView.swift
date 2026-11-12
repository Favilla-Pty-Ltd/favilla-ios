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
//
// 11ax (issue #30, 12 Nov 2026): add, edit and delete here too, so the owner
// never switches the KEY to NOSTR mode for it: PW_SAVE 0x47 (its body crosses
// encrypted), PW_DELETE 0x48 (up to 20), PW_RESULT 0x49 polled while the KEY
// asks, each confirmed on the KEY with a held ENTER; ASSESS_ONE 0x4A scores one
// entry now, and its prefix comes back among the others, unlinked.

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
    @Published private(set) var listOff = false     // codes on the KEY, but the keyboard list is off: iOS can't offer them
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
                // The list above the keyboard (when on) follows the KEY's: this is
                // where iOS learns which sites have a code, so Favilla shows on
                // their code fields.
                if AccountList.isOn { AccountList.replace(with: got) { n in Bunker.log("accounts: \(n) listed for the keyboard bar") } }
                listOff = !AccountList.isOn && got.contains { $0.health?.hasCode == true }
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
                // 11ab: have the KEY score the entries it has never assessed (24
                // per unlock), then wait for its loop before asking for prefixes.
                var opening = 0, unseen = 0
                let ar = try await s.request(AppChannel.cAssess, Data([24]), timeout: 10)
                if ar.rsp == AppChannel.rAck, ar.body.count >= 4, ar.body[0] == 0x00 {
                    opening = Int(ar.body[1]); unseen = Int(ar.body[2]) | Int(ar.body[3]) << 8
                    note("assess: opening \(opening), never assessed \(unseen)")
                    if opening > 0 {
                        busy = "Scoring \(opening)…"
                        try await Task.sleep(nanoseconds: UInt64(opening) * 300_000_000)
                    }
                } else if ar.rsp == AppChannel.rErr, let st = ar.body.first, st != 0x07, st != 0x04 {
                    throw KeySession.Failure(AccountsModel.refusal(st))
                } else {
                    note("assess: not on this KEY (before 11ab); checking what it has scored")
                }
                busy = "Checking breaches…"
                let (buckets, pending) = try await healthRounds(s)
                status = pending == 0 ? "Checked \(buckets) bucket\(buckets == 1 ? "" : "s"). Every password the KEY has seen this sitting is checked."
                    : "Checked \(buckets) bucket\(buckets == 1 ? "" : "s"). \(pending) account\(pending == 1 ? "" : "s") not scored yet" + (unseen > opening ? ": the KEY scores 24 per unlock. Lock and unlock the KEY and check again." : ". Check again in a moment.")
                load()
            } catch {
                status = "\(error)"
                note("breach check failed: \(error)")
            }
        }
    }

    /// HEALTH rounds until the KEY wants no more buckets: (buckets sent, still pending).
    private func healthRounds(_ s: KeySession) async throws -> (Int, Int) {
        var buckets = 0, rounds = 0, lastPending = -1
        while rounds < 40 {
            rounds += 1
            let page = try await health(s, body: Data())
            if page.prefixes.isEmpty { return (buckets, page.pending) }
            if page.pending == lastPending, page.prefixes.isEmpty { return (buckets, page.pending) }
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
        return (buckets, lastPending)
    }

    // MARK: 11ax: add, edit, delete, check one (issue #30)

    /// What the sheet shows while the KEY asks.
    @Published private(set) var asking = ""

    /// One edit job: busy while it runs, then the list read again when asked.
    /// The work returns (what to tell the owner, nil when done; reload?).
    private func job(_ label: String, _ work: (KeySession) async throws -> (String?, Bool)) async -> String? {
        guard busy.isEmpty else { return "The page is still talking to the KEY. Try again in a moment." }
        busy = label
        var out: String?, reload = false
        do { (out, reload) = try await work(try await open()) }
        catch { out = "\(error)"; note("\(label) failed: \(error)") }
        busy = ""; asking = ""
        if reload { load() }
        return out
    }

    /// PW_SAVE then PW_RESULT until the KEY is answered. nil = saved.
    /// `id` nil: a new entry.
    func save(id: Data?, site: String, user: String, pass: String, note text: String) async -> String? {
        let body: Data
        switch AppChannel.pwSaveBody(id: id, site: site, user: user, pass: pass, note: text) {
        case .success(let b): body = b
        case .failure(let p): return AppChannel.pwProblemText(p)
        }
        return await job(id == nil ? "Adding…" : "Saving…") { s in
            let a = try await s.request(AppChannel.cPwSave, body, timeout: 10)
            if let why = self.immediate(a, "save") { return (why, a.body.first == 0x03) }
            self.asking = "Check your KEY: it shows \(id == nil ? "NEW ENTRY" : "CHANGE ENTRY") for \(site)\(user.isEmpty ? "" : " as \(user)"). Hold ENTER there to save it, or BACK to cancel."
            self.note("save \(site): asked on the KEY")
            let r = try await self.result(s)
            self.note("save \(site): " + (r ?? "saved"))
            return (r, true)
        }
    }

    /// PW_DELETE (1 to 20 ids) then PW_RESULT. nil = deleted.
    func delete(_ list: [AppChannel.ListEntry]) async -> String? {
        let ids = list.compactMap { $0.id }
        guard ids.count == list.count, let body = AppChannel.pwDeleteBody(ids) else {
            return ids.count > 20 ? "Up to 20 at a time." : "This KEY can't delete from the app yet (firmware 11ax)."
        }
        return await job("Deleting…") { s in
            let a = try await s.request(AppChannel.cPwDelete, body, timeout: 10)
            if let why = self.immediate(a, "delete") { return (why, a.body.first == 0x03) }
            self.asking = list.count == 1
                ? "Check your KEY: it shows DELETE ENTRY for \(list[0].site)\(list[0].user.isEmpty ? "" : " as \(list[0].user)"). Hold ENTER there to delete it, or BACK to keep it."
                : "Check your KEY: it shows DELETE ENTRIES (\(list.count)). Hold ENTER there for 2 seconds to delete them, or BACK to keep them."
            self.note("delete \(list.count): asked on the KEY")
            let r = try await self.result(s)
            self.note("delete \(list.count): " + (r ?? "deleted"))
            return (r, true)
        }
    }

    /// An at-once answer to PW_SAVE / PW_DELETE: nil when the KEY is now asking.
    private func immediate(_ a: AppChannel.Answer, _ what: String) -> String? {
        if a.rsp == AppChannel.rErr {
            let st = a.body.first ?? 0xFF
            return st == 0x07 ? "This KEY can't \(what) from the app yet: it needs firmware 11ax." : AppChannel.pwStatusText(st)
        }
        guard a.rsp == AppChannel.rAck, let st = a.body.first else { return "The KEY's answer couldn't be read." }
        return st == 0x00 ? nil : AppChannel.pwStatusText(st)
    }

    /// PW_RESULT every second until the KEY is answered: nil = done. The KEY
    /// may hold the job up to 90 s for its home screen, then 60 s on the question.
    private func result(_ s: KeySession) async throws -> String? {
        let until = Date().addingTimeInterval(170)
        while Date() < until {
            try await Task.sleep(nanoseconds: 1_000_000_000)
            let a = try await s.request(AppChannel.cPwResult, Data(), timeout: 6)
            if a.rsp == AppChannel.rErr { return AppChannel.pwStatusText(a.body.first ?? 0xFF) }
            guard a.rsp == AppChannel.rAck, let r = AppChannel.parsePwResult(a.body) else { return "The KEY's answer couldn't be read." }
            switch r.state {
            case 0x00: continue
            case 0x01: return nil
            case 0x02: return "Cancelled on the KEY. Nothing was changed."
            case 0x03: return "No answer on the KEY in time. Nothing was changed."
            case 0x04: return "That entry changed on the KEY meanwhile. The list has been read again."
            case 0x05:
                if r.reason == 0x06 { return "A sign-in on a website took the KEY's screen. Nothing was changed; try again." }
                if r.reason == 0x05 { return "The KEY locked while it was asking. Nothing was changed." }
                return AppChannel.pwStatusText(r.reason)
            case 0x06: return "The KEY lost the request (it restarted?). Nothing was changed."
            default: return String(format: "The KEY answered with state 0x%02X.", r.state)
            }
        }
        return "No answer on the KEY in time."
    }

    /// ASSESS_ONE, then the HEALTH rounds; the verdict comes back with the list.
    /// The KEY gives no prefix for the entry: it sits among the others, so this
    /// iPhone never learns anything about one account's password.
    func checkOne(_ e: AppChannel.ListEntry) async -> String {
        guard let id = e.id else { return "This KEY can't check one entry yet (firmware 11ax)." }
        let why = await job("Checking \(e.site)…") { s in
            let a = try await s.request(AppChannel.cAssessOne, id, timeout: 8)
            if a.rsp == AppChannel.rErr {
                let st = a.body.first ?? 0xFF
                return (st == 0x07 ? "This KEY can't check one entry yet: it needs firmware 11ax." : AppChannel.pwStatusText(st), false)
            }
            guard a.rsp == AppChannel.rAck, a.body.count >= 2 else { return ("The KEY's answer couldn't be read.", false) }
            if a.body[0] != 0x00 { return (AppChannel.pwStatusText(a.body[0]), false) }
            self.note("assess one \(e.site): queued \(a.body[1])")
            try await Task.sleep(nanoseconds: 600_000_000)
            let (buckets, _) = try await self.healthRounds(s)
            self.note("check one \(e.site): \(buckets) bucket\(buckets == 1 ? "" : "s")")
            return (nil, true)
        }
        if let why { return why }
        // The list is being read again: wait for it, then report this entry.
        for _ in 0..<80 where !busy.isEmpty { try? await Task.sleep(nanoseconds: 250_000_000) }
        guard let h = entries.first(where: { $0.id == id })?.health else { return "Checked. Refresh the list to see the result." }
        if !h.checked { return "The KEY hasn't scored this one yet. Try again in a few seconds." }
        return h.breached ? "Seen in a breach. Change this password." : "Not in any known breach."
    }
}

// MARK: - The page

struct AccountsView: View {
    var pushed = false                 // inside Settings' stack: no Done, no stack of its own
    @StateObject private var m = AccountsModel()
    @State private var picked: PickedAccount?
    @State private var filter = ""
    @State private var qr: SetupKeyQR.Prefill?
    @State private var adding = false
    @State private var selecting = false
    @State private var selected: Set<String> = []
    @State private var selStatus = ""
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
        if pushed { page } else { NavigationStack { page }.preferredColorScheme(.dark) }
    }

    private var page: some View {
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
                            let key = PickedAccount(e: e).id
                            Button {
                                if selecting { toggle(key) } else { picked = PickedAccount(e: e) }
                            } label: { AccountRow(e: e, selecting: selecting, selected: selected.contains(key)) }
                            Divider().overlay(Brand.line).padding(.leading, 16)
                        }
                    }
                    .background(Brand.card)
                    .clipShape(RoundedRectangle(cornerRadius: 14))
                    .padding(.horizontal, 16)
                    if selecting { selectionBar }
                    if m.listOff {
                        Text("To get these codes above the keyboard, turn on \"Show my accounts in the keyboard bar\" on the Settings page (it holds sites and usernames only, never a password or code), then Refresh here.")
                            .font(Brand.small).foregroundStyle(Brand.brass).fixedSize(horizontal: false, vertical: true).padding(.horizontal, 16)
                    }
                    if m.oldFirmware {
                        Text("Health badges need KEY firmware 11s or later.").font(Brand.small).foregroundStyle(Brand.grey).padding(.horizontal, 16)
                    }
                    Text("Health is scored on the KEY when a password is saved or imported; Check breaches scores older entries too, 24 per unlock. The breach check sends Have I Been Pwned the first 5 characters of a password's hash and nothing else; the KEY does the matching.")
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
            .toolbarBackground(Brand.bg, for: .navigationBar)
            .toolbar {
                if !pushed { ToolbarItem(placement: .cancellationAction) { Button("Done") { m.close(); dismiss() }.font(Brand.button).foregroundStyle(Brand.brass) } }
                if !m.entries.isEmpty && m.entries.contains(where: { $0.id != nil }) {
                    ToolbarItem(placement: .primaryAction) {
                        Button(selecting ? "Cancel" : "Select") { selecting.toggle(); selected = []; selStatus = "" }
                            .font(Brand.button).foregroundStyle(Brand.brass).disabled(!m.busy.isEmpty)
                    }
                }
            }
            .sheet(item: $picked) { p in AccountSheet(e: p.e, model: m) }
            .sheet(isPresented: $adding) { EntryEditor(entry: nil, model: m) { adding = false } }
            .sheet(item: $qr) { p in SetupKeyQR(prefill: p) }
            .onAppear { if m.entries.isEmpty { m.load() } }
            .onDisappear { m.close() }
    }

    private func toggle(_ key: String) {
        if selected.contains(key) { selected.remove(key) }
        else if selected.count < 20 { selected.insert(key) }
        else { selStatus = "Up to 20 at a time." }
    }

    /// Select mode: delete up to 20 at once, one question on the KEY.
    private var selectionBar: some View {
        let list = m.entries.filter { selected.contains(PickedAccount(e: $0).id) }
        return VStack(alignment: .leading, spacing: 10) {
            Button {
                selStatus = ""
                Task {
                    if let why = await m.delete(list) { selStatus = why }
                    else { selStatus = ""; selected = []; selecting = false }
                }
            } label: {
                Text(m.busy == "Deleting…" ? "WAITING FOR THE KEY…" : list.isEmpty ? "SELECT ACCOUNTS TO DELETE" : "DELETE \(list.count)")
                    .font(Brand.button).tracking(2)
                    .frame(maxWidth: .infinity, minHeight: 50)
                    .foregroundStyle(list.isEmpty ? Brand.grey : Brand.danger)
                    .background(Brand.card)
                    .clipShape(RoundedRectangle(cornerRadius: 12))
            }
            .disabled(list.isEmpty || !m.busy.isEmpty)
            if !m.asking.isEmpty { Text(m.asking).font(Brand.small).foregroundStyle(Brand.brass).fixedSize(horizontal: false, vertical: true) }
            if !selStatus.isEmpty { Text(selStatus).font(Brand.small).foregroundStyle(Brand.ink).fixedSize(horizontal: false, vertical: true) }
        }
        .padding(.horizontal, 16)
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
            Button { adding = true } label: {
                HStack(spacing: 6) { Image(systemName: "plus"); Text("Add an account") }
                    .font(Brand.small).foregroundStyle(Brand.brass)
            }
            .disabled(!m.busy.isEmpty)
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
    var selecting = false
    var selected = false
    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            if selecting {
                Image(systemName: selected ? "checkmark.circle.fill" : "circle")
                    .font(.system(size: 20)).foregroundStyle(selected ? Brand.brass : Brand.faint).padding(.top, 1)
            }
            details
        }
        .padding(.horizontal, 16).padding(.vertical, 12)
        .contentShape(Rectangle())
    }
    private var details: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .firstTextBaseline) {
                Text(e.site).font(Brand.font(16, .semibold)).foregroundStyle(Brand.ink).lineLimit(1)
                Spacer()
                if !selecting { Image(systemName: "chevron.right").font(.system(size: 13, weight: .semibold)).foregroundStyle(Brand.grey) }
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
    @State private var editing = false
    @State private var manageNote = ""
    @State private var checkNote = ""

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
                            if !h.checked { Line("Breach check pending", "Not scored yet. Check this one now, or Check breaches on the list for up to 24 at a time.", bad: false) }
                        }
                    }
                    if e.id != nil {
                        Button { checkOne() } label: {
                            HStack(spacing: 6) {
                                Image(systemName: "shield.lefthalf.filled")
                                Text(model.busy.hasPrefix("Checking") ? "Checking…" : "Check this one for breaches")
                            }
                            .font(Brand.small).foregroundStyle(Brand.brass)
                        }
                        .disabled(!model.busy.isEmpty)
                        if !checkNote.isEmpty { Text(checkNote).font(Brand.small).foregroundStyle(Brand.ink).fixedSize(horizontal: false, vertical: true) }
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

                    if e.id != nil {
                        Text("ON THE KEY").font(Brand.label).tracking(2).foregroundStyle(Brand.brass).padding(.top, 6)
                        VStack(alignment: .leading, spacing: 0) {
                            Button { editing = true } label: {
                                HStack {
                                    Text("Edit site, username, password or note").font(Brand.body).foregroundStyle(Brand.ink)
                                    Spacer()
                                    Image(systemName: "chevron.right").font(.system(size: 13, weight: .semibold)).foregroundStyle(Brand.grey)
                                }
                                .padding(.horizontal, 14).frame(minHeight: 50).contentShape(Rectangle())
                            }
                            .disabled(!model.busy.isEmpty)
                            Divider().overlay(Brand.line)
                            Button { deleteIt() } label: {
                                HStack {
                                    Text(model.busy == "Deleting…" ? "Waiting for the KEY…" : "Delete from the KEY").font(Brand.body).foregroundStyle(Brand.danger)
                                    Spacer()
                                }
                                .padding(.horizontal, 14).frame(minHeight: 50).contentShape(Rectangle())
                            }
                            .disabled(!model.busy.isEmpty)
                        }
                        .background(Brand.card)
                        .clipShape(RoundedRectangle(cornerRadius: 14))
                        if !model.asking.isEmpty && model.busy == "Deleting…" {
                            Text(model.asking).font(Brand.small).foregroundStyle(Brand.brass).fixedSize(horizontal: false, vertical: true)
                        }
                        if !manageNote.isEmpty { Text(manageNote).font(Brand.small).foregroundStyle(Brand.ink).fixedSize(horizontal: false, vertical: true) }
                        Text("Every change shows on the KEY first: hold ENTER there to make it, or press BACK. Nothing changes without that.")
                            .font(Brand.small).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true)
                    }
                }
                .padding(16)
            }
            .background(Brand.bg.ignoresSafeArea())
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Close") { dismiss() }.font(Brand.button).foregroundStyle(Brand.brass) } }
            .sheet(item: $qr) { p in SetupKeyQR(prefill: p) }
            .sheet(isPresented: $editing) { EntryEditor(entry: e, model: model) { editing = false; dismiss() } }
        }
        .preferredColorScheme(.dark)
        .onDisappear { code = "" }
    }

    private func deleteIt() {
        manageNote = ""
        Task {
            if let why = await model.delete([e]) { manageNote = why } else { dismiss() }
        }
    }

    private func checkOne() {
        checkNote = ""
        Task { checkNote = await model.checkOne(e) }
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

// MARK: - Add or edit an entry (11ax, issue #30)

/// The KEY shows the entry (NEW ENTRY or CHANGE ENTRY) and saves it on a held
/// ENTER. The password goes to the KEY encrypted on the app channel and is
/// never shown back: an edit with the password box empty keeps the old one.
struct EntryEditor: View {
    let entry: AppChannel.ListEntry?          // nil: a new entry
    @ObservedObject var model: AccountsModel
    let done: () -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var site = ""
    @State private var user = ""
    @State private var pass = ""
    @State private var note = ""
    @State private var reveal = false
    @State private var status = ""
    @State private var working = false

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    Text(entry == nil ? "New account" : "Edit account").font(Brand.font(20, .semibold)).foregroundStyle(Brand.ink)
                    field("SITE", text: $site, hint: "example.com", kind: .URL)
                    field("USERNAME", text: $user, hint: "you@example.com", kind: .emailAddress)
                    if entry != nil && (entry?.user ?? "").isEmpty {
                        Text("The KEY listed no username for this entry. What you type here replaces it; leave it empty only if the entry has none.")
                            .font(Brand.small).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true)
                    }
                    VStack(alignment: .leading, spacing: 6) {
                        Text("PASSWORD").font(Brand.label).tracking(2).foregroundStyle(Brand.brass)
                        HStack {
                            Group {
                                if reveal { TextField(entry == nil ? "Required" : "Leave empty to keep it", text: $pass) }
                                else { SecureField(entry == nil ? "Required" : "Leave empty to keep it", text: $pass) }
                            }
                            .textInputAutocapitalization(.never).autocorrectionDisabled()
                            .font(Brand.body).foregroundStyle(Brand.ink)
                            Button { reveal.toggle() } label: { Image(systemName: reveal ? "eye.slash" : "eye").foregroundStyle(Brand.grey) }
                                .accessibilityLabel(reveal ? "Hide password" : "Show password")
                        }
                        .padding(12).background(Brand.card).clipShape(RoundedRectangle(cornerRadius: 10))
                        if entry != nil {
                            Text("The KEY never sends a password back, so this box starts empty. Type a new one only to change it.")
                                .font(Brand.small).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true)
                        }
                    }
                    field("NOTE", text: $note, hint: entry == nil ? "Optional" : "Leave empty to keep it", kind: .default)
                    Text(sizeLine).font(Brand.small).foregroundStyle(overLimit ? Brand.danger : Brand.faint)

                    BrandButton(title: working ? "WAITING FOR THE KEY…" : (entry == nil ? "ADD TO THE KEY" : "SAVE ON THE KEY"), filled: !working) { save() }
                        .disabled(working || site.trimmingCharacters(in: .whitespaces).isEmpty || (entry == nil && pass.isEmpty))
                    if working && !model.asking.isEmpty {
                        Text(model.asking).font(Brand.small).foregroundStyle(Brand.brass).fixedSize(horizontal: false, vertical: true)
                    }
                    if !status.isEmpty { Text(status).font(Brand.small).foregroundStyle(Brand.ink).fixedSize(horizontal: false, vertical: true) }
                    Text("The KEY shows the entry and saves it only when you hold ENTER there. BACK cancels and nothing changes.")
                        .font(Brand.small).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true)
                }
                .padding(16)
            }
            .background(Brand.bg.ignoresSafeArea())
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() }.font(Brand.button).foregroundStyle(Brand.brass).disabled(working) } }
        }
        .preferredColorScheme(.dark)
        .interactiveDismissDisabled(working)
        .onAppear { if let e = entry, site.isEmpty { site = e.site; user = e.user } }
        .onDisappear { pass = "" }
    }

    private var bytes: Int { [site, user, pass, note].reduce(0) { $0 + $1.utf8.count } }
    private var overLimit: Bool { bytes > AppChannel.pwAllMax }
    private var sizeLine: String { "\(bytes) of \(AppChannel.pwAllMax) bytes the KEY holds per entry" }

    private func field(_ label: String, text: Binding<String>, hint: String, kind: UIKeyboardType) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(label).font(Brand.label).tracking(2).foregroundStyle(Brand.brass)
            TextField(hint, text: text)
                .keyboardType(kind).textInputAutocapitalization(.never).autocorrectionDisabled()
                .font(Brand.body).foregroundStyle(Brand.ink)
                .padding(12).background(Brand.card).clipShape(RoundedRectangle(cornerRadius: 10))
        }
    }

    private func save() {
        working = true
        status = ""
        let s = site.trimmingCharacters(in: .whitespaces), u = user.trimmingCharacters(in: .whitespaces)
        Task {
            let why = await model.save(id: entry?.id, site: s, user: u, pass: pass, note: note)
            working = false
            if let why { status = why; return }
            pass = ""
            done()
        }
    }
}
