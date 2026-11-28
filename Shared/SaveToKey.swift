// SaveToKey.swift - iOS's "save this password" onto the KEY (KEY 11bi, issue #38).
//
// iOS 26.2 hands the site, username and password after a form is sent. The
// app looks the login up in LIST: found, PW_SAVE with its id and flags bit0 so
// the KEY keeps the old password as "<site> (old)" (CHANGE ENTRY); not found,
// a new entry (NEW ENTRY). The KEY asks; the owner holds ENTER; PW_RESULT says
// how it went. The password crosses encrypted and is dropped when the sheet goes.

import AuthenticationServices
import SwiftUI

@MainActor
final class SaveJob: ObservableObject {
    enum Phase: Equatable { case connecting, reading, needUser, asking(change: Bool), saved(change: Bool), failed(String) }
    @Published var phase: Phase = .connecting
    let site: String
    /// A reset form has no username box, so iOS hands none over: the owner
    /// gives one (needUser) before the KEY is asked.
    @Published var user: String
    @Published var suggestions: [String] = []
    private var waiter: CheckedContinuation<Void, Never>?
    private var abandoned = false
    func confirmUser() { waiter?.resume(); waiter = nil }
    func abandon() { abandoned = true; confirmUser() }
    private var pass: String
    private var session: KeySession?

    private let isApp: Bool

    init(site: String, user: String, pass: String, isApp: Bool = false) {
        self.site = NewPassword.name(site, isApp: isApp)
        self.isApp = isApp
        self.user = user
        self.pass = pass
    }

    /// One request; if the link went while the sheet waited on the owner (nothing
    /// was sent), once more on a new session.
    private func ask(_ cmd: UInt8, _ body: Data, timeout: TimeInterval) async throws -> AppChannel.Answer {
        if let s = session {
            do { return try await s.request(cmd, body, timeout: timeout) }
            catch { guard KeySession.neverSent(error) else { throw error }; s.close(); session = nil }
        }
        guard let c = Credentials.load() else { throw KeySession.Failure("Pair the app with the KEY first: open Favilla and follow Your KEY.") }
        let s = KeySession(c)
        session = s
        try await s.open()
        return try await s.request(cmd, body, timeout: timeout)
    }

    func run() async {
        defer { pass = ""; session?.close(); session = nil }
        do {
            guard let c = Credentials.load() else { phase = .failed("Pair the app with the KEY first: open Favilla and follow Your KEY."); return }
            let s = KeySession(c)
            session = s
            try await s.open()
            phase = .reading
            // The login, if the KEY has it (site and username, as LIST shows them).
            var found: AppChannel.ListEntry?, start = 0
            var here: [AppChannel.ListEntry] = [], seen: [String: Int] = [:]
            // 11gm (issue #93): one site from the KEY (FIND), not its whole list.
            var paged = false
            switch try await ListCache.find(s, site: site, isApp: isApp) {
            case .hits(let h):
                here = h
                seen = await ListCache.usernames(s)
            case .refused(let st):
                phase = .failed(st == 0x04 ? "Saving to the KEY needs its VAULT mode. On the KEY choose VAULT, enter the VAULT PIN, then save again from the site." : AppChannel.pwStatusText(st))
                return
            case .old:
                paged = true
            }
            while paged {
                let a = try await s.request(AppChannel.cList, AppChannel.listBody(start: start, health: true), timeout: 35)
                if a.rsp == AppChannel.rErr {
                    phase = .failed(a.body.first == 0x04 ? "Saving to the KEY needs its VAULT mode. On the KEY choose VAULT, enter the VAULT PIN, then save again from the site." : AppChannel.pwStatusText(a.body.first ?? 0xFF))
                    return
                }
                let page = try AppChannel.parseList(a.body)
                for e in page.entries where !e.passkey && !e.site.hasSuffix(" (old)") {
                    if NewPassword.same(e.site, site, isApp: isApp) { here.append(e) }
                    if !e.user.isEmpty { seen[e.user, default: 0] += 1 }
                }
                if !page.more || page.entries.isEmpty { break }
                start += page.entries.count
            }
            if user.isEmpty {
                if here.count == 1 {
                    user = here[0].user          // the site's one login: this is its new password
                } else {
                    suggestions = UsernameField.suggest(here.map { $0.user }, seen)
                    phase = .needUser
                    await withCheckedContinuation { waiter = $0 }
                    if abandoned { return }
                    user = user.trimmingCharacters(in: .whitespaces)
                    phase = .reading
                }
            }
            found = here.first { $0.user.lowercased() == user.lowercased() }
            let change = found?.id != nil
            var flags: UInt8? = change ? 0x01 : nil
            for _ in 0..<2 {
                let body: Data
                switch AppChannel.pwSaveBody(id: found?.id, site: found?.site ?? site, user: user, pass: pass, note: "", flags: flags) {
                case .success(let b): body = b
                case .failure(let p): phase = .failed(AppChannel.pwProblemText(p)); return
                }
                let a = try await ask(AppChannel.cPwSave, body, timeout: 10)
                let st = a.rsp == AppChannel.rAck ? (a.body.first ?? 0xFF) : 0xFF
                if a.rsp == AppChannel.rErr { phase = .failed(a.body.first == 0x04 ? "Saving to the KEY needs its VAULT mode." : AppChannel.pwStatusText(a.body.first ?? 0xFF)); return }
                if st == 0x07, flags != nil { flags = nil; continue }   // a KEY before 11bi: save without keeping the old one
                guard st == 0x00 else { phase = .failed(AppChannel.pwStatusText(st)); return }
                break
            }
            phase = .asking(change: change)
            // The KEY's answer: up to 90 s for its home screen plus 60 s on the question.
            let until = Date().addingTimeInterval(170)
            while Date() < until {
                try await Task.sleep(nanoseconds: 1_000_000_000)
                let a = try await ask(AppChannel.cPwResult, Data(), timeout: 6)
                guard a.rsp == AppChannel.rAck, let r = AppChannel.parsePwResult(a.body) else { continue }
                switch r.state {
                case 0x00: continue
                case 0x01:
                    // iOS can ask again for the same form: that one is skipped.
                    NewPassword.recordFill(site: site, user: user, password: pass)
                    phase = .saved(change: change); return
                case 0x02: phase = .failed("Cancelled on the KEY. Nothing was saved."); return
                case 0x03: phase = .failed("No answer on the KEY in time. Nothing was saved."); return
                case 0x04: phase = .failed("That login changed on the KEY meanwhile. Nothing was saved."); return
                case 0x05:
                    phase = .failed(r.reason == 0x17
                        ? "An old copy of this login is already waiting on the KEY. Finish it first (open Favilla's Accounts and tap It works, or on the KEY the copy's MORE: NEW ONE WORKS), then save again."
                        : AppChannel.pwFailedText(r.reason))
                    return
                default: phase = .failed("The KEY lost the request. Nothing was saved."); return
                }
            }
            phase = .failed("No answer on the KEY in time. Nothing was saved.")
        } catch {
            phase = .failed("\(error)")
        }
    }
}

struct SaveToKeyView: View {
    @ObservedObject var job: SaveJob
    var onDone: () -> Void
    var onCancel: () -> Void

    private var headline: String {
        switch job.phase {
        case .connecting, .reading: return "Connecting to your KEY"
        case .needUser: return "Which username?"
        case .asking(let change): return change ? "Save the new password on your KEY" : "Save the new login on your KEY"
        case .saved: return "Saved on your KEY"
        case .failed: return "Not saved"
        }
    }

    private var steps: [(String, Int)] {
        let connected: Bool, asked: Bool, done: Bool
        switch job.phase {
        case .connecting: (connected, asked, done) = (false, false, false)
        case .reading, .needUser: (connected, asked, done) = (true, false, false)
        case .asking: (connected, asked, done) = (true, true, false)
        case .saved: (connected, asked, done) = (true, true, true)
        case .failed: (connected, asked, done) = (false, false, false)
        }
        let change: Bool = { if case .asking(let c) = job.phase { return c }; if case .saved(let c) = job.phase { return c }; return false }()
        return [("Connected to your KEY", connected ? 2 : 1),
                (change ? "CHANGE ENTRY on the KEY: hold ENTER" : "NEW ENTRY on the KEY: hold ENTER", done ? 2 : (asked ? 1 : 0)),
                (change ? "The old password is kept as an (old) copy" : "Favilla offers it at your next sign-in", done ? 2 : 0)]
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack {
                Lockup(mark: 22, word: 15)
                Spacer()
                if case .saved = job.phase {} else {
                    Button("Cancel") { job.abandon(); onCancel() }.font(Brand.body).foregroundStyle(Brand.grey).frame(minHeight: 44)
                }
            }
            Text(headline).font(Brand.headline).foregroundStyle(Brand.ink)
            if job.phase != .needUser { siteCard }

            if case .failed(let why) = job.phase {
                Text(why).font(Brand.body).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true)
            } else if job.phase == .needUser {
                // The card scrolls with the box, so the box and the usernames to
                // tap stay reachable above the keyboard.
                ScrollView(showsIndicators: false) {
                    VStack(alignment: .leading, spacing: 18) {
                        siteCard
                        UsernameField(text: $job.user, suggestions: job.suggestions)
                        Text("This form didn't give a username. The KEY saves the login under the one you put here.")
                            .font(Brand.small).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true)
                    }
                }
                .scrollDismissesKeyboard(.interactively)
            } else {
                VStack(alignment: .leading, spacing: 14) {
                    ForEach(Array(steps.enumerated()), id: \.offset) { _, s in StepRow(text: s.0, state: s.1) }
                }
                .padding(.horizontal, 2)
                if case .asking(true) = job.phase {
                    Text("Once you've signed in with the new password, open Favilla's Accounts and tap It works: the KEY then drops the old copy.")
                        .font(Brand.small).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true)
                }
            }
            Spacer()
            switch job.phase {
            case .needUser:
                BrandButton(title: "SAVE ON THE KEY", filled: true) { job.confirmUser() }
                    .disabled(job.user.trimmingCharacters(in: .whitespaces).isEmpty)
            case .saved: BrandButton(title: "DONE", filled: true, action: onDone)
            case .failed: BrandButton(title: "CLOSE", filled: false, action: onCancel)
            default: EmptyView()
            }
        }
        .padding(20)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(Brand.bg)
    }

    private var siteCard: some View {
            VStack(alignment: .leading, spacing: 8) {
                Text("SAVING FOR").font(Brand.label).tracking(2).foregroundStyle(Brand.grey)
                Text(job.site).font(Brand.font(30, .bold)).foregroundStyle(Brand.ink).lineLimit(2).minimumScaleFactor(0.6)
                if !job.user.isEmpty, job.phase != .needUser { Text("as \(job.user)").font(Brand.body).foregroundStyle(Brand.grey) }
            }
            .padding(20)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Brand.card)
            .clipShape(RoundedRectangle(cornerRadius: 14))
    }
}

/// The username for a login about to be saved: a box that reads as a box, and
/// the usernames the KEY already holds to tap instead of typing.
struct UsernameField: View {
    @Binding var text: String
    var suggestions: [String]

    /// This site's usernames first, then the KEY's three most used.
    static func suggest(_ site: [String], _ seen: [String: Int]) -> [String] {
        var out: [String] = []
        let common = seen.sorted { $0.value == $1.value ? $0.key < $1.key : $0.value > $1.value }.prefix(3).map { $0.key }
        for u in site + common where !u.isEmpty && !out.contains(where: { $0.lowercased() == u.lowercased() }) { out.append(u) }
        return Array(out.prefix(4))
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("USERNAME OR EMAIL").font(Brand.label).tracking(2).foregroundStyle(Brand.brass)
            // verbatim: a literal email in a Text is made a link (and drawn blue).
            TextField("", text: $text, prompt: Text(verbatim: "you@example.com").foregroundColor(Brand.grey))
                .keyboardType(.emailAddress).textInputAutocapitalization(.never).autocorrectionDisabled()
                .textContentType(.username)
                .font(Brand.body).foregroundStyle(Brand.ink)
                .padding(.horizontal, 14).frame(minHeight: 48)
                .background(Brand.bg)
                .clipShape(RoundedRectangle(cornerRadius: 10))
                .overlay(RoundedRectangle(cornerRadius: 10).stroke(Brand.brass.opacity(0.6), lineWidth: 1))
            // The KEY's own usernames as chips (21 Nov: as rows with a circle
            // they read as more logins to choose between).
            if !suggestions.isEmpty {
                Text("Or tap one your KEY already has").font(Brand.small).foregroundStyle(Brand.grey).padding(.top, 2)
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 8) {
                        ForEach(suggestions, id: \.self) { u in
                            let on = text.lowercased() == u.lowercased()
                            Button { text = u } label: {
                                Text(verbatim: u).font(Brand.font(14, .semibold)).foregroundStyle(on ? Brand.bg : Brand.ink).lineLimit(1)
                                    .padding(.horizontal, 14).frame(minHeight: 40)
                                    .background(on ? Brand.brass : Color.clear)
                                    .clipShape(Capsule())
                                    .overlay(Capsule().stroke(on ? Color.clear : Brand.grey.opacity(0.6), lineWidth: 1))
                            }
                            .accessibilityLabel("Use \(u)")
                        }
                    }
                    .padding(.vertical, 2)
                }
            }
        }
    }
}
