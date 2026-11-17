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
    enum Phase: Equatable { case connecting, reading, asking(change: Bool), saved(change: Bool), failed(String) }
    @Published var phase: Phase = .connecting
    let site: String
    let user: String
    private var pass: String
    private var session: KeySession?

    init(site: String, user: String, pass: String) {
        self.site = NewPassword.host(site)
        self.user = user
        self.pass = pass
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
            scan: while true {
                let a = try await s.request(AppChannel.cList, AppChannel.listBody(start: start), timeout: 35)
                if a.rsp == AppChannel.rErr {
                    phase = .failed(a.body.first == 0x04 ? "Saving to the KEY needs its VAULT mode. On the KEY choose VAULT, enter the VAULT PIN, then save again from the site." : AppChannel.pwStatusText(a.body.first ?? 0xFF))
                    return
                }
                let page = try AppChannel.parseList(a.body)
                for e in page.entries where !e.passkey && !e.site.hasSuffix(" (old)") {
                    if NewPassword.host(e.site) == site && e.user.lowercased() == user.lowercased() { found = e; break scan }
                }
                if !page.more || page.entries.isEmpty { break }
                start += page.entries.count
            }
            let change = found?.id != nil
            var flags: UInt8? = change ? 0x01 : nil
            for _ in 0..<2 {
                let body: Data
                switch AppChannel.pwSaveBody(id: found?.id, site: found?.site ?? site, user: user, pass: pass, note: "", flags: flags) {
                case .success(let b): body = b
                case .failure(let p): phase = .failed(AppChannel.pwProblemText(p)); return
                }
                let a = try await s.request(AppChannel.cPwSave, body, timeout: 10)
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
                let a = try await s.request(AppChannel.cPwResult, Data(), timeout: 6)
                guard a.rsp == AppChannel.rAck, let r = AppChannel.parsePwResult(a.body) else { continue }
                switch r.state {
                case 0x00: continue
                case 0x01: phase = .saved(change: change); return
                case 0x02: phase = .failed("Cancelled on the KEY. Nothing was saved."); return
                case 0x03: phase = .failed("No answer on the KEY in time. Nothing was saved."); return
                case 0x04: phase = .failed("That login changed on the KEY meanwhile. Nothing was saved."); return
                case 0x05:
                    phase = .failed(r.reason == 0x17
                        ? "An old copy of this login is already waiting on the KEY. Finish it first (Accounts in Favilla, or the copy's MORE on the KEY: NEW ONE WORKS), then save again."
                        : AppChannel.pwStatusText(r.reason))
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
        case .asking(let change): return change ? "Save the new password on your KEY" : "Save the new login on your KEY"
        case .saved: return "Saved on your KEY"
        case .failed: return "Not saved"
        }
    }

    private var steps: [(String, Int)] {
        let connected: Bool, asked: Bool, done: Bool
        switch job.phase {
        case .connecting: (connected, asked, done) = (false, false, false)
        case .reading: (connected, asked, done) = (true, false, false)
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
                    Button("Cancel", action: onCancel).font(Brand.body).foregroundStyle(Brand.grey).frame(minHeight: 44)
                }
            }
            Text(headline).font(Brand.headline).foregroundStyle(Brand.ink)
            VStack(alignment: .leading, spacing: 8) {
                Text("SAVING FOR").font(Brand.label).tracking(2).foregroundStyle(Brand.grey)
                Text(job.site).font(Brand.font(30, .bold)).foregroundStyle(Brand.ink).lineLimit(2).minimumScaleFactor(0.6)
                if !job.user.isEmpty { Text("as \(job.user)").font(Brand.body).foregroundStyle(Brand.grey) }
            }
            .padding(20)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Brand.card)
            .clipShape(RoundedRectangle(cornerRadius: 14))

            if case .failed(let why) = job.phase {
                Text(why).font(Brand.body).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true)
            } else {
                VStack(alignment: .leading, spacing: 14) {
                    ForEach(Array(steps.enumerated()), id: \.offset) { _, s in StepRow(text: s.0, state: s.1) }
                }
                .padding(.horizontal, 2)
                if case .asking(true) = job.phase {
                    Text("Once the site has taken the new password, finish it in Favilla's Accounts: NEW ONE WORKS drops the old copy.")
                        .font(Brand.small).foregroundStyle(Brand.faint).fixedSize(horizontal: false, vertical: true)
                }
            }
            Spacer()
            switch job.phase {
            case .saved: BrandButton(title: "DONE", filled: true, action: onDone)
            case .failed: BrandButton(title: "CLOSE", filled: false, action: onCancel)
            default: EmptyView()
            }
        }
        .padding(20)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(Brand.bg)
    }
}
