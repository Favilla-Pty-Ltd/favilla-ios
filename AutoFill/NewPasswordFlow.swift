// NewPasswordFlow.swift - a new password from the AutoFill sheet, run by the app
// (18 Nov 2026 rethink: the app does the work, the KEY only asks for ENTER).
//
// From the sign-in sheet: NEW PASSWORD FOR THIS SITE. The app reads the KEY's
// list for the site's logins, the owner picks which one changes (or a new
// login), and the app does the rest over the app channel: GEN_PW (the KEY
// makes the password), PW_SAVE with the keep-the-old-one flag (the KEY shows
// CHANGE ENTRY or NEW ENTRY: hold ENTER), PW_RESULT. Then the login goes to
// iOS, which fills the form's first password box, and the password is copied
// (this iPhone only, 60 s) for a confirm box, which iOS won't fill.

import SwiftUI
import UIKit

@MainActor
final class ChangeJob: ObservableObject {
    enum Phase: Equatable { case reading, choose, making, asking(change: Bool), done(change: Bool), failed(String) }
    @Published var phase: Phase = .reading
    @Published var matches: [AppChannel.ListEntry] = []
    // pick (below): an index into matches; matches.count = a new login
    @Published var newUser = ""
    @Published var plain = false       // letters and digits only, for sites that refuse symbols
    /// iOS puts a login into the form's first password box, whichever box was
    /// tapped. Right for a sign-up; wrong for a change form whose first box is
    /// the current password. So a change is copied only (paste into the boxes
    /// you choose) and a new login is filled, unless the owner sets otherwise.
    @Published var fillFirst = false { didSet { if fillFirst != oldValue { ChangeJob.store.set(fillFirst, forKey: isNew ? "fillOnNew" : "fillOnChange") } } }
    @Published var pick = 0 { didSet { fillFirst = ChangeJob.fillDefault(new: isNew) } }
    private static let store = UserDefaults(suiteName: "group.io.favillakey.app") ?? .standard
    static func fillDefault(new: Bool) -> Bool { (store.object(forKey: new ? "fillOnNew" : "fillOnChange") as? Bool) ?? new }
    static let copySeconds: TimeInterval = 120
    let site: String
    private var session: KeySession?
    private(set) var result: (user: String, password: String)?

    init(site: String) { self.site = site }

    var isNew: Bool { pick >= matches.count }
    var user: String { isNew ? newUser.trimmingCharacters(in: .whitespaces) : matches[pick].user }

    private static func vaultOnly(_ st: UInt8) -> String {
        st == 0x04 ? "New passwords need the KEY's VAULT mode. On the KEY choose VAULT and enter the VAULT PIN, then try again." : AppChannel.pwStatusText(st)
    }

    /// Connect and find this site's logins on the KEY.
    func load() async {
        do {
            guard let c = Credentials.load() else { phase = .failed("Pair the app with the KEY first: open Favilla and follow Your KEY."); return }
            let s = KeySession(c)
            session = s
            try await s.open()
            var found: [AppChannel.ListEntry] = [], start = 0, busy = 0
            let want = NewPassword.host(site)
            while true {
                let a = try await s.request(AppChannel.cList, AppChannel.listBody(start: start), timeout: 35)
                if a.rsp == AppChannel.rErr, a.body.first == 0x06, busy < 10 {
                    // The KEY's login picker (from the sign-in sheet) is still closing.
                    busy += 1
                    try await Task.sleep(nanoseconds: 1_000_000_000)
                    continue
                }
                if a.rsp == AppChannel.rErr { phase = .failed(ChangeJob.vaultOnly(a.body.first ?? 0xFF)); close(); return }
                let page = try AppChannel.parseList(a.body)
                found += page.entries.filter { !$0.passkey && $0.id != nil && !$0.site.hasSuffix(" (old)") && NewPassword.host($0.site) == want }
                if !page.more || page.entries.isEmpty { break }
                start += page.entries.count
            }
            matches = found
            pick = 0
            phase = .choose
        } catch {
            phase = .failed("\(error)")
            close()
        }
    }

    /// The KEY makes the password and saves it: the owner holds ENTER.
    func make() async {
        guard phase == .choose else { return }
        let change = !isNew
        let user = self.user
        phase = .making
        do {
            guard let s = session else { phase = .failed("The link to the KEY closed. Try again."); return }
            // 1. The password, from the KEY's generator.
            var rules = NewPassword.Rules()
            if plain { rules.required = 0x07; rules.allowed = 0x07 }
            let g = try await s.request(AppChannel.cGenPw, NewPassword.genBody(rules, kind: plain ? 0x02 : 0x01), timeout: 8)
            if g.rsp == AppChannel.rErr {
                phase = .failed(g.body.first == 0x07 ? "This KEY can't make passwords for the app yet: it needs firmware 11bi." : ChangeJob.vaultOnly(g.body.first ?? 0xFF)); close(); return
            }
            guard g.rsp == AppChannel.rGenPw else { phase = .failed("The KEY's answer couldn't be read."); close(); return }
            let pass: String
            switch NewPassword.parseGen(g.body) {
            case .success(let p): pass = p
            case .failure(.status(let st)): phase = .failed(NewPassword.genText(st)); close(); return
            }
            // 2. Save it: CHANGE ENTRY keeping the old one as (old), or NEW ENTRY.
            let entry = change ? matches[pick] : nil
            let body: Data
            switch AppChannel.pwSaveBody(id: entry?.id, site: entry?.site ?? NewPassword.host(site), user: user, pass: pass, note: "", flags: change ? 0x01 : nil) {
            case .success(let b): body = b
            case .failure(let p): phase = .failed(AppChannel.pwProblemText(p)); close(); return
            }
            let a = try await s.request(AppChannel.cPwSave, body, timeout: 10)
            if a.rsp == AppChannel.rErr { phase = .failed(ChangeJob.vaultOnly(a.body.first ?? 0xFF)); close(); return }
            guard a.rsp == AppChannel.rAck, a.body.first == 0x00 else { phase = .failed(AppChannel.pwStatusText(a.body.first ?? 0xFF)); close(); return }
            phase = .asking(change: change)
            // 3. The KEY's answer.
            let until = Date().addingTimeInterval(170)
            while Date() < until {
                try await Task.sleep(nanoseconds: 1_000_000_000)
                let r0 = try await s.request(AppChannel.cPwResult, Data(), timeout: 6)
                guard r0.rsp == AppChannel.rAck, let r = AppChannel.parsePwResult(r0.body) else { continue }
                switch r.state {
                case 0x00: continue
                case 0x01:
                    result = (user, pass)
                    // For the boxes iOS won't fill: this iPhone only, cleared in two minutes.
                    UIPasteboard.general.setItems([[UIPasteboard.typeAutomatic: pass]],
                                                  options: [.localOnly: true, .expirationDate: Date().addingTimeInterval(ChangeJob.copySeconds)])
                    phase = .done(change: change)
                    close(); return
                case 0x02: phase = .failed("Cancelled on the KEY. Nothing was changed."); close(); return
                case 0x03: phase = .failed("No answer on the KEY in time. Nothing was changed."); close(); return
                case 0x05:
                    phase = .failed(r.reason == 0x17
                        ? "An earlier change to this login is still waiting. In Favilla's Accounts tap New one works for it (or put the old one back on the KEY), then try again."
                        : AppChannel.pwStatusText(r.reason))
                    close(); return
                default: phase = .failed("The KEY lost the request. Nothing was changed."); close(); return
                }
            }
            phase = .failed("No answer on the KEY in time. Nothing was changed.")
            close()
        } catch {
            phase = .failed("\(error)")
            close()
        }
    }

    func close() { session?.close(); session = nil }
}

struct NewPasswordView: View {
    @ObservedObject var job: ChangeJob
    var onCancel: () -> Void

    private var headline: String {
        switch job.phase {
        case .reading: return "Connecting to your KEY"
        case .choose: return "New password"
        case .making: return "Your KEY is making it"
        case .asking: return "Hold ENTER on your KEY"
        case .done: return "Saved on your KEY"
        case .failed: return "No new password"
        }
    }

    private var steps: [(String, Int)] {
        let stage: Int
        var change = !job.isNew
        switch job.phase {
        case .making: stage = 0
        case .asking(let c): stage = 1; change = c
        case .done(let c): stage = 3; change = c
        default: stage = -1
        }
        return [("The KEY makes the password", stage > 0 ? 2 : (stage == 0 ? 1 : 0)),
                (change ? "CHANGE ENTRY on the KEY: hold ENTER" : "NEW ENTRY on the KEY: hold ENTER", stage > 1 ? 2 : (stage == 1 ? 1 : 0)),
                (job.fillFirst ? "Filled in, and copied for a confirm box" : "Copied: paste it into the boxes you choose", stage > 2 ? 2 : 0)]
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack {
                Lockup(mark: 22, word: 15)
                Spacer()
                if case .done = job.phase {} else {
                    Button("Cancel", action: onCancel).font(Brand.body).foregroundStyle(Brand.grey).frame(minHeight: 44)
                }
            }
            Text(headline).font(Brand.headline).foregroundStyle(Brand.ink)
            VStack(alignment: .leading, spacing: 8) {
                Text("NEW PASSWORD FOR").font(Brand.label).tracking(2).foregroundStyle(Brand.grey)
                Text(NewPassword.host(job.site)).font(Brand.font(30, .bold)).foregroundStyle(Brand.ink).lineLimit(2).minimumScaleFactor(0.6)
                if job.phase != .reading, job.phase != .choose, !job.user.isEmpty {
                    Text("as \(job.user)").font(Brand.body).foregroundStyle(Brand.grey)
                }
            }
            .padding(20)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Brand.card)
            .clipShape(RoundedRectangle(cornerRadius: 14))

            switch job.phase {
            case .reading:
                HStack(spacing: 10) { ProgressView().tint(Brand.brass); Text("Reading this site's logins from the KEY").font(Brand.body).foregroundStyle(Brand.grey) }
            case .choose: chooser
            case .failed(let why):
                Text(why).font(Brand.body).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true)
            default:
                VStack(alignment: .leading, spacing: 14) {
                    ForEach(Array(steps.enumerated()), id: \.offset) { _, s in StepRow(text: s.0, state: s.1) }
                }
                .padding(.horizontal, 2)
                if case .asking(true) = job.phase {
                    Text("The KEY keeps the old password until you tell Favilla the new one works.")
                        .font(Brand.small).foregroundStyle(Brand.faint).fixedSize(horizontal: false, vertical: true)
                }
                if case .done = job.phase {
                    Text(job.fillFirst
                         ? "The form's first password box fills now. For a confirm box, tap it and choose Paste. The copy stays on this iPhone and clears in 2 minutes."
                         : "Tap the new password box and choose Paste. Do the same in the confirm box. The copy stays on this iPhone and clears in 2 minutes.")
                        .font(Brand.small).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true)
                }
            }
            Spacer()
            switch job.phase {
            case .choose:
                BrandButton(title: job.isNew ? "MAKE THE LOGIN ON THE KEY" : "CHANGE IT ON THE KEY", filled: true) { Task { await job.make() } }
                    .disabled(job.isNew && job.user.isEmpty)
            case .failed: BrandButton(title: "CLOSE", filled: false, action: onCancel)
            default: EmptyView()
            }
        }
        .padding(20)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(Brand.bg)
    }

    /// Which login gets the new password, or a new login for the site.
    private var chooser: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(job.matches.isEmpty ? "NEW LOGIN" : "WHICH LOGIN").font(Brand.label).tracking(2).foregroundStyle(Brand.brass)
            VStack(alignment: .leading, spacing: 0) {
                ForEach(Array(job.matches.enumerated()), id: \.offset) { i, e in
                    choice(i, title: e.user.isEmpty ? "(no username)" : e.user, sub: "Change this login's password")
                    Divider().overlay(Brand.line)
                }
                choice(job.matches.count, title: "A new login", sub: "For signing up to this site")
                if job.isNew {
                    TextField("Username or email", text: $job.newUser)
                        .keyboardType(.emailAddress).textInputAutocapitalization(.never).autocorrectionDisabled()
                        .font(Brand.body).foregroundStyle(Brand.ink)
                        .padding(12).background(Brand.bg).clipShape(RoundedRectangle(cornerRadius: 10))
                        .padding([.horizontal, .bottom], 14)
                }
            }
            .background(Brand.card)
            .clipShape(RoundedRectangle(cornerRadius: 14))
            Toggle(isOn: $job.plain) {
                Text("Letters and digits only").font(Brand.body).foregroundStyle(Brand.ink)
            }
            .tint(Brand.brass)
            Text("20 characters from the KEY's generator. Turn this on for a site that refuses symbols.")
                .font(Brand.small).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true)
            Toggle(isOn: $job.fillFirst) {
                Text("Fill the form's first password box").font(Brand.body).foregroundStyle(Brand.ink)
            }
            .tint(Brand.brass)
            Text("iPhone always fills a form's first password box, whichever box you tapped. Off: the password is copied and you paste it into the boxes you choose.")
                .font(Brand.small).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true)
        }
    }

    private func choice(_ i: Int, title: String, sub: String) -> some View {
        Button { job.pick = i } label: {
            HStack(spacing: 12) {
                Image(systemName: job.pick == i ? "largecircle.fill.circle" : "circle")
                    .font(.system(size: 20)).foregroundStyle(job.pick == i ? Brand.brass : Brand.faint)
                VStack(alignment: .leading, spacing: 2) {
                    Text(title).font(Brand.body).foregroundStyle(Brand.ink).lineLimit(1)
                    Text(sub).font(Brand.small).foregroundStyle(Brand.grey)
                }
                Spacer()
            }
            .padding(.horizontal, 14).frame(minHeight: 56).contentShape(Rectangle())
        }
    }
}
