// SignInView.swift - the AutoFill sheet (mockups 1b and 3b, 6 Nov 2026).
//
//  - Passwords (KEY 9c): the sheet asks the KEY for the site's login and stays
//    open while the owner picks it on the KEY; iOS fills the fields.
//  - Passkeys (KEY 9a): the sheet stays open while the KEY shows the site and
//    waits for a press, then hands the KEY's signature to iOS.
// The site name is the largest thing on the sheet: it is what the owner checks
// against the KEY's screen.

import SwiftUI

enum SheetPurpose: Equatable {
    case password
    case passkeySignIn(rp: String)
    case passkeyCreate(rp: String, user: String)
    case oneTimeCode
}

struct SignInView: View {
    @ObservedObject var link: KeyLink
    var purpose: SheetPurpose = .password
    /// The account, when iOS told us which one (a listed account, or a passkey being made).
    var user: String = ""
    /// Shown instead of a request (something iOS asked for that the KEY can't do).
    var notice: String?
    var onRetry: () -> Void = {}
    /// Passwords and codes, when iOS named nothing the KEY can take: the owner
    /// types the app's name and this sends it.
    var onName: ((String) -> Void)? = nil
    @State private var typed = ""
    @FocusState private var typing: Bool
    /// Passwords only: the app-run change (NEW PASSWORD FOR THIS SITE).
    var onNewPassword: (() -> Void)? = nil
    var onClose: () -> Void

    private var creating: Bool { if case .passkeyCreate = purpose { return true }; return false }
    private var failed: String? { if case .failed(let w)? = link.outcome { return w }; return nil }

    private var place: String {
        switch purpose {
        case .password, .oneTimeCode: return (link.siteIsAppName ? KeyLink.cleanAppName(link.site) : KeyLink.cleanSite(link.site)) ?? link.site
        case .passkeySignIn(let rp), .passkeyCreate(let rp, _): return rp
        }
    }

    /// iOS gave no name the KEY can use, and the owner can type one.
    private var nameless: Bool {
        guard notice == nil, onName != nil, purpose == .password || purpose == .oneTimeCode else { return false }
        return KeyLink.siteBytes(site: link.site, appName: link.siteIsAppName) == nil
    }
    private func sendName() {
        guard let n = KeyLink.cleanAppName(typed) else { return }
        typing = false
        onName?(n)
    }

    private var headline: String {
        if notice != nil { return "Not available yet" }
        if nameless { return "Which app is this?" }
        if link.pairing { return "Check the code on your KEY" }
        switch link.outcome {
        case .otp?: return "Code sent"
        case .answer?, .ctap?: return creating ? "Passkey made" : "Signed in"
        case .failed?: return creating ? "No passkey made" : "Not signed in"
        case .cancelled?: return "Cancelled"
        default:
            if link.waitingOnKey {
                switch purpose {
                case .password: return "Choose the login on your KEY"
                case .oneTimeCode: return "Choose the code on your KEY"
                default: return "Approve on your KEY"
                }
            }
            return link.securing ? "Connecting securely" : "Connecting to your KEY"
        }
    }

    /// What the KEY's screen shows while the sheet waits on it.
    private var onKey: String {
        switch purpose {
        case .password: return "It shows the login for this site. Press ENTER there."
        case .oneTimeCode: return "It shows the code for this site. Press ENTER there."
        case .passkeySignIn: return "It shows the site. Press ENTER there to sign in."
        case .passkeyCreate: return "It shows the site. Press ENTER there to make the passkey."
        }
    }

    private var steps: [(String, Int)] {   // 0 to do, 1 now, 2 done
        let connected = link.waitingOnKey || link.outcome?.isReply == true
        let done = link.outcome?.isReply == true
        let second: String
        switch purpose {
        case .password: second = "Pick the login on the KEY, press ENTER"
        case .passkeySignIn: second = "Check the site on the KEY, press to sign in"
        case .passkeyCreate: second = "Check the site on the KEY, press to make it"
        case .oneTimeCode: second = "Pick the code on the KEY, press ENTER"
        }
        let third = creating ? "The site saves your passkey" : purpose == .oneTimeCode ? "iOS fills in the code" : "Safari signs you in"
        return [(connected ? "Connected to your KEY" : link.securing ? "Connecting securely to your KEY" : "Connecting to your KEY", connected ? 2 : 1),
                (second, done ? 2 : (connected ? 1 : 0)),
                (third, done ? 2 : 0)]
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack {
                Lockup(mark: 22, word: 15)
                Spacer()
                Button("Close", action: onClose).font(Brand.body).foregroundStyle(Brand.grey).frame(minHeight: 44)
            }
            Text(headline).font(Brand.headline).foregroundStyle(Brand.ink)

            VStack(alignment: .leading, spacing: 8) {
                Text(creating ? "MAKING A PASSKEY FOR" : purpose == .oneTimeCode ? "ONE-TIME CODE FOR" : "SIGNING IN TO").font(Brand.label).tracking(2).foregroundStyle(Brand.grey)
                if nameless {
                    TextField("", text: $typed, prompt: Text("App or site name").foregroundColor(Brand.grey))
                        .font(Brand.font(24, .bold)).foregroundStyle(Brand.ink).tint(Brand.brass)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                        .submitLabel(.go).focused($typing).onSubmit(sendName)
                        .frame(minHeight: 44)
                        .onAppear { typing = true }
                } else {
                    Text(place).font(Brand.font(30, .bold)).foregroundStyle(Brand.ink).lineLimit(2).minimumScaleFactor(0.6)
                }
                if !user.isEmpty { Text("as \(user)").font(Brand.body).foregroundStyle(Brand.grey) }
            }
            .padding(20)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Brand.card)
            .clipShape(RoundedRectangle(cornerRadius: 14))

            if let n = notice {
                Text(n).font(Brand.body).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true)
            } else if nameless {
                Text("iOS didn't give Favilla a name the KEY can use for this app. Type the name it is saved under on your KEY. If nothing matches, the KEY offers all your logins and can save this name on the one you pick.")
                    .font(Brand.body).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true)
                Text("What iOS gave: \(link.given.isEmpty ? "nothing" : link.given)")
                    .font(Brand.small).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true)
            } else if link.pairing {
                WaitCard(title: "Check your KEY", detail: "This iPhone isn't paired with it yet. If the numbers in iOS's prompt match the KEY's screen, tap Pair, then press ENTER on the KEY. PAIR A PHONE must be open on the KEY.")
            } else if let why = failed {
                Text(why).font(Brand.body).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true)
                LogBox(lines: link.lines, maxHeight: 160)
            } else {
                VStack(alignment: .leading, spacing: 14) {
                    ForEach(Array(steps.enumerated()), id: \.offset) { _, s in StepRow(text: s.0, state: s.1) }
                }
                .padding(.horizontal, 2)
                // Waiting on a press on the KEY: say so, name what it shows, and move (issue #59).
                if link.waitingOnKey, link.outcome == nil { WaitCard(title: "Check your KEY", detail: onKey) }
                if purpose == .password {
                    // Some apps fill only the field the sheet was opened from.
                    Text("Opened from the username box? Some apps fill only that field: tap the password box and pick Favilla again to fill both.")
                        .font(Brand.small).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true)
                }
            }

            if purpose == .password, notice == nil, !nameless, !link.pairing, link.outcome?.isReply != true, let go = onNewPassword {
                // Changing or making a password (also when the KEY has no login
                // for the site yet): the app runs it, the KEY only asks for ENTER.
                // A row that reads as a choice (21 Nov: on a reset form the plain
                // link under the sign-in steps was easy to miss).
                Button(action: go) {
                    HStack(spacing: 12) {
                        Image(systemName: "plus.circle").font(.system(size: 20, weight: .semibold)).foregroundStyle(Brand.brass)
                        VStack(alignment: .leading, spacing: 2) {
                            Text("New password for this site").font(Brand.font(15, .semibold)).foregroundStyle(Brand.ink)
                            Text("Signing up, or changing a password? The KEY makes it and saves it.")
                                .font(Brand.small).foregroundStyle(Brand.grey).multilineTextAlignment(.leading).fixedSize(horizontal: false, vertical: true)
                        }
                        Spacer(minLength: 4)
                        Image(systemName: "chevron.right").font(.system(size: 13, weight: .semibold)).foregroundStyle(Brand.grey)
                    }
                    .padding(14)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .overlay(RoundedRectangle(cornerRadius: 12).stroke(Brand.brass.opacity(0.5), lineWidth: 1))
                    .contentShape(Rectangle())
                }
                .padding(.top, 4)
            }

            Spacer()
            if nameless {
                BrandButton(title: "FIND ON KEY", filled: true, action: sendName)
                    .disabled(KeyLink.cleanAppName(typed) == nil)
                    .opacity(KeyLink.cleanAppName(typed) == nil ? 0.4 : 1)
            } else if notice == nil {
                if link.busy {
                    BrandButton(title: "CANCEL", filled: false) { link.cancel() }
                } else if failed != nil || link.outcome == .cancelled {
                    BrandButton(title: "TRY AGAIN", filled: true, action: onRetry)
                }
            }
        }
        .padding(20)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(Brand.bg)
    }
}

struct StepRow: View {
    let text: String
    let state: Int   // 0 to do, 1 now, 2 done

    var body: some View {
        HStack(spacing: 12) {
            ZStack {
                if state == 2 {
                    Circle().fill(Brand.brassFill)
                    Image(systemName: "checkmark").font(.system(size: 11, weight: .bold)).foregroundStyle(Brand.onBrass)
                } else if state == 1 {
                    TurningRing(size: 22)      // the running step turns, like the KEY's (issue #59)
                } else {
                    Circle().strokeBorder(Brand.line, lineWidth: 2)
                }
            }
            .frame(width: 22, height: 22)
            .accessibilityHidden(true)
            Text(text)
                .font(state == 1 ? Brand.font(15, .semibold) : Brand.body)
                .foregroundStyle(state == 1 ? Brand.ink : Brand.grey)   // faint fails 4.5:1 for body text
        }
        .accessibilityElement(children: .combine)
        .accessibilityValue(state == 2 ? "done" : state == 1 ? "now" : "next")
    }
}

extension KeyLink.Outcome {
    /// The KEY answered (password or passkey).
    var isReply: Bool { switch self { case .answer, .ctap, .otp: return true; default: return false } }
}
