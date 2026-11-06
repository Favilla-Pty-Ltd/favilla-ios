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
}

struct SignInView: View {
    @ObservedObject var link: KeyLink
    var purpose: SheetPurpose = .password
    /// The account, when iOS told us which one (a listed account, or a passkey being made).
    var user: String = ""
    /// Shown instead of a request (something iOS asked for that the KEY can't do).
    var notice: String?
    var onRetry: () -> Void = {}
    var onClose: () -> Void

    private var creating: Bool { if case .passkeyCreate = purpose { return true }; return false }
    private var failed: String? { if case .failed(let w)? = link.outcome { return w }; return nil }

    private var place: String {
        switch purpose {
        case .password: return KeyLink.cleanSite(link.site) ?? link.site
        case .passkeySignIn(let rp), .passkeyCreate(let rp, _): return rp
        }
    }

    private var headline: String {
        if notice != nil { return "Not available yet" }
        if link.pairing { return "Check the code on your KEY" }
        switch link.outcome {
        case .answer?, .ctap?: return creating ? "Passkey made" : "Signed in"
        case .failed?: return creating ? "No passkey made" : "Not signed in"
        case .cancelled?: return "Cancelled"
        default:
            if link.waitingOnKey { return purpose == .password ? "Choose the login on your KEY" : "Approve on your KEY" }
            return "Connecting to your KEY"
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
        }
        let third = creating ? "The site saves your passkey" : "Safari signs you in"
        return [("Connected to your KEY", connected ? 2 : 1),
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
                Text(creating ? "MAKING A PASSKEY FOR" : "SIGNING IN TO").font(Brand.label).tracking(2).foregroundStyle(Brand.grey)
                Text(place).font(Brand.font(30, .bold)).foregroundStyle(Brand.ink).lineLimit(2).minimumScaleFactor(0.6)
                if !user.isEmpty { Text("as \(user)").font(Brand.body).foregroundStyle(Brand.grey) }
            }
            .padding(20)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Brand.card)
            .clipShape(RoundedRectangle(cornerRadius: 14))

            if let n = notice {
                Text(n).font(Brand.body).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true)
            } else if link.pairing {
                Text("This iPhone isn't paired with the KEY yet. If the numbers in iOS's prompt match the KEY's screen, tap Pair, then press ENTER on the KEY. PAIR A PHONE must be open on the KEY.")
                    .font(Brand.body).foregroundStyle(Brand.brass).fixedSize(horizontal: false, vertical: true)
            } else if let why = failed {
                Text(why).font(Brand.body).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true)
                LogBox(lines: link.lines, maxHeight: 160)
            } else {
                VStack(alignment: .leading, spacing: 14) {
                    ForEach(Array(steps.enumerated()), id: \.offset) { _, s in StepRow(text: s.0, state: s.1) }
                }
                .padding(.horizontal, 2)
            }

            Spacer()
            if notice == nil {
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

private struct StepRow: View {
    let text: String
    let state: Int   // 0 to do, 1 now, 2 done

    var body: some View {
        HStack(spacing: 12) {
            ZStack {
                if state == 2 {
                    Circle().fill(Brand.brass)
                    Image(systemName: "checkmark").font(.system(size: 11, weight: .bold)).foregroundStyle(Brand.bg)
                } else {
                    Circle().strokeBorder(state == 1 ? Brand.brass : Brand.line, lineWidth: 2)
                    if state == 1 { Circle().fill(Brand.brass).frame(width: 8, height: 8) }
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
    var isReply: Bool { switch self { case .answer, .ctap: return true; default: return false } }
}
