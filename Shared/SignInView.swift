// SignInView.swift - the AutoFill sheet's screen.
//
//  - Passwords (KEY drop 9c): the sheet asks the KEY for the site's login and
//    stays open while the owner picks it on the KEY; iOS fills the fields.
//  - Passkeys (KEY drop 9a): the sheet stays open while the KEY shows the site
//    and waits for a press, then hands the KEY's signature to iOS.
// Type scale follows the probe screen: FAVILLA label 13 tracked, headline 22,
// body 15, button 14 tracked.

import SwiftUI

enum SheetPurpose: Equatable {
    case password
    case passkeySignIn(rp: String)
    case passkeyCreate(rp: String, user: String)
}

struct SignInView: View {
    @ObservedObject var link: KeyLink
    var purpose: SheetPurpose = .password
    /// Shown instead of a request (something iOS asked for that the KEY can't do).
    var notice: String?
    var onRetry: () -> Void = {}
    var onClose: () -> Void

    private var isPasskey: Bool { purpose != .password }
    private var creating: Bool { if case .passkeyCreate = purpose { return true }; return false }

    private var place: String {
        switch purpose {
        case .password: return KeyLink.cleanSite(link.site) ?? link.site
        case .passkeySignIn(let rp), .passkeyCreate(let rp, _): return rp
        }
    }

    private var headline: String {
        if notice != nil { return "Not available yet" }
        switch link.outcome {
        case .answer?, .ctap?: return creating ? "Passkey made" : "Signed in"
        case .failed?: return creating ? "No passkey made" : "Not signed in"
        case .cancelled?: return "Cancelled"
        default:
            if link.waitingOnKey { return purpose == .password ? "Choose the login on your KEY" : "Approve on your KEY" }
            return link.busy ? "Connecting to your KEY" : (creating ? "Make a passkey on your KEY" : "Sign in with Favilla")
        }
    }

    private var detail: String {
        if let n = notice { return n }
        switch link.outcome {
        case .answer?, .ctap?: return ""
        case .failed(let why)?: return why
        default:
            if link.waitingOnKey {
                switch purpose {
                case .password: return "Check \(place) on the KEY's screen, pick the login and press ENTER."
                case .passkeySignIn: return "Check \(place) on the KEY's screen, then press to sign in."
                case .passkeyCreate: return "Check \(place) on the KEY's screen, then press to make the passkey."
                }
            }
            let what: String
            switch purpose {
            case .password: what = "Signing in to \(place)."
            case .passkeySignIn: what = "Signing in to \(place) with a passkey."
            case .passkeyCreate(_, let user): what = "Making a passkey\(user.isEmpty ? "" : " for \(user)") on \(place)."
            }
            return link.busy ? what + " If your KEY's Bluetooth is set to App and keyboard, press a button on it." : what
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Text("FAVILLA")
                    .font(.system(size: 13, weight: .semibold))
                    .tracking(3)
                    .foregroundStyle(Brand.brass)
                Spacer()
                Button("Close", action: onClose).foregroundStyle(Brand.grey)
            }
            Text(headline)
                .font(.system(size: 22, weight: .bold))
                .foregroundStyle(Brand.ink)
            if !detail.isEmpty {
                Text(detail)
                    .font(.system(size: 15))
                    .foregroundStyle(link.waitingOnKey ? Brand.brass : Brand.grey)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if case .failed? = link.outcome {
                ScrollView {
                    VStack(alignment: .leading, spacing: 4) {
                        ForEach(Array(link.lines.enumerated()), id: \.offset) { _, line in
                            Text(line)
                                .font(.system(size: 12, design: .monospaced))
                                .foregroundStyle(Brand.grey)
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }
                    .padding(12)
                }
                .frame(maxHeight: 180)
                .background(Brand.card)
                .clipShape(RoundedRectangle(cornerRadius: 10))
            }
            Spacer()
            if notice == nil {
                if link.busy {
                    button("CANCEL", filled: false) { link.cancel() }
                } else if case .failed? = link.outcome {
                    button("TRY AGAIN", filled: true, onRetry)
                } else if link.outcome == .cancelled {
                    button("TRY AGAIN", filled: true, onRetry)
                }
            }
        }
        .padding(20)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(Brand.bg)
    }

    private func button(_ title: String, filled: Bool, _ action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Text(title)
                .font(.system(size: 14, weight: .semibold))
                .tracking(2)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 14)
                .background(filled ? Brand.brass : Brand.card)
                .foregroundStyle(filled ? Brand.bg : Brand.ink)
                .clipShape(RoundedRectangle(cornerRadius: 10))
        }
    }
}
