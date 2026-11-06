// SignInView.swift - the AutoFill sheet's screen.
//
//  - Passwords (KEY drop 8z7): the sheet sends the site to the KEY, then closes
//    so the page's login field has the focus again; the owner picks the login
//    on the KEY and the KEY types it.
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
        case .sent?: return "Choose the login on your KEY"
        case .ctap?: return creating ? "Passkey made" : "Signed in"
        case .failed?: return isPasskey ? (creating ? "No passkey made" : "Not signed in") : "Not sent to your KEY"
        case .cancelled?: return "Cancelled"
        default:
            if link.waitingOnKey { return "Approve on your KEY" }
            return link.busy ? "Press a button on your KEY" : (creating ? "Make a passkey on your KEY" : "Sign in with Favilla")
        }
    }

    private var detail: String {
        if let n = notice { return n }
        switch link.outcome {
        case .sent?: return "Then press to type it. This sheet closes now, so the login field is ready."
        case .ctap?: return ""
        case .failed(let why)?: return why
        default:
            if link.waitingOnKey {
                return creating ? "Check \(place) on the KEY's screen, then press to make the passkey."
                                : "Check \(place) on the KEY's screen, then press to sign in."
            }
            switch purpose {
            case .password: return link.busy ? "Signing in to \(place). Your KEY wakes its Bluetooth when you press." : "Signing in to \(place)."
            case .passkeySignIn: return "Signing in to \(place) with a passkey. Your KEY wakes its Bluetooth when you press any button on its home screen."
            case .passkeyCreate(_, let user):
                let who = user.isEmpty ? "" : " for \(user)"
                return "Making a passkey\(who) on \(place). Your KEY wakes its Bluetooth when you press any button on its home screen."
            }
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
                    .foregroundStyle(link.outcome == .sent || link.waitingOnKey ? Brand.brass : Brand.grey)
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
