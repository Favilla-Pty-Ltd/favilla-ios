// SignInView.swift - the AutoFill sheet's sign-in screen (KEY drop 8z7).
//
// The sheet sends the site to the KEY, then closes so the page's login field has
// the focus again; the owner picks the login on the KEY and the KEY types it.
// Type scale follows the probe screen: FAVILLA label 13 tracked, headline 22,
// body 15, button 14 tracked.

import SwiftUI

struct SignInView: View {
    @ObservedObject var link: KeyLink
    /// Shown instead of signing in (e.g. a passkey ask, not supported yet).
    var notice: String?
    var onClose: () -> Void

    private var headline: String {
        if notice != nil { return "Not available yet" }
        switch link.outcome {
        case .sent?: return "Choose the login on your KEY"
        case .failed?: return "Not sent to your KEY"
        case .cancelled?: return "Cancelled"
        default: return link.busy ? "Press a button on your KEY" : "Sign in with Favilla"
        }
    }

    private var detail: String {
        if let n = notice { return n }
        let site = KeyLink.cleanSite(link.site) ?? link.site
        switch link.outcome {
        case .sent?: return "Then press to type it. This sheet closes now, so the login field is ready."
        case .failed(let why)?: return why
        default: return link.busy ? "Signing in to \(site). Your KEY wakes its Bluetooth when you press." : "Signing in to \(site)."
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
            Text(detail)
                .font(.system(size: 15))
                .foregroundStyle(link.outcome == .sent ? Brand.brass : Brand.grey)
                .fixedSize(horizontal: false, vertical: true)
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
                } else if link.outcome != .sent {
                    button("TRY AGAIN", filled: true) { link.signIn() }
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
