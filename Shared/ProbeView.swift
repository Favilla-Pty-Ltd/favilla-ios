// ProbeView.swift - the link check / pairing screen, shown from iOS Settings >
// AutoFill & Passwords > Favilla. The app's home uses KeyCard (FavillaApp).

import SwiftUI

struct ProbeView: View {
    @ObservedObject var link: KeyLink
    var onClose: (() -> Void)?

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack {
                Lockup(mark: 22, word: 15)
                Spacer()
                if let close = onClose {
                    Button("Close", action: close).font(Brand.body).foregroundStyle(Brand.grey).frame(minHeight: 44)
                }
            }
            Text(KeyStatus.headline(link)).font(Brand.headline).foregroundStyle(Brand.ink)
            if let d = KeyStatus.detail(link) {
                Text(d).font(Brand.body).foregroundStyle(link.pairing ? Brand.brass : Brand.grey).fixedSize(horizontal: false, vertical: true)
            }
            LogBox(lines: link.lines)
            BrandButton(title: link.busy ? "CANCEL" : "FIND MY KEY", filled: !link.busy) {
                link.busy ? link.cancel() : link.probe()
            }
        }
        .padding(20)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(Brand.bg)
    }
}

/// Words for the link check, shared by the probe screen and the app's KEY card.
enum KeyStatus {
    static func headline(_ link: KeyLink) -> String {
        if link.pairing || link.appCode != nil { return "Check the code on your KEY" }
        if link.busy { return link.mode == .pairApp ? "Pairing the app" : link.securing ? "Connecting securely" : "Connecting to your KEY" }
        switch link.outcome {
        case .ok?: return "Your KEY is paired"
        case .appPaired?: return "The app is paired"
        case .list(let l)?: return "\(l.count) accounts from your KEY"
        case .failed?: return "Couldn't reach your KEY"
        default: return "Check the link to your KEY"
        }
    }

    static func detail(_ link: KeyLink) -> String? {
        if link.pairing { return "If the numbers in iOS's prompt match the KEY's screen, tap Pair, then press ENTER on the KEY." }
        if let c = link.appCode { return "The KEY shows PAIR THE APP. If its number is \(c), press ENTER on the KEY." }
        switch link.outcome {
        case .appPaired?: return "Passwords, passkeys, codes and the account list now go over the app's own locked channel."
        case .ok(let t)?: return t
        case .failed(let why)?: return why
        default: return nil
        }
    }
}

/// The step log, small and monospaced, for the bench.
struct LogBox: View {
    let lines: [String]
    var maxHeight: CGFloat = 220

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 4) {
                ForEach(Array(lines.enumerated()), id: \.offset) { _, line in
                    Text(line)
                        .font(.system(size: 12, design: .monospaced))
                        .foregroundStyle(Brand.grey)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            .padding(12)
        }
        .frame(maxHeight: maxHeight)
        .background(Brand.card)
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }
}
