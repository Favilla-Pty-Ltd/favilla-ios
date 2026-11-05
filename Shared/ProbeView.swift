// ProbeView.swift - the probe's screen, used by the app and the AutoFill sheet.

import SwiftUI

enum Brand {
    static let bg     = Color(red: 0.055, green: 0.051, blue: 0.047)
    static let brass  = Color(red: 0.902, green: 0.690, blue: 0.290)
    static let ink    = Color(red: 0.96, green: 0.94, blue: 0.90)
    static let grey   = Color(red: 0.55, green: 0.53, blue: 0.50)
    static let card   = Color(red: 0.10, green: 0.095, blue: 0.09)
}

struct ProbeView: View {
    @ObservedObject var link: KeyLink
    var title: String
    var onClose: (() -> Void)?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Text(title)
                    .font(.system(size: 13, weight: .semibold))
                    .tracking(3)
                    .foregroundStyle(Brand.brass)
                Spacer()
                if let close = onClose {
                    Button("Close", action: close).foregroundStyle(Brand.grey)
                }
            }
            Text(link.busy ? "Press a button on your KEY" : (link.result == nil ? "Check the link to your KEY" : "Result"))
                .font(.system(size: 22, weight: .bold))
                .foregroundStyle(Brand.ink)
            if let r = link.result {
                Text(r)
                    .font(.system(size: 15))
                    .foregroundStyle(r.hasPrefix("OK") ? Brand.brass : Brand.ink)
            }
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
            .background(Brand.card)
            .clipShape(RoundedRectangle(cornerRadius: 10))
            Button(action: { link.busy ? link.cancel() : link.probe() }) {
                Text(link.busy ? "CANCEL" : "FIND MY KEY")
                    .font(.system(size: 14, weight: .semibold))
                    .tracking(2)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 14)
                    .background(link.busy ? Brand.card : Brand.brass)
                    .foregroundStyle(link.busy ? Brand.ink : Brand.bg)
                    .clipShape(RoundedRectangle(cornerRadius: 10))
            }
        }
        .padding(20)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(Brand.bg)
    }
}
