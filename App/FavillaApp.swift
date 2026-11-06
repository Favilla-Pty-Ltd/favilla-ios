// FavillaApp.swift - the Favilla app (probe stage).
// The app's main jobs come later: pairing the AutoFill side with the KEY and
// settings. For now it asks for Bluetooth permission (the AutoFill extension
// shares it) and runs the same probe as the sign-in sheet.

import SwiftUI

@main
struct FavillaApp: App {
    @StateObject private var link = KeyLink()

    var body: some Scene {
        WindowGroup {
            VStack(spacing: 0) {
                ProbeView(link: link, title: "FAVILLA")
                VStack(alignment: .leading, spacing: 6) {
                    Text("TO PAIR A KEY")
                        .font(.system(size: 11, weight: .semibold))
                        .tracking(2)
                        .foregroundStyle(Brand.brass)
                    Text("On the KEY, open PAIR A PHONE. Then tap FIND MY KEY here and accept the code when the numbers match the KEY's screen, and press ENTER on the KEY.")
                        .font(.system(size: 13))
                        .foregroundStyle(Brand.grey)
                        .padding(.bottom, 10)
                    Text("TO USE IT WHEN SIGNING IN")
                        .font(.system(size: 11, weight: .semibold))
                        .tracking(2)
                        .foregroundStyle(Brand.brass)
                    Text("Settings > General > AutoFill & Passwords, turn on Favilla. Then tap a login field in Safari and choose Favilla. Pick the login (or approve the passkey) on your KEY.")
                        .font(.system(size: 13))
                        .foregroundStyle(Brand.grey)
                }
                .padding(20)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Brand.bg)
                LastRequestView()
            }
            .preferredColorScheme(.dark)
        }
    }
}

/// The last AutoFill request's log (saved by the sheet), for the bench.
struct LastRequestView: View {
    @State private var open = false
    @State private var text: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Button(action: { text = LastRequest.load(); open.toggle() }) {
                Text(open ? "HIDE LAST REQUEST" : "SHOW LAST REQUEST")
                    .font(.system(size: 11, weight: .semibold))
                    .tracking(2)
                    .foregroundStyle(Brand.brass)
            }
            if open {
                ScrollView {
                    Text(text ?? "No request yet.")
                        .font(.system(size: 12, design: .monospaced))
                        .foregroundStyle(Brand.grey)
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(12)
                }
                .frame(maxHeight: 240)
                .background(Brand.card)
                .clipShape(RoundedRectangle(cornerRadius: 10))
            }
        }
        .padding(.horizontal, 20)
        .padding(.bottom, 20)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Brand.bg)
    }
}
