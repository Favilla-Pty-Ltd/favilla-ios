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
                    Text("TO USE IT WHEN SIGNING IN")
                        .font(.system(size: 11, weight: .semibold))
                        .tracking(2)
                        .foregroundStyle(Brand.brass)
                    Text("Settings > General > AutoFill & Passwords, turn on Favilla. Then tap a login field in Safari, choose Favilla, and press a button on your KEY.")
                        .font(.system(size: 13))
                        .foregroundStyle(Brand.grey)
                }
                .padding(20)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Brand.bg)
            }
            .preferredColorScheme(.dark)
        }
    }
}
