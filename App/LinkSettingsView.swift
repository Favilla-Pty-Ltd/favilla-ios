// LinkSettingsView.swift - the subtitle of the "This iPhone" row bridge.js adds
// to the Nostr client's Settings. The screen itself is ThisPhoneView
// (SettingsPages.swift, 12 Nov 2026).

import Foundation

enum LinkSettingsView {
    /// The subtitle on the Settings row in the page.
    static func routeText(_ r: KeyRoute) -> String {
        if r == .bluetooth { return "Bluetooth" }
        let h = UserDefaults.standard.string(forKey: WifiTransport.hostKey) ?? ""
        return h.isEmpty ? "Wi-Fi" : "Wi-Fi: \(h)"
    }
}
