// LinkSettingsView.swift - "Link to the KEY", opened from the Nostr client's
// Settings (the "This iPhone" row bridge.js adds). How this iPhone reaches the
// KEY for Nostr, then the KEY pairing, the AutoFill settings and the last
// sign-in log (HomeBody in FavillaApp.swift).

import SwiftUI

struct LinkSettingsView: View {
    @ObservedObject var link: KeyLink
    @ObservedObject private var nostr = NostrLink.shared
    @Binding var route: KeyRoute
    @State private var host = UserDefaults.standard.string(forKey: WifiTransport.hostKey) ?? ""
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 22) {
                    VStack(alignment: .leading, spacing: 10) {
                        Text("NOSTR").font(Brand.label).tracking(2).foregroundStyle(Brand.brass)
                        VStack(alignment: .leading, spacing: 12) {
                            Text("How this iPhone reaches the KEY").font(Brand.font(17, .semibold)).foregroundStyle(Brand.ink)
                            Picker("Route", selection: $route) {
                                ForEach(KeyRoute.allCases, id: \.self) { Text($0.title).tag($0) }
                            }
                            .pickerStyle(.segmented)
                            if route == .bluetooth {
                                Text("Choose NOSTR BT on the KEY's Select Mode screen and enter the NOSTR PIN. The KEY never starts Wi-Fi; the app reaches it over the paired Bluetooth link and reaches relays over this iPhone's own internet.")
                                    .font(Brand.small).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true)
                                Text(btStatus)
                                    .font(Brand.small).foregroundStyle(btStatusColour).fixedSize(horizontal: false, vertical: true)
                            } else {
                                Text("Choose NOSTR on the KEY's Select Mode screen, on the same Wi-Fi as this iPhone. The address is filled in when you pair the KEY in the app's Settings, or type it here.")
                                    .font(Brand.small).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true)
                                TextField("favilla-xxxxxxxx.local or 192.168.x.x", text: $host)
                                    .font(Brand.body).foregroundStyle(Brand.ink)
                                    .textInputAutocapitalization(.never).autocorrectionDisabled().keyboardType(.URL)
                                    .padding(12).background(Brand.bg).clipShape(RoundedRectangle(cornerRadius: 10))
                                    .onSubmit(saveHost)
                                if !host.isEmpty && !WifiTransport.isLocal(host) {
                                    Text("That isn't a local address. Use the KEY's .local name or its 192.168 / 10. address.")
                                        .font(Brand.small).foregroundStyle(Brand.danger).fixedSize(horizontal: false, vertical: true)
                                }
                            }
                        }
                        .padding(16)
                        .background(Brand.card)
                        .clipShape(RoundedRectangle(cornerRadius: 14))
                    }
                    HomeBody(link: link)
                    BluetoothLogSection()
                }
                .padding(20)
            }
            .background(Brand.bg.ignoresSafeArea())
            .toolbar {
                ToolbarItem(placement: .principal) { Lockup(mark: 22, word: 15) }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { saveHost(); dismiss() }.font(Brand.button).foregroundStyle(Brand.brass)
                }
            }
            .toolbarBackground(Brand.bg, for: .navigationBar)
            .onChange(of: route) { _, r in
                KeyRoute.current = r
                if r == .wifi { nostr.disconnect() }
            }
        }
        .preferredColorScheme(.dark)
    }

    private var btStatus: String {
        guard KeyLink.appPaired else { return "First pair the app with the KEY: PAIR THE APP below, with PAIR A PHONE open on the KEY (PASSKEY mode), or Settings > Network > Pair a phone in NOSTR BT." }
        switch nostr.state {
        case .ready: return "Connected to your KEY over Bluetooth."
        case .connecting: return "Connecting to your KEY..."
        case .failed(let why): return why
        case .idle: return "App paired. The link opens when the Nostr client next calls the KEY."
        }
    }

    private var btStatusColour: Color {
        if case .failed = nostr.state { return Brand.danger }
        return KeyLink.appPaired ? Brand.brass : Brand.grey
    }

    private func saveHost() {
        let h = host.trimmingCharacters(in: .whitespaces)
        if h.isEmpty || WifiTransport.isLocal(h) { UserDefaults.standard.set(h, forKey: WifiTransport.hostKey) }
    }

    /// The subtitle on the Settings row in the page.
    static func routeText(_ r: KeyRoute) -> String {
        if r == .bluetooth { return "Bluetooth" }
        let h = UserDefaults.standard.string(forKey: WifiTransport.hostKey) ?? ""
        return h.isEmpty ? "Wi-Fi" : "Wi-Fi: \(h)"
    }
}


/// Settings > This iPhone > Bluetooth log (issue #9): what the Nostr client's
/// Bluetooth link did, to copy and send. Lengths, counters and reasons only.
struct BluetoothLogSection: View {
    @ObservedObject private var log = LinkLog.shared
    @State private var open = false
    @State private var copied = false

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("BLUETOOTH LOG").font(Brand.label).tracking(2).foregroundStyle(Brand.brass)
            VStack(alignment: .leading, spacing: 12) {
                Text("What the Nostr client's Bluetooth link did: connects, requests, notifications, answers and why any failed. No keys or message contents.")
                    .font(Brand.small).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true)
                HStack(spacing: 12) {
                    Button(copied ? "Copied" : "Copy log") {
                        UIPasteboard.general.string = log.text
                        copied = true
                        DispatchQueue.main.asyncAfter(deadline: .now() + 2) { copied = false }
                    }
                    .font(Brand.button).foregroundStyle(Brand.brass)
                    .disabled(log.lines.isEmpty)
                    Button(open ? "Hide" : "Show (\(log.lines.count) lines)") { open.toggle() }
                        .font(Brand.button).foregroundStyle(Brand.ink)
                    Spacer()
                    Button("Clear") { log.clear() }
                        .font(Brand.button).foregroundStyle(Brand.grey)
                        .disabled(log.lines.isEmpty)
                }
                if open {
                    ScrollView([.horizontal, .vertical]) {
                        Text(log.lines.suffix(200).joined(separator: "\n"))
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundStyle(Brand.ink)
                            .textSelection(.enabled)
                            .fixedSize(horizontal: true, vertical: true)
                    }
                    .frame(height: 360)
                }
            }
            .padding(16)
            .background(Brand.card)
            .clipShape(RoundedRectangle(cornerRadius: 14))
        }
    }
}
