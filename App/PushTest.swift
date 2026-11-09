// PushTest.swift - the app side of the push test (9 Nov 2026): turn on
// notifications, show this iPhone's push token to paste into Apple's Push
// Notifications Console, and show what the extension (PushProbe) found each
// time a test push arrived.

import SwiftUI
import UIKit
import UserNotifications

final class PushTest: NSObject, ObservableObject, @unchecked Sendable {
    static let shared = PushTest()
    private static let group = "group.io.favillakey.app"
    private var store: UserDefaults { UserDefaults(suiteName: PushTest.group) ?? .standard }

    @Published var token: String = ""
    @Published var status: String = ""
    @Published var results: [String] = []

    override init() {
        super.init()
        token = store.string(forKey: "pushToken") ?? ""
        reload()
    }

    func reload() {
        results = (store.stringArray(forKey: "pushProbeResults") ?? []).reversed()
    }

    func clear() {
        store.removeObject(forKey: "pushProbeResults")
        reload()
    }

    /// Ask for notifications, then register with Apple for a token.
    func enable() {
        status = "Asking iOS..."
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { ok, err in
            DispatchQueue.main.async {
                if ok {
                    self.status = "Registering with Apple..."
                    UIApplication.shared.registerForRemoteNotifications()
                } else {
                    self.status = "Notifications are off for Favilla. Turn them on in Settings > Notifications > Favilla." + (err.map { " (\($0.localizedDescription))" } ?? "")
                }
            }
        }
    }

    func got(_ t: Data) {
        let hex = t.map { String(format: "%02x", $0) }.joined()
        store.set(hex, forKey: "pushToken")
        DispatchQueue.main.async {
            let changed = self.token != hex
            self.token = hex; self.status = "Ready. Copy the token into the Push Notifications Console."
            if changed || Bunker.on { Task { @MainActor in BunkerService.shared.tokenChanged() } }
        }
    }

    func failed(_ e: Error) {
        DispatchQueue.main.async { self.status = "Apple refused the push registration: \(e.localizedDescription)" }
    }
}

final class AppDelegate: NSObject, UIApplicationDelegate, UNUserNotificationCenterDelegate {
    func application(_ app: UIApplication, didFinishLaunchingWithOptions o: [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {
        UNUserNotificationCenter.current().delegate = self
        // Keep the token fresh once notifications are allowed (it can change).
        UNUserNotificationCenter.current().getNotificationSettings { s in
            if s.authorizationStatus == .authorized {
                DispatchQueue.main.async { app.registerForRemoteNotifications() }
            }
        }
        return true
    }

    func application(_ app: UIApplication, didRegisterForRemoteNotificationsWithDeviceToken t: Data) { PushTest.shared.got(t) }
    func application(_ app: UIApplication, didFailToRegisterForRemoteNotificationsWithError e: Error) { PushTest.shared.failed(e) }

    // A test push while the app is open still shows as a banner (the extension has already run).
    // A bunker push while the app is open is the app's own work (it listens to the relays itself): no banner.
    func userNotificationCenter(_ c: UNUserNotificationCenter, willPresent n: UNNotification, withCompletionHandler h: @escaping (UNNotificationPresentationOptions) -> Void) {
        let bunker = n.request.content.userInfo["fv"] != nil
        Task { @MainActor in PushTest.shared.reload(); BunkerService.shared.reloadLog() }
        h(bunker ? [] : [.banner, .list, .sound])
    }
}

/// Settings > This iPhone > Push test.
struct PushTestSection: View {
    @ObservedObject private var t = PushTest.shared
    @State private var copied = false
    @State private var showAll = false

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("PUSH TEST").font(Brand.label).tracking(2).foregroundStyle(Brand.brass)
            VStack(alignment: .leading, spacing: 12) {
                Text("Checks whether a notification can reach your KEY over Bluetooth by itself, with this app closed. Each test push asks the KEY one harmless question (HELLO) and puts the answer in the notification.")
                    .font(Brand.small).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true)
                if t.token.isEmpty {
                    Button("Turn on notifications") { t.enable() }
                        .font(Brand.button).foregroundStyle(Brand.brass)
                } else {
                    Text(t.token)
                        .font(.system(size: 11, design: .monospaced)).foregroundStyle(Brand.ink)
                        .textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                    Button(copied ? "Copied" : "Copy push token") {
                        UIPasteboard.general.string = t.token
                        copied = true
                        DispatchQueue.main.asyncAfter(deadline: .now() + 2) { copied = false }
                    }
                    .font(Brand.button).foregroundStyle(Brand.brass)
                }
                if !t.status.isEmpty {
                    Text(t.status).font(Brand.small).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true)
                }
                HStack(spacing: 12) {
                    Text("Results (\(t.results.count))").font(Brand.button).foregroundStyle(Brand.ink)
                    Spacer()
                    Button("Refresh") { t.reload() }.font(Brand.button).foregroundStyle(Brand.brass)
                    Button("Copy") { UIPasteboard.general.string = t.results.joined(separator: "\n\n") }
                        .font(Brand.button).foregroundStyle(Brand.brass).disabled(t.results.isEmpty)
                    Button("Clear") { t.clear() }.font(Brand.button).foregroundStyle(Brand.grey).disabled(t.results.isEmpty)
                }
                ForEach(Array(t.results.prefix(showAll ? 20 : 3).enumerated()), id: \.offset) { _, r in
                    Text(r)
                        .font(.system(size: 11, design: .monospaced)).foregroundStyle(Brand.ink)
                        .textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                        .padding(10).frame(maxWidth: .infinity, alignment: .leading)
                        .background(Brand.bg).clipShape(RoundedRectangle(cornerRadius: 10))
                }
                if t.results.count > 3 {
                    Button(showAll ? "Show fewer" : "Show all") { showAll.toggle() }
                        .font(Brand.button).foregroundStyle(Brand.grey)
                }
            }
            .padding(16)
            .background(Brand.card)
            .clipShape(RoundedRectangle(cornerRadius: 14))
            .onAppear { t.reload() }
        }
    }
}
