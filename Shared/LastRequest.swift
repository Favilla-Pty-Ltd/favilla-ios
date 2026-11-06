// LastRequest.swift - a record of the last AutoFill request, for the bench.
// The sheet closes the moment it hands iOS a credential, so its log is gone;
// it saves the log here (the app group both share) and the app shows it.
// Never holds a secret: only the steps, sizes, flags and statuses.

import Foundation

enum LastRequest {
    private static let key = "lastRequestLog"
    private static var store: UserDefaults { UserDefaults(suiteName: "group.io.favillakey.app") ?? .standard }

    static func save(_ title: String, _ lines: [String]) {
        let stamp = DateFormatter.localizedString(from: Date(), dateStyle: .none, timeStyle: .medium)
        store.set(([title + " at " + stamp] + lines).joined(separator: "\n"), forKey: key)
    }

    static func load() -> String? { store.string(forKey: key) }
}
