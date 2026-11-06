// AccountList.swift - the opt-in list of accounts iOS shows above the keyboard.
//
// Ruled (Josh, 6 Nov 2026, option 1): off by default, a switch in the app. While
// it is on, the sheet records each account you use through Favilla: a password
// filled from the KEY (site + username) or a passkey made on it (site, username,
// credential id, user handle). They go to iOS's credential identity store, so
// tapping a login field offers "joshtest, example.com (Favilla)" straight away,
// and Safari's passkey prompt offers Favilla first. No password or key is ever
// in the list. Switching it off removes everything from iOS and from here.
//
// A one-go "fill the list from my KEY" needs a list request on the KEY (not in
// firmware 9c); until then the list grows as accounts are used.

import AuthenticationServices
import Foundation

enum AccountList {
    struct Entry: Codable, Equatable {
        var passkey: Bool
        var site: String
        var user: String
        var credentialID: Data?
        var userHandle: Data?
    }

    private static let onKey = "accountListOn"
    private static let entriesKey = "accountListEntries"
    private static var store: UserDefaults { UserDefaults(suiteName: "group.io.favillakey.app") ?? .standard }

    static var isOn: Bool { store.bool(forKey: onKey) }

    static var entries: [Entry] {
        guard let d = store.data(forKey: entriesKey), let e = try? JSONDecoder().decode([Entry].self, from: d) else { return [] }
        return e
    }

    private static func save(_ e: [Entry]) {
        store.set(try? JSONEncoder().encode(e), forKey: entriesKey)
    }

    /// Turn the list on (empty; it fills as accounts are used) or off (cleared here and in iOS).
    static func setOn(_ on: Bool, done: @escaping (Bool) -> Void) {
        store.set(on, forKey: onKey)
        if on { done(true); return }
        save([])
        ASCredentialIdentityStore.shared.removeAllCredentialIdentities { ok, _ in DispatchQueue.main.async { done(ok) } }
    }

    /// Record an account if the list is on, then call `then` once iOS has it
    /// (or after a second, so a sign-in is never held up by the list).
    static func record(_ e: Entry, then: @escaping () -> Void) {
        guard isOn, !e.site.isEmpty, !e.user.isEmpty else { then(); return }
        var all = entries
        all.removeAll { $0.passkey == e.passkey && $0.site == e.site && $0.user == e.user && $0.credentialID == e.credentialID }
        all.append(e)
        save(all)
        var called = false
        let once = { DispatchQueue.main.async { if !called { called = true; then() } } }
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) { once() }
        ASCredentialIdentityStore.shared.getState { state in
            guard state.isEnabled else { once(); return }
            ASCredentialIdentityStore.shared.saveCredentialIdentities([identity(e)]) { _, _ in once() }
        }
    }

    private static func identity(_ e: Entry) -> ASCredentialIdentity {
        if e.passkey, let id = e.credentialID, let handle = e.userHandle {
            return ASPasskeyCredentialIdentity(relyingPartyIdentifier: e.site, userName: e.user, credentialID: id, userHandle: handle, recordIdentifier: nil)
        }
        return ASPasswordCredentialIdentity(serviceIdentifier: ASCredentialServiceIdentifier(identifier: e.site, type: .domain), user: e.user, recordIdentifier: nil)
    }
}
