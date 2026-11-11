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
// From KEY 9h the list can also be filled in one go from the KEY (LIST on the
// app channel, "Fill the list from my KEY"): it then replaces what is here.

import AuthenticationServices
import Foundation

enum AccountList {
    struct Entry: Codable, Equatable {
        var passkey: Bool
        var site: String
        var user: String
        var credentialID: Data?
        var userHandle: Data?
        var code: Bool? = nil        // 11v: a one-time code is linked (LIST v2 health bit 7)
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

    /// Replace the list with the KEY's (LIST, 9h). Entries iOS can't list under a
    /// website (an app's name, a passkey without its id) are left out.
    /// Why the last replace left entries out, for the note under the button.
    static var leftOut: (name: Int, noUser: Int, passkey: Int) = (0, 0, 0)
    static func leftOutText() -> String {
        var p: [String] = []
        if leftOut.name > 0 { p.append("\(leftOut.name) saved under a name rather than a website") }
        if leftOut.noUser > 0 { p.append("\(leftOut.noUser) with no username") }
        if leftOut.passkey > 0 { p.append("\(leftOut.passkey) passkey\(leftOut.passkey == 1 ? "" : "s") without a record") }
        return p.joined(separator: ", ")
    }

    static func replace(with list: [AppChannel.ListEntry], done: @escaping (Int) -> Void) {
        guard isOn else { done(0); return }
        leftOut = (0, 0, 0)
        let e: [Entry] = list.compactMap { x in
            let site = x.site.lowercased()
            guard !x.user.isEmpty else { leftOut.noUser += 1; return nil }
            guard site.contains("."), !site.contains(" ") else { leftOut.name += 1; return nil }
            if x.passkey {
                guard let id = x.credentialID, !id.isEmpty, let h = x.userHandle else { leftOut.passkey += 1; return nil }
                return Entry(passkey: true, site: site, user: x.user, credentialID: id, userHandle: h)
            }
            return Entry(passkey: false, site: site, user: x.user, code: x.health?.hasCode == true)
        }
        save(e)
        ASCredentialIdentityStore.shared.removeAllCredentialIdentities { _, _ in
            ASCredentialIdentityStore.shared.getState { state in
                guard state.isEnabled, !e.isEmpty else { DispatchQueue.main.async { done(e.count) }; return }
                ASCredentialIdentityStore.shared.saveCredentialIdentities(e.flatMap(identities)) { _, _ in
                    DispatchQueue.main.async { done(e.count) }
                }
            }
        }
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
            ASCredentialIdentityStore.shared.saveCredentialIdentities(identities(e)) { _, _ in once() }
        }
    }

    /// What iOS lists for an entry. A one-time-code identity is what makes
    /// Favilla appear above the keyboard on a code field at all: without one
    /// iOS offers only the codes it read from Messages and Mail.
    private static func identities(_ e: Entry) -> [ASCredentialIdentity] {
        if e.passkey, let id = e.credentialID, let handle = e.userHandle {
            return [ASPasskeyCredentialIdentity(relyingPartyIdentifier: e.site, userName: e.user, credentialID: id, userHandle: handle, recordIdentifier: nil)]
        }
        let sid = ASCredentialServiceIdentifier(identifier: e.site, type: .domain)
        var out: [ASCredentialIdentity] = [ASPasswordCredentialIdentity(serviceIdentifier: sid, user: e.user, recordIdentifier: nil)]
        if e.code == true, #available(iOS 18.0, *) {
            out.append(ASOneTimeCodeCredentialIdentity(serviceIdentifier: sid, label: e.user, recordIdentifier: nil))
        }
        return out
    }
}
