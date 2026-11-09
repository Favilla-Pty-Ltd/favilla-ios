// NotificationService.swift - the notification extension (9 Nov 2026).
//
// Two kinds of push run this:
//
//  - The Bluetooth bunker (payload "fv": {"pk": the KEY's pubkey}): the push
//    bridge saw a NIP-46 request for this KEY on a relay. Fetch the waiting
//    requests from the bridge, hand each to the KEY over the paired app channel
//    (NIP46 0x3B), poll for replies the KEY finishes later (0x3C), publish every
//    reply to the bunker relays, and say what happened in the notification.
//    If the app is open with the bunker on, it already has them: leave the KEY
//    to the app.
//  - The push test (anything else): connect, HELLO, report the timings. Kept
//    so the Push Notifications Console test still works.
//
// iOS gives an extension about 30 s; the work stops at 24 s to leave room.

import Foundation
import UserNotifications

final class NotificationService: UNNotificationServiceExtension {
    static let resultsKey = "pushProbeResults"
    private static let group = "group.io.favillakey.app"

    private let lock = NSLock()
    private var handler: ((UNNotificationContent) -> Void)?
    private var content: UNMutableNotificationContent?
    private var _best: (String, String)?
    private var best: (String, String)? {      // the text to show if time runs out
        get { lock.lock(); defer { lock.unlock() }; return _best }
        set { lock.lock(); _best = newValue; lock.unlock() }
    }
    private var session: KeySession?
    private let t0 = Date()

    override func didReceive(_ request: UNNotificationRequest, withContentHandler h: @escaping (UNNotificationContent) -> Void) {
        handler = h
        content = request.content.mutableCopy() as? UNMutableNotificationContent
        let fv = request.content.userInfo["fv"] as? [String: Any]
        Task {
            if let pk = fv?["pk"] as? String { await bunker(pk) } else { await probe() }
        }
    }

    override func serviceExtensionTimeWillExpire() {
        session?.close()
        let (t, b) = best ?? ("Favilla", "Ran out of time reaching your KEY.")
        Bunker.log("extension: out of time")
        deliver(t, b)
    }

    private func deliver(_ title: String, _ body: String) {
        lock.lock()
        let h = handler; handler = nil
        lock.unlock()
        guard let h, let c = content else { return }
        c.title = title
        c.body = body
        h(c)
    }

    private var ms: Int { Int(Date().timeIntervalSince(t0) * 1000) }

    // MARK: - Bunker

    private func bunker(_ pk: String) async {
        let title = "Favilla bunker"
        best = (title, "Signing request from a Nostr app. Open Favilla to answer it.")
        guard Bunker.on, let info = Bunker.Info.load(), info.pubkey == pk else {
            deliver(title, "Signing for other apps is off on this iPhone."); return
        }
        if Bunker.appActive {
            deliver(title, "Answered in the Favilla app."); return
        }
        guard let creds = Credentials.load() else {
            deliver(title, "Open Favilla and PAIR THE APP to sign for other apps."); return
        }
        let reqs: [(String, Data)]
        do { reqs = try await Bunker.pending(pubkey: pk) } catch {
            Bunker.log("extension: bridge unreachable: \(error.localizedDescription)")
            deliver(title, "Couldn't fetch the request: \(error.localizedDescription)"); return
        }
        guard !reqs.isEmpty else { deliver(title, "Nothing waiting: the request was already answered."); return }
        Bunker.log("extension: \(reqs.count) request\(reqs.count == 1 ? "" : "s") waiting")

        let s = KeySession(creds)
        session = s
        do { try await s.open() } catch {
            Bunker.log("extension: \(error) (\(ms) ms, \(s.how))")
            deliver(title, "Couldn't reach your KEY. \(error)"); return
        }
        Bunker.log("extension: KEY open in \(ms) ms (\(s.how))")
        let deadline = t0.addingTimeInterval(24)
        let o = await Bunker.serve(reqs, via: s, relays: info.relays, until: deadline) { [weak self] o in
            if o.sent > 0 { self?.best = (title, Self.text(o)) }
            else if o.taken > 0 { self?.best = (title, "Approve it on your KEY.") }
        }
        s.close()
        Bunker.log("extension: done in \(ms) ms: taken \(o.taken), replies \(o.replies), accepted \(o.sent)" + (o.waiting ? ", still waiting" : "") + (o.error.map { ", \($0)" } ?? ""))
        if let e = o.error, o.taken == 0 { deliver(title, e); return }
        deliver(title, Self.text(o))
    }

    static func text(_ o: Bunker.Outcome) -> String {
        if o.waiting { return o.sent > 0 ? "Answered \(o.sent). Another request is waiting for you on the KEY: approve it, then open Favilla to send the answer." : "Approve it on your KEY, then open Favilla to send the answer." }
        if o.replies > 0 && o.sent == 0 { return "The KEY answered but no relay took the reply. Open Favilla to try again." }
        if o.sent > 0 { return o.sent == 1 ? "Answered a Nostr app's request." : "Answered \(o.sent) Nostr app requests." }
        return o.error ?? "The KEY took the request."
    }

    // MARK: - Push test

    private func probe() async {
        guard let creds = Credentials.load() else { finishProbe(false, "the app isn't paired with the KEY (PAIR THE APP first)", nil); return }
        let s = KeySession(creds)
        session = s
        do {
            try await s.open()
            let a = try await s.request(AppChannel.cHello, Data(), timeout: 4)
            guard a.rsp == AppChannel.rHello else { finishProbe(false, String(format: "KEY answered type %02x", a.rsp), s); return }
            let b = [UInt8](a.body)
            let life = b.count > 1 ? (b[1] == 0x03 ? "NOSTR, Bluetooth mode" : String(format: "life 0x%02x", b[1])) : "?"
            let drop = b.count >= 10 ? String(bytes: b[2..<10].filter { $0 != 0 }, encoding: .ascii) ?? "?" : "?"
            finishProbe(true, "KEY answered: \(life), drop \(drop)", s)
        } catch {
            finishProbe(false, "\(error)", s)
        }
    }

    private func finishProbe(_ ok: Bool, _ why: String, _ s: KeySession?) {
        s?.close()
        let how = s?.how ?? ""
        let head = ok ? "KEY reached in \(ms) ms" : "KEY NOT reached (\(ms) ms)"
        let line = ISO8601DateFormatter().string(from: Date()) + " " + head + ". " + why + (how.isEmpty ? "" : " [\(how)]")
        if let d = UserDefaults(suiteName: NotificationService.group) {
            var all = d.stringArray(forKey: NotificationService.resultsKey) ?? []
            all.append(line + "\n" + (s?.steps ?? []).joined(separator: "\n"))
            d.set(Array(all.suffix(20)), forKey: NotificationService.resultsKey)
        }
        deliver("Favilla push test: " + (ok ? "OK" : "failed"), head + ". " + why + (how.isEmpty ? "" : " [\(how)]"))
    }
}
