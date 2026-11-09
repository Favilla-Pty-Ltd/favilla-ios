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
            if let pk = fv?["pk"] as? String {
                await bunker(pk, round: (fv?["r"] as? Int) ?? 0, carried: NotificationService.events(fv?["evs"]))
            } else { await probe() }
        }
    }

    override func serviceExtensionTimeWillExpire() {
        session?.close()
        let (t, b) = best ?? ("Favilla", "Ran out of time reaching your KEY.")
        Bunker.log("extension: out of time at \(ms) ms")
        deliver(t, b)
    }

    // Bunker notifications are quiet (10 Nov, Josh: no banner when the KEY signs
    // by itself): they go to Notification Centre with no banner, sound or buzz.
    // iOS won't run this extension without delivering something. A banner shows
    // only when you are needed: an approval on the KEY, or a KEY that can't be used.
    private var quiet = false
    private var sentSoFar = 0
    private var finished = false

    /// A problem you can fix (KEY locked, out of reach, not paired): a banner, at most one a minute.
    private func problem(_ title: String, _ body: String) {
        let d = Bunker.store, now = Date().timeIntervalSince1970
        if now - d.double(forKey: "bunkerProblemAt") > 60 { d.set(now, forKey: "bunkerProblemAt"); quiet = false }
        deliver(title, body)
    }

    /// The KEY has had the request 10 s and sent nothing: it is waiting for a
    /// button press. Say so now, with a banner (this run may wait 20 s more).
    private func askApprovalIfStuck() {
        Task { [weak self] in
            try? await Task.sleep(nanoseconds: 10_000_000_000)
            guard let self else { return }
            self.lock.lock(); let stuck = !self.finished && self.sentSoFar == 0; self.lock.unlock()
            guard stuck else { return }
            let c = UNMutableNotificationContent()
            c.title = "Favilla bunker"
            c.body = "Signing request from a Nostr app. Approve it on your KEY."
            c.threadIdentifier = "bunker"
            try? await UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: "bunker-approve", content: c, trigger: nil))
            Bunker.log("extension: asked for an approval on the KEY")
        }
    }

    private func deliver(_ title: String, _ body: String) {
        lock.lock()
        let h = handler; handler = nil
        lock.unlock()
        guard let h, let c = content else { return }
        c.title = title
        c.body = body
        if quiet, #available(iOS 15.0, *) { c.interruptionLevel = .passive }
        h(c)
    }

    private var ms: Int { Int(Date().timeIntervalSince(t0) * 1000) }

    // MARK: - Bunker

    /// Connect to the KEY; nil, or why not.
    static func open(_ s: KeySession) async -> String? {
        do { try await s.open(); return nil } catch { return "\(error)" }
    }

    /// The requests the bridge put in the push itself (when they fit in 4 KB).
    static func events(_ any: Any?) -> [(String, Data)] {
        guard let evs = any as? [[String: Any]] else { return [] }
        return evs.compactMap { e in
            guard let id = e["id"] as? String, id.count == 64, e["kind"] as? Int == 24133, !Bunker.seen(id),
                  let d = try? JSONSerialization.data(withJSONObject: e) else { return nil }
            return (id, d)
        }
    }

    private func bunker(_ pk: String, round: Int, carried: [(String, Data)]) async {
        let title = "Favilla bunker"
        quiet = true
        best = (title, "Signing request from a Nostr app. Open Favilla to answer it.")
        guard Bunker.on, let info = Bunker.Info.load(), info.pubkey == pk else {
            deliver(title, "Signing for other apps is off on this iPhone."); return
        }
        if Bunker.appActive {
            deliver(title, "Answered in the Favilla app."); return
        }
        guard let creds = Credentials.load() else {
            problem(title, "Open Favilla and PAIR THE APP to sign for other apps."); return
        }
        // iOS shows the banner only when this run finishes, and handing requests
        // to the KEY can take several seconds (it holds each up to 4 s). So the
        // first run shows the banner at once and asks the bridge to wake the
        // phone again straight away; that quiet run does the work.
        if round == 0, await Bunker.again(pubkey: pk, round: 1, delay: 0) {
            Bunker.log("extension: banner shown in \(ms) ms, work handed to the next wake")
            deliver(title, "Signing request from a Nostr app.")
            return
        }
        // Bluetooth first, in parallel with everything else: the connect is the
        // slow, variable part (issue #11, 9 Nov). The requests usually came in the
        // push itself; the bridge is asked as well, for any that didn't fit.
        let s = KeySession(creds)
        session = s
        async let opening: String? = NotificationService.open(s)
        async let fetched: [(String, Data)]? = try? await Bunker.pending(pubkey: pk)
        var reqs = carried
        let more = await fetched
        for r in more ?? [] where !reqs.contains(where: { $0.0 == r.0 }) { reqs.append(r) }
        if more == nil { Bunker.log("extension: bridge unreachable, \(carried.count) request(s) from the push") }
        if let e = await opening {
            Bunker.log("extension: \(e) (\(ms) ms, \(s.how))")
            problem(title, "Couldn't reach your KEY. \(e)"); return
        }
        // A follow-up push (round 1 and on) may come with nothing new: it is here
        // to collect replies the KEY finished after the last run (an approval).
        guard !reqs.isEmpty || round > 0 else { s.close(); deliver(title, "Nothing waiting: the request was already answered."); return }
        Bunker.log("extension: " + (round > 0 ? "follow-up \(round), " : "") + "KEY open in \(ms) ms (\(s.how)), \(reqs.count) request\(reqs.count == 1 ? "" : "s") (\(carried.count) in the push)")
        // iOS shows the notification only when this finishes. The first run hands
        // the request over and stops within about 6 s (time for the KEY to sign on
        // its own), so "approve it on your KEY" shows at once; follow-up runs then
        // wait for the approval, up to 22 s each (iOS allows about 30).
        let deadline = t0.addingTimeInterval(round == 0 ? 6 : 22)
        let askedAt = Bunker.store.double(forKey: "bunkerAskedAt"), now = Date().timeIntervalSince1970
        if !reqs.isEmpty, now - askedAt > 30 {
            Bunker.store.set(now, forKey: "bunkerAskedAt")
            askApprovalIfStuck()
        }
        let o = await Bunker.serve(reqs, via: s, relays: info.relays, until: deadline, poll: true) { [weak self] o in
            if let self { self.lock.lock(); self.sentSoFar = o.sent; self.lock.unlock() }
            if o.sent > 0 { self?.best = (title, Self.text(o)) }
            else if o.taken > 0 { self?.best = (title, "Approve it on your KEY.") }
        }
        s.close()
        // The KEY is still waiting (a button press): ask the bridge to wake this
        // iPhone again in a moment, so the reply goes out without opening Favilla.
        var again = false
        if o.waiting, round < Bunker.againMax {
            again = await Bunker.again(pubkey: pk, round: round + 1)
            Bunker.log("extension: follow-up push \(round + 1) " + (again ? "asked for" : "refused"))
        }
        Bunker.log("extension: done in \(ms) ms: taken \(o.taken), replies \(o.replies), accepted \(o.sent)" + (o.waiting ? ", still waiting" : "") + (o.error.map { ", \($0)" } ?? ""))
        lock.lock(); finished = true; lock.unlock()
        if o.sent > 0 { UNUserNotificationCenter.current().removeDeliveredNotifications(withIdentifiers: ["bunker-approve"]) }
        if let e = o.error, o.taken == 0 { problem(title, e); return }
        if o.waiting && again && o.sent == 0 { deliver(title, "Approve it on your KEY. It sends as soon as you do."); return }
        if o.waiting && o.sent == 0 { quiet = false }      // no follow-up coming: you need to know
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
