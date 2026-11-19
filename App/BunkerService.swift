// BunkerService.swift - the app's side of the Bluetooth bunker (9 Nov 2026).
//
// Josh: "turn the nostr client into a bunker like amber so you can be bluetooth
// connected - app - to other client". Other Nostr apps (Amethyst, Primal,
// Coracle) connect to the KEY's own NIP-46 bunker with the bunker:// link the
// PWA's Settings > Connect apps makes (the same page as on Wi-Fi; the KEY lets
// it work in Bluetooth mode from the issue #11 drop). In Bluetooth mode the KEY
// has no internet, so this iPhone carries the requests:
//
//  - App open: listen to the bunker relays here (kind 24133, #p the KEY), hand
//    each request to the KEY on the shared Bluetooth link (NostrLink), publish
//    the replies. A heartbeat in the app group tells the extension to stand back.
//  - App closed: the push bridge on relay.favillakey.io watches the same relays
//    and wakes the notification extension, which does the same (PushProbe).
//  - Coming back to the app: fetch anything the extension missed from the bridge,
//    and poll the KEY once for replies it finished after the extension ran out
//    of time (an approval on the KEY).
//
// Turning it on: BUNKER_INFO (0x3D) gives the KEY's bunker pubkey and relays;
// the push token goes to the bridge with them.

import Foundation
import SwiftUI
import UIKit
import UserNotifications

@MainActor
final class BunkerService: ObservableObject {
    static let shared = BunkerService()

    @Published private(set) var on = Bunker.on
    @Published private(set) var info = Bunker.Info.load()
    @Published private(set) var status = ""
    @Published private(set) var busy = false
    @Published private(set) var listening = 0          // relays connected
    @Published private(set) var log: [String] = []

    private var sockets: [URLSessionWebSocketTask] = []
    private var beatTimer: Timer?
    private var active = false
    private var serving = false
    private var gen = 0                                 // bumped by stop(): a dropped socket from before doesn't reconnect
    private var queue: [(String, Data)] = []

    init() { reloadLog() }

    /// App launch (also a background relaunch by iOS for the Bluetooth link).
    func start() {
        guard nudgeObserver == nil else { return }
        nudgeObserver = NotificationCenter.default.addObserver(forName: NostrLink.nudged, object: nil, queue: .main) { n in
            let w = n.userInfo?["waiting"] as? Int ?? 0
            let v = n.userInfo?["vault"] as? Int ?? 0
            Task { @MainActor in
                BunkerService.shared.nudged(waiting: w)
                if v != 0 { VaultService.shared.asked(UInt8(v)) }
            }
        }
        NostrLink.shared.stayUp()
    }

    private var nudgeObserver: NSObjectProtocol?
    private var nudging = false
    private var askedApproval = Set<String>()

    // MARK: - Path B: the KEY nudges the app over Bluetooth (KEY 11i)

    /// A nudge from the KEY (every few seconds while the link is up). iOS gives
    /// a backgrounded app about 10 s per nudge: ask the bridge for waiting
    /// requests, collect replies the KEY already built, hand the requests over on
    /// this link and publish the replies. In the foreground the relay listener
    /// does this already, so only the KEY's outbox is collected here.
    func nudged(waiting: Int) {
        guard !nudging else { return }
        // KEY 11o (issue #13): the KEY also nudges for its own events (SHARE RUN
        // in CIPHER), with the bunker off and without NUDGE_SET. Anything waiting
        // in its outbox is collected and published whatever the bunker switch says.
        guard on || waiting > 0 else { return }
        if active && waiting == 0 { return }
        nudging = true
        let bg = UIApplication.shared.beginBackgroundTask(withName: "bunker-nudge") {}
        Task {
            defer {
                nudging = false
                UIApplication.shared.endBackgroundTask(bg)
            }
            // The relays: saved when the bunker was turned on, else asked now.
            var known = info
            if known == nil, let a = try? await NostrLink.shared.call(Bunker.cInfo, Data()), a.rsp == Bunker.rInfo, let got = Bunker.decodeInfo(a.body) {
                got.save(); info = got; known = got
            }
            let i = known ?? Bunker.Info(pubkey: "", relays: ["wss://relay.favillakey.io"])
            var reqs: [(String, Data)] = []
            if on, !active, !i.pubkey.isEmpty {
                reqs = ((try? await Bunker.pending(pubkey: i.pubkey, link: true)) ?? []).filter { r in !queue.contains { $0.0 == r.0 } }
            }
            guard !reqs.isEmpty || waiting > 0 else { return }
            if !reqs.isEmpty { Bunker.log("nudge: \(reqs.count) request\(reqs.count == 1 ? "" : "s") from the bridge") }
            var o = await Bunker.serve(reqs, via: NostrLink.shared, relays: i.relays, until: Date().addingTimeInterval(8), poll: waiting > 0)
            if o.taken + o.replies > 0 || o.error != nil {
                Bunker.log("nudge: taken \(o.taken), replies \(o.replies), accepted \(o.sent)" + (o.waiting ? ", still waiting" : "") + (o.error.map { ", \($0)" } ?? ""))
            }
            // A Nostr app sends its requests one after another, each when the last
            // is answered (19 Nov bench: 10 to 15 s apart). Don't wait for the next
            // nudge: keep asking the bridge for 6 s after each answer, 20 s at most.
            let stop = Date().addingTimeInterval(20)
            var quietAt = Date().addingTimeInterval(6)
            while on, !active, o.sent > 0, o.error == nil, !o.waiting, !i.pubkey.isEmpty, Date() < min(stop, quietAt) {
                try? await Task.sleep(nanoseconds: 400_000_000)
                let next = ((try? await Bunker.pending(pubkey: i.pubkey, link: true)) ?? []).filter { r in !queue.contains { $0.0 == r.0 } }
                guard !next.isEmpty else { continue }
                Bunker.log("follow-on: \(next.count) request\(next.count == 1 ? "" : "s") from the bridge")
                reqs += next
                o = await Bunker.serve(next, via: NostrLink.shared, relays: i.relays, until: Date().addingTimeInterval(8))
                Bunker.log("follow-on: taken \(o.taken), replies \(o.replies), accepted \(o.sent)" + (o.waiting ? ", still waiting" : "") + (o.error.map { ", \($0)" } ?? ""))
                quietAt = Date().addingTimeInterval(6)
            }
            // Waiting for a button press on the KEY: say so once (no push came).
            let ids = Set(reqs.map { $0.0 })
            if o.waiting, !ids.isEmpty, !ids.isSubset(of: askedApproval), !active {
                askedApproval.formUnion(ids)
                let c = UNMutableNotificationContent()
                c.title = "Favilla bunker"
                c.body = "Signing request from a Nostr app. Approve it on your KEY."
                c.threadIdentifier = "bunker"
                try? await UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: "bunker-approve", content: c, trigger: nil))
            }
            if o.sent > 0 { UNUserNotificationCenter.current().removeDeliveredNotifications(withIdentifiers: ["bunker-approve"]) }
            // A CIPHER run the KEY handed over: the phone is the only side that sees the relays' answer.
            if !o.shared.isEmpty || o.sharedRefused {
                Bunker.log(o.shared.isEmpty ? "CIPHER run: no relay took it" : "CIPHER run shared: favillakey.io/cipher#run=\(o.shared[0])")
                let c = UNMutableNotificationContent()
                c.title = "CIPHER"
                c.body = o.shared.isEmpty ? "The relays didn't take your run. Press SHARE RUN on the KEY again." : "Score shared."
                c.threadIdentifier = "cipher"
                try? await UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: "cipher-share", content: c, trigger: nil))
            }
            if askedApproval.count > 200 { askedApproval.removeAll() }
            reloadLog()
        }
    }

    func reloadLog() { log = (Bunker.store.stringArray(forKey: "bunkerLog") ?? []).reversed() }

    #if DEBUG
    static let env = "development"
    #else
    static let env = "production"     // TestFlight and the App Store
    #endif

    // MARK: - On and off

    func turnOn() {
        guard !busy else { return }
        guard KeyRoute.current == .bluetooth else { status = "Choose Bluetooth above first. On Wi-Fi the KEY reaches the relays itself."; return }
        guard Credentials.isPaired else { status = NostrLink.notPaired; return }
        busy = true
        status = "Asking the KEY for its bunker relays..."
        Task {
            defer { busy = false }
            do {
                let a = try await NostrLink.shared.call(Bunker.cInfo, Data())
                if a.rsp == AppChannel.rErr { status = Bunker.refusal(a.body.first ?? 0xFF); return }
                guard a.rsp == Bunker.rInfo, let i = Bunker.decodeInfo(a.body) else {
                    status = String(format: "The KEY answered type %02x. It needs the Bluetooth bunker drop (firmware issue #11).", a.rsp); return
                }
                i.save(); info = i
                Bunker.on = true; on = true
                start()
                NostrLink.shared.stayUp()
                Bunker.log("turned on: \(i.relays.joined(separator: ", "))")
                await registerPush()
                startIfReady()
            } catch {
                status = "\(error)"
            }
        }
    }

    func turnOff() {
        Task { _ = try? await NostrLink.shared.call(Bunker.cNudgeSet, Data([0])) }   // the KEY stops nudging
        let tok = PushTest.shared.token
        if let i = info, !tok.isEmpty { Task { await Bunker.unregister(token: tok, pubkey: i.pubkey) } }
        Bunker.on = false; on = false
        Bunker.log("turned off")
        stop()
        status = "Off. Other apps can't reach your KEY through this iPhone."
        reloadLog()
    }

    /// The token goes to the bridge with the KEY's relays. Notifications must be
    /// allowed; PushTest asks iOS and keeps the token fresh.
    /// One registration covers the bunker (when on) and incoming calls (always,
    /// once the client has said who you are): the identity's pubkey, the union
    /// of the bunker's and the call relays, the APNs token and the VoIP token.
    func registerPush() async {
        let client = Bunker.ClientInfo.load()
        let pk = (on ? info?.pubkey : nil) ?? client?.pubkey
        guard let pk else { return }
        var relays = client?.relays ?? []
        if on, let i = info { for r in i.relays where !relays.contains(r) { relays.append(r) } }
        if relays.isEmpty { relays = ["wss://relay.favillakey.io"] }
        let tok = PushTest.shared.token
        guard !tok.isEmpty else {
            if on {
                status = "Allow notifications so the KEY can sign while Favilla is closed..."
                PushTest.shared.enable()
            }
            return
        }
        let voip = CallRing.shared.voipToken
        do {
            try await Bunker.register(token: tok, env: BunkerService.env, info: Bunker.Info(pubkey: pk, relays: relays), voip: voip)
            if on { status = "On. Other apps can reach your KEY through this iPhone, even with Favilla closed." }
            Bunker.log("push bridge: registered" + (voip.isEmpty ? " (no call ring token yet)" : ", calls ring"))
        } catch {
            if on { status = "On while Favilla is open. The push bridge isn't answering (\(error.localizedDescription)), so it can't sign while Favilla is closed." }
            Bunker.log("push bridge: \(error.localizedDescription)")
        }
        reloadLog()
    }

    /// The Nostr client said who you are and which relays it takes calls on.
    func clientInfo(pubkey: String, relays: [String]) {
        let c = Bunker.ClientInfo(pubkey: pubkey, relays: relays)
        guard c != Bunker.ClientInfo.load() else { return }
        c.save()
        Task { await registerPush() }
    }

    /// A new push token arrived (PushTest calls this).
    func tokenChanged() { Task { await registerPush() } }

    // MARK: - App open: listen here

    func appActive(_ yes: Bool) {
        if yes {
            NostrLink.shared.stayUp()
            // The quiet bunker notes in Notification Centre are history once you're here.
            let nc = UNUserNotificationCenter.current()
            nc.getDeliveredNotifications { all in
                nc.removeDeliveredNotifications(withIdentifiers: all.filter { $0.request.content.threadIdentifier == "bunker" || $0.request.content.userInfo["fv"] != nil }.map { $0.request.identifier })
            }
        }
        active = yes
        if yes { startIfReady() } else { stop() }
    }

    /// The route changed: the listener only runs on Bluetooth.
    func refresh() { stop(); if active { startIfReady() }; NostrLink.shared.stayUp() }

    private func startIfReady() {
        guard active, on, let i = info, KeyRoute.current == .bluetooth, Credentials.isPaired else { return }
        guard sockets.isEmpty else { return }
        Bunker.beat()
        beatTimer?.invalidate()
        beatTimer = Timer.scheduledTimer(withTimeInterval: 3, repeats: true) { _ in Bunker.beat() }
        for r in i.relays { if let u = URL(string: r) { listen(u, pubkey: i.pubkey) } }
        // Anything the extension missed, and replies the KEY finished after it stopped.
        Task {
            if let missed = try? await Bunker.pending(pubkey: i.pubkey), !missed.isEmpty {
                Bunker.log("app: \(missed.count) missed request\(missed.count == 1 ? "" : "s") from the bridge")
                enqueue(missed)
            } else {
                await serveQueue(poll: true)
            }
        }
    }

    private func stop() {
        gen += 1
        beatTimer?.invalidate(); beatTimer = nil
        Bunker.stopBeat()
        sockets.forEach { $0.cancel(with: .goingAway, reason: nil) }
        sockets = []
        listening = 0
    }

    private func listen(_ url: URL, pubkey: String) {
        let ws = URLSession.shared.webSocketTask(with: url)
        sockets.append(ws)
        ws.resume()
        let sub: [Any] = ["REQ", "fvbunker", ["kinds": [24133], "#p": [pubkey], "since": Int(Date().timeIntervalSince1970) - 10]]
        guard let d = try? JSONSerialization.data(withJSONObject: sub), let s = String(data: d, encoding: .utf8) else { return }
        ws.send(.string(s)) { _ in }
        listening += 1
        receive(ws, url: url, pubkey: pubkey, gen: gen)
    }

    private func receive(_ ws: URLSessionWebSocketTask, url: URL, pubkey: String, gen g: Int) {
        ws.receive { [weak self] r in
            Task { @MainActor in
                guard let self, self.sockets.contains(where: { $0 === ws }) else { return }
                switch r {
                case .failure:
                    // Dropped: try again in 5 s while still open.
                    self.sockets.removeAll { $0 === ws }
                    self.listening = max(0, self.listening - 1)
                    try? await Task.sleep(nanoseconds: 5_000_000_000)
                    if self.gen == g, self.active, self.on { self.listen(url, pubkey: pubkey) }
                case .success(let m):
                    if case .string(let s) = m { self.relayMessage(s, pubkey: pubkey) }
                    self.receive(ws, url: url, pubkey: pubkey, gen: g)
                }
            }
        }
    }

    private func relayMessage(_ s: String, pubkey: String) {
        guard let j = try? JSONSerialization.jsonObject(with: Data(s.utf8)) as? [Any], j.count >= 3,
              j[0] as? String == "EVENT", let ev = j[2] as? [String: Any],
              let id = ev["id"] as? String, id.count == 64, ev["kind"] as? Int == 24133,
              let tags = ev["tags"] as? [[Any]], tags.contains(where: { $0.count >= 2 && $0[0] as? String == "p" && $0[1] as? String == pubkey }),
              !Bunker.seen(id), !queue.contains(where: { $0.0 == id }),
              let d = try? JSONSerialization.data(withJSONObject: ev) else { return }
        enqueue([(id, d)])
    }

    private func enqueue(_ reqs: [(String, Data)]) {
        queue.append(contentsOf: reqs)
        Task { await serveQueue(poll: false) }
    }

    private func serveQueue(poll: Bool) async {
        guard !serving, let i = info else { return }
        serving = true
        defer { serving = false; reloadLog() }
        repeat {
            let batch = queue; queue = []
            // An approval on the KEY can take a while; keep polling up to a minute (the KEY keeps replies 60 s).
            let o = await Bunker.serve(batch, via: NostrLink.shared, relays: i.relays, until: Date().addingTimeInterval(60), poll: poll)
            if o.taken + o.replies > 0 || o.error != nil {
                Bunker.log("app: taken \(o.taken), replies \(o.replies), accepted \(o.sent)" + (o.error.map { ", \($0)" } ?? ""))
            }
            if let e = o.error { status = e }
            if !o.later.isEmpty, active {
                // The KEY was busy for these and stayed busy: try again in a few seconds.
                try? await Task.sleep(nanoseconds: 3_000_000_000)
                queue.append(contentsOf: o.later.filter { !Bunker.seen($0.0) })
            }
        } while !queue.isEmpty && active
    }
}


