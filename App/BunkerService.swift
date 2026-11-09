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
            Task { @MainActor in BunkerService.shared.nudged(waiting: w) }
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
        guard on, let i = info, !nudging else { return }
        if active && waiting == 0 { return }
        nudging = true
        let bg = UIApplication.shared.beginBackgroundTask(withName: "bunker-nudge") {}
        Task {
            defer {
                nudging = false
                UIApplication.shared.endBackgroundTask(bg)
            }
            var reqs: [(String, Data)] = []
            if !active {
                reqs = ((try? await Bunker.pending(pubkey: i.pubkey, link: true)) ?? []).filter { r in !queue.contains { $0.0 == r.0 } }
            }
            guard !reqs.isEmpty || waiting > 0 else { return }
            if !reqs.isEmpty { Bunker.log("nudge: \(reqs.count) request\(reqs.count == 1 ? "" : "s") from the bridge") }
            let o = await Bunker.serve(reqs, via: NostrLink.shared, relays: i.relays, until: Date().addingTimeInterval(8), poll: waiting > 0)
            if o.taken + o.replies > 0 || o.error != nil {
                Bunker.log("nudge: taken \(o.taken), replies \(o.replies), accepted \(o.sent)" + (o.waiting ? ", still waiting" : "") + (o.error.map { ", \($0)" } ?? ""))
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
    func registerPush() async {
        guard on, let i = info else { return }
        let tok = PushTest.shared.token
        guard !tok.isEmpty else {
            status = "Allow notifications so the KEY can sign while Favilla is closed..."
            PushTest.shared.enable()
            return
        }
        do {
            try await Bunker.register(token: tok, env: BunkerService.env, info: i)
            status = "On. Other apps can reach your KEY through this iPhone, even with Favilla closed."
            Bunker.log("push bridge: registered")
        } catch {
            status = "On while Favilla is open. The push bridge isn't answering (\(error.localizedDescription)), so it can't sign while Favilla is closed."
            Bunker.log("push bridge: \(error.localizedDescription)")
        }
        reloadLog()
    }

    /// A new push token arrived (PushTest calls this).
    func tokenChanged() { Task { await registerPush() } }

    // MARK: - App open: listen here

    func appActive(_ yes: Bool) {
        if yes { NostrLink.shared.stayUp() }
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

// MARK: - Settings > This iPhone > BUNKER

struct BunkerSection: View {
    @ObservedObject private var b = BunkerService.shared
    @State private var showAll = false

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("BUNKER").font(Brand.label).tracking(2).foregroundStyle(Brand.brass)
            VStack(alignment: .leading, spacing: 12) {
                Text("Lets Nostr apps like Amethyst, Primal and Coracle sign with your KEY while it is in Bluetooth mode. This iPhone passes each request to the KEY over Bluetooth and sends the answer back, even with Favilla closed. Make each app's bunker link in the Nostr client: Settings > Connect apps.")
                    .font(Brand.small).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true)
                Toggle(isOn: Binding(get: { b.on }, set: { $0 ? b.turnOn() : b.turnOff() })) {
                    Text("Sign for other apps").font(Brand.button).foregroundStyle(Brand.ink)
                }
                .tint(Brand.brass)
                .disabled(b.busy)
                if !b.status.isEmpty {
                    Text(b.status).font(Brand.small).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true)
                }
                if b.on, let i = b.info {
                    Text("Relays: " + i.relays.map { $0.replacingOccurrences(of: "wss://", with: "") }.joined(separator: ", "))
                        .font(Brand.small).foregroundStyle(Brand.ink).fixedSize(horizontal: false, vertical: true)
                    Text(b.listening > 0 ? "Listening on \(b.listening) relay\(b.listening == 1 ? "" : "s") while Favilla is open." : "Favilla is closed or in the background: the push bridge wakes this iPhone.")
                        .font(Brand.small).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true)
                }
                if !b.log.isEmpty {
                    HStack(spacing: 12) {
                        Text("Log (\(b.log.count))").font(Brand.button).foregroundStyle(Brand.ink)
                        Spacer()
                        Button("Refresh") { b.reloadLog() }.font(Brand.button).foregroundStyle(Brand.brass)
                        Button("Copy") { UIPasteboard.general.string = b.log.joined(separator: "\n") }.font(Brand.button).foregroundStyle(Brand.brass)
                    }
                    Text(b.log.prefix(showAll ? 40 : 6).joined(separator: "\n"))
                        .font(.system(size: 11, design: .monospaced)).foregroundStyle(Brand.ink)
                        .textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                        .padding(10).frame(maxWidth: .infinity, alignment: .leading)
                        .background(Brand.bg).clipShape(RoundedRectangle(cornerRadius: 10))
                    if b.log.count > 6 {
                        Button(showAll ? "Show fewer" : "Show all") { showAll.toggle() }.font(Brand.button).foregroundStyle(Brand.grey)
                    }
                }
            }
            .padding(16)
            .background(Brand.card)
            .clipShape(RoundedRectangle(cornerRadius: 14))
        }
        .onAppear { b.reloadLog() }
    }
}
