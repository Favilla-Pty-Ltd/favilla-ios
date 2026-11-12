// NostrLink.swift - the Nostr client's Bluetooth link to the KEY (7 Nov 2026).
//
// Built against favilla-key-firmware docs/BLE_PASSKEY_PROTOCOL.md, "The app
// channel (9g)" and "NOSTR over Bluetooth (9k)". The KEY is in its NOSTR Bluetooth life (9p: chosen in Settings > Network > Change mode > Bluetooth)
// life (Wi-Fi never starts) and this install is paired with its app channel
// (PAIR THE APP). Unlike KeyLink, which connects for one sign-in and lets go,
// this link stays up while the Nostr client runs, because the PWA calls the KEY
// all the time (link checks, signing, DM decryption).
//
// Per connect: subscribe to 8F1A0006, send TIME (the doc: after every connect,
// before anything else), then the queued API requests, one at a time:
//   [0x3A][clientId 8][ctr 4][ApiWire request][mac16]  ->  0xB8 enc [ApiWire answer]
// A replay refusal raises the counter and resends; "not paired" forgets the
// stored pairing. If the link drops, the request in flight fails (the PWA
// retries as it does on Wi-Fi) and the next request reconnects.

import CoreBluetooth
import Foundation

/// All state is touched only on the main queue (CoreBluetooth delegate queue .main,
/// and every entry point hops there), hence @unchecked Sendable.
final class NostrLink: NSObject, ObservableObject, @unchecked Sendable {
    static let shared = NostrLink()

    enum State: Equatable { case idle, connecting, ready, failed(String) }
    /// What the settings screen shows.
    @Published private(set) var state: State = .idle

    private struct Job {
        let id: UInt64
        let body: Data                       // ApiWire request (or a bunker body)
        var cmd: UInt8 = AppChannel.cApi
        let done: (Result<AppChannel.Answer, Error>) -> Void
        var ctr: UInt32 = 0
        var replays = 0
    }

    private var central: CBCentralManager?
    private var peripheral: CBPeripheral?
    private var chanIn: CBCharacteristic?
    private var chanOut: CBCharacteristic?
    private var creds: Credentials?
    private var reasm = AppChannel.Reassembler(limit: AppChannel.msgMaxApi)
    private var writes: [Data] = []
    private var writing = Data()
    private var busyRetries = 0
    private var writeStarted = Date()
    private var writeBytes = 0
    private var pendingLimit: Double = 0          // the current request's answer limit, counted from its last write
    private var reconnectDelay: TimeInterval = 0  // back-off after a drop: 0, 0.25, 0.5 ... 8 s
    private var timeCtr: UInt32 = 0          // the TIME request, while it is out
    private var lastTimeCtr: UInt32 = 0      // the last TIME sent: its answer may come after we moved on (#9 item 5)
    private var helloCtr: UInt32 = 0         // HELLO, while it is out: which life the KEY is in (#9, 9 Nov)
    private var timeRetried = false
    private var nudgeSet = false             // NUDGE_SET sent on this connection (path B, KEY 11i)
    private var nudges = 0
    private var lastPer = 0                  // reports per write last used (#9 item 2: the MTU grows after connect)
    private var skipToStart = false          // after a failed message: drop its leftover reports until the next start (#9 item 3)
    private var skipped = 0
    private var queue: [Job] = []
    private var notes = 0                    // notifications since the last message went out (log)
    private var current: Job?
    private var timer: DispatchWorkItem?
    private var connectTimer: DispatchWorkItem?
    private let store = UserDefaults(suiteName: "group.io.favillakey.app") ?? .standard

    /// While KeyLink runs an operation (PAIR THE APP, a sign-in) this link steps
    /// aside: the KEY serves one request at a time, and pairing replaces K.
    private var paused = false
    private var observers: [NSObjectProtocol] = []

    override init() {
        super.init()
        let nc = NotificationCenter.default
        observers.append(nc.addObserver(forName: KeyLink.didStart, object: nil, queue: .main) { [weak self] _ in self?.pause() })
        observers.append(nc.addObserver(forName: KeyLink.didFinish, object: nil, queue: .main) { [weak self] _ in self?.resume() })
    }

    private func pause() {
        paused = true
        if current != nil || peripheral != nil {
            drop()
            state = .idle
            if current != nil { finishCurrent(.failure(KeyApiError.notReady("The KEY is busy with the Favilla app."))) }
        }
    }

    private func resume() {
        paused = false
        pump()
        stayUp()
    }

    static let notPaired = "Pair the app with the KEY first: Settings > This iPhone > PAIR THE APP."
    static let notNostrBT = "Your KEY isn't in Bluetooth mode. On the KEY: Settings > Network > Change mode > Bluetooth."
    static let locked = "Your KEY is locked. Enter the NOSTR PIN on the KEY."
    static let notFound = "Can't find your KEY. Check it's on, in Bluetooth mode, and near this iPhone."

    // MARK: - Sending

    /// One API call: the ApiWire request body in, the ApiWire answer out.
    func send(_ body: Data) async throws -> ApiResponse {
        let a = try await call(AppChannel.cApi, body)
        guard a.rsp == AppChannel.rApi, let r = ApiWire.decodeAnswer(a.body) else {
            LinkLog.shared.add(String(format: "  bad API answer: type %02x, body %d bytes", a.rsp, a.body.count))
            throw KeyApiError.badAnswer
        }
        return r
    }

    /// The commands that share this link: API, and the bunker's NIP46 / POLL / INFO.
    static let ours: Set<UInt8> = [AppChannel.cApi, AppChannel.cTime, AppChannel.cHello, Bunker.cNip46, Bunker.cPoll, Bunker.cInfo, Bunker.cNudgeSet]

    /// Posted on the main queue for each KEY nudge (path B): userInfo "waiting" (Int).
    static let nudged = Notification.Name("NostrLink.nudged")
    /// Posted when the KEY drops the link the client was using (off, out of
    /// range, Bluetooth off): the client wipes its plaintext DMs at once
    /// instead of after 45 s of failed polls (12 Nov).
    static let keyGone = Notification.Name("NostrLink.keyGone")

    /// One app-channel request on the shared link; the answer whatever its type
    /// (an API refusal becomes an error; for the bunker commands the caller reads 0xBF itself).
    func call(_ cmd: UInt8, _ body: Data) async throws -> AppChannel.Answer {
        let id = UInt64.random(in: 1...UInt64.max)
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (k: CheckedContinuation<AppChannel.Answer, Error>) in
                DispatchQueue.main.async {
                    var once = false
                    let job = Job(id: id, body: body, cmd: cmd) { r in
                        guard !once else { return }
                        once = true
                        k.resume(with: r)
                    }
                    self.queue.append(job)
                    self.pump()
                }
            }
        } onCancel: {
            DispatchQueue.main.async {
                // Not sent yet: drop it. Already on the air: let the answer arrive and be ignored.
                if let i = self.queue.firstIndex(where: { $0.id == id }) {
                    self.queue.remove(at: i).done(.failure(CancellationError()))
                }
            }
        }
    }

    /// Drop the link (the route was switched away from Bluetooth).
    func disconnect() {
        DispatchQueue.main.async {
            self.failAll(KeyApiError.notReady("The link was closed."))
            self.drop()
            self.state = .idle
        }
    }

    private func pump() {
        guard current == nil, !queue.isEmpty, !paused else { return }
        // The pairing is read from the Keychain before every request: PAIR THE APP
        // (or the AutoFill sheet) may have replaced it since the link opened. A
        // link opened with an old pairing would be refused, so start again.
        let fresh = Credentials.load()
        if fresh == nil {
            state = .failed(NostrLink.notPaired)
            failAll(KeyApiError.notReady(NostrLink.notPaired)); return
        }
        if fresh != creds, creds != nil {
            drop()
            state = .idle
        }
        creds = fresh
        guard state == .ready, peripheral?.state == .connected, chanIn != nil else { connectIfNeeded(); return }
        var j = queue.removeFirst()
        j.ctr = Credentials.nextCounter()
        current = j
        LinkLog.shared.add("request ctr \(j.ctr): \(LinkLog.what(j.cmd, j.body)), \(j.body.count) bytes, \(queue.count) waiting")
        transmit(j)
    }

    private func transmit(_ j: Job) {
        guard let c = creds else { return }
        let msg = AppChannel.request(j.cmd, c, ctr: j.ctr, body: j.body)
        guard msg.count <= AppChannel.msgMaxApi else { finishCurrent(.failure(KeyApiError.refused("request too large"))); return }
        // The KEY's handlers answer at once (doc 9k); 32 KB crosses in about a
        // second. No answer in that time means the link is dead (the KEY restarted
        // or walked off, and iOS hasn't noticed yet): drop it so the next request
        // reconnects at once instead of every call waiting out a long timeout.
        // A NIP46 request waits up to 4 s on the KEY (10p), and a bunker answer can
        // carry up to 40 KB back: give those 12 s.
        // 11 Nov: a video call offer is an 11 KB /nip-decrypt; the KEY took more
        // than the 7 s this gave it (4 KB voice offers got through). Until the
        // KEY side is measured (firmware issue), a big API body gets 1 s per KB
        // each way on top.
        // The limit counts from the request's LAST write (issue #20 item 3): a
        // 31 KB VAULT_PUT took 12 s to write with-response and the limit ran out
        // while it was still going out.
        let limit = (j.cmd == Bunker.cNip46 || j.cmd == Bunker.cPoll ? 12 : 6) + Double(msg.count) / (j.cmd == AppChannel.cApi ? 500 : 8_000)
        pendingLimit = limit
        arm(limit + Double(msg.count) / 2_000) { [weak self] in
            guard let self else { return }
            let pr = self.reasm.progress
            LinkLog.shared.add("TIMEOUT ctr \(j.ctr) after \(String(format: "%.1f", limit)) s: \(self.notes) notifications since the request, holding \(pr.have) of \(pr.want) bytes; dropping the link")
            self.drop()
            self.state = .idle
            self.finishCurrent(.failure(KeyApiError.timedOut))
        }
        sendMessage(msg)
    }

    private func finishCurrent(_ r: Result<AppChannel.Answer, Error>) {
        timer?.cancel(); timer = nil
        guard let j = current else { return }
        current = nil
        switch r {
        case .success(let a): LinkLog.shared.add(String(format: "answer ctr %u: type %02x, %d bytes", j.ctr, a.rsp, a.body.count))
        case .failure(let e): LinkLog.shared.add("failed ctr \(j.ctr): \(e)")
        }
        j.done(r)
        pump()
    }

    private func failAll(_ e: Error) {
        timer?.cancel(); timer = nil
        let jobs = (current.map { [$0] } ?? []) + queue
        current = nil; queue = []
        jobs.forEach { $0.done(.failure(e)) }
    }

    private func arm(_ s: Double, _ f: @escaping () -> Void) {
        timer?.cancel()
        let t = DispatchWorkItem(block: f)
        timer = t
        DispatchQueue.main.asyncAfter(deadline: .now() + s, execute: t)
    }

    // MARK: - Writing

    /// One message on 8F1A0005, as whole 64-byte reports, up to 8 per write
    /// (512 bytes). Written without response from KEY 11ad (issue #20): iOS
    /// pipelines those, so a 31 KB vault backup crosses in a second or two
    /// instead of 12 s of round trips; paced on canSendWriteWithoutResponse.
    /// A KEY before 11ad (no write-without-response on the characteristic)
    /// still gets with-response writes.
    private func sendMessage(_ msg: Data) {
        guard let p = peripheral else { return }
        let wnr = p.maximumWriteValueLength(for: .withoutResponse)
        let per = max(1, min(8, wnr / 64))
        if per != lastPer {
            LinkLog.shared.add("write size: \(per) report\(per == 1 ? "" : "s") per write (ATT MTU \(wnr + 3), \(withoutResponse ? "without" : "with") response)")
            lastPer = per
        }
        notes = 0
        writes = AppChannel.writes(msg, perWrite: per, limit: AppChannel.msgMaxApi)
        busyRetries = 0
        writeStarted = Date(); writeBytes = msg.count
        writeNext()
    }

    private var withoutResponse: Bool { chanIn?.properties.contains(.writeWithoutResponse) == true }

    private func writeNext() {
        guard let p = peripheral, let ci = chanIn, !writes.isEmpty else { return }
        if withoutResponse {
            while !writes.isEmpty, p.canSendWriteWithoutResponse {
                writing = writes.removeFirst()
                p.writeValue(writing, for: ci, type: .withoutResponse)
            }
            if writes.isEmpty { written() }
            return                                   // the rest when peripheralIsReady fires
        }
        writing = writes.removeFirst()
        p.writeValue(writing, for: ci, type: .withResponse)
    }

    /// The request's last write has gone out: its answer limit starts now.
    private func written() {
        let ms = Int(Date().timeIntervalSince(writeStarted) * 1000)
        if writeBytes >= 2048 { LinkLog.shared.add("wrote \(writeBytes) bytes in \(ms) ms") }
        guard current != nil, pendingLimit > 0 else { return }
        let limit = pendingLimit; pendingLimit = 0
        arm(limit) { [weak self] in
            guard let self, let j = self.current else { return }
            let pr = self.reasm.progress
            LinkLog.shared.add("TIMEOUT ctr \(j.ctr) \(String(format: "%.1f", limit)) s after the last write: \(self.notes) notifications, holding \(pr.have) of \(pr.want) bytes; dropping the link")
            self.drop()
            self.state = .idle
            self.finishCurrent(.failure(KeyApiError.timedOut))
        }
    }

    func peripheralIsReady(toSendWriteWithoutResponse p: CBPeripheral) {
        writeNext()
    }

    // MARK: - Connecting

    private func connectIfNeeded() {
        guard state != .connecting, !paused else { return }
        guard creds != nil else { return }
        state = .connecting
        LinkLog.shared.add("connecting")
        connectTimer?.cancel()
        let t = DispatchWorkItem { [weak self] in
            guard let self, self.state == .connecting else { return }
            self.state = .failed(NostrLink.notFound)
            self.failAll(KeyApiError.notReady(NostrLink.notFound))
            self.drop()
        }
        connectTimer = t
        DispatchQueue.main.asyncAfter(deadline: .now() + 12, execute: t)
        if let c = central, c.state == .poweredOn { go(c) } else if central == nil { makeCentral() }
    }

    /// With state restoration, so iOS keeps the link for the app in the background
    /// and relaunches it to carry on (bluetooth-central background mode).
    private func makeCentral() {
        central = CBCentralManager(delegate: self, queue: .main, options: [
            CBCentralManagerOptionRestoreIdentifierKey: NostrLink.restoreId,
            CBCentralManagerOptionShowPowerAlertKey: false,
        ])
    }
    static let restoreId = "io.favillakey.nostrlink"

    /// Whether the link should stay up with nothing to send: the Bluetooth
    /// bunker is on (path B: the KEY wakes the app over this link).
    static var wantUp: Bool { Bunker.on && KeyRoute.current == .bluetooth && Credentials.isPaired }

    /// Keep the link up for the bunker (app launch, foreground, after a drop). A
    /// connect with no request waiting has no time limit: iOS completes it
    /// whenever the KEY comes into range, even with the app in the background.
    func stayUp() {
        DispatchQueue.main.async {
            guard NostrLink.wantUp, !self.paused, self.state != .connecting, self.state != .ready else { return }
            self.creds = Credentials.load()
            guard self.creds != nil else { return }
            self.state = .connecting
            LinkLog.shared.add("connecting (kept up for the bunker)")
            if let c = self.central, c.state == .poweredOn { self.go(c) } else if self.central == nil { self.makeCentral() }
        }
    }

    private func go(_ c: CBCentralManager) {
        if let p = c.retrieveConnectedPeripherals(withServices: [KeyLink.favService]).first(where: { ($0.name ?? "").hasPrefix(KeyLink.keyName) }) {
            connect(p, c); return
        }
        if let s = store.string(forKey: "keyPeripheralId"), let id = UUID(uuidString: s), let p = c.retrievePeripherals(withIdentifiers: [id]).first {
            connect(p, c)
        }
        c.scanForPeripherals(withServices: [KeyLink.favService], options: nil)
    }

    private func connect(_ p: CBPeripheral, _ c: CBCentralManager) {
        peripheral = p
        p.delegate = self
        c.connect(p, options: nil)
    }

    private func drop() {
        connectTimer?.cancel(); connectTimer = nil
        central?.stopScan()
        if let p = peripheral { central?.cancelPeripheralConnection(p) }
        peripheral = nil; chanIn = nil; chanOut = nil
        reasm = AppChannel.Reassembler(limit: AppChannel.msgMaxApi)
        writes = []; timeCtr = 0; helloCtr = 0; lastPer = 0; skipToStart = false; skipped = 0; nudgeSet = false
    }

    private func lost(_ why: String) {
        LinkLog.shared.add("lost: \(why)")
        drop()
        state = .failed(why)
        failAll(KeyApiError.notReady(why))
    }

    /// Subscribed: ask which life the KEY is in (HELLO), set its clock (TIME),
    /// then serve the queue. API and the bunker are the NOSTR Bluetooth life's
    /// only: in another life nothing is sent (issue #9, 9 Nov).
    private func subscribed() {
        guard let c = creds else { return }
        helloCtr = Credentials.nextCounter()
        timeRetried = false
        LinkLog.shared.add("subscribed to 8F1A0006; HELLO ctr \(helloCtr)")
        arm(2) { [weak self] in self?.helloCtr = 0; self?.sendTime() }    // no answer to HELLO: carry on
        sendMessage(AppChannel.request(AppChannel.cHello, c, ctr: helloCtr, body: Data()))
    }

    private func sendTime() {
        guard let c = creds else { return }
        timeCtr = Credentials.nextCounter()
        lastTimeCtr = timeCtr
        LinkLog.shared.add("TIME ctr \(timeCtr)")
        arm(3) { [weak self] in self?.ready() }      // no answer to TIME: carry on regardless
        sendMessage(AppChannel.request(AppChannel.cTime, c, ctr: timeCtr, body: AppChannel.timeBody()))
    }

    private func ready() {
        timer?.cancel(); timer = nil
        timeCtr = 0
        reconnectDelay = 0
        connectTimer?.cancel(); connectTimer = nil
        if state != .ready { LinkLog.shared.add("ready") }
        state = .ready
        if Bunker.on, !nudgeSet {
            nudgeSet = true
            Task {
                do {
                    let a = try await self.call(Bunker.cNudgeSet, Data([Bunker.nudgeSeconds]))
                    LinkLog.shared.add(a.rsp == AppChannel.rAck && a.body.first == 0 ? "nudges every \(Bunker.nudgeSeconds) s" : String(format: "NUDGE_SET answered %02x", a.rsp))
                } catch { LinkLog.shared.add("NUDGE_SET: \(error)") }
            }
        }
        pump()
    }

    // MARK: - Answers

    private func received(_ m: Data) {
        guard let c = creds else { return }
        let a: AppChannel.Answer
        let head = [UInt8](m.prefix(13))
        let mctr = head.count >= 13 ? UInt32(head[9]) | UInt32(head[10]) << 8 | UInt32(head[11]) << 16 | UInt32(head[12]) << 24 : 0
        if head.first == Bunker.rNudge, let n = try? AppChannel.open(m, c), let d = Bunker.decodeNudge(n.body) {
            nudges += 1
            if d.waiting > 0 || d.vault != 0 || nudges % 60 == 1 { LinkLog.shared.add("nudge \(d.seq): \(d.waiting) repl\(d.waiting == 1 ? "y" : "ies") waiting" + (d.vault != 0 ? String(format: ", vault asks %02x", d.vault) : "") + " (\(nudges) this session)") }
            NotificationCenter.default.post(name: NostrLink.nudged, object: nil, userInfo: ["waiting": d.waiting, "vault": Int(d.vault)])
            return
        }
        LinkLog.shared.add(String(format: "message %d bytes, type %02x", m.count, head.first ?? 0) + (head.count >= 13 ? ", ctr \(mctr)" : ""))
        do {
            a = try AppChannel.open(m, c)
        } catch AppChannel.Failure.unauthenticated(let cmd, let st) {
            LinkLog.shared.add(String(format: "  refused: command %02x, status %02x", cmd, st))
            // Only refusals of our own commands count: PAIR THE APP shares 8F1A0006.
            guard NostrLink.ours.contains(cmd) else { return }
            if st == 0x08 || st == 0x0A {                 // this client gone, or (11ah) the KEY knows no phone: not paired
                // Clear only if the pairing is still the one this link used: a
                // re-pair saved meanwhile must survive the old link's refusal.
                if Credentials.load() == c { PairIdentity.resetAll(why: String(format: "refused 0x%02X on the link", st)) }
                lost(AppChannel.statusText(st)); return
            }
            if helloCtr != 0, cmd == AppChannel.cHello { helloCtr = 0; sendTime(); return }
            if timeCtr != 0 { ready(); return }
            finishCurrent(.failure(KeyApiError.notReady(NostrLink.message(st)))); return
        } catch {
            // Not for this pairing (PAIR THE APP's messages share the characteristic), or damaged: wait for ours.
            let cid = head.count >= 9 ? (Data(head[1..<9]) == c.clientId ? "this client" : "another client") : "?"
            LinkLog.shared.add("  NOT OPENED (\(error)), \(cid)" + (current.map { ", waiting for ctr \($0.ctr)" } ?? ""))
            return
        }
        if helloCtr != 0, a.ctr == helloCtr {
            helloCtr = 0
            let b = [UInt8](a.body)
            if a.rsp == AppChannel.rHello, b.count >= 2 {
                LinkLog.shared.add(String(format: "  HELLO: life %02x", b[1]) + (b.count >= 18 ? ", pair id " + b[10..<18].map { String(format: "%02x", $0) }.joined() : ""))
                if PairIdentity.note(helloBody: a.body) {
                    LinkLog.shared.add("  the KEY's pairing identity changed: everything kept for it was cleared; pair again")
                    lost("This KEY was set up again since it was paired. Pair it again in Settings > This iPhone."); return
                }
                if b[1] != 0x03 { lost(NostrLink.notNostrBT); return }
            } else if a.rsp == AppChannel.rErr, let f = KeySession.replayFloor(a.body) {
                LinkLog.shared.add("  HELLO refused as a replay: counter raised above \(f)")
                Credentials.raiseCounter(above: f)
            }
            sendTime(); return
        }
        if timeCtr != 0, a.ctr == timeCtr {                               // TIME taken (or refused)
            if a.rsp == AppChannel.rErr, let f = KeySession.replayFloor(a.body), !timeRetried {
                // A stale counter after a reconnect: the clock wasn't set. Again, above the KEY's floor.
                LinkLog.shared.add("  TIME refused as a replay: again above \(f)")
                Credentials.raiseCounter(above: f)
                timeRetried = true
                sendTime(); return
            }
            ready(); return
        }
        if a.ctr == lastTimeCtr, a.ctr != current?.ctr {                // TIME's answer after its 3 s wait: nothing waits for it
            LinkLog.shared.add("  late TIME answer (ctr \(a.ctr)), ignored")
            return
        }
        guard var j = current, a.ctr == j.ctr else {                    // an answer to a cancelled or older request
            LinkLog.shared.add("  ignored: no request waits for ctr \(a.ctr)" + (current.map { " (waiting for \($0.ctr))" } ?? ""))
            return
        }
        if a.rsp == AppChannel.rErr {
            let b = [UInt8](a.body)
            if b.count >= 5, b[0] == 0x09, j.replays < 2 {               // replay: continue above the KEY's floor
                let floor = UInt32(b[1]) | UInt32(b[2]) << 8 | UInt32(b[3]) << 16 | UInt32(b[4]) << 24
                Credentials.raiseCounter(above: floor)
                j.replays += 1
                j.ctr = Credentials.nextCounter()
                current = j
                transmit(j)
                return
            }
            if j.cmd != AppChannel.cApi { finishCurrent(.success(a)); return }
            finishCurrent(.failure(KeyApiError.notReady(NostrLink.message(b.first ?? 0xFF)))); return
        }
        finishCurrent(.success(a))
    }

    static func message(_ st: UInt8) -> String {
        switch st {
        case 0x04: return notNostrBT
        case 0x05: return locked
        default: return AppChannel.statusText(st)
        }
    }
}

extension NostrLink: ChannelCaller {
    func request(_ cmd: UInt8, _ body: Data, timeout: TimeInterval) async throws -> AppChannel.Answer { try await call(cmd, body) }
}

// MARK: - CBCentralManagerDelegate

extension NostrLink: CBCentralManagerDelegate {
    /// iOS relaunched the app in the background to hand back the link it kept.
    func centralManager(_ c: CBCentralManager, willRestoreState dict: [String: Any]) {
        central = c
        guard let p = (dict[CBCentralManagerRestoredStatePeripheralsKey] as? [CBPeripheral])?.first else { return }
        LinkLog.shared.add("restored by iOS: link \(p.state == .connected ? "connected" : "pending")")
        creds = Credentials.load()
        peripheral = p
        p.delegate = self
        state = .connecting
    }

    func centralManagerDidUpdateState(_ c: CBCentralManager) {
        switch c.state {
        case .poweredOn:
            // After a restore: carry on with the link iOS kept (find the channel, subscribe, HELLO, TIME, NUDGE_SET).
            if let p = peripheral, chanIn == nil, state == .connecting {
                if p.state == .connected { p.discoverServices([KeyLink.favService]) } else { c.connect(p, options: nil) }
                return
            }
            if state == .connecting { go(c) }
        case .unauthorized: lost("Bluetooth permission is off for Favilla. Turn it on in Settings > Favilla.")
        case .poweredOff: lost("Bluetooth is off on this iPhone. Turn it on in Control Centre.")
        default: break
        }
    }

    func centralManager(_ c: CBCentralManager, didDiscover p: CBPeripheral, advertisementData: [String: Any], rssi: NSNumber) {
        let uuids = (advertisementData[CBAdvertisementDataServiceUUIDsKey] as? [CBUUID]) ?? []
        let name = (advertisementData[CBAdvertisementDataLocalNameKey] as? String) ?? p.name ?? ""
        guard uuids.contains(KeyLink.favService) || name.hasPrefix(KeyLink.keyName) else { return }
        c.stopScan()
        if let old = peripheral {
            if old.identifier == p.identifier { return }                   // the pending connect completes
            c.cancelPeripheralConnection(old)                              // a re-paired KEY has a new identity
        }
        connect(p, c)
    }

    func centralManager(_ c: CBCentralManager, didConnect p: CBPeripheral) {
        c.stopScan()
        store.set(p.identifier.uuidString, forKey: "keyPeripheralId")
        let wnr = p.maximumWriteValueLength(for: .withoutResponse), wr = p.maximumWriteValueLength(for: .withResponse)
        LinkLog.shared.add("connected: ATT MTU \(wnr + 3) (write without response \(wnr), with response \(wr)); requests go \(max(1, min(8, wnr / 64))) reports per write")
        p.discoverServices([KeyLink.favService])
    }

    func centralManager(_ c: CBCentralManager, didFailToConnect p: CBPeripheral, error: Error?) {
        guard p.identifier == peripheral?.identifier else { return }
        lost(KeyLink.keyForgotPhone(error) ? KeyLink.forgetOnPhone : "Couldn't connect to your KEY.")
    }

    func centralManager(_ c: CBCentralManager, didDisconnectPeripheral p: CBPeripheral, error: Error?) {
        guard p.identifier == peripheral?.identifier else { return }
        LinkLog.shared.add("disconnected" + (error.map { ": \($0.localizedDescription)" } ?? ""))
        if KeyLink.keyForgotPhone(error) { lost(KeyLink.forgetOnPhone); return }
        // Keep the queue: the next request reconnects. Only the one in flight fails.
        let wasUp = state == .ready || current != nil
        drop()
        state = .idle
        if wasUp { NotificationCenter.default.post(name: NostrLink.keyGone, object: nil, userInfo: ["why": error?.localizedDescription ?? "the KEY dropped the link"]) }
        // Back-off (issue #20 item 2): 75 connect/disconnect pairs in 350 ms
        // after a drop, because the queue reconnected at once each time.
        let delay = reconnectDelay
        reconnectDelay = min(8, max(0.25, reconnectDelay * 2))
        if delay > 0 { LinkLog.shared.add("reconnect in \(String(format: "%.2g", delay)) s") }
        if current != nil { finishCurrent(.failure(KeyApiError.notReady("Your KEY dropped the link."))) }
        DispatchQueue.main.asyncAfter(deadline: .now() + delay) { [weak self] in
            guard let self, self.state == .idle else { return }
            self.pump()
            if NostrLink.wantUp { DispatchQueue.main.asyncAfter(deadline: .now() + 2) { [weak self] in self?.stayUp() } }
        }
    }
}

// MARK: - CBPeripheralDelegate

extension NostrLink: CBPeripheralDelegate {
    func peripheral(_ p: CBPeripheral, didDiscoverServices error: Error?) {
        guard let s = p.services?.first(where: { $0.uuid == KeyLink.favService }) else { lost("Your KEY's Bluetooth table looks old. Restart the KEY."); return }
        p.discoverCharacteristics([KeyLink.chanInChar, KeyLink.chanOutChar], for: s)
    }

    func peripheral(_ p: CBPeripheral, didDiscoverCharacteristicsFor s: CBService, error: Error?) {
        let cs = s.characteristics ?? []
        chanIn = cs.first { $0.uuid == KeyLink.chanInChar }
        chanOut = cs.first { $0.uuid == KeyLink.chanOutChar }
        guard let out = chanOut, chanIn != nil else { lost("Your KEY needs firmware 9k or later for Nostr over Bluetooth."); return }
        p.setNotifyValue(true, for: out)
    }

    func peripheral(_ p: CBPeripheral, didUpdateNotificationStateFor ch: CBCharacteristic, error: Error?) {
        guard ch.uuid == KeyLink.chanOutChar else { return }
        if let e = error {
            lost(KeyLink.needsPairing(e) ? "This iPhone isn't paired with the KEY. Pair it in Settings > This iPhone." : "Couldn't open the link to your KEY.")
            return
        }
        subscribed()
    }

    func peripheral(_ p: CBPeripheral, didWriteValueFor ch: CBCharacteristic, error: Error?) {
        guard ch.uuid == KeyLink.chanInChar else { return }
        if let e = error as? CBATTError {
            if e.code.rawValue == 0x86, busyRetries < 20 {                // busy: the KEY hasn't taken the last one yet
                busyRetries += 1
                LinkLog.shared.add("write busy, retry \(busyRetries)")
                let w = writing
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) { [weak self] in
                    guard let self, let ci = self.chanIn else { return }
                    p.writeValue(w, for: ci, type: .withResponse)
                }
                return
            }
            if e.code.rawValue == 0x84 || e.code.rawValue == 0x8F { lost(NostrLink.notNostrBT); return }
        }
        if let e = error {
            LinkLog.shared.add("write failed: \(e.localizedDescription)")
            if timeCtr != 0 { ready() } else { finishCurrent(.failure(KeyApiError.notReady("The KEY didn't take the request."))) }
            return
        }
        busyRetries = 0
        if writes.isEmpty { written() } else { writeNext() }
    }

    func peripheral(_ p: CBPeripheral, didUpdateValueFor ch: CBCharacteristic, error: Error?) {
        guard ch.uuid == KeyLink.chanOutChar, var v = ch.value else { return }
        notes += 1
        if skipToStart {
            // The rest of a message that already failed: drop its reports quietly
            // until a report starts a new message (#9 item 3).
            let b = [UInt8](v)
            var off = 0
            while off < b.count, b[off] != AppChannel.fStart { off += 64 }
            if off >= b.count { skipped += 1; return }
            let n = skipped + (off > 0 ? 1 : 0)
            LinkLog.shared.add("  dropped \(n) leftover notification(s) of the failed message; a new message starts")
            skipToStart = false; skipped = 0
            v = v.subdata(in: off..<v.count)
        }
        let pr0 = reasm.progress
        let quiet = v.count >= 4 && v[v.startIndex] == AppChannel.fStart && v[v.startIndex + 3] == Bunker.rNudge && pr0.want == 0
        if !quiet { LinkLog.shared.add("notify \(v.count) bytes: \(LinkLog.describe(v))" + (pr0.want > 0 ? " (holding \(pr0.have) of \(pr0.want))" : "") + (error.map { ", error \($0.localizedDescription)" } ?? "")) }
        do {
            for m in try reasm.feed(v) { received(m) }
        } catch {
            LinkLog.shared.add("  REASSEMBLY FAILED (\(error)), holding \(pr0.have) of \(pr0.want); dropping the rest of it")
            reasm = AppChannel.Reassembler(limit: AppChannel.msgMaxApi)
            skipToStart = true; skipped = 0
            if timeCtr == 0 { finishCurrent(.failure(KeyApiError.badAnswer)) }
        }
    }
}
