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
    private var timeCtr: UInt32 = 0          // the TIME request, while it is out
    private var lastTimeCtr: UInt32 = 0      // the last TIME sent: its answer may come after we moved on (#9 item 5)
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
    static let ours: Set<UInt8> = [AppChannel.cApi, AppChannel.cTime, Bunker.cNip46, Bunker.cPoll, Bunker.cInfo]

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
        let limit = (j.cmd == Bunker.cNip46 || j.cmd == Bunker.cPoll ? 12 : 6) + Double(msg.count) / 8_000
        arm(limit) { [weak self] in
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

    /// One message on 8F1A0005, as whole 64-byte reports, up to 8 per write (512 bytes).
    private func sendMessage(_ msg: Data) {
        guard let p = peripheral else { return }
        let wnr = p.maximumWriteValueLength(for: .withoutResponse)
        let per = max(1, min(8, wnr / 64))
        if per != lastPer {
            LinkLog.shared.add("write size: \(per) report\(per == 1 ? "" : "s") per write (ATT MTU \(wnr + 3))")
            lastPer = per
        }
        notes = 0
        writes = AppChannel.writes(msg, perWrite: per, limit: AppChannel.msgMaxApi)
        busyRetries = 0
        writeNext()
    }

    private func writeNext() {
        guard let p = peripheral, let ci = chanIn, !writes.isEmpty else { return }
        writing = writes.removeFirst()
        p.writeValue(writing, for: ci, type: .withResponse)
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
        if let c = central, c.state == .poweredOn { go(c) } else if central == nil { central = CBCentralManager(delegate: self, queue: .main) }
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
        writes = []; timeCtr = 0; lastPer = 0; skipToStart = false; skipped = 0
    }

    private func lost(_ why: String) {
        LinkLog.shared.add("lost: \(why)")
        drop()
        state = .failed(why)
        failAll(KeyApiError.notReady(why))
    }

    /// Subscribed: set the KEY's clock, then serve the queue.
    private func subscribed() {
        guard let c = creds else { return }
        timeCtr = Credentials.nextCounter()
        lastTimeCtr = timeCtr
        LinkLog.shared.add("subscribed to 8F1A0006; TIME ctr \(timeCtr)")
        arm(3) { [weak self] in self?.ready() }      // no answer to TIME: carry on regardless
        sendMessage(AppChannel.request(AppChannel.cTime, c, ctr: timeCtr, body: AppChannel.timeBody()))
    }

    private func ready() {
        timer?.cancel(); timer = nil
        timeCtr = 0
        connectTimer?.cancel(); connectTimer = nil
        if state != .ready { LinkLog.shared.add("ready") }
        state = .ready
        pump()
    }

    // MARK: - Answers

    private func received(_ m: Data) {
        guard let c = creds else { return }
        let a: AppChannel.Answer
        let head = [UInt8](m.prefix(13))
        let mctr = head.count >= 13 ? UInt32(head[9]) | UInt32(head[10]) << 8 | UInt32(head[11]) << 16 | UInt32(head[12]) << 24 : 0
        LinkLog.shared.add(String(format: "message %d bytes, type %02x", m.count, head.first ?? 0) + (head.count >= 13 ? ", ctr \(mctr)" : ""))
        do {
            a = try AppChannel.open(m, c)
        } catch AppChannel.Failure.unauthenticated(let cmd, let st) {
            LinkLog.shared.add(String(format: "  refused: command %02x, status %02x", cmd, st))
            // Only refusals of our own commands count: PAIR THE APP shares 8F1A0006.
            guard NostrLink.ours.contains(cmd) else { return }
            if st == 0x08 {
                // Forget the pairing only if it is still the one this link used: a
                // re-pair saved meanwhile must survive the old link's refusal.
                if Credentials.load() == c { Credentials.forget() }
                lost(AppChannel.statusText(st)); return
            }
            if timeCtr != 0 { ready(); return }
            finishCurrent(.failure(KeyApiError.notReady(NostrLink.message(st)))); return
        } catch {
            // Not for this pairing (PAIR THE APP's messages share the characteristic), or damaged: wait for ours.
            let cid = head.count >= 9 ? (Data(head[1..<9]) == c.clientId ? "this client" : "another client") : "?"
            LinkLog.shared.add("  NOT OPENED (\(error)), \(cid)" + (current.map { ", waiting for ctr \($0.ctr)" } ?? ""))
            return
        }
        if timeCtr != 0, a.ctr == timeCtr { ready(); return }          // TIME taken (or refused): go on
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
    func centralManagerDidUpdateState(_ c: CBCentralManager) {
        switch c.state {
        case .poweredOn: if state == .connecting { go(c) }
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
        drop()
        state = .idle
        if current != nil { finishCurrent(.failure(KeyApiError.notReady("Your KEY dropped the link."))) } else { pump() }
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
        writeNext()
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
        LinkLog.shared.add("notify \(v.count) bytes: \(LinkLog.describe(v))" + (pr0.want > 0 ? " (holding \(pr0.have) of \(pr0.want))" : "") + (error.map { ", error \($0.localizedDescription)" } ?? ""))
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
