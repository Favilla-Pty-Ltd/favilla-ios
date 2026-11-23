// KeySession.swift - one short app-channel session with the KEY, for the
// notification extension (9 Nov 2026).
//
// The push test showed the extension can reach the KEY on its own in under a
// second, even with the app swiped away. This is that connect, made reusable:
// connect, subscribe to 8F1A0006, wait for the MTU (iOS starts at 23, and a
// 64-byte report needs 67), set the KEY's clock with TIME (the doc: after every
// connect, before anything else), then any number of requests, one at a time.
//
// Everything runs on the session's own serial queue; the async API hops there.

import CoreBluetooth
import Foundation

final class KeySession: NSObject, CBCentralManagerDelegate, CBPeripheralDelegate, @unchecked Sendable {
    struct Failure: Error, CustomStringConvertible { let description: String; init(_ s: String) { description = s } }
    static let linkClosed = "The link to the KEY closed."
    /// True for the failure thrown before a request went out: the link had
    /// already gone (a sheet left waiting on the owner). Nothing reached the
    /// KEY, so the same request can go again on a new session.
    static func neverSent(_ e: Error) -> Bool { (e as? Failure)?.description == linkClosed }

    private let q = DispatchQueue(label: "io.favillakey.keysession")
    private let creds: Credentials
    private var central: CBCentralManager?
    private var peripheral: CBPeripheral?
    private var chanIn: CBCharacteristic?
    private var reasm = AppChannel.Reassembler(limit: AppChannel.msgMaxApi)
    private var writes: [Data] = []
    private var opened: CheckedContinuation<Void, Error>?
    private var waiting: (cmd: UInt8, ctr: UInt32, k: CheckedContinuation<AppChannel.Answer, Error>)?
    private var timer: DispatchWorkItem?
    private var closed = false
    private let t0 = Date()

    /// Timed steps, for the log the app shows.
    private(set) var steps: [String] = []
    private(set) var how = ""
    var log: ((String) -> Void)?

    init(_ creds: Credentials) { self.creds = creds }

    private func mark(_ s: String) {
        let line = String(format: "%5.0f ms %@", Date().timeIntervalSince(t0) * 1000, s)
        steps.append(line)
        log?(line)
    }

    // MARK: - API

    /// Set by the app: the Nostr client's own link (NostrLink) steps aside
    /// while a session holds the KEY, and comes back when it closes (issue
    /// #36 bench, 17 Nov: the two links on one KEY, NostrLink dropping and
    /// redialling in a VAULT life, cut this session's notifications three
    /// times during one LIST). Called on the main thread.
    static var willOpen: (() -> Void)?
    static var didClose: (() -> Void)?

    /// Connect and open the channel; throws with a sentence for the notification.
    func open(timeout: TimeInterval = 8) async throws {
        if let hook = KeySession.willOpen {
            await MainActor.run { hook() }
            try? await Task.sleep(nanoseconds: 300_000_000)   // let its cancel settle before this link subscribes
        }
        try await withCheckedThrowingContinuation { (k: CheckedContinuation<Void, Error>) in
            q.async {
                self.opened = k
                self.arm(timeout) { self.failOpen("Can't find your KEY. Check it's on, in Bluetooth mode, and near this iPhone.") }
                self.central = CBCentralManager(delegate: self, queue: self.q, options: [CBCentralManagerOptionShowPowerAlertKey: false])
                self.mark("waiting for Bluetooth")
            }
        }
    }

    /// One request; the answer whatever its type (the caller checks it). A replay
    /// refusal raises the counter and resends once.
    func request(_ cmd: UInt8, _ body: Data = Data(), timeout: TimeInterval = 6) async throws -> AppChannel.Answer {
        var a = try await once(cmd, body, timeout)
        if a.rsp == AppChannel.rErr, let floor = KeySession.replayFloor(a.body) {
            Credentials.raiseCounter(above: floor)
            a = try await once(cmd, body, timeout)
        }
        return AppChannel.unsealAck(a, for: cmd, creds)   // 11ay: ASSESS_ONE's 0xB1 is encrypted (issue #66)
    }

    func close() {
        if let hook = KeySession.didClose { DispatchQueue.main.async { hook() } }
        q.async {
            self.closed = true
            self.timer?.cancel()
            if let p = self.peripheral { self.central?.cancelPeripheralConnection(p) }
            self.central?.stopScan()
            self.waiting?.k.resume(throwing: Failure("closed")); self.waiting = nil
        }
    }

    static func replayFloor(_ b: Data) -> UInt32? {
        let v = [UInt8](b)
        guard v.count >= 5, v[0] == 0x09 else { return nil }
        return UInt32(v[1]) | UInt32(v[2]) << 8 | UInt32(v[3]) << 16 | UInt32(v[4]) << 24
    }

    private func once(_ cmd: UInt8, _ body: Data, _ timeout: TimeInterval) async throws -> AppChannel.Answer {
        try await withCheckedThrowingContinuation { (k: CheckedContinuation<AppChannel.Answer, Error>) in
            q.async {
                guard !self.closed, let p = self.peripheral, p.state == .connected, self.chanIn != nil else {
                    k.resume(throwing: Failure(KeySession.linkClosed)); return
                }
                guard self.waiting == nil else { k.resume(throwing: Failure("busy")); return }
                let ctr = Credentials.nextCounter()
                let msg = AppChannel.request(cmd, self.creds, ctr: ctr, body: body)
                guard msg.count <= AppChannel.msgMaxApi else { k.resume(throwing: Failure("request too large")); return }
                self.waiting = (cmd, ctr, k)
                // Generous while the request is going out; the real limit is
                // armed from the last write (issue #20 item 3).
                self.pendingLimit = timeout
                self.arm(timeout + Double(msg.count) / 1_000) { self.noAnswer(cmd, ctr) }
                let per = max(1, min(8, p.maximumWriteValueLength(for: .withoutResponse) / 64))
                self.writes = AppChannel.writes(msg, perWrite: per, limit: AppChannel.msgMaxApi)
                self.writeStarted = Date(); self.writeBytes = msg.count
                self.writeNext()
            }
        }
    }

    // MARK: - Internals (on q)

    private func arm(_ s: TimeInterval, _ f: @escaping () -> Void) {
        timer?.cancel()
        let t = DispatchWorkItem(block: f)
        timer = t
        q.asyncAfter(deadline: .now() + s, execute: t)
    }

    private func failOpen(_ why: String) {
        mark(why)
        timer?.cancel()
        if let p = peripheral { central?.cancelPeripheralConnection(p) }
        central?.stopScan()
        opened?.resume(throwing: Failure(why)); opened = nil
    }

    private var pendingLimit: TimeInterval = 0
    private var writeStarted = Date()
    private var writeBytes = 0

    private func noAnswer(_ cmd: UInt8, _ ctr: UInt32) {
        mark(String(format: "no answer to %02x ctr %u", cmd, ctr))
        waiting?.k.resume(throwing: Failure("The KEY didn't answer.")); waiting = nil
    }

    /// Without response from KEY 11ad (the characteristic says so), paced on
    /// canSendWriteWithoutResponse; with response on an older KEY.
    private func writeNext() {
        guard let p = peripheral, let ci = chanIn, !writes.isEmpty else { return }
        if ci.properties.contains(.writeWithoutResponse) {
            while !writes.isEmpty, p.canSendWriteWithoutResponse {
                p.writeValue(writes.removeFirst(), for: ci, type: .withoutResponse)
            }
            if writes.isEmpty { written() }
            return
        }
        p.writeValue(writes.removeFirst(), for: ci, type: .withResponse)
    }

    /// The last write went out: the answer limit counts from here.
    private func written() {
        let ms = Int(Date().timeIntervalSince(writeStarted) * 1000)
        if writeBytes >= 2048 { mark("wrote \(writeBytes) bytes in \(ms) ms") }
        guard let w = waiting, pendingLimit > 0 else { return }
        let limit = pendingLimit; pendingLimit = 0
        arm(limit) { self.noAnswer(w.cmd, w.ctr) }
    }

    func peripheralIsReady(toSendWriteWithoutResponse p: CBPeripheral) {
        q.async { self.writeNext() }
    }

    func centralManagerDidUpdateState(_ c: CBCentralManager) {
        switch c.state {
        case .poweredOn:
            mark("Bluetooth on")
            if let p = c.retrieveConnectedPeripherals(withServices: [KeyLink.favService]).first {
                how = "already connected to iOS"; connect(p, c); return
            }
            let store = UserDefaults(suiteName: "group.io.favillakey.app")
            if let s = store?.string(forKey: "keyPeripheralId"), let id = UUID(uuidString: s), let p = c.retrievePeripherals(withIdentifiers: [id]).first {
                // A pending connect to the KEY as this phone last knew it, and a
                // search as well: a KEY that forgot its phones comes back under a
                // new address (11dp, issue #63), and whichever answers is taken.
                how = "saved KEY, and searching"; connect(p, c)
            } else {
                how = "scanning"
                mark("scanning")
            }
            c.scanForPeripherals(withServices: [KeyLink.favService], options: nil)
        case .unauthorized: failOpen("Bluetooth isn't allowed for Favilla. iPhone Settings > Favilla > Bluetooth.")
        case .poweredOff: failOpen("Bluetooth is off on this iPhone.")
        case .unsupported: failOpen("Bluetooth unsupported.")
        default: break
        }
    }

    private func connect(_ p: CBPeripheral, _ c: CBCentralManager) {
        mark("connecting (\(how))")
        peripheral = p
        p.delegate = self
        c.connect(p, options: nil)
    }

    func centralManager(_ c: CBCentralManager, didDiscover p: CBPeripheral, advertisementData: [String: Any], rssi: NSNumber) {
        if let old = peripheral {
            if old.identifier == p.identifier || old.state == .connected { return }   // the pending connect completes
            mark("found the KEY under a new identity")
            c.cancelPeripheralConnection(old)
            how = "found by its service"
        }
        c.stopScan()
        connect(p, c)
    }

    func centralManager(_ c: CBCentralManager, didConnect p: CBPeripheral) {
        guard p.identifier == peripheral?.identifier else { return }
        c.stopScan()
        mark("connected")
        UserDefaults(suiteName: "group.io.favillakey.app")?.set(p.identifier.uuidString, forKey: "keyPeripheralId")
        p.discoverServices([KeyLink.favService])
    }

    func centralManager(_ c: CBCentralManager, didFailToConnect p: CBPeripheral, error: Error?) {
        guard p.identifier == peripheral?.identifier else { return }   // an old identity we let go
        failOpen("Couldn't connect to the KEY: \(error?.localizedDescription ?? "no reason")")
    }

    func centralManager(_ c: CBCentralManager, didDisconnectPeripheral p: CBPeripheral, error: Error?) {
        guard p.identifier == peripheral?.identifier else { return }   // an old identity we let go
        mark("disconnected")
        if error != nil, !closed { KeyLife.forget("the KEY dropped the Accounts link") }
        chanIn = nil
        if opened != nil { failOpen("The KEY dropped the link.") }
        waiting?.k.resume(throwing: Failure("The KEY dropped the link.")); waiting = nil
    }

    func peripheral(_ p: CBPeripheral, didDiscoverServices error: Error?) {
        guard let s = p.services?.first(where: { $0.uuid == KeyLink.favService }) else { failOpen("No Favilla service on the KEY."); return }
        p.discoverCharacteristics([KeyLink.chanInChar, KeyLink.chanOutChar], for: s)
    }

    func peripheral(_ p: CBPeripheral, didDiscoverCharacteristicsFor s: CBService, error: Error?) {
        let cs = s.characteristics ?? []
        chanIn = cs.first { $0.uuid == KeyLink.chanInChar }
        guard let out = cs.first(where: { $0.uuid == KeyLink.chanOutChar }), chanIn != nil else { failOpen("No app channel on the KEY."); return }
        p.setNotifyValue(true, for: out)
    }

    func peripheral(_ p: CBPeripheral, didUpdateNotificationStateFor ch: CBCharacteristic, error: Error?) {
        guard ch.uuid == KeyLink.chanOutChar else { return }
        if let e = error { failOpen("Subscribe failed: \(e.localizedDescription)"); return }
        mark("subscribed, MTU \(p.maximumWriteValueLength(for: .withoutResponse) + 3)")
        waitForMtu(p, tries: 20)
    }

    /// The push test saw MTU 23 at connect. A 64-byte report needs 67; the KEY
    /// asks for more and iOS grows it shortly after. Wait up to 2 s.
    private func waitForMtu(_ p: CBPeripheral, tries: Int) {
        if p.maximumWriteValueLength(for: .withoutResponse) >= 64 || tries == 0 {
            mark("MTU \(p.maximumWriteValueLength(for: .withoutResponse) + 3)")
            sendTime()
            return
        }
        q.asyncAfter(deadline: .now() + 0.1) { self.waitForMtu(p, tries: tries - 1) }
    }

    private func sendTime() {
        guard let p = peripheral else { return }
        let ctr = Credentials.nextCounter()
        timeCtr = ctr
        arm(2.5) { self.timeDone("no TIME answer, going on") }
        let per = max(1, min(8, p.maximumWriteValueLength(for: .withoutResponse) / 64))
        writes = AppChannel.writes(AppChannel.request(AppChannel.cTime, creds, ctr: ctr, body: AppChannel.timeBody()), perWrite: per)
        writeNext()
    }

    private var timeCtr: UInt32 = 0
    private var timeRetried = false
    private func timeDone(_ s: String) {
        guard timeCtr != 0 else { return }
        timeCtr = 0
        timer?.cancel()
        mark(s)
        opened?.resume(); opened = nil
    }

    func peripheral(_ p: CBPeripheral, didWriteValueFor ch: CBCharacteristic, error: Error?) {
        if let e = error {
            mark("write failed: \(e.localizedDescription)")
            writes = []
            waiting?.k.resume(throwing: Failure("Write to the KEY failed.")); waiting = nil
            return
        }
        if writes.isEmpty { written() } else { writeNext() }
    }

    func peripheral(_ p: CBPeripheral, didUpdateValueFor ch: CBCharacteristic, error: Error?) {
        guard ch.uuid == KeyLink.chanOutChar, let v = ch.value else { return }
        guard let msgs = try? reasm.feed(v) else { reasm = AppChannel.Reassembler(limit: AppChannel.msgMaxApi); return }
        for m in msgs { received(m) }
    }

    private func received(_ m: Data) {
        do {
            let a = try AppChannel.open(m, creds)
            if timeCtr != 0, a.ctr == timeCtr {
                if a.rsp == AppChannel.rErr, let f = KeySession.replayFloor(a.body), !timeRetried {
                    timeRetried = true
                    Credentials.raiseCounter(above: f)
                    mark("TIME refused as a replay: again above \(f)")
                    sendTime(); return
                }
                timeDone("clock set"); return
            }
            guard let w = waiting, a.ctr == w.ctr else { return }
            timer?.cancel()
            waiting = nil
            w.k.resume(returning: a)
        } catch AppChannel.Failure.unauthenticated(let cmd, let st) {
            if timeCtr != 0, cmd == AppChannel.cTime { timeDone(String(format: "TIME refused %02x", st)); return }
            guard let w = waiting, cmd == w.cmd else { return }
            timer?.cancel()
            waiting = nil
            mark(String(format: "refused %02x: %02x", cmd, st))
            w.k.resume(throwing: Failure(KeySession.refusal(st)))
        } catch {
            return      // another client's message on the shared characteristic
        }
    }

    static func refusal(_ st: UInt8) -> String {
        switch st {
        case 0x08: return "This iPhone isn't paired with the KEY any more. Open Favilla and PAIR THE APP."
        case 0x0A: return "The KEY doesn't know this iPhone. On the KEY: Settings > Network > Pair a phone, then PAIR THE APP in Favilla (Settings > This iPhone)."
        default: return Bunker.refusal(st)
        }
    }
}
