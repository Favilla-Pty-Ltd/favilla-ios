// NostrLink.swift - the Nostr client's Bluetooth link to the KEY (7 Nov 2026).
//
// Built against favilla-key-firmware docs/BLE_PASSKEY_PROTOCOL.md, "The app
// channel (9g)" and "NOSTR over Bluetooth (9k)". The KEY is in its NOSTR BT
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
        let body: Data                       // ApiWire request
        let done: (Result<ApiResponse, Error>) -> Void
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
    private var queue: [Job] = []
    private var current: Job?
    private var timer: DispatchWorkItem?
    private var connectTimer: DispatchWorkItem?
    private let store = UserDefaults(suiteName: "group.io.favillakey.app") ?? .standard

    static let notPaired = "Pair the app with the KEY first: Settings > This iPhone > PAIR THE APP."
    static let notNostrBT = "Your KEY isn't in NOSTR BT. Restart it and choose NOSTR BT at Select Mode."
    static let locked = "Your KEY is locked. Enter the NOSTR PIN on the KEY."
    static let notFound = "Can't find your KEY. Check it's on, in NOSTR BT, and near this iPhone."

    // MARK: - Sending

    /// One API call: the ApiWire request body in, the ApiWire answer out.
    func send(_ body: Data) async throws -> ApiResponse {
        let id = UInt64.random(in: 1...UInt64.max)
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (k: CheckedContinuation<ApiResponse, Error>) in
                DispatchQueue.main.async {
                    var once = false
                    let job = Job(id: id, body: body) { r in
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
        guard current == nil, !queue.isEmpty else { return }
        guard state == .ready, peripheral?.state == .connected, chanIn != nil, creds != nil else { connectIfNeeded(); return }
        var j = queue.removeFirst()
        j.ctr = Credentials.nextCounter()
        current = j
        transmit(j)
    }

    private func transmit(_ j: Job) {
        guard let c = creds else { return }
        let msg = AppChannel.request(AppChannel.cApi, c, ctr: j.ctr, body: j.body)
        guard msg.count <= AppChannel.msgMaxApi else { finishCurrent(.failure(KeyApiError.refused("request too large"))); return }
        // The KEY answers within 10 s; give the transfer of a large body time on top.
        arm(15 + Double(msg.count) / 8_000) { [weak self] in self?.finishCurrent(.failure(KeyApiError.timedOut)) }
        sendMessage(msg)
    }

    private func finishCurrent(_ r: Result<ApiResponse, Error>) {
        timer?.cancel(); timer = nil
        guard let j = current else { return }
        current = nil
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
        let per = max(1, min(8, p.maximumWriteValueLength(for: .withoutResponse) / 64))
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
        guard state != .connecting else { return }
        guard let c = Credentials.load() else {
            state = .failed(NostrLink.notPaired)
            failAll(KeyApiError.notReady(NostrLink.notPaired)); return
        }
        creds = c
        state = .connecting
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
        writes = []; timeCtr = 0
    }

    private func lost(_ why: String) {
        drop()
        state = .failed(why)
        failAll(KeyApiError.notReady(why))
    }

    /// Subscribed: set the KEY's clock, then serve the queue.
    private func subscribed() {
        guard let c = creds else { return }
        timeCtr = Credentials.nextCounter()
        arm(10) { [weak self] in self?.ready() }      // no answer to TIME: carry on regardless
        sendMessage(AppChannel.request(AppChannel.cTime, c, ctr: timeCtr, body: AppChannel.timeBody()))
    }

    private func ready() {
        timer?.cancel(); timer = nil
        timeCtr = 0
        connectTimer?.cancel(); connectTimer = nil
        state = .ready
        pump()
    }

    // MARK: - Answers

    private func received(_ m: Data) {
        guard let c = creds else { return }
        let a: AppChannel.Answer
        do {
            a = try AppChannel.open(m, c)
        } catch AppChannel.Failure.unauthenticated(_, let st) {
            if st == 0x08 {
                Credentials.forget()
                lost(AppChannel.statusText(st)); return
            }
            if timeCtr != 0 { ready(); return }
            finishCurrent(.failure(KeyApiError.notReady(NostrLink.message(st)))); return
        } catch {
            if timeCtr == 0 { finishCurrent(.failure(KeyApiError.badAnswer)) }
            return
        }
        if timeCtr != 0, a.ctr == timeCtr { ready(); return }          // TIME taken (or refused): go on
        guard var j = current, a.ctr == j.ctr else { return }           // an answer to a cancelled or older request
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
            finishCurrent(.failure(KeyApiError.notReady(NostrLink.message(b.first ?? 0xFF)))); return
        }
        guard a.rsp == AppChannel.rApi, let r = ApiWire.decodeAnswer(a.body) else {
            finishCurrent(.failure(KeyApiError.badAnswer)); return
        }
        finishCurrent(.success(r))
    }

    static func message(_ st: UInt8) -> String {
        switch st {
        case 0x04: return notNostrBT
        case 0x05: return locked
        default: return AppChannel.statusText(st)
        }
    }
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
        p.discoverServices([KeyLink.favService])
    }

    func centralManager(_ c: CBCentralManager, didFailToConnect p: CBPeripheral, error: Error?) {
        guard p.identifier == peripheral?.identifier else { return }
        lost(KeyLink.keyForgotPhone(error) ? KeyLink.forgetOnPhone : "Couldn't connect to your KEY.")
    }

    func centralManager(_ c: CBCentralManager, didDisconnectPeripheral p: CBPeripheral, error: Error?) {
        guard p.identifier == peripheral?.identifier else { return }
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
                let w = writing
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) { [weak self] in
                    guard let self, let ci = self.chanIn else { return }
                    p.writeValue(w, for: ci, type: .withResponse)
                }
                return
            }
            if e.code.rawValue == 0x84 || e.code.rawValue == 0x8F { lost(NostrLink.notNostrBT); return }
        }
        if error != nil {
            if timeCtr != 0 { ready() } else { finishCurrent(.failure(KeyApiError.notReady("The KEY didn't take the request."))) }
            return
        }
        busyRetries = 0
        writeNext()
    }

    func peripheral(_ p: CBPeripheral, didUpdateValueFor ch: CBCharacteristic, error: Error?) {
        guard ch.uuid == KeyLink.chanOutChar, let v = ch.value else { return }
        do {
            for m in try reasm.feed(v) { received(m) }
        } catch {
            reasm = AppChannel.Reassembler(limit: AppChannel.msgMaxApi)
            if timeCtr == 0 { finishCurrent(.failure(KeyApiError.badAnswer)) }
        }
    }
}
