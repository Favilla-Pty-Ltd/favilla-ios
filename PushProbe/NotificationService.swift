// NotificationService.swift - the push test (9 Nov 2026).
//
// Question: can a notification service extension reach the KEY over Bluetooth
// on its own, with the Favilla app in the background or closed? If it can, a
// Bluetooth bunker (NIP-46 through the app) can sign without opening the app.
//
// Each push with "mutable-content": 1 runs this. It loads the app channel
// pairing, connects to the KEY, opens the channel (8F1A0005 / 8F1A0006), sends
// one HELLO (0x30) and reads R_HELLO (0xB0: [status][life][drop 8]). Every step
// is timed, and the result replaces the notification's text, so it shows on the
// lock screen. The last 20 results are kept in the app group for the app's
// Settings > This iPhone > Push test.
//
// Nothing is signed: HELLO only asks the KEY which mode it is in.

import CoreBluetooth
import UserNotifications

final class NotificationService: UNNotificationServiceExtension, CBCentralManagerDelegate, CBPeripheralDelegate {
    static let resultsKey = "pushProbeResults"
    private static let group = "group.io.favillakey.app"

    private var handler: ((UNNotificationContent) -> Void)?
    private var content: UNMutableNotificationContent?
    private let q = DispatchQueue(label: "io.favillakey.pushprobe")
    private var central: CBCentralManager?
    private var peripheral: CBPeripheral?
    private var chanIn: CBCharacteristic?
    private var creds: Credentials?
    private var ctr: UInt32 = 0
    private var reasm = AppChannel.Reassembler()
    private var writes: [Data] = []
    private var t0 = Date()
    private var steps: [String] = []
    private var stage = "start"
    private var finished = false
    private var how = ""

    // MARK: - Push in

    override func didReceive(_ request: UNNotificationRequest, withContentHandler h: @escaping (UNNotificationContent) -> Void) {
        handler = h
        content = request.content.mutableCopy() as? UNMutableNotificationContent
        q.async { self.start() }
    }

    override func serviceExtensionTimeWillExpire() {
        q.sync { self.finish(ok: false, "TIMED OUT at: \(self.stage)") }
    }

    // MARK: - Steps

    private func mark(_ s: String) {
        stage = s
        steps.append(String(format: "%5.0f ms %@", Date().timeIntervalSince(t0) * 1000, s))
    }

    private func start() {
        t0 = Date()
        mark("push received")
        guard let c = Credentials.load() else { finish(ok: false, "the app isn't paired with the KEY (PAIR THE APP first)"); return }
        creds = c
        mark("pairing loaded")
        central = CBCentralManager(delegate: self, queue: q, options: [CBCentralManagerOptionShowPowerAlertKey: false])
        mark("waiting for Bluetooth")
    }

    func centralManagerDidUpdateState(_ c: CBCentralManager) {
        switch c.state {
        case .poweredOn:
            mark("Bluetooth on")
            go(c)
        case .unauthorized:
            finish(ok: false, "Bluetooth NOT ALLOWED in the extension (unauthorized, auth \(CBManager.authorization.rawValue))")
        case .unsupported:
            finish(ok: false, "Bluetooth unsupported in the extension")
        case .poweredOff:
            finish(ok: false, "Bluetooth is off on this iPhone")
        default:
            mark("Bluetooth state \(c.state.rawValue)")
        }
    }

    private func go(_ c: CBCentralManager) {
        if let p = c.retrieveConnectedPeripherals(withServices: [KeyLink.favService]).first {
            how = "already connected to iOS"
            connect(p, c); return
        }
        let store = UserDefaults(suiteName: NotificationService.group)
        if let s = store?.string(forKey: "keyPeripheralId"), let id = UUID(uuidString: s), let p = c.retrievePeripherals(withIdentifiers: [id]).first {
            how = "saved KEY, not connected"
            connect(p, c); return
        }
        how = "scanning"
        mark("scanning for the KEY")
        c.scanForPeripherals(withServices: [KeyLink.favService], options: nil)
    }

    private func connect(_ p: CBPeripheral, _ c: CBCentralManager) {
        mark("connecting (\(how))")
        peripheral = p
        p.delegate = self
        c.connect(p, options: nil)
    }

    func centralManager(_ c: CBCentralManager, didDiscover p: CBPeripheral, advertisementData: [String: Any], rssi: NSNumber) {
        guard peripheral == nil else { return }
        c.stopScan()
        mark("found by scan, RSSI \(rssi)")
        connect(p, c)
    }

    func centralManager(_ c: CBCentralManager, didConnect p: CBPeripheral) {
        mark("connected, MTU \(p.maximumWriteValueLength(for: .withoutResponse) + 3)")
        p.discoverServices([KeyLink.favService])
    }

    func centralManager(_ c: CBCentralManager, didFailToConnect p: CBPeripheral, error: Error?) {
        finish(ok: false, "connect failed: \(error?.localizedDescription ?? "no reason")")
    }

    func centralManager(_ c: CBCentralManager, didDisconnectPeripheral p: CBPeripheral, error: Error?) {
        if !finished { finish(ok: false, "disconnected: \(error?.localizedDescription ?? "no reason")") }
    }

    func peripheral(_ p: CBPeripheral, didDiscoverServices error: Error?) {
        guard let s = p.services?.first(where: { $0.uuid == KeyLink.favService }) else { finish(ok: false, "no Favilla service on the KEY"); return }
        mark("service found")
        p.discoverCharacteristics([KeyLink.chanInChar, KeyLink.chanOutChar], for: s)
    }

    func peripheral(_ p: CBPeripheral, didDiscoverCharacteristicsFor s: CBService, error: Error?) {
        let cs = s.characteristics ?? []
        chanIn = cs.first { $0.uuid == KeyLink.chanInChar }
        guard let out = cs.first(where: { $0.uuid == KeyLink.chanOutChar }), chanIn != nil else { finish(ok: false, "no app channel on the KEY (needs 9g or later)"); return }
        mark("channel found")
        p.setNotifyValue(true, for: out)
    }

    func peripheral(_ p: CBPeripheral, didUpdateNotificationStateFor ch: CBCharacteristic, error: Error?) {
        guard ch.uuid == KeyLink.chanOutChar else { return }
        if let e = error { finish(ok: false, "subscribe failed: \(e.localizedDescription)"); return }
        guard let c = creds else { return }
        mark("subscribed")
        ctr = Credentials.nextCounter()
        let per = max(1, min(8, p.maximumWriteValueLength(for: .withoutResponse) / 64))
        writes = AppChannel.writes(AppChannel.request(AppChannel.cHello, c, ctr: ctr), perWrite: per)
        writeNext()
        mark("HELLO sent, ctr \(ctr)")
    }

    private func writeNext() {
        guard let p = peripheral, let ci = chanIn, !writes.isEmpty else { return }
        p.writeValue(writes.removeFirst(), for: ci, type: .withResponse)
    }

    func peripheral(_ p: CBPeripheral, didWriteValueFor ch: CBCharacteristic, error: Error?) {
        if let e = error { finish(ok: false, "write failed: \(e.localizedDescription)"); return }
        writeNext()
    }

    func peripheral(_ p: CBPeripheral, didUpdateValueFor ch: CBCharacteristic, error: Error?) {
        guard ch.uuid == KeyLink.chanOutChar, let v = ch.value, let c = creds else { return }
        guard let msgs = try? reasm.feed(v) else { reasm = AppChannel.Reassembler(); return }
        for m in msgs {
            do {
                let a = try AppChannel.open(m, c)
                guard a.ctr == ctr else { continue }
                if a.rsp == AppChannel.rHello {
                    let b = [UInt8](a.body)
                    let life = b.count > 1 ? (b[1] == 0x03 ? "NOSTR, Bluetooth mode" : String(format: "life 0x%02x", b[1])) : "?"
                    let drop = b.count >= 10 ? String(bytes: b[2..<10].filter { $0 != 0 }, encoding: .ascii) ?? "?" : "?"
                    finish(ok: true, "KEY answered: \(life), drop \(drop)")
                } else {
                    finish(ok: false, String(format: "KEY answered type %02x", a.rsp))
                }
            } catch AppChannel.Failure.unauthenticated(_, let st) {
                finish(ok: false, "KEY refused: " + AppChannel.statusText(st))
            } catch {
                continue   // not ours (another client's message on the shared characteristic)
            }
        }
    }

    // MARK: - Result

    private func finish(ok: Bool, _ why: String) {
        guard !finished else { return }
        finished = true
        mark(why)
        let ms = Int(Date().timeIntervalSince(t0) * 1000)
        if let p = peripheral { central?.cancelPeripheralConnection(p) }
        central?.stopScan()

        let head = ok ? "KEY reached in \(ms) ms" : "KEY NOT reached (\(ms) ms)"
        let line = ISO8601DateFormatter().string(from: Date()) + " " + head + ". " + why + (how.isEmpty ? "" : " [\(how)]")
        if let d = UserDefaults(suiteName: NotificationService.group) {
            var all = d.stringArray(forKey: NotificationService.resultsKey) ?? []
            all.append(line + "\n" + steps.joined(separator: "\n"))
            d.set(Array(all.suffix(20)), forKey: NotificationService.resultsKey)
        }
        guard let c = content, let h = handler else { return }
        c.title = "Favilla push test: " + (ok ? "OK" : "failed")
        c.body = head + ". " + why + (how.isEmpty ? "" : " [\(how)]")
        handler = nil
        h(c)
    }
}
