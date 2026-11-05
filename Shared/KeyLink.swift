// KeyLink.swift - the Bluetooth link to a Favilla KEY (probe stage, Nov 2026).
//
// Probe: find the KEY the phone is paired with, connect, read the Favilla
// service's probe characteristic and disconnect. The characteristic is
// readable only on an encrypted (bonded) link, so a successful read proves
// the app, or the AutoFill extension, reached THIS KEY on the phone's own bond.
//
// The KEY does not advertise at rest (drop 8m). A press on its home screen
// makes it findable for 15 s (drop 8y). CoreBluetooth's connect() waits for
// that, so the flow is: start the probe, then press a button on the KEY.

import CoreBluetooth
import Foundation

final class KeyLink: NSObject, ObservableObject {
    static let favService = CBUUID(string: "8F1A0001-6B2E-4C8D-9A3E-5F7C2D1E0B4A")
    static let probeChar  = CBUUID(string: "8F1A0002-6B2E-4C8D-9A3E-5F7C2D1E0B4A")
    static let hidService = CBUUID(string: "1812")
    static let keyName    = "Favilla KEY"
    private static let savedIdKey = "keyPeripheralId"
    private static let groupId    = "group.io.favillakey.app"

    @Published private(set) var lines: [String] = []
    @Published private(set) var result: String?
    @Published private(set) var busy = false
    /// The site or app iOS asked about, when run from the AutoFill sheet.
    var site: String = ""

    private var central: CBCentralManager?
    private var peripheral: CBPeripheral?
    private var started = Date()
    private var timeout: DispatchWorkItem?
    private let store = UserDefaults(suiteName: KeyLink.groupId) ?? .standard

    // MARK: - Probe

    func probe() {
        guard !busy else { return }
        busy = true
        result = nil
        lines = []
        started = Date()
        if !site.isEmpty { add("Asked for: \(site)") }
        add("Starting Bluetooth")
        let t = DispatchWorkItem { [weak self] in self?.finish("Timed out after 30 s. Press a button on the KEY's home screen, then try again.") }
        timeout = t
        DispatchQueue.main.asyncAfter(deadline: .now() + 30, execute: t)
        if let c = central, c.state == .poweredOn { go(c) } else { central = CBCentralManager(delegate: self, queue: .main) }
    }

    func cancel() { finish("Cancelled") }

    private func go(_ c: CBCentralManager) {
        // 1. The KEY this phone used before (saved by an earlier probe).
        if let s = store.string(forKey: KeyLink.savedIdKey), let id = UUID(uuidString: s),
           let p = c.retrievePeripherals(withIdentifiers: [id]).first {
            add("Known KEY: waiting for it. Press a button on the KEY.")
            connect(p, c)
            return
        }
        // 2. A KEY the system is already connected to (as a keyboard).
        if let p = c.retrieveConnectedPeripherals(withServices: [KeyLink.hidService, KeyLink.favService])
            .first(where: { ($0.name ?? "").hasPrefix(KeyLink.keyName) }) {
            add("KEY already connected to the phone")
            connect(p, c)
            return
        }
        // 3. Look for it. It is findable for 15 s after a press on its home screen.
        add("Looking for the KEY. Press a button on the KEY's home screen.")
        c.scanForPeripherals(withServices: [KeyLink.hidService], options: nil)
    }

    private func connect(_ p: CBPeripheral, _ c: CBCentralManager) {
        peripheral = p
        p.delegate = self
        c.connect(p, options: nil)
    }

    private func add(_ s: String) {
        let ms = Int(Date().timeIntervalSince(started) * 1000)
        lines.append(String(format: "%5d ms  %@", ms, s))
    }

    private func finish(_ outcome: String) {
        guard busy else { return }
        timeout?.cancel(); timeout = nil
        central?.stopScan()
        if let p = peripheral { central?.cancelPeripheralConnection(p) }
        peripheral = nil
        add(outcome)
        result = outcome
        busy = false
    }
}

// MARK: - CBCentralManagerDelegate

extension KeyLink: CBCentralManagerDelegate {
    func centralManagerDidUpdateState(_ c: CBCentralManager) {
        switch c.state {
        case .poweredOn: if busy { go(c) }
        case .unauthorized: finish("Bluetooth permission is off for Favilla. Turn it on in Settings > Favilla.")
        case .poweredOff: finish("Bluetooth is off on this iPhone.")
        case .unsupported: finish("This device has no Bluetooth LE.")
        default: break
        }
    }

    func centralManager(_ c: CBCentralManager, didDiscover p: CBPeripheral, advertisementData: [String: Any], rssi: NSNumber) {
        let name = (advertisementData[CBAdvertisementDataLocalNameKey] as? String) ?? p.name ?? ""
        guard name.hasPrefix(KeyLink.keyName) else { return }
        c.stopScan()
        add("Found \(name) (RSSI \(rssi))")
        connect(p, c)
    }

    func centralManager(_ c: CBCentralManager, didConnect p: CBPeripheral) {
        add("Connected")
        store.set(p.identifier.uuidString, forKey: KeyLink.savedIdKey)
        p.discoverServices([KeyLink.favService])
    }

    func centralManager(_ c: CBCentralManager, didFailToConnect p: CBPeripheral, error: Error?) {
        finish("Could not connect: \(error?.localizedDescription ?? "unknown")")
    }

    func centralManager(_ c: CBCentralManager, didDisconnectPeripheral p: CBPeripheral, error: Error?) {
        if busy { finish("The KEY dropped the link: \(error?.localizedDescription ?? "no reason given")") }
    }
}

// MARK: - CBPeripheralDelegate

extension KeyLink: CBPeripheralDelegate {
    func peripheral(_ p: CBPeripheral, didDiscoverServices error: Error?) {
        guard let s = p.services?.first(where: { $0.uuid == KeyLink.favService }) else {
            finish("The KEY has no Favilla service. Flash drop 8y or later. If it is flashed, forget Favilla KEY in iPhone Bluetooth settings and pair again.")
            return
        }
        add("Favilla service found")
        p.discoverCharacteristics([KeyLink.probeChar], for: s)
    }

    func peripheral(_ p: CBPeripheral, didDiscoverCharacteristicsFor s: CBService, error: Error?) {
        guard let ch = s.characteristics?.first(where: { $0.uuid == KeyLink.probeChar }) else {
            finish("Probe characteristic missing")
            return
        }
        add("Reading (encrypted)")
        p.readValue(for: ch)
    }

    func peripheral(_ p: CBPeripheral, didUpdateValueFor ch: CBCharacteristic, error: Error?) {
        if let e = error { finish("Read refused: \(e.localizedDescription). The phone may not be paired with this KEY."); return }
        let text = ch.value.flatMap { String(data: $0, encoding: .utf8) } ?? "(no data)"
        let ms = Int(Date().timeIntervalSince(started) * 1000)
        finish("OK in \(ms) ms: \(text)")
    }
}
