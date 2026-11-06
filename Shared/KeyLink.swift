// KeyLink.swift - the Bluetooth link to a Favilla KEY (Nov 2026).
//
// Two jobs, same link:
//  - probe(): read the Favilla service's probe characteristic. It is readable
//    only on an encrypted (bonded) link, so a successful read proves the app, or
//    the AutoFill extension, reached THIS KEY on the phone's own bond.
//  - signIn(site:): write the site iOS asked about to the KEY's sign-in request
//    characteristic (KEY drop 8z7). The KEY puts it on its screen, the owner
//    picks the login there, and the KEY types it as the phone's Bluetooth
//    keyboard. Nothing comes back but success or a status: never a password,
//    username or site name the KEY holds (ruled 6 Nov 2026).
//
// The KEY does not advertise at rest (drop 8m). A press on its home screen
// makes it findable for 15 s (drop 8y). CoreBluetooth's connect() waits for
// that, so the flow is: start, then press a button on the KEY.

import CoreBluetooth
import Foundation

final class KeyLink: NSObject, ObservableObject {
    static let favService = CBUUID(string: "8F1A0001-6B2E-4C8D-9A3E-5F7C2D1E0B4A")
    static let probeChar  = CBUUID(string: "8F1A0002-6B2E-4C8D-9A3E-5F7C2D1E0B4A")
    static let reqChar    = CBUUID(string: "8F1A0003-6B2E-4C8D-9A3E-5F7C2D1E0B4A")
    static let hidService = CBUUID(string: "1812")
    static let keyName    = "Favilla KEY"
    private static let savedIdKey = "keyPeripheralId"
    private static let groupId    = "group.io.favillakey.app"
    private static let cmdSignIn: UInt8 = 0x31   // chan::C_SIGN_IN
    private static let siteMax = 100            // chan::FIELD_MAX

    enum Mode { case probe, signIn }
    enum Outcome: Equatable { case ok(String), sent, failed(String), cancelled }

    @Published private(set) var lines: [String] = []
    @Published private(set) var result: String?
    @Published private(set) var outcome: Outcome?
    @Published private(set) var busy = false
    /// The site or app iOS asked about, when run from the AutoFill sheet.
    var site: String = ""
    private(set) var mode: Mode = .probe

    private var central: CBCentralManager?
    private var peripheral: CBPeripheral?
    private var started = Date()
    private var timeout: DispatchWorkItem?
    private let store = UserDefaults(suiteName: KeyLink.groupId) ?? .standard

    // MARK: - Start

    func probe() { start(.probe) }

    /// Send the sign-in ask for `site` (set before calling).
    func signIn() { start(.signIn) }

    func cancel() { finish(.cancelled, "Cancelled") }

    private func start(_ m: Mode) {
        guard !busy else { return }
        mode = m
        busy = true
        result = nil
        outcome = nil
        lines = []
        started = Date()
        if !site.isEmpty { add("Asked for: \(site)") }
        if m == .signIn, KeyLink.requestBody(site: site) == nil {
            finish(.failed("This site's name can't be sent to the KEY."), "Site name not usable: \(site)")
            return
        }
        add("Starting Bluetooth")
        let t = DispatchWorkItem { [weak self] in
            self?.finish(.failed("Your KEY didn't answer. Press a button on the KEY's home screen, then try again."), "Timed out after 30 s")
        }
        timeout = t
        DispatchQueue.main.asyncAfter(deadline: .now() + 30, execute: t)
        if let c = central, c.state == .poweredOn { go(c) } else { central = CBCentralManager(delegate: self, queue: .main) }
    }

    private func go(_ c: CBCentralManager) {
        // 1. The KEY this phone used before (saved by an earlier run).
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

    private func finish(_ o: Outcome, _ log: String) {
        guard busy else { return }
        timeout?.cancel(); timeout = nil
        central?.stopScan()
        if let p = peripheral { central?.cancelPeripheralConnection(p) }
        peripheral = nil
        add(log)
        result = log
        outcome = o
        busy = false
    }

    // MARK: - The request

    /// The host part of what iOS gave us, lower-case, or nil if it can't go to the KEY.
    static func cleanSite(_ raw: String) -> String? {
        var s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if s.contains("://"), let h = URL(string: s)?.host { s = h }
        if let slash = s.firstIndex(of: "/") { s = String(s[..<slash]) }
        s = s.lowercased()
        guard !s.isEmpty, s.utf8.count <= siteMax,
              s.utf8.allSatisfy({ $0 >= 0x21 && $0 <= 0x7E }) else { return nil }
        return s
    }

    /// [0x31 SIGN_IN][sLen][site][uLen = 0], as the KEY's chan::parseLogin expects.
    static func requestBody(site: String) -> Data? {
        guard let s = cleanSite(site) else { return nil }
        var d = Data([cmdSignIn, UInt8(s.utf8.count)])
        d.append(contentsOf: Array(s.utf8))
        d.append(0)
        return d
    }

    /// What the KEY's refusal means, in plain words (ATT error 0x80 + chan::Status).
    static func refusal(_ code: Int) -> String {
        switch code - 0x80 {
        case 4:  return "Your KEY isn't in PASSKEY mode. Restart it and choose PASSKEY."
        case 5:  return "Your KEY is locked. Enter the passkey PIN on the KEY, then try again."
        case 6:  return "Your KEY is already showing a sign-in. Finish it on the KEY, then try again."
        case 7:  return "The KEY couldn't read this site's name."
        case 8:  return "This iPhone isn't confirmed on the KEY. Pair it again in Settings > Bluetooth on the KEY."
        default: return "The KEY refused the request (code \(code))."
        }
    }
}

// MARK: - CBCentralManagerDelegate

extension KeyLink: CBCentralManagerDelegate {
    func centralManagerDidUpdateState(_ c: CBCentralManager) {
        switch c.state {
        case .poweredOn: if busy { go(c) }
        case .unauthorized: finish(.failed("Bluetooth permission is off for Favilla. Turn it on in Settings > Favilla."), "Bluetooth permission off")
        case .poweredOff: finish(.failed("Bluetooth is off on this iPhone. Turn it on in Control Centre."), "Bluetooth off")
        case .unsupported: finish(.failed("This device has no Bluetooth LE."), "No Bluetooth LE")
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
        finish(.failed("Couldn't connect to your KEY. Try again."), "Could not connect: \(error?.localizedDescription ?? "unknown")")
    }

    func centralManager(_ c: CBCentralManager, didDisconnectPeripheral p: CBPeripheral, error: Error?) {
        if busy { finish(.failed("Your KEY dropped the link. Try again."), "The KEY dropped the link: \(error?.localizedDescription ?? "no reason given")") }
    }
}

// MARK: - CBPeripheralDelegate

extension KeyLink: CBPeripheralDelegate {
    func peripheral(_ p: CBPeripheral, didDiscoverServices error: Error?) {
        guard let s = p.services?.first(where: { $0.uuid == KeyLink.favService }) else {
            finish(.failed("Your KEY needs newer firmware (drop 8y or later). If it has it, forget Favilla KEY in iPhone Bluetooth settings and pair again."), "No Favilla service")
            return
        }
        add("Favilla service found")
        p.discoverCharacteristics([mode == .probe ? KeyLink.probeChar : KeyLink.reqChar], for: s)
    }

    func peripheral(_ p: CBPeripheral, didDiscoverCharacteristicsFor s: CBService, error: Error?) {
        let want = mode == .probe ? KeyLink.probeChar : KeyLink.reqChar
        guard let ch = s.characteristics?.first(where: { $0.uuid == want }) else {
            finish(.failed(mode == .probe ? "Probe characteristic missing." : "Your KEY needs firmware drop 8z7 or later for signing in."), "Characteristic \(want) missing")
            return
        }
        switch mode {
        case .probe:
            add("Reading (encrypted)")
            p.readValue(for: ch)
        case .signIn:
            guard let body = KeyLink.requestBody(site: site) else {
                finish(.failed("This site's name can't be sent to the KEY."), "Site name not usable")
                return
            }
            add("Sending the sign-in ask (encrypted)")
            p.writeValue(body, for: ch, type: .withResponse)
        }
    }

    func peripheral(_ p: CBPeripheral, didUpdateValueFor ch: CBCharacteristic, error: Error?) {
        if let e = error { finish(.failed("This iPhone may not be paired with this KEY."), "Read refused: \(e.localizedDescription)"); return }
        let text = ch.value.flatMap { String(data: $0, encoding: .utf8) } ?? "(no data)"
        let ms = Int(Date().timeIntervalSince(started) * 1000)
        finish(.ok(text), "OK in \(ms) ms: \(text)")
    }

    func peripheral(_ p: CBPeripheral, didWriteValueFor ch: CBCharacteristic, error: Error?) {
        if let e = error as NSError? {
            let code = e.domain == CBATTErrorDomain ? e.code : -1
            if code >= 0x80 { finish(.failed(KeyLink.refusal(code)), "KEY refused: code \(code)") }
            else { finish(.failed("This iPhone may not be paired with this KEY."), "Write refused: \(e.localizedDescription)") }
            return
        }
        let ms = Int(Date().timeIntervalSince(started) * 1000)
        finish(.sent, "On the KEY in \(ms) ms")
    }
}
