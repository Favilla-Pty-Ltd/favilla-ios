// KeyLink.swift - the Bluetooth link to a Favilla KEY.
// Built against favilla-key-firmware docs/BLE_PASSKEY_PROTOCOL.md (drops 9a to 9c).
//
// Three jobs, same link:
//  - probe(): read the probe characteristic 8F1A0002. It is readable only on an
//    encrypted (bonded) link. With PAIR A PHONE open on the KEY, that read is
//    also how the app pairs a KEY in "App only" mode (it isn't listed in iOS
//    Bluetooth settings): iOS shows its 6-digit prompt, the owner checks the
//    KEY's screen and presses ENTER there.
//  - fill(): passwords (9c). Subscribe to the sign-in answer 8F1A0004, write
//    [0x34 FILL][site len][site][0x00] to 8F1A0003; the owner picks the login on
//    the KEY and the answer comes back on 8F1A0004 as .answer(body).
//  - ctap(_:): passkeys (9a). One CTAP2 request in the FIDO Bluetooth framing on
//    8F1A0010/11/12; the reply body comes back as .ctap(body).
//
// Finding the KEY: in "App only" it advertises the Favilla service the whole
// PASSKEY life. In "App and keyboard" it advertises (the keyboard service) for
// 15 s after a press on its home screen. The app scans for both.

import CoreBluetooth
import Foundation

final class KeyLink: NSObject, ObservableObject {
    static let favService = CBUUID(string: "8F1A0001-6B2E-4C8D-9A3E-5F7C2D1E0B4A")
    static let probeChar  = CBUUID(string: "8F1A0002-6B2E-4C8D-9A3E-5F7C2D1E0B4A")   // read, encrypted
    static let reqChar    = CBUUID(string: "8F1A0003-6B2E-4C8D-9A3E-5F7C2D1E0B4A")   // sign-in request: write, encrypted
    static let answerChar = CBUUID(string: "8F1A0004-6B2E-4C8D-9A3E-5F7C2D1E0B4A")   // sign-in answer: notify (9c)
    static let fidoCP     = CBUUID(string: "8F1A0010-6B2E-4C8D-9A3E-5F7C2D1E0B4A")   // control point: write, encrypted
    static let fidoStatus = CBUUID(string: "8F1A0011-6B2E-4C8D-9A3E-5F7C2D1E0B4A")   // status: notify
    static let fidoCPLen  = CBUUID(string: "8F1A0012-6B2E-4C8D-9A3E-5F7C2D1E0B4A")   // control point length: read, 2 bytes BE
    static let hidService = CBUUID(string: "1812")
    static let keyName    = "Favilla KEY"
    private static let savedIdKey = "keyPeripheralId"
    private static let groupId    = "group.io.favillakey.app"
    private static let cmdFill: UInt8 = 0x34
    private static let siteMax = 100

    enum Mode { case probe, fill, ctap }
    enum Outcome: Equatable {
        case ok(String)          // probe read
        case answer(Data)        // password answer body (status byte first); never logged
        case ctap(Data)          // passkey reply body (CTAP status byte first)
        case failed(String)
        case cancelled
    }

    @Published private(set) var lines: [String] = []
    @Published private(set) var result: String?
    @Published private(set) var outcome: Outcome?
    @Published private(set) var busy = false
    /// The KEY has the request on its screen and is waiting for the owner.
    @Published private(set) var waitingOnKey = false
    /// iOS is pairing with the KEY (6-digit comparison): the link is kept open.
    @Published private(set) var pairing = false
    /// The site or app iOS asked about, when run from the AutoFill sheet.
    var site: String = ""
    /// `site` is a native app's name (iOS 26.2+ gives an app ID and name for apps
    /// not linked to a website), not a domain: sent as written, not as a host name.
    var siteIsAppName = false
    /// The account iOS named (a listed account), sent with FILL so the KEY can
    /// open that entry straight away (9d). Empty: the KEY shows the site's matches.
    var fillUser: String = ""
    private(set) var mode: Mode = .probe

    private var central: CBCentralManager?
    private var peripheral: CBPeripheral?
    private var started = Date()
    private var timeout: DispatchWorkItem?
    private let store = UserDefaults(suiteName: KeyLink.groupId) ?? .standard
    private var reasm = Ctap.Reassembler()
    // Passkeys: the request and its writes still to send.
    private var ctapRequest = Data()
    private var pendingFrames: [Data] = []
    private var requestSent = false
    private var cpChar: CBCharacteristic?
    private var cpLenChar: CBCharacteristic?
    // Passwords: where the request goes.
    private var reqCh: CBCharacteristic?

    // MARK: - Start

    func probe() { start(.probe) }

    /// Ask the KEY for the login for `site` (set before calling).
    func fill() { start(.fill) }

    /// Send one CTAP2 request (command byte + CBOR) to the KEY's passkey service.
    func ctap(_ request: Data) {
        ctapRequest = request
        start(.ctap)
    }

    /// Add a line to the visible log (e.g. the checks on the KEY's reply).
    func note(_ s: String) { add(s) }

    /// Show a failure found after the reply came back (e.g. a refusal in the body).
    func showFailure(_ why: String) {
        guard !busy else { return }
        add("Refused: \(why)")
        result = why
        outcome = .failed(why)
    }

    func cancel() {
        // Passkeys: tell the KEY to stop waiting for a press, then let the link go.
        if busy, mode == .ctap, requestSent, let p = peripheral, let cp = cpChar {
            add("Cancelling on the KEY")
            p.writeValue(Data([Ctap.cmdCancel, 0x00, 0x00]), for: cp, type: .withResponse)
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) { [weak self] in self?.finish(.cancelled, "Cancelled") }
            return
        }
        finish(.cancelled, "Cancelled")
    }

    private func start(_ m: Mode) {
        guard !busy else { return }
        mode = m
        busy = true
        result = nil
        outcome = nil
        lines = []
        waitingOnKey = false
        pairing = false
        pendingFrames = []; requestSent = false; reasm = Ctap.Reassembler(); cpChar = nil; cpLenChar = nil; reqCh = nil
        started = Date()
        if !site.isEmpty { add("Asked for: \(site)") }
        if m == .fill, KeyLink.fillBody(site: site, appName: siteIsAppName, user: fillUser) == nil {
            finish(.failed("This site's name can't be sent to the KEY."), "Site name not usable: \(site)")
            return
        }
        add("Starting Bluetooth")
        armTimeout(m == .probe ? 60 : 30, "Your KEY didn't answer. Check it's on its home screen in PASSKEY mode with Bluetooth on. If its Bluetooth is set to App and keyboard, press a button on it first.")
        if let c = central, c.state == .poweredOn { go(c) } else { central = CBCentralManager(delegate: self, queue: .main) }
    }

    private func go(_ c: CBCentralManager) {
        // 1. A KEY the system is already connected to: use that link.
        if let p = c.retrieveConnectedPeripherals(withServices: [KeyLink.favService, KeyLink.hidService])
            .first(where: { ($0.name ?? "").hasPrefix(KeyLink.keyName) }) {
            add("KEY already connected to the phone")
            connect(p, c)
            return
        }
        // 2. The KEY this phone used before. A pending connect waits for it to
        //    advertise. iOS gives a re-paired KEY a new identity, so search as
        //    well and take whichever answers (bench, 6 Nov 2026).
        if let s = store.string(forKey: KeyLink.savedIdKey), let id = UUID(uuidString: s),
           let p = c.retrievePeripherals(withIdentifiers: [id]).first {
            add("Known KEY: connecting, and searching")
            connect(p, c)
        } else {
            add("Looking for the KEY")
        }
        // 3. Search: the Favilla service ("App only", always advertised) or the
        //    keyboard service ("App and keyboard", 15 s after a press).
        c.scanForPeripherals(withServices: [KeyLink.favService, KeyLink.hidService], options: nil)
    }

    private func armTimeout(_ seconds: Double, _ why: String) {
        timeout?.cancel()
        let t = DispatchWorkItem { [weak self] in self?.finish(.failed(why), "Timed out (\(Int(seconds)) s)") }
        timeout = t
        DispatchQueue.main.asyncAfter(deadline: .now() + seconds, execute: t)
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
        cpChar = nil; cpLenChar = nil; reqCh = nil; pendingFrames = []
        reasm = Ctap.Reassembler()   // drop any partial reply (it may hold part of a password)
        add(log)
        result = log
        outcome = o
        waitingOnKey = false
        pairing = false
        busy = false
    }

    // MARK: - Pairing on demand
    //
    // A KEY the phone isn't bonded with refuses encrypted reads, writes and
    // subscriptions with "insufficient authentication" (ATT 0x05) or
    // "insufficient encryption" (0x0F), and iOS starts pairing. Bench 6 Nov
    // 2026: giving up on that refusal dropped the link and killed iOS's prompt
    // after a fraction of a second. So keep the link and retry while the owner
    // compares the code and presses ENTER on the KEY (PAIR A PHONE open).

    static func needsPairing(_ e: Error) -> Bool {
        let n = e as NSError
        return n.domain == CBATTErrorDomain && (n.code == CBATTError.insufficientAuthentication.rawValue ||
                                                n.code == CBATTError.insufficientEncryption.rawValue)
    }

    private func awaitPairing(_ retry: @escaping () -> Void) {
        if !pairing {
            pairing = true
            add("Not paired yet: iOS is asking to pair. Compare the code with the KEY's screen, tap Pair, then press ENTER on the KEY.")
            armTimeout(60, KeyLink.notConfirmed)
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 2) { [weak self] in
            guard let self, self.busy, self.pairing, self.peripheral != nil else { return }
            retry()
        }
    }

    private func paired() {
        guard pairing else { return }
        pairing = false
        add("Paired")
        armTimeout(45, "Your KEY didn't answer. Try again.")
    }

    /// Forget a password answer once it has been handed to iOS.
    func clearAnswer() {
        if case .answer = outcome { outcome = nil }
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

    /// A native app's name for the KEY: printable ASCII (the KEY's rule for a
    /// site), spaces kept, up to 100 bytes; nil if nothing usable is left.
    static func cleanAppName(_ raw: String) -> String? {
        let ascii = String(raw.unicodeScalars.filter { $0.value >= 0x20 && $0.value <= 0x7E }.map(Character.init))
        let s = String(ascii.trimmingCharacters(in: .whitespaces).prefix(siteMax))
        return s.contains(where: { $0 != " " }) ? s : nil
    }

    /// [0x34 FILL][site length][site][user length][user] (protocol doc, Passwords; user from 9d).
    static func fillBody(site: String, appName: Bool = false, user: String = "") -> Data? {
        guard let s = appName ? cleanAppName(site) : cleanSite(site) else { return nil }
        var d = Data([cmdFill, UInt8(s.utf8.count)])
        d.append(contentsOf: Array(s.utf8))
        // A username the KEY can't take (too long) is left out: it then shows the site's matches.
        let u = Array(user.utf8)
        if !u.isEmpty, u.count <= siteMax {
            d.append(UInt8(u.count)); d.append(contentsOf: u)
        } else {
            d.append(0)
        }
        return d
    }

    /// What the KEY's refusal of a write means (ATT error 0x80 + status).
    static func refusal(_ code: Int) -> String {
        switch code - 0x80 {
        case 4:  return "Your KEY isn't in PASSKEY mode. Restart it and choose PASSKEY."
        case 5:  return "Your KEY is locked. Enter the passkey PIN on the KEY, then try again."
        case 6:  return "Your KEY is already showing a sign-in. Finish it on the KEY, then try again."
        case 7:  return "The KEY couldn't read this site's name."
        case 8:  return KeyLink.notConfirmed
        default: return "The KEY refused the request (code \(code))."
        }
    }

    static let notConfirmed = "This iPhone isn't confirmed on the KEY. On the KEY open PAIR A PHONE, then tap FIND MY KEY in the Favilla app and accept the code."
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
        let uuids = (advertisementData[CBAdvertisementDataServiceUUIDsKey] as? [CBUUID]) ?? []
        guard name.hasPrefix(KeyLink.keyName) || uuids.contains(KeyLink.favService) else { return }
        c.stopScan()
        if let old = peripheral {
            if old.identifier == p.identifier { add("Found it advertising"); return }   // the pending connect completes
            add("Found the KEY under a new identity (re-paired?)")
            c.cancelPeripheralConnection(old)
        } else {
            add("Found \(name.isEmpty ? "the KEY" : name) (RSSI \(rssi))")
        }
        connect(p, c)
    }

    func centralManager(_ c: CBCentralManager, didConnect p: CBPeripheral) {
        c.stopScan()
        add("Connected")
        store.set(p.identifier.uuidString, forKey: KeyLink.savedIdKey)
        p.discoverServices([KeyLink.favService])
    }

    func centralManager(_ c: CBCentralManager, didFailToConnect p: CBPeripheral, error: Error?) {
        guard p.identifier == peripheral?.identifier else { return }
        finish(.failed("Couldn't connect to your KEY. Try again."), "Could not connect: \(error?.localizedDescription ?? "unknown")")
    }

    func centralManager(_ c: CBCentralManager, didDisconnectPeripheral p: CBPeripheral, error: Error?) {
        guard p.identifier == peripheral?.identifier else { return }   // an old identity we let go
        if busy { finish(.failed("Your KEY dropped the link. Try again."), "The KEY dropped the link: \(error?.localizedDescription ?? "no reason given")") }
    }
}

// MARK: - CBPeripheralDelegate

extension KeyLink: CBPeripheralDelegate {
    func peripheral(_ p: CBPeripheral, didDiscoverServices error: Error?) {
        guard let s = p.services?.first(where: { $0.uuid == KeyLink.favService }) else {
            finish(.failed("Your KEY's Bluetooth table looks old. Restart the KEY; if that doesn't help, forget Favilla KEY on this iPhone and pair again."), "No Favilla service")
            return
        }
        add("Favilla service found")
        switch mode {
        case .probe: p.discoverCharacteristics([KeyLink.probeChar], for: s)
        case .fill: p.discoverCharacteristics([KeyLink.reqChar, KeyLink.answerChar], for: s)
        case .ctap: p.discoverCharacteristics([KeyLink.fidoCP, KeyLink.fidoStatus, KeyLink.fidoCPLen], for: s)
        }
    }

    func peripheral(_ p: CBPeripheral, didDiscoverCharacteristicsFor s: CBService, error: Error?) {
        let cs = s.characteristics ?? []
        switch mode {
        case .probe:
            guard let ch = cs.first(where: { $0.uuid == KeyLink.probeChar }) else {
                finish(.failed("The KEY's probe is missing."), "Probe characteristic missing"); return
            }
            add("Reading (encrypted; pairs this iPhone if PAIR A PHONE is open on the KEY)")
            p.readValue(for: ch)
        case .fill:
            guard let rq = cs.first(where: { $0.uuid == KeyLink.reqChar }),
                  let an = cs.first(where: { $0.uuid == KeyLink.answerChar }) else {
                finish(.failed("Your KEY needs firmware 9c or later for passwords. If it has it, restart the KEY."), "Sign-in answer characteristic missing"); return
            }
            reqCh = rq
            add("Subscribing to the answer")
            p.setNotifyValue(true, for: an)   // the answer only goes to a subscribed link
        case .ctap:
            guard let cp = cs.first(where: { $0.uuid == KeyLink.fidoCP }),
                  let st = cs.first(where: { $0.uuid == KeyLink.fidoStatus }),
                  let len = cs.first(where: { $0.uuid == KeyLink.fidoCPLen }) else {
                finish(.failed("Your KEY needs firmware 9a or later for passkeys. If it has it, restart the KEY."), "FIDO characteristics missing"); return
            }
            cpChar = cp; cpLenChar = len
            add("Passkey service found; subscribing")
            p.setNotifyValue(true, for: st)   // replies to an unsubscribed app are dropped
        }
    }

    func peripheral(_ p: CBPeripheral, didUpdateNotificationStateFor ch: CBCharacteristic, error: Error?) {
        if let e = error {
            if KeyLink.needsPairing(e) { awaitPairing { p.setNotifyValue(true, for: ch) }; return }
            finish(.failed(KeyLink.notConfirmed), "Subscribe refused: \(e.localizedDescription)"); return
        }
        paired()
        switch mode {
        case .fill where ch.uuid == KeyLink.answerChar:
            guard let rq = reqCh, let body = KeyLink.fillBody(site: site, appName: siteIsAppName, user: fillUser) else { return }
            add("Subscribed; sending the ask (encrypted)")
            p.writeValue(body, for: rq, type: .withResponse)
        case .ctap where ch.uuid == KeyLink.fidoStatus:
            guard let len = cpLenChar else { return }
            add("Subscribed; reading the write size")
            p.readValue(for: len)
        default: break
        }
    }

    private func sendNextFrame(_ p: CBPeripheral) {
        guard let cp = cpChar else { return }
        if pendingFrames.isEmpty {
            requestSent = true
            add("Request sent; waiting for the KEY")
            armTimeout(45, "Your KEY didn't reply. Try again.")
            return
        }
        p.writeValue(pendingFrames.removeFirst(), for: cp, type: .withResponse)
    }

    private func notified(_ d: Data) {
        do {
            guard let ev = try reasm.feed(d) else { return }
            let ms = Int(Date().timeIntervalSince(started) * 1000)
            switch ev {
            case .keepalive(let k):
                if k == 0x02, !waitingOnKey { waitingOnKey = true; add("The KEY is waiting for your press") }
                armTimeout(10, "The KEY stopped answering. Try again.")
            case .message(let body) where mode == .ctap:
                finish(.ctap(body), String(format: "Reply in %d ms (status 0x%02X, %d bytes)", ms, body.first ?? 0xFF, body.count))
            case .answer(let body) where mode == .fill:
                // Log the status only: the body holds the password.
                finish(.answer(body), String(format: "Answer in %d ms (status 0x%02X)", ms, body.first ?? 0xFF))
            case .ping(let b):
                add("Ping back (\(b.count) bytes)")
            case .error(let e):
                finish(.failed(Ctap.message(forFramingError: e)), String(format: "KEY framing error 0x%02X", e))
            default:
                finish(.failed("The KEY's reply didn't make sense. Try again."), "Reply of the wrong kind for this request")
            }
        } catch {
            finish(.failed("The KEY's reply didn't make sense. Try again."), "Bad reply: \(error)")
        }
    }

    func peripheral(_ p: CBPeripheral, didUpdateValueFor ch: CBCharacteristic, error: Error?) {
        if ch.uuid == KeyLink.fidoStatus || ch.uuid == KeyLink.answerChar {
            if let d = ch.value, error == nil { notified(d) }
            return
        }
        if let e = error {
            if KeyLink.needsPairing(e) { awaitPairing { p.readValue(for: ch) }; return }
            finish(.failed(KeyLink.notConfirmed), "Read refused: \(e.localizedDescription)"); return
        }
        paired()
        if ch.uuid == KeyLink.fidoCPLen {
            let v = [UInt8](ch.value ?? Data())
            guard v.count >= 2 else { finish(.failed("The KEY's passkey service didn't answer properly."), "Bad control point length"); return }
            let max = Swift.min(Int(v[0]) << 8 | Int(v[1]), 512)
            guard max >= 4 else { finish(.failed("The KEY's passkey service didn't answer properly."), "Control point length \(max)"); return }
            guard ctapRequest.count <= Ctap.maxBody else { finish(.failed("The request is too big for the KEY."), "Request \(ctapRequest.count) bytes"); return }
            pendingFrames = Ctap.frames(cmd: Ctap.cmdMsg, payload: ctapRequest, max: max)
            add("Sending the request (\(ctapRequest.count) bytes in \(pendingFrames.count) write\(pendingFrames.count == 1 ? "" : "s"))")
            sendNextFrame(p)
            return
        }
        // The probe.
        let text = ch.value.flatMap { String(data: $0, encoding: .utf8) } ?? "(no data)"
        let ms = Int(Date().timeIntervalSince(started) * 1000)
        finish(.ok(text), "OK in \(ms) ms: \(text)")
    }

    func peripheral(_ p: CBPeripheral, didWriteValueFor ch: CBCharacteristic, error: Error?) {
        if let e = error as NSError? {
            if mode == .fill, KeyLink.needsPairing(e), let body = KeyLink.fillBody(site: site, appName: siteIsAppName, user: fillUser) {
                awaitPairing { p.writeValue(body, for: ch, type: .withResponse) }; return
            }
            let code = e.domain == CBATTErrorDomain ? e.code : -1
            if code >= 0x80 { finish(.failed(KeyLink.refusal(code)), "KEY refused: code \(code)") }
            else if code == 0x05 { finish(.failed(KeyLink.notConfirmed), "Write refused: not a confirmed phone") }
            else { finish(.failed("The KEY refused the request."), "Write refused: \(e.localizedDescription)") }
            return
        }
        paired()
        switch mode {
        case .ctap:
            if !requestSent { sendNextFrame(p) }
        case .fill:
            waitingOnKey = true
            add("On the KEY: pick the login there")
            armTimeout(45, "Your KEY didn't answer. Try again.")   // the KEY answers cancelled after 30 s itself
        case .probe: break
        }
    }
}
