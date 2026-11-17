// KeyLink.swift - the Bluetooth link to a Favilla KEY.
// Built against favilla-key-firmware docs/BLE_PASSKEY_PROTOCOL.md (drops 9a to 9j).
//
// Two ways to talk to the KEY on the same link:
//
//  - The app channel (9g, AppChannel.swift), once this install is paired with
//    the KEY (PAIR THE APP). Requests go to 8F1A0005 with a counter and a MAC,
//    answers come back on 8F1A0006, the secret ones encrypted. After every
//    connect the app first sends TIME (9j), then the request: HELLO (the link
//    check), FILL, CTAP, OTP (9i) or LIST (9h). Once an app is paired the KEY
//    refuses the raw paths below with ATT 0x8F.
//  - The raw paths (9a to 9c), for an install not paired yet and older KEYs:
//    the probe read 8F1A0002, FILL on 8F1A0003 / 8F1A0004, and CTAP2 in the FIDO
//    Bluetooth framing on 8F1A0010 to 0012.
//
// The probe read is also how the phone bonds with the KEY: with PAIR A PHONE
// open, iOS shows its 6-digit prompt and the owner presses ENTER on the KEY.
//
// Finding the KEY: in "App only" it advertises the Favilla service the whole
// PASSKEY life. In "App and keyboard" it advertises (the keyboard service) for
// 15 s after a press on its home screen. The app scans for both.

import Combine
import CoreBluetooth
import Foundation

final class KeyLink: NSObject, ObservableObject {
    static let favService = CBUUID(string: "8F1A0001-6B2E-4C8D-9A3E-5F7C2D1E0B4A")
    static let probeChar  = CBUUID(string: "8F1A0002-6B2E-4C8D-9A3E-5F7C2D1E0B4A")   // read, encrypted
    static let reqChar    = CBUUID(string: "8F1A0003-6B2E-4C8D-9A3E-5F7C2D1E0B4A")   // sign-in request: write, encrypted
    static let answerChar = CBUUID(string: "8F1A0004-6B2E-4C8D-9A3E-5F7C2D1E0B4A")   // sign-in answer: notify (9c)
    static let chanInChar = CBUUID(string: "8F1A0005-6B2E-4C8D-9A3E-5F7C2D1E0B4A")   // app channel in: write, encrypted (9g)
    static let chanOutChar = CBUUID(string: "8F1A0006-6B2E-4C8D-9A3E-5F7C2D1E0B4A")  // app channel out: notify (9g)
    static let fidoCP     = CBUUID(string: "8F1A0010-6B2E-4C8D-9A3E-5F7C2D1E0B4A")   // control point: write, encrypted
    static let fidoStatus = CBUUID(string: "8F1A0011-6B2E-4C8D-9A3E-5F7C2D1E0B4A")   // status: notify
    static let fidoCPLen  = CBUUID(string: "8F1A0012-6B2E-4C8D-9A3E-5F7C2D1E0B4A")   // control point length: read, 2 bytes BE
    static let hidService = CBUUID(string: "1812")
    static let keyName    = "Favilla KEY"
    /// Posted when an operation starts and ends, so the Nostr client's link
    /// (NostrLink, app only) can step aside while this one has the KEY.
    static let didStart = Notification.Name("FavillaKeyLinkDidStart")
    static let didFinish = Notification.Name("FavillaKeyLinkDidFinish")
    private static let savedIdKey = "keyPeripheralId"
    private static let groupId    = "group.io.favillakey.app"
    private static let cmdFill: UInt8 = 0x34
    private static let siteMax = 100

    enum Mode { case probe, fill, ctap, otp, list, pairApp }
    enum Outcome: Equatable {
        case ok(String)          // the link check
        case answer(Data)        // password answer body (status byte first); never logged
        case ctap(Data)          // passkey reply body (CTAP status byte first)
        case otp(String)         // a one-time code; never logged
        case list([AppChannel.ListEntry])
        case appPaired
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
    /// PAIR THE APP: the code to compare with the KEY's screen ("123 456").
    @Published private(set) var appCode: String?
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
    // Passkeys (raw path): the request and its writes still to send.
    private var ctapRequest = Data()
    private var pendingFrames: [Data] = []
    private var requestSent = false
    private var cpChar: CBCharacteristic?
    private var cpLenChar: CBCharacteristic?
    // Passwords (raw path): where the request goes.
    private var reqCh: CBCharacteristic?

    // The app channel.
    private enum Stage { case idle, pairCommit, pairReveal, time, op }
    private var chanIn: CBCharacteristic?
    private var chanOut: CBCharacteristic?
    private var creds: Credentials?
    private var stage = Stage.idle
    private var chanReasm = AppChannel.Reassembler()
    private var chanWrites: [Data] = []
    private var chanWriting = Data()
    private var lastCmd: UInt8 = 0
    private var lastBody = Data()
    private var lastCtr: UInt32 = 0
    private var replays = 0
    private var appPairing: AppChannel.Pairing?
    private var pairCreds: Credentials?
    private var listStart = 0
    private var listGot: [AppChannel.ListEntry] = []

    /// This install is paired with a KEY's app channel.
    static var appPaired: Bool { Credentials.isPaired }

    // MARK: - Start

    /// The link check: HELLO on the app channel once paired, else the probe read
    /// (which also bonds the phone with PAIR A PHONE open on the KEY).
    func probe() { start(.probe) }

    /// Ask the KEY for the login for `site` (set before calling).
    func fill() { start(.fill) }

    /// Send one CTAP2 request (command byte + CBOR) to the KEY's passkey service.
    func ctap(_ request: Data) {
        ctapRequest = request
        start(.ctap)
    }

    /// Ask the KEY for a one-time code for `site` (9i; app channel only).
    func oneTimeCode() { start(.otp) }

    /// Ask the KEY for its list of sites and usernames (9h; app channel only).
    func list() { start(.list) }

    /// PAIR THE APP: pair this install with the KEY's app channel (PAIR A PHONE open on the KEY).
    func pairApp() { start(.pairApp) }

    /// Forget this install's pairing with the KEY's app channel.
    func forgetApp() { Credentials.forget(); objectWillChange.send() }

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
        if busy, mode == .ctap, let p = peripheral {
            if stage == .op, let c = creds, let ci = chanIn {
                add("Cancelling on the KEY")
                p.writeValue(AppChannel.reports(AppChannel.request(AppChannel.cCancel, c, ctr: Credentials.nextCounter()))[0], for: ci, type: .withResponse)
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) { [weak self] in self?.finish(.cancelled, "Cancelled") }
                return
            }
            if requestSent, let cp = cpChar {
                add("Cancelling on the KEY")
                p.writeValue(Data([Ctap.cmdCancel, 0x00, 0x00]), for: cp, type: .withResponse)
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) { [weak self] in self?.finish(.cancelled, "Cancelled") }
                return
            }
        }
        finish(.cancelled, "Cancelled")
    }

    private func start(_ m: Mode) {
        guard !busy else { return }
        mode = m
        busy = true
        NotificationCenter.default.post(name: KeyLink.didStart, object: self)
        result = nil
        outcome = nil
        lines = []
        waitingOnKey = false
        pairing = false
        appCode = nil
        resetLinkState()
        started = Date()
        if !site.isEmpty, m != .probe, m != .list, m != .pairApp { add("Asked for: \(site)") }
        if m == .fill || m == .otp, KeyLink.fillBody(site: site, appName: siteIsAppName, user: fillUser) == nil {
            finish(.failed("This site's name can't be sent to the KEY."), "Site name not usable: \(site)")
            return
        }
        add("Starting Bluetooth")
        armTimeout(m == .probe || m == .pairApp ? 60 : 30, "Your KEY didn't answer. Check it's on its home screen in VAULT mode with Bluetooth on. If its Bluetooth is set to App and keyboard, press a button on it first.")
        if let c = central, c.state == .poweredOn { go(c) } else { central = CBCentralManager(delegate: self, queue: .main) }
    }

    private func resetLinkState() {
        pendingFrames = []; requestSent = false; reasm = Ctap.Reassembler(); cpChar = nil; cpLenChar = nil; reqCh = nil
        chanIn = nil; chanOut = nil; creds = nil; stage = .idle; chanReasm = AppChannel.Reassembler()
        chanWrites = []; chanWriting = Data(); lastBody = Data(); replays = 0
        appPairing = nil; pairCreds = nil; listStart = 0; listGot = []
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

    private var ms: Int { Int(Date().timeIntervalSince(started) * 1000) }

    private func finish(_ o: Outcome, _ log: String) {
        guard busy else { return }
        timeout?.cancel(); timeout = nil
        central?.stopScan()
        if let p = peripheral { central?.cancelPeripheralConnection(p) }
        peripheral = nil
        resetLinkState()   // drops any partial reply (it may hold part of a password)
        add(log)
        result = log
        outcome = o
        waitingOnKey = false
        pairing = false
        appCode = nil
        busy = false
        NotificationCenter.default.post(name: KeyLink.didFinish, object: self)
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

    /// Forget a password or code once it has been handed to iOS.
    func clearAnswer() {
        switch outcome {
        case .answer?, .otp?: outcome = nil
        default: break
        }
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

    /// The site as sent to the KEY (for OTP: the same rule as FILL).
    static func siteBytes(site: String, appName: Bool) -> Data? {
        (appName ? cleanAppName(site) : cleanSite(site)).map { Data($0.utf8) }
    }

    /// What the KEY's refusal of a raw write means (ATT error 0x80 + status).
    static func refusal(_ code: Int) -> String {
        switch code - 0x80 {
        case 4:  return "Your KEY isn't in VAULT mode. Restart it and choose VAULT."
        case 5:  return "Your KEY is locked. Enter the VAULT PIN on the KEY, then try again."
        case 6:  return "Your KEY is already showing a sign-in. Finish it on the KEY, then try again."
        case 7:  return "The KEY couldn't read this site's name."
        case 8:  return KeyLink.notConfirmed
        case 0x0F: return KeyLink.pairTheApp
        default: return "The KEY refused the request (code \(code))."
        }
    }

    static let notConfirmed = "This iPhone isn't confirmed on the KEY. On the KEY open PAIR A PHONE, then tap FIND MY KEY in the Favilla app and accept the code."
    static let pairTheApp = "Your KEY now answers only the paired Favilla app. On the KEY open PAIR A PHONE, then in the Favilla app open Settings > This iPhone and tap PAIR THE APP."
    static let needsChannel = "This needs the Favilla app paired with your KEY. On the KEY open PAIR A PHONE, then in the Favilla app open Settings > This iPhone and tap PAIR THE APP."
    /// The KEY forgot this phone (reflashed, or Forget phones) but iOS kept its keys.
    static func keyForgotPhone(_ e: Error?) -> Bool {
        guard let n = e as NSError? else { return false }
        return n.domain == CBErrorDomain && n.code == CBError.peerRemovedPairingInformation.rawValue
    }
    static let forgetOnPhone = "Your KEY no longer has this iPhone's pairing, but the iPhone still does. On the KEY set Settings > Bluetooth to App and keyboard and press a button. On the iPhone open Settings > Bluetooth, tap (i) next to Favilla KEY and tap Forget This Device. On the KEY set Bluetooth back to App only, open PAIR A PHONE, then tap PAIR THE APP in the Favilla app."
    static let oldFirmware = "Your KEY needs firmware 9g or later for this. If it has it, restart the KEY."
    static let unreadable = "The KEY's reply didn't make sense. Try again."

    static func lifeText(_ l: UInt8) -> String {
        switch l {
        case 1: return "VAULT, locked"
        case 2: return "VAULT, ready"
        case 3: return "NOSTR"
        default: return "another mode"
        }
    }

    static func otpMessage(_ s: UInt8) -> String {
        switch s {
        case 0x02: return "Cancelled on the KEY, or nobody picked a code in time."
        case 0x03: return "No one-time code is saved on the KEY. Add one on the KEY: VAULT > Codes > ADD BY QR."
        default: return AppChannel.statusText(s)
        }
    }

    static func listMessage(_ s: UInt8) -> String {
        s == 0x02 ? "The KEY didn't share the list (refused, or no answer in 30 s)." : AppChannel.statusText(s)
    }
}

// MARK: - The app channel

extension KeyLink {
    /// Send one message on 8F1A0005, as whole reports, several per write.
    private func sendChan(_ msg: Data) {
        guard let p = peripheral else { return }
        let per = max(1, min(8, p.maximumWriteValueLength(for: .withoutResponse) / 64))
        chanWrites = AppChannel.writes(msg, perWrite: per)
        writeNextChan(p)
    }

    private func writeNextChan(_ p: CBPeripheral) {
        guard let ci = chanIn else { return }
        if chanWrites.isEmpty { chanSent(); return }
        chanWriting = chanWrites.removeFirst()
        p.writeValue(chanWriting, for: ci, type: .withResponse)
    }

    /// A MAC'd request with the next counter.
    private func sendReq(_ cmd: UInt8, _ body: Data = Data()) {
        guard let c = creds else { return }
        lastCmd = cmd; lastBody = body; lastCtr = Credentials.nextCounter()
        sendChan(AppChannel.request(cmd, c, ctr: lastCtr, body: body))
    }

    /// The last write of a message was taken.
    private func chanSent() {
        switch stage {
        case .pairCommit: armTimeout(15, "Your KEY didn't answer the pairing. Check PAIR A PHONE is open on the KEY, then try again.")
        case .pairReveal: armTimeout(60, "The code wasn't confirmed on the KEY in time. Try again.")
        case .time: armTimeout(10, "Your KEY didn't answer. Try again.")
        case .op:
            switch mode {
            case .otp:
                waitingOnKey = true; add("On the KEY: pick the code there")
            case .list where listStart == 0:
                waitingOnKey = true; add("On the KEY: press ENTER to share the list")
            case .ctap:
                add("Request sent; waiting for the KEY")
            default: break
            }
            armTimeout(45, "Your KEY didn't answer. Try again.")
        case .idle: break
        }
    }

    /// Subscribed to 8F1A0006: pair, or set the clock and then ask.
    fileprivate func chanReady() {
        if mode == .pairApp {
            let pr = AppChannel.Pairing()
            appPairing = pr
            stage = .pairCommit
            add("Asking the KEY to pair with the app")
            sendChan(pr.commit)
            return
        }
        stage = .time
        add("App channel: setting the KEY's clock")
        sendReq(AppChannel.cTime, AppChannel.timeBody())
    }

    private func startOp() {
        stage = .op
        replays = 0
        switch mode {
        case .probe:
            sendReq(AppChannel.cHello)
        case .fill:
            guard let b = KeyLink.fillBody(site: site, appName: siteIsAppName, user: fillUser) else { return }
            add("Sending the ask (app channel)")
            sendReq(AppChannel.cFill, b.dropFirst())
        case .ctap:
            guard ctapRequest.count <= Ctap.maxBody else { finish(.failed("The request is too big for the KEY."), "Request \(ctapRequest.count) bytes"); return }
            add("Sending the request (\(ctapRequest.count) bytes, app channel)")
            sendReq(AppChannel.cCtap, ctapRequest)
        case .otp:
            guard let s = KeyLink.siteBytes(site: site, appName: siteIsAppName) else { return }
            add("Asking for a one-time code")
            sendReq(AppChannel.cOtp, AppChannel.otpBody(site: s))
        case .list:
            add("Asking for the list")
            sendReq(AppChannel.cList, AppChannel.listBody(start: 0, health: true))
        case .pairApp:
            break
        }
    }

    fileprivate func chanNotified(_ d: Data) {
        let msgs: [Data]
        do { msgs = try chanReasm.feed(d) } catch { finish(.failed(KeyLink.unreadable), "Bad report: \(error)"); return }
        for m in msgs {
            guard busy else { return }
            if mode == .pairApp { pairAnswer(m) } else { answer(m) }
        }
    }

    private func pairAnswer(_ m: Data) {
        let b = [UInt8](m)
        if b.count == 3, b[0] == AppChannel.rErr {
            finish(.failed(AppChannel.statusText(b[2])), String(format: "KEY refused the pairing (status 0x%02X)", b[2])); return
        }
        switch (b.first, stage) {
        case (AppChannel.rPairKey?, .pairCommit):
            guard let pr = appPairing, let derived = try? pr.derive(m) else {
                finish(.failed(KeyLink.unreadable), "Pairing key unreadable"); return
            }
            let (c, code) = derived
            pairCreds = c
            appCode = AppChannel.spaced(code)
            stage = .pairReveal
            add("Code \(AppChannel.spaced(code)): check it matches PAIR THE APP on the KEY, then press ENTER there")
            waitingOnKey = true
            sendChan(pr.reveal)
        case (AppChannel.rPairDone?, .pairReveal):
            guard let c = pairCreds, let a = try? AppChannel.open(m, c), a.rsp == AppChannel.rPairDone, let st = a.body.first else {
                finish(.failed(KeyLink.unreadable), "Pairing answer failed its check"); return
            }
            guard st == 0x00 else { finish(.failed(AppChannel.statusText(st)), String(format: "Pairing refused (status 0x%02X)", st)); return }
            guard c.save() else { finish(.failed("The pairing couldn't be saved on this iPhone. Try again."), "Keychain save failed"); return }
            PairIdentity.pairedAgain()      // the Nostr client enrols afresh with this KEY (issue #22)
            finish(.appPaired, "The app is paired with the KEY in \(ms) ms")
        default:
            add(String(format: "Ignored a 0x%02X during pairing", b.first ?? 0))
        }
    }

    private func answer(_ m: Data) {
        guard let c = creds else { return }
        let a: AppChannel.Answer
        do {
            a = try AppChannel.open(m, c)
        } catch AppChannel.Failure.unauthenticated(_, let st) {
            if st == 0x08 || st == 0x0A {
                // 0x08: this client is gone from the KEY. 0x0A (11ah): the KEY
                // knows no phone at all (wiped). Either way: not paired, and
                // everything kept for the KEY goes (issue #22 ruling).
                PairIdentity.resetAll(why: String(format: "refused 0x%02X", st))
                finish(.failed(AppChannel.statusText(st)), String(format: "KEY: not paired (0x%02X; forgot the stored pairing)", st)); return
            }
            if stage == .time { add(String(format: "The KEY didn't take the time (0x%02X); carrying on", st)); startOp(); return }
            finish(.failed(AppChannel.statusText(st)), String(format: "KEY refused (status 0x%02X)", st)); return
        } catch {
            finish(.failed(KeyLink.unreadable), "Answer failed its check: \(error)"); return
        }
        guard a.ctr == lastCtr else { add("Ignored an answer to an older request"); return }
        if a.rsp == AppChannel.rErr { refused(a.body); return }
        if stage == .time {
            if a.rsp == AppChannel.rAck {
                add(a.body.first == 0x00 ? "KEY clock set" : String(format: "The KEY didn't take the time (0x%02X); carrying on", a.body.first ?? 0xFF))
            }
            startOp(); return
        }
        guard stage == .op else { return }
        let st = a.body.first ?? 0xFF
        switch (mode, a.rsp) {
        case (.probe, AppChannel.rHello):
            KeyLife.heard(helloBody: a.body, from: "FIND MY KEY")
            let b = [UInt8](a.body)
            if PairIdentity.note(helloBody: a.body) {
                finish(.failed("This KEY was set up again since it was paired. Pair it again."), "The KEY's pairing identity changed: everything kept for it was cleared"); return
            }
            let drop = b.count >= 10 ? String(decoding: b[2..<10].filter { $0 != 0 }, as: UTF8.self) : "?"
            let life = b.count >= 2 ? KeyLink.lifeText(b[1]) : "?"
            finish(.ok("App paired. KEY firmware \(drop), \(life)."), "OK in \(ms) ms: app channel, firmware \(drop), \(life)")
        case (_, AppChannel.rAck):
            guard st == 0x00 else { finish(.failed(AppChannel.statusText(st)), String(format: "KEY refused (status 0x%02X)", st)); return }
            if mode == .fill { waitingOnKey = true; add("On the KEY: pick the login there") }
            armTimeout(45, "Your KEY didn't answer. Try again.")   // the KEY answers cancelled after 30 s itself
        case (.fill, AppChannel.rLogin):
            finish(.answer(a.body), String(format: "Answer in %d ms (status 0x%02X)", ms, st))   // the body holds the password
        case (.ctap, AppChannel.rKeepalive):
            if st == 0x02, !waitingOnKey { waitingOnKey = true; add("The KEY is waiting for your press") }
            armTimeout(10, "The KEY stopped answering. Try again.")
        case (.ctap, AppChannel.rCtap):
            finish(.ctap(a.body), String(format: "Reply in %d ms (status 0x%02X, %d bytes)", ms, st, a.body.count))
        case (.otp, AppChannel.rOtp):
            do {
                let code = try AppChannel.parseOtp(a.body)
                finish(.otp(code), "Code in \(ms) ms (\(code.count) digits)")
            } catch AppChannel.BodyFailure.status(let s) {
                finish(.failed(KeyLink.otpMessage(s)), String(format: "No code (status 0x%02X)", s))
            } catch {
                finish(.failed(KeyLink.unreadable), "Code answer unreadable")
            }
        case (.list, AppChannel.rList):
            do {
                let page = try AppChannel.parseList(a.body)
                listGot += page.entries
                add("List: \(listGot.count) of \(page.total)")
                if page.more, !page.entries.isEmpty, listGot.count < 2000 {
                    listStart += page.entries.count
                    sendReq(AppChannel.cList, AppChannel.listBody(start: listStart, health: true))
                } else {
                    finish(.list(listGot), "List in \(ms) ms: \(listGot.count) entries")
                }
            } catch AppChannel.BodyFailure.status(let s) {
                finish(.failed(KeyLink.listMessage(s)), String(format: "No list (status 0x%02X)", s))
            } catch {
                finish(.failed(KeyLink.unreadable), "List answer unreadable")
            }
        default:
            add(String(format: "Ignored a 0x%02X answer", a.rsp))
        }
    }

    /// 0xBF with a MAC: replay (resend above the KEY's floor) or a refusal.
    private func refused(_ body: Data) {
        let b = [UInt8](body)
        if b.count >= 5, b[0] == 0x09 {
            let floor = UInt32(b[1]) | UInt32(b[2]) << 8 | UInt32(b[3]) << 16 | UInt32(b[4]) << 24
            Credentials.raiseCounter(above: floor)
            replays += 1
            guard replays <= 2 else { finish(.failed(KeyLink.unreadable), "Counter refused twice"); return }
            add("Counter behind the KEY's (\(floor)): sending again")
            sendReq(lastCmd, lastBody)
            return
        }
        let st = b.first ?? 0xFF
        if stage == .time { add(String(format: "The KEY didn't take the time (0x%02X); carrying on", st)); startOp(); return }
        finish(.failed(AppChannel.statusText(st)), String(format: "KEY refused (status 0x%02X)", st))
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
        if KeyLink.keyForgotPhone(error) { finish(.failed(KeyLink.forgetOnPhone), "The KEY no longer has this iPhone's pairing (peer removed pairing information)"); return }
        finish(.failed("Couldn't connect to your KEY. Try again."), "Could not connect: \(error?.localizedDescription ?? "unknown")")
    }

    func centralManager(_ c: CBCentralManager, didDisconnectPeripheral p: CBPeripheral, error: Error?) {
        guard p.identifier == peripheral?.identifier else { return }   // an old identity we let go
        if error != nil { KeyLife.forget("the KEY dropped a link") }
        if busy, KeyLink.keyForgotPhone(error) { finish(.failed(KeyLink.forgetOnPhone), "The KEY no longer has this iPhone's pairing (peer removed pairing information)"); return }
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
        p.discoverCharacteristics(nil, for: s)
    }

    func peripheral(_ p: CBPeripheral, didDiscoverCharacteristicsFor s: CBService, error: Error?) {
        let cs = s.characteristics ?? []
        func find(_ u: CBUUID) -> CBCharacteristic? { cs.first { $0.uuid == u } }
        chanIn = find(KeyLink.chanInChar)
        chanOut = find(KeyLink.chanOutChar)
        let hasChan = chanIn != nil && chanOut != nil
        creds = Credentials.load()

        // The app channel: paired, or pairing now.
        if hasChan, let out = chanOut, creds != nil, mode != .pairApp {
            add("App channel: subscribing")
            p.setNotifyValue(true, for: out)
            return
        }
        switch mode {
        case .pairApp:
            guard hasChan, let pr = find(KeyLink.probeChar) else { finish(.failed(KeyLink.oldFirmware), "App channel missing"); return }
            add("Checking this iPhone is paired with the KEY")
            p.readValue(for: pr)   // bonds first if needed (iOS prompt)
        case .otp, .list:
            finish(.failed(hasChan ? KeyLink.needsChannel : KeyLink.oldFirmware), hasChan ? "App not paired" : "App channel missing")
        case .probe:
            guard let ch = find(KeyLink.probeChar) else {
                finish(.failed("The KEY's probe is missing."), "Probe characteristic missing"); return
            }
            add("Reading (encrypted; pairs this iPhone if PAIR A PHONE is open on the KEY)")
            p.readValue(for: ch)
        case .fill:
            guard let rq = find(KeyLink.reqChar), let an = find(KeyLink.answerChar) else {
                finish(.failed("Your KEY needs firmware 9c or later for passwords. If it has it, restart the KEY."), "Sign-in answer characteristic missing"); return
            }
            reqCh = rq
            add("Subscribing to the answer")
            p.setNotifyValue(true, for: an)   // the answer only goes to a subscribed link
        case .ctap:
            guard let cp = find(KeyLink.fidoCP), let st = find(KeyLink.fidoStatus), let len = find(KeyLink.fidoCPLen) else {
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
        if ch.uuid == KeyLink.chanOutChar { chanReady(); return }
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
                finish(.failed(KeyLink.unreadable), "Reply of the wrong kind for this request")
            }
        } catch {
            finish(.failed(KeyLink.unreadable), "Bad reply: \(error)")
        }
    }

    func peripheral(_ p: CBPeripheral, didUpdateValueFor ch: CBCharacteristic, error: Error?) {
        if ch.uuid == KeyLink.chanOutChar {
            if let d = ch.value, error == nil { chanNotified(d) }
            return
        }
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
        if mode == .pairApp, let out = chanOut {
            add("This iPhone is paired; opening the app channel")
            p.setNotifyValue(true, for: out)
            return
        }
        let text = ch.value.flatMap { String(data: $0, encoding: .utf8) } ?? "(no data)"
        let hint = chanIn != nil && creds == nil ? " The app isn't paired yet: tap PAIR THE APP." : ""
        finish(.ok(text + hint), "OK in \(ms) ms: \(text)")
    }

    func peripheral(_ p: CBPeripheral, didWriteValueFor ch: CBCharacteristic, error: Error?) {
        if ch.uuid == KeyLink.chanInChar {
            chanWritten(p, ch, error)
            return
        }
        if let e = error as NSError? {
            if mode == .fill, KeyLink.needsPairing(e), let body = KeyLink.fillBody(site: site, appName: siteIsAppName, user: fillUser) {
                awaitPairing { p.writeValue(body, for: ch, type: .withResponse) }; return
            }
            let code = e.domain == CBATTErrorDomain ? e.code : -1
            // A KEY before 9d refuses FILL with a username as a bad request (0x87):
            // ask again without it, and the KEY shows the site's matches as before.
            if mode == .fill, code == 0x87, !fillUser.isEmpty {
                add("This KEY doesn't take a username yet (firmware before 9d): asking for the site's logins instead")
                fillUser = ""
                if let body = KeyLink.fillBody(site: site, appName: siteIsAppName) { p.writeValue(body, for: ch, type: .withResponse); return }
            }
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
        default: break
        }
    }

    private func chanWritten(_ p: CBPeripheral, _ ch: CBCharacteristic, _ error: Error?) {
        guard busy, stage != .idle else { return }   // e.g. a CANCEL on the way out
        if let e = error as NSError? {
            if KeyLink.needsPairing(e) {
                let again = chanWriting
                awaitPairing { p.writeValue(again, for: ch, type: .withResponse) }; return
            }
            let code = e.domain == CBATTErrorDomain ? e.code : -1
            if code == 0x86 { finish(.failed(AppChannel.statusText(0x06)), "App channel busy (ATT 0x86)"); return }
            finish(.failed("The KEY refused the request."), "App channel write refused: \(e.localizedDescription) (\(code))")
            return
        }
        paired()
        writeNextChan(p)
    }
}


// MARK: - Which life the KEY is in (issue #37, 17 Nov 2026)

/// The KEY's life from the first HELLO on a connection, whichever part of the
/// app sent it (NostrLink, KeyLink, KeySession): 1 VAULT locked, 2 VAULT
/// ready, 3 NOSTR Bluetooth, 4 other. A life is fixed for a power-on and a
/// restart always drops the link, so the answer holds until the KEY drops a
/// link (or its pair id changes). Main thread.
final class KeyLife: ObservableObject {
    static let shared = KeyLife()
    @Published private(set) var life: UInt8?
    /// The app's Bluetooth log (LinkLog), set by the app.
    static var log: ((String) -> Void)?

    var isVault: Bool { life == 1 || life == 2 }
    var isNostr: Bool { life == 3 }

    static func name(_ l: UInt8?) -> String {
        switch l {
        case 1: return "VAULT mode (locked)"
        case 2: return "VAULT mode"
        case 3: return "NOSTR Bluetooth mode"
        case 4: return "another mode"
        default: return "not known yet"
        }
    }

    /// A HELLO answer's body ([status][life]...). Any thread.
    static func heard(helloBody b: Data, from who: String) {
        guard b.count >= 2 else { return }
        let l = b[b.startIndex + 1]
        DispatchQueue.main.async {
            let me = KeyLife.shared
            if me.life != l { log?("life: \(name(me.life)) -> \(name(l)) (HELLO on the \(who) link)") }
            me.life = l
        }
    }

    /// The KEY dropped a link (it may have restarted into another life), or
    /// its pair id changed. Any thread.
    static func forget(_ why: String) {
        DispatchQueue.main.async {
            let me = KeyLife.shared
            guard me.life != nil else { return }
            log?("life: \(name(me.life)) -> not known (\(why))")
            me.life = nil
        }
    }
}
