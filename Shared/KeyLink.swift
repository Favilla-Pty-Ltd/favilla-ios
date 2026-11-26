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
    #if targetEnvironment(simulator)
    /// Sample sheets only (App/DemoGallery.swift): show the wait on the KEY.
    func demoWaiting() { waitingOnKey = true }
    #endif
    /// iOS is pairing with the KEY (6-digit comparison): the link is kept open.
    @Published private(set) var pairing = false
    /// A paired iPhone's link is not encrypted yet (issue #80): "Connecting
    /// securely", not the pairing card. iOS encrypts with the stored keys by itself.
    @Published private(set) var securing = false
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
    static var appPaired: Bool { Demo.mode != nil || Credentials.isPaired }

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

    /// Forget this install's pairing with the KEY's app channel: everything
    /// kept for the KEY, the same as when the KEY says it was set up again
    /// (the channel key, the counter, the KEY to stay with, its pair id).
    /// Issue #83: this used to leave the old pair id, and the next pairing was
    /// cleared by its own first HELLO.
    func forgetApp() {
        PairIdentity.resetAll(why: "Forget the app's pairing")
        maybeReset = false
        objectWillChange.send()
    }

    /// The owner says the KEY was reset or restored: forget the old pairing and
    /// pair, in one go (issue #83). The owner's tap is the proof; the app never
    /// does this by itself.
    func pairAgain() {
        forgetApp()
        pairApp()
    }

    /// A request failed while this iPhone's KEY stayed silent and another
    /// Favilla KEY was in range that this iPhone couldn't use: the owner's own
    /// KEY after a reset or restore looks exactly like that (a new address, no
    /// pairing), and so does a stranger's. Only the owner can tell: the cards
    /// offer PAIR AGAIN.
    @Published private(set) var maybeReset = false
    private var sawUnusable = false
    /// After a pairing that replaced an older one: iOS keeps the old entry.
    @Published private(set) var oldEntryHint = false
    private static let everPairedKey = "keyEverPairedId"

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
        // Issue #83: a tap on pair must never do nothing. Whatever is running
        // (a probe waiting on a KEY that has gone) stops for it.
        if busy, m == .pairApp { finish(.cancelled, "Stopped: pairing starts") }
        guard !busy else { return }
        mode = m
        busy = true
        NotificationCenter.default.post(name: KeyLink.didStart, object: self)
        result = nil
        outcome = nil
        lines = []
        waitingOnKey = false
        pairing = false
        securing = false; secured = false; secureSince = nil; relinks = 0; linkGen += 1
        rejected = []; toldOther = false; pendingMine = nil
        sawUnusable = false
        if m == .pairApp { maybeReset = false; oldEntryHint = false; add("Pairing: starting Bluetooth, searching for a KEY by its service") }
        appCode = nil
        resetLinkState()
        started = Date()
        // Issue #63: a KEY that forgot its phones comes back under a new address
        // (11dp), so the identity remembered from before points at nothing. A
        // pairing starts by finding the KEY afresh, by its service.
        if m == .pairApp { afterPair = 0 }      // a pairing run looks for any KEY (bonded is false)
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
        // Issue #81: a paired iPhone stays with the KEY that has proved it holds
        // the pairing (KeyTrust). Another KEY nearby is not taken in its place.
        // 1. A KEY the system is already connected to: this iPhone's own first.
        let linked = c.retrieveConnectedPeripherals(withServices: [KeyLink.favService, KeyLink.hidService])
            .filter { ($0.name ?? "").hasPrefix(KeyLink.keyName) }
        if let p = linked.first(where: { verdict($0.identifier) == .mine }) ?? linked.first(where: { verdict($0.identifier) == .tryIt }) {
            add("KEY already connected to the phone")
            connect(p, c)
            return
        }
        // 2. This iPhone's KEY (or, before one has proved itself, the one used
        //    last): a pending connect waits for it to advertise.
        //    Never in a pairing run (issue #83): after a KEY reset the old
        //    identifier points at an address the KEY has left, and a connect
        //    to it never completes.
        if mode != .pairApp, let id = bonded ? (KeyTrust.id ?? KeyTrust.guess) : KeyTrust.guess, !rejected.contains(id),
           let p = c.retrievePeripherals(withIdentifiers: [id]).first {
            add(KeyTrust.id == id && bonded ? "Paired KEY: connecting" : "Known KEY: connecting, and searching")
            connect(p, c)
        } else {
            add("Looking for the KEY")
        }
        // 3. Search: the Favilla service ("App only", always advertised) or the
        //    keyboard service ("App and keyboard", 15 s after a press). With a
        //    paired KEY the search only matters once it has been silent for
        //    KeyTrust.wait; a KEY is reported once per search, so search anew then.
        c.scanForPeripherals(withServices: [KeyLink.favService, KeyLink.hidService], options: nil)
        let left = bonded ? KeyTrust.wait - KeyTrust.silentFor() : 0
        if bonded, KeyTrust.id != nil, left > 0 {
            let gen = linkGen
            DispatchQueue.main.asyncAfter(deadline: .now() + left + 0.2) { [weak self] in
                guard let self, self.busy, self.linkGen == gen, self.peripheral?.state != .connected, let c = self.central else { return }
                c.stopScan()
                c.scanForPeripherals(withServices: [KeyLink.favService, KeyLink.hidService], options: nil)
            }
        }
    }

    // MARK: - Whose KEY (issue #81)

    private var rejected: Set<UUID> = []      // KEYs let go in this request: not this iPhone's
    private var toldOther = false
    private var pendingMine: CBPeripheral?    // the paired KEY's connect, still waiting while another is tried

    private func verdict(_ id: UUID) -> KeyTrust.Verdict {
        KeyTrust.verdict(candidate: id, trusted: KeyTrust.id, paired: bonded, waited: bonded ? KeyTrust.silentFor() : 0, rejected: rejected)
    }

    /// The connected KEY is the one that has proved itself before.
    private var isMine: Bool { peripheral != nil && peripheral?.identifier == KeyTrust.id }

    /// An answer passed the MAC: this is this iPhone's KEY, whatever it was before.
    private func proved() {
        linkSecure()
        guard let p = peripheral else { return }
        if KeyTrust.trust(p.identifier) { add("This KEY holds this iPhone's pairing: it is the one to stay with") }
        if let m = pendingMine { pendingMine = nil; central?.cancelPeripheralConnection(m) }
    }

    /// Not this iPhone's KEY: let it go for the rest of this request, save
    /// nothing about it, and go back to waiting for the paired one.
    private func reject(_ why: String) {
        guard busy, let p = peripheral else { return }
        sawUnusable = true
        if mode != .pairApp, Credentials.isPaired { maybeReset = true }
        rejected.insert(p.identifier)
        add("Not this iPhone's KEY (\(why)): let go" + (KeyTrust.id != nil ? ", waiting for the paired one" : ", looking again"))
        peripheral = nil
        central?.stopScan()
        central?.cancelPeripheralConnection(p)
        if let m = pendingMine { pendingMine = nil; central?.cancelPeripheralConnection(m) }
        resetLinkState()
        secured = false; secureSince = nil; securing = false; waitingOnKey = false
        linkGen += 1
        let gen = linkGen
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) { [weak self] in
            guard let self, self.busy, self.linkGen == gen, self.peripheral == nil, let c = self.central else { return }
            self.go(c)
        }
    }

    /// A link that is not secure, dropped or refused: this iPhone's KEY is tried
    /// again (issue #80); any other KEY is let go (issue #81).
    private func retryOrReject(_ why: String) {
        if isMine { relink(why) } else { reject(why) }
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

    /// Where the app also keeps these lines (its Bluetooth log). Until 27 Nov
    /// the steps of a pairing or FIND MY KEY in the app were shown nowhere.
    static var logSink: ((String) -> Void)?

    private func add(_ s: String) {
        let ms = Int(Date().timeIntervalSince(started) * 1000)
        lines.append(String(format: "%5d ms  %@", ms, s))
        KeyLink.logSink?(s)
    }

    private var ms: Int { Int(Date().timeIntervalSince(started) * 1000) }

    private var afterPair = 0     // link checks left to try after a pairing

    private func probeAfterPairing(_ delay: Double) {
        DispatchQueue.main.asyncAfter(deadline: .now() + delay) { [weak self] in
            guard let self, self.afterPair > 0, !self.busy, KeyLink.appPaired else { return }
            self.afterPair -= 1
            self.probe()
        }
    }

    private func finish(_ o: Outcome, _ log: String) {
        guard busy else { return }
        // Issue #83: the paired KEY never answered and another KEY was there.
        if mode != .pairApp {
            if case .failed = o {
                if sawUnusable, !secured, Credentials.isPaired {
                    maybeReset = true
                    add("The paired KEY stayed silent and another KEY was in range: if yours was reset or restored, PAIR AGAIN")
                }
            } else if o != .cancelled {
                maybeReset = false
            }
        }
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
        securing = false
        appCode = nil
        busy = false
        NotificationCenter.default.post(name: KeyLink.didFinish, object: self)
        // The link check after a pairing: again in 3 s if the KEY wasn't there yet.
        if mode == .probe, afterPair > 0 {
            if case .failed = o { probeAfterPairing(3) } else { afterPair = 0 }
        }
    }

    // MARK: - Pairing on demand
    //
    // A KEY the phone isn't bonded with refuses encrypted reads, writes and
    // subscriptions with "insufficient authentication" (ATT 0x05) or
    // "insufficient encryption" (0x0F), and iOS starts pairing. Bench 6 Nov
    // 2026: giving up on that refusal dropped the link and killed iOS's prompt
    // after a fraction of a second. So keep the link and retry while the owner
    // compares the code and presses ENTER on the KEY (PAIR A PHONE open).

    /// iOS's error for a dropped or failed link, for the log: domain and code
    /// (issue #80, to line up with the KEY's own disconnect reasons).
    static func code(_ e: Error?) -> String {
        guard let n = e as NSError? else { return "no error given" }
        return "\(n.domain) \(n.code)"
    }

    static func needsPairing(_ e: Error) -> Bool {
        let n = e as NSError
        return n.domain == CBATTErrorDomain && (n.code == CBATTError.insufficientAuthentication.rawValue ||
                                                n.code == CBATTError.insufficientEncryption.rawValue)
    }

    // Issue #80 (KEY 11fh): on an iPhone that has paired before, that same
    // refusal only means the link is not encrypted YET. The bench showed links
    // that were gone before encryption finished, with the bond intact and the
    // next connect fine. So a paired iPhone waits about 3 s for the link to
    // become secure, then drops it and connects again, up to 2 more times.

    static let notSecure = "Couldn't make a secure link to your KEY. Try again. If it keeps happening, the KEY may have forgotten this iPhone: pair again in Favilla, Settings."

    /// This iPhone holds app-channel credentials: it has paired with a KEY before.
    private var bonded: Bool { mode != .pairApp && Credentials.isPaired }
    private var secured = false          // an encrypted read, write or subscription has worked on this link
    private var secureSince: Date?       // when "not secure yet" was first seen on this link
    private var relinks = 0              // reconnects made for this request, up to 2
    private var linkGen = 0              // one per link, so a late timer leaves a newer link alone

    /// Drop the link and connect again (the second try nearly always works).
    private func relink(_ why: String) {
        guard busy else { return }
        guard relinks < 2 else { finish(.failed(KeyLink.notSecure), "\(why). Gave up after 3 tries"); return }
        relinks += 1
        add("\(why): connecting again (try \(relinks + 1) of 3)")
        let old = peripheral
        peripheral = nil            // its disconnect is ours, not the KEY's
        central?.stopScan()
        if let old { central?.cancelPeripheralConnection(old) }
        resetLinkState()
        secured = false; secureSince = nil; securing = true; waitingOnKey = false
        linkGen += 1
        let gen = linkGen
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.4) { [weak self] in
            guard let self, self.busy, self.linkGen == gen, self.peripheral == nil, let c = self.central else { return }
            self.go(c)
        }
    }

    private func awaitPairing(_ retry: @escaping () -> Void) {
        if bonded, !pairing {
            if secureSince == nil {
                secureSince = Date()
                securing = true
                add("The link isn't secure yet (this iPhone is paired): waiting for encryption")
                let gen = linkGen
                DispatchQueue.main.asyncAfter(deadline: .now() + 3) { [weak self] in
                    guard let self, self.busy, self.linkGen == gen, !self.secured, self.secureSince != nil else { return }
                    self.retryOrReject("Not secure after 3 s")
                }
            }
            let gen = linkGen
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { [weak self] in
                guard let self, self.busy, self.linkGen == gen, !self.secured, self.peripheral != nil else { return }
                retry()
            }
            return
        }
        if !pairing {
            pairing = true
            add("Not paired yet: iOS is asking to pair. Compare the code with the KEY's screen, tap Pair, then press ENTER on the KEY.")
            // Issue #83: the KEY's PAIR A PHONE window is 90 s. The app must
            // not hang up on a confirmation the KEY would still take, so it
            // waits a little longer than the KEY and lets the KEY end it.
            armTimeout(100, KeyLink.notConfirmed)
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 2) { [weak self] in
            guard let self, self.busy, self.pairing, self.peripheral != nil else { return }
            retry()
        }
    }

    /// Issue #81: only real encrypted traffic counts. The KEY accepts the
    /// subscription before the link is encrypted, so a subscribe that worked
    /// proves nothing; a write the KEY took, or an answer that passed the MAC, does.
    private func linkSecure() {
        guard !secured else { return }
        secured = true
        if securing { securing = false; add("Link secure" + (relinks > 0 ? " on try \(relinks + 1)" : "")) }
        secureSince = nil
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
    /// iOS says the KEY has dropped this iPhone's Bluetooth bond (CBError 14).
    /// The app's own pairing is useless with it: say what to do on the KEY and
    /// put the pairing button on the card. Nothing is cleared until it is tapped.
    private func keyForgot() {
        let wasPairing = mode == .pairApp
        finish(.failed(KeyLink.forgetOnPhone), "The KEY no longer has this iPhone's pairing (peer removed pairing information, CBError 14)")
        if !wasPairing, Credentials.isPaired { maybeReset = true }
    }

    static func keyForgotPhone(_ e: Error?) -> Bool {
        guard let n = e as NSError? else { return false }
        return n.domain == CBErrorDomain && n.code == CBError.peerRemovedPairingInformation.rawValue
    }
    // Issue #83 (27 Nov): Forget all phones gives the KEY a new Bluetooth
    // address, so the iPhone's stale entry for the old one stops mattering.
    // The old text sent the owner through iPhone Settings first.
    static let forgetOnPhone = "Your KEY no longer has this iPhone's pairing. On the KEY: Settings > Forget all phones, then PAIR A PHONE. Then tap PAIR here."
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
                add("Reading the list (the KEY no longer asks first, 11cg)")
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
            PairIdentity.forgetId()         // the id on record is the old pairing's (issue #83)
            if let p = peripheral {
                KeyTrust.trust(p.identifier)   // the KEY just paired with is this iPhone's
                let was = store.string(forKey: KeyLink.everPairedKey)
                oldEntryHint = was != nil && was != p.identifier.uuidString
                store.set(p.identifier.uuidString, forKey: KeyLink.everPairedKey)
            }
            maybeReset = false
            PairIdentity.pairedAgain()      // the Nostr client enrols afresh with this KEY (issue #22)
            finish(.appPaired, "The app is paired with the KEY in \(ms) ms")
            // Issue #63: bring the link up now (one HELLO says which mode the
            // KEY is in), not at the next launch. Twice more if the KEY is still
            // settling after the pairing.
            afterPair = 3
            probeAfterPairing(1.2)
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
                // Issue #81: that refusal carries no MAC, so ANY device can send
                // it. It is believed only from the KEY that has proved itself
                // before. From another KEY it means "not mine": nothing is cleared.
                guard isMine else {
                    if KeyTrust.id != nil { reject(String(format: "it doesn't know this iPhone, 0x%02X", st)); return }
                    sawUnusable = true
                    finish(.failed(AppChannel.statusText(st)), String(format: "A KEY that hasn't proved itself said not paired (0x%02X): nothing was cleared", st)); return
                }
                PairIdentity.resetAll(why: String(format: "refused 0x%02X", st))
                finish(.failed(AppChannel.statusText(st)), String(format: "KEY: not paired (0x%02X; forgot the stored pairing)", st)); return
            }
            if stage == .time { add(String(format: "The KEY didn't take the time (0x%02X); carrying on", st)); startOp(); return }
            finish(.failed(AppChannel.statusText(st)), String(format: "KEY refused (status 0x%02X)", st)); return
        } catch {
            if !isMine, bonded, KeyTrust.id != nil { reject("its answer failed the check") ; return }
            finish(.failed(KeyLink.unreadable), "Answer failed its check: \(error)"); return
        }
        proved()        // only this iPhone's KEY holds the key that MAC needs
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
        switch verdict(p.identifier) {
        case .never:
            return
        case .wait:
            // Issue #81: another KEY (a second one in the house, a neighbour's).
            // The pending connect to this iPhone's own KEY stays.
            if !toldOther {
                toldOther = true
                add("Another KEY is nearby (\(name.isEmpty ? "no name" : name)): staying with the paired one")
                // Issue #83: if the paired KEY is still silent in a few seconds,
                // say what that may mean and offer PAIR AGAIN, without waiting
                // for the request to fail. Nothing is cleared unless the owner taps.
                let gen = linkGen
                DispatchQueue.main.asyncAfter(deadline: .now() + 4) { [weak self] in
                    guard let self, self.busy, self.linkGen == gen, self.mode != .pairApp, !self.secured, self.peripheral?.state != .connected else { return }
                    self.sawUnusable = true
                    if !self.maybeReset { self.maybeReset = true; self.add("The paired KEY is silent and another KEY is in range: if yours was reset or restored, PAIR AGAIN") }
                }
            }
            return
        case .mine:
            c.stopScan()
            if let old = peripheral {
                if old.identifier == p.identifier { add("Found it advertising"); return }   // the pending connect completes
                c.cancelPeripheralConnection(old)     // another KEY was being tried: the paired one is here
                resetLinkState()
                secured = false; secureSince = nil; securing = false; linkGen += 1
            }
            pendingMine = nil
            add("Found the paired KEY (RSSI \(rssi))")
            connect(p, c)
        case .tryIt:
            if let old = peripheral {
                if old.identifier == p.identifier { add("Found it advertising"); c.stopScan(); return }
                if old.state == .connected || pendingMine != nil { return }        // one at a time
                if bonded, KeyTrust.id == old.identifier {
                    add("The paired KEY has been silent for \(Int(KeyTrust.wait)) s: trying \(name.isEmpty ? "another KEY" : name), to be checked before it is used")
                    pendingMine = old                 // its connect stays pending
                } else {
                    add("Found the KEY under a new identity")
                    c.cancelPeripheralConnection(old)
                }
            } else {
                add("Found \(name.isEmpty ? "the KEY" : name) (RSSI \(rssi))")
            }
            c.stopScan()
            connect(p, c)
        }
    }

    func centralManager(_ c: CBCentralManager, didConnect p: CBPeripheral) {
        // The paired KEY turned up while another was being tried: take it.
        if let m = pendingMine, m.identifier == p.identifier {
            if let trial = peripheral, trial.identifier != p.identifier { c.cancelPeripheralConnection(trial) }
            pendingMine = nil
            resetLinkState()
            secured = false; secureSince = nil; securing = false
            linkGen += 1
            peripheral = p
            p.delegate = self
            add("The paired KEY answered after all")
        }
        guard p.identifier == peripheral?.identifier else { return }
        c.stopScan()
        if isMine { KeyTrust.heard() }
        add("Connected")
        // Nothing is saved here (issue #81): a KEY is remembered only once an
        // answer from it has passed the MAC (proved()).
        p.discoverServices([KeyLink.favService])
    }

    func centralManager(_ c: CBCentralManager, didFailToConnect p: CBPeripheral, error: Error?) {
        guard p.identifier == peripheral?.identifier else { return }
        if KeyLink.keyForgotPhone(error) { keyForgot(); return }
        if busy, bonded { retryOrReject("Could not connect, \(KeyLink.code(error))"); return }
        finish(.failed("Couldn't connect to your KEY. Try again."), "Could not connect, \(KeyLink.code(error)): \(error?.localizedDescription ?? "unknown")")
    }

    func centralManager(_ c: CBCentralManager, didDisconnectPeripheral p: CBPeripheral, error: Error?) {
        guard p.identifier == peripheral?.identifier else { return }   // an old identity we let go
        if error != nil { KeyLife.forget("the KEY dropped a link") }
        if busy, KeyLink.keyForgotPhone(error) { keyForgot(); return }
        // Issue #80: a paired iPhone's link that went before it was secure is tried again.
        if busy, bonded, !secured { retryOrReject("The link dropped before it was secure, \(KeyLink.code(error))"); return }
        if busy { finish(.failed("Your KEY dropped the link. Try again."), "The KEY dropped the link, \(KeyLink.code(error)): \(error?.localizedDescription ?? "no reason given")") }
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
        linkSecure()
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
        linkSecure()
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
    /// The last life heard on any connection, kept across launches, so the app
    /// opens in the right shape with the KEY off (the UI topology, 17 Nov).
    @Published private(set) var lastSeen: UInt8?
    private(set) var lastSeenAt: Date?
    /// The app's Bluetooth log (LinkLog), set by the app.
    static var log: ((String) -> Void)?

    private static let lastKey = "keyLifeLast", lastAtKey = "keyLifeLastAt"
    private init() {
        let d = UserDefaults.standard
        if let v = d.object(forKey: KeyLife.lastKey) as? Int, (1...4).contains(v) { lastSeen = UInt8(v) }
        lastSeenAt = d.object(forKey: KeyLife.lastAtKey) as? Date
    }

    /// The life to shape the app by: this connection's, else the last seen.
    var shape: UInt8? { life ?? lastSeen }

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
            me.set(l)
        }
    }

    /// A life worked out from an answer rather than HELLO: LIST answered means
    /// a VAULT life; a VAULT command refused 0x04 means not VAULT. Any thread.
    static func inferred(_ l: UInt8, from why: String) {
        DispatchQueue.main.async {
            let me = KeyLife.shared
            if me.life == l { return }
            log?("life: \(name(me.life)) -> \(name(l)) (\(why))")
            me.set(l)
        }
    }

    private func set(_ l: UInt8) {
        life = l
        lastSeen = l; lastSeenAt = Date()
        UserDefaults.standard.set(Int(l), forKey: KeyLife.lastKey)
        UserDefaults.standard.set(Date(), forKey: KeyLife.lastAtKey)
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


// MARK: - Screenshot demo (simulator only)

/// CI takes screenshots of each shape in the simulator: launched with
/// `-FavillaDemo nostr|vault|unknown|settings-nostr|settings-vault`, the app
/// shows that shape with sample accounts and talks to no KEY. Compiled out of
/// device builds.
enum Demo {
    static var mode: String? {
        #if targetEnvironment(simulator)
        let a = ProcessInfo.processInfo.arguments
        if let i = a.firstIndex(of: "-FavillaDemo"), i + 1 < a.count { return a[i + 1] }
        #endif
        return nil
    }
    static var life: UInt8? {
        guard let m = mode else { return nil }
        if m.hasPrefix("to-nostr") { return 2 }      // the hand-over page: KEY in the other mode
        if m.hasPrefix("to-vault") { return 3 }
        return m.contains("vault") ? 2 : m.contains("nostr") ? 3 : nil
    }
    /// The door a sample run opens on: "home-…" and "unknown" stay on the home page.
    static var doorName: String? {
        guard let m = mode, !m.hasPrefix("home"), m != "unknown" else { return nil }
        return m.contains("nostr") ? "nostr" : m.contains("vault") ? "vault" : nil
    }
    static var settings: Bool { mode?.hasPrefix("settings") == true }

    private static func entry(_ n: UInt8, _ site: String, _ user: String, _ raw: UInt8) -> AppChannel.ListEntry {
        AppChannel.ListEntry(passkey: false, site: site, user: user, credentialID: nil, userHandle: nil,
                             health: AppChannel.Health(raw: raw), id: Data(repeating: n, count: 8))
    }
    static let accounts: [AppChannel.ListEntry] = [
        entry(1, "example-bank.com", "you@example.com", 0x62),
        entry(2, "mail.example.com", "you@example.com", 0x52),
        entry(3, "shop.example.net", "you", 0x41),
        entry(4, "code.example.org", "you", 0xC3),
        entry(5, "news.example.com", "reader", 0x4F),
        entry(6, "cloud.example.io", "you@example.com", 0x03),
    ]
}
