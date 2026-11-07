// AppChannel.swift - the app channel to the KEY (firmware 9g to 9j).
// Built against favilla-key-firmware docs/BLE_PASSKEY_PROTOCOL.md, "The app channel".
//
// Ruled 7 Nov 2026: the Bluetooth link is locked to the Favilla app. On an
// iPhone the bond belongs to the phone, so any app could otherwise send a FILL
// or CTAP request and read the answer. Once this install is paired with the
// KEY, every request carries a counter and a MAC, and answers that hold secrets
// come back encrypted. The KEY then refuses the raw paths (ATT 0x8F).
//
// Wire: messages in 64-byte reports on 8F1A0005 (write) / 8F1A0006 (notify).
// Little-endian counter and report length; H(k, x) = HMAC-SHA256.
// No Bluetooth here, so it can be tested on its own (Tests/main.swift).

import CryptoKit
import Foundation
import Security

enum AppChannel {
    // Reports
    static let fStart: UInt8 = 0x10
    static let fCont: UInt8 = 0x11
    static let msgMax = 1088

    // Requests
    static let pairCommit: UInt8 = 0x20
    static let pairReveal: UInt8 = 0x22
    static let cHello: UInt8 = 0x30
    static let cFill: UInt8 = 0x34
    static let cCtap: UInt8 = 0x35
    static let cCancel: UInt8 = 0x36
    static let cList: UInt8 = 0x37
    static let cOtp: UInt8 = 0x38
    static let cTime: UInt8 = 0x39

    // Answers
    static let rPairKey: UInt8 = 0xA0
    static let rPairDone: UInt8 = 0xA1
    static let rHello: UInt8 = 0xB0
    static let rAck: UInt8 = 0xB1
    static let rLogin: UInt8 = 0xB3
    static let rCtap: UInt8 = 0xB4
    static let rKeepalive: UInt8 = 0xB5
    static let rList: UInt8 = 0xB6
    static let rOtp: UInt8 = 0xB7
    static let rErr: UInt8 = 0xBF

    /// Answers whose body is encrypted.
    static let encrypted: Set<UInt8> = [rLogin, rCtap, rList, rOtp]

    // MARK: - Reports

    /// One message as 64-byte reports: [0x10][len lo][len hi][61] then [0x11][i][62], zero padded.
    static func reports(_ msg: Data) -> [Data] {
        let m = [UInt8](msg)
        precondition(!m.isEmpty && m.count <= msgMax, "message size")
        var out: [Data] = []
        var r = [UInt8](repeating: 0, count: 64)
        r[0] = fStart; r[1] = UInt8(m.count & 0xFF); r[2] = UInt8(m.count >> 8)
        let n = min(61, m.count)
        r.replaceSubrange(3..<3 + n, with: m[0..<n])
        out.append(Data(r))
        var off = n, i: UInt8 = 1
        while off < m.count {
            var c = [UInt8](repeating: 0, count: 64)
            c[0] = fCont; c[1] = i
            let k = min(62, m.count - off)
            c.replaceSubrange(2..<2 + k, with: m[off..<off + k])
            out.append(Data(c))
            off += k; i &+= 1
        }
        return out
    }

    /// Put whole reports together into writes of up to `perWrite` reports each.
    static func writes(_ msg: Data, perWrite: Int) -> [Data] {
        let rs = reports(msg), k = max(1, perWrite)
        return stride(from: 0, to: rs.count, by: k).map { rs[$0..<min($0 + k, rs.count)].reduce(Data(), +) }
    }

    /// Reassembles reports (a notification may carry several) into whole messages.
    struct Reassembler {
        private var want = 0
        private var buf: [UInt8] = []
        private var next: UInt8 = 0

        enum Failure: Error, Equatable { case order, length }

        /// Feed one notification value; returns the messages it completes.
        mutating func feed(_ value: Data) throws -> [Data] {
            var done: [Data] = []
            let v = [UInt8](value)
            var off = 0
            while off < v.count {
                let r = Array(v[off..<min(off + 64, v.count)])
                off += 64
                guard let h = r.first else { continue }
                if h == AppChannel.fStart {
                    guard r.count >= 3 else { throw Failure.length }
                    let len = Int(r[1]) | Int(r[2]) << 8
                    guard len > 0, len <= AppChannel.msgMax else { reset(); throw Failure.length }
                    want = len; buf = Array(r[3...].prefix(min(61, len))); next = 1
                } else if h == AppChannel.fCont {
                    guard want > 0, r.count >= 2, r[1] == next else { reset(); throw Failure.order }
                    buf.append(contentsOf: r[2...].prefix(want - buf.count)); next &+= 1
                } else {
                    continue
                }
                if want > 0, buf.count >= want { done.append(Data(buf)); reset() }
            }
            return done
        }

        mutating func reset() { want = 0; buf = []; next = 0 }
    }

    // MARK: - MACs and the keystream

    static func h(_ key: Data, _ msg: Data) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: msg, using: SymmetricKey(data: key)))
    }

    static func le32(_ v: UInt32) -> Data { Data([UInt8(v & 0xFF), UInt8((v >> 8) & 0xFF), UInt8((v >> 16) & 0xFF), UInt8(v >> 24)]) }
    static func be64(_ v: UInt64) -> Data { Data((0..<8).map { UInt8((v >> (56 - 8 * UInt64($0))) & 0xFF) }) }

    /// [cmd][clientId 8][ctr 4 LE][body][mac16], mac16 = H(K, "REQ" || everything before it)[0..15].
    static func request(_ cmd: UInt8, _ creds: Credentials, ctr: UInt32, body: Data = Data()) -> Data {
        var m = Data([cmd]); m.append(creds.clientId); m.append(le32(ctr)); m.append(body)
        m.append(h(creds.key, Data("REQ".utf8) + m).prefix(16))
        return m
    }

    /// XOR with the keystream: Ke = H(K, "FAVILLA-CHAN-ENC-1"),
    /// block i = H(Ke, rsp || clientId || ctr || i). The same call decrypts.
    static func keystream(_ body: Data, rsp: UInt8, ctr: UInt32, _ creds: Credentials) -> Data {
        let ke = h(creds.key, Data("FAVILLA-CHAN-ENC-1".utf8))
        var out = [UInt8](body)
        var i = 0
        while i < out.count {
            var seed = Data([rsp]); seed.append(creds.clientId); seed.append(le32(ctr)); seed.append(UInt8(i / 32))
            let ks = [UInt8](h(ke, seed))
            for j in 0..<min(32, out.count - i) { out[i + j] ^= ks[j] }
            i += 32
        }
        return Data(out)
    }

    struct Answer: Equatable {
        let rsp: UInt8
        let ctr: UInt32
        let body: Data   // decrypted when the answer type is encrypted
    }

    enum Failure: Error, Equatable {
        case unauthenticated(cmd: UInt8, status: UInt8)   // [0xBF][cmd][status], no mac
        case badMac
        case wrongClient
        case short
    }

    /// Check an answer's mac and client, decrypt its body if it is an encrypted type.
    static func open(_ m: Data, _ creds: Credentials) throws -> Answer {
        let b = [UInt8](m)
        if b.count == 3, b[0] == rErr { throw Failure.unauthenticated(cmd: b[1], status: b[2]) }
        guard b.count >= 1 + 8 + 4 + 16 else { throw Failure.short }
        let head = m.prefix(m.count - 16), tag = m.suffix(16)
        let want = h(creds.key, Data("RSP".utf8) + head).prefix(16)
        guard constantTimeEqual(want, tag) else { throw Failure.badMac }
        guard Data(b[1..<9]) == creds.clientId else { throw Failure.wrongClient }
        let ctr = UInt32(b[9]) | UInt32(b[10]) << 8 | UInt32(b[11]) << 16 | UInt32(b[12]) << 24
        var body = Data(b[13..<(b.count - 16)])
        if encrypted.contains(b[0]) { body = keystream(body, rsp: b[0], ctr: ctr, creds) }
        return Answer(rsp: b[0], ctr: ctr, body: body)
    }

    static func constantTimeEqual(_ a: Data, _ b: Data) -> Bool {
        guard a.count == b.count else { return false }
        var d: UInt8 = 0
        for (x, y) in zip(a, b) { d |= x ^ y }
        return d == 0
    }

    // MARK: - Request bodies

    /// TIME: [unix time 8, big endian].
    static func timeBody(_ now: Date = Date()) -> Data { be64(UInt64(max(0, now.timeIntervalSince1970))) }

    /// OTP: [sLen][site][unix time 8, big endian].
    static func otpBody(site: Data, now: Date = Date()) -> Data {
        var d = Data([UInt8(site.count)]); d.append(site); d.append(timeBody(now)); return d
    }

    /// LIST: [start hi][start lo].
    static func listBody(start: Int) -> Data { Data([UInt8((start >> 8) & 0xFF), UInt8(start & 0xFF)]) }

    // MARK: - Pairing

    /// One pairing attempt (needs PAIR A PHONE open on the KEY).
    struct Pairing {
        let priv: P256.KeyAgreement.PrivateKey
        let nonce: Data

        init(priv: P256.KeyAgreement.PrivateKey = .init(), nonce: Data? = nil) {
            self.priv = priv
            if let n = nonce { self.nonce = n } else {
                var n = [UInt8](repeating: 0, count: 16)
                _ = SecRandomCopyBytes(kSecRandomDefault, 16, &n)
                self.nonce = Data(n)
            }
        }

        var extPub: Data { priv.publicKey.x963Representation }

        /// [0x20][C], C = H("FAVILLA-COMMIT-1", extPub || nonce).
        var commit: Data { Data([AppChannel.pairCommit]) + AppChannel.h(Data("FAVILLA-COMMIT-1".utf8), extPub + nonce) }

        /// [0x22][extPub 65][nonce 16].
        var reveal: Data { Data([AppChannel.pairReveal]) + extPub + nonce }

        /// From the KEY's [0xA0][keyPub 65][clientId 8]: the channel key and the 6-digit code.
        func derive(_ a0: Data) throws -> (Credentials, String) {
            let b = [UInt8](a0)
            guard b.count == 1 + 65 + 8, b[0] == AppChannel.rPairKey else { throw Failure.short }
            let keyPub = Data(b[1..<66]), clientId = Data(b[66..<74])
            let peer = try P256.KeyAgreement.PublicKey(x963Representation: keyPub)
            let z = try priv.sharedSecretFromKeyAgreement(with: peer).withUnsafeBytes { Data($0) }
            let prk = AppChannel.h(Data("FAVILLA-CHAN-1".utf8), z)
            let k = AppChannel.h(prk, Data("key".utf8) + extPub + keyPub + Data([1]))
            let t = [UInt8](AppChannel.h(prk, Data("code".utf8) + extPub + keyPub + Data([1])))
            let n = (UInt32(t[0]) << 24 | UInt32(t[1]) << 16 | UInt32(t[2]) << 8 | UInt32(t[3])) % 1_000_000
            return (Credentials(key: k, clientId: clientId), String(format: "%06u", n))
        }
    }

    /// The code as the KEY shows it: "123 456".
    static func spaced(_ code: String) -> String {
        guard code.count == 6 else { return code }
        return String(code.prefix(3)) + " " + String(code.suffix(3))
    }

    static func statusText(_ s: UInt8) -> String {
        switch s {
        case 0x05: return "Your KEY is locked. Enter the passkey PIN on the KEY, then try again."
        case 0x06: return "Your KEY is busy with another request. Finish it on the KEY, then try again."
        case 0x07: return "The KEY couldn't read the request."
        case 0x08: return "This app isn't paired with the KEY any more. Pair it again in the Favilla app: This iPhone > PAIR THE APP."
        case 0x0A: return "PAIR A PHONE isn't open on the KEY. Open it, then try again."
        case 0x0B: return "Pairing was refused on the KEY."
        case 0x0C: return "The KEY already has 4 apps paired. Forget phones on the KEY (Settings > Bluetooth), then pair again."
        case 0x0E: return "The KEY couldn't save the pairing. Try again."
        default: return String(format: "The KEY refused the request (status 0x%02X).", s)
        }
    }
}

// MARK: - Stored pairing

/// The channel key and client id, in the Keychain (this device only), shared
/// by the app and the AutoFill extension through the app group. The request
/// counter lives in the app group's defaults: it only has to rise.
struct Credentials: Equatable {
    let key: Data        // K, 32 bytes
    let clientId: Data   // 8 bytes

    private static let group = "group.io.favillakey.app"
    private static let service = "io.favillakey.app.channel"
    private static let account = "key"
    private static let ctrKey = "appChannelCounter"
    private static var defaults: UserDefaults { UserDefaults(suiteName: group) ?? .standard }

    private static var query: [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: account,
         kSecAttrAccessGroup as String: group]
    }

    static func load() -> Credentials? {
        var q = query
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let d = out as? Data, d.count == 40 else { return nil }
        return Credentials(key: d.prefix(32), clientId: d.suffix(8))
    }

    @discardableResult
    func save() -> Bool {
        Credentials.forget()
        var q = Credentials.query
        q[kSecValueData as String] = key + clientId
        q[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let ok = SecItemAdd(q as CFDictionary, nil) == errSecSuccess
        if ok { Credentials.defaults.set(0, forKey: Credentials.ctrKey) }   // the next request uses 1
        return ok
    }

    static func forget() {
        SecItemDelete(query as CFDictionary)
        defaults.removeObject(forKey: ctrKey)
    }

    static var isPaired: Bool { load() != nil }

    /// The next counter (strictly rising across the app and the extension).
    static func nextCounter() -> UInt32 {
        let n = UInt32(clamping: defaults.integer(forKey: ctrKey) + 1)
        defaults.set(Int(n), forKey: ctrKey)
        return n
    }

    /// After a replay refusal: continue above the KEY's floor.
    static func raiseCounter(above floor: UInt32) {
        if defaults.integer(forKey: ctrKey) <= Int(floor) { defaults.set(Int(floor), forKey: ctrKey) }
    }
}
