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
    /// API requests and answers (9k) cross many reports: up to 32 KB of body plus
    /// the path and headers. The start report's u16 length allows it.
    static let msgMaxApi = 40_960

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
    static let cApi: UInt8 = 0x3A   // 9k: one /api call from the Nostr client

    // Answers
    static let rPairKey: UInt8 = 0xA0
    static let rPairDone: UInt8 = 0xA1
    static let rHello: UInt8 = 0xB0
    static let rAck: UInt8 = 0xB1
    static let rLogin: UInt8 = 0xB3
    /// Voice sign-in (KEY 11gk, issue #90): [sLen][site][uLen][user] as FILL ->
    /// rAck [status] at once, then rLogin, ONE status byte and never a login.
    /// The KEY types the login on the computer its USB cable is in.
    static let cTypeLogin: UInt8 = 0x51

    /// "log into Forge PC" -> "Forge PC": the leading words off, then "the" or
    /// "my", the dots out of spoken letters ("P.C." -> "PC"), printable ASCII,
    /// at most 100 bytes. nil when nothing is left.
    static func spokenName(_ heard: String) -> String? {
        var s = heard.replacingOccurrences(of: "\u{2019}", with: "'").replacingOccurrences(of: "\u{2018}", with: "'")
        s = String(s.unicodeScalars.filter { $0.value >= 0x20 && $0.value < 0x7F }.map(Character.init))
        func tidy(_ t: String) -> String { t.split(separator: " ", omittingEmptySubsequences: true).joined(separator: " ") }
        s = tidy(s)
        func strip(_ words: [String]) {
            let low = s.lowercased()
            for w in words where low == w || low.hasPrefix(w + " ") {
                s = tidy(String(s.dropFirst(w.count))); return
            }
        }
        strip(["log into", "log in to", "login to", "sign into", "sign in to", "open"])
        strip(["the", "my"])
        // A single letter followed by a dot is a spoken letter; "amazon.com" keeps its dot.
        s = s.replacingOccurrences(of: "(?<![A-Za-z0-9])([A-Za-z])\\.", with: "$1", options: .regularExpression)
        while let l = s.last, ".,!?;:".contains(l) { s.removeLast() }
        s = tidy(s)
        while s.utf8.count > 100 { s.removeLast() }
        s = tidy(s)
        return s.isEmpty ? nil : s
    }

    /// TYPE_LOGIN's status at once, when it is not "on the KEY".
    static func typeLoginAck(_ st: UInt8) -> String {
        switch st {
        case 0x04: return "Your KEY isn't in VAULT mode. Restart it and choose VAULT."
        case 0x05: return "Enter the VAULT PIN on the KEY first."
        default: return statusText(st)
        }
    }

    /// TYPE_LOGIN's outcome (the rLogin byte).
    static func typeLoginText(_ st: UInt8, name: String) -> String {
        switch st {
        case 0x01: return "Typed on the computer."
        case 0x02: return "Cancelled on the KEY."
        case 0x03: return "No saved login called \(name)."
        case 0x05: return "Enter the VAULT PIN on the KEY first."
        case 0x18: return "Plug the KEY into the computer by USB, then try again."
        default: return String(format: "The KEY answered with a status this app doesn't know (0x%02X).", st)
        }
    }
    static let rCtap: UInt8 = 0xB4
    static let rKeepalive: UInt8 = 0xB5
    static let rList: UInt8 = 0xB6
    static let rOtp: UInt8 = 0xB7
    static let rApi: UInt8 = 0xB8   // 9k, encrypted
    // 11s: password health
    static let cShow: UInt8 = 0x43
    static let cAssess: UInt8 = 0x46   // 11ab: [max] -> rAck [status][opening][unseen u16 LE]: score never-assessed entries (0x45 is the browser channel's)     // [id 8] -> rAck [status]: the entry's PASSWORD screen on the KEY
    static let cHealth: UInt8 = 0x44   // none -> prefixes wanted; [prefix 3][n u16][suffix 18 x n] -> what is still pending
    static let rHealth: UInt8 = 0xC0   // encrypted: [status][pending u16][count][prefix 3 x count]
    // 11ax (issue #30): add, edit and delete from the Accounts page, VAULT mode.
    static let cPwSave: UInt8 = 0x47     // ENCRYPTED request body [id 8][sLen][site][uLen][user][pLen][pass][nLen][note] -> rAck [status]
    static let cPwDelete: UInt8 = 0x48   // [n][id 8 x n], n 1..20 -> rAck [status]
    static let cPwResult: UInt8 = 0x49   // none -> rAck [state][id 8][reason]
    static let cAssessOne: UInt8 = 0x4A  // [id 8] -> rAck, ENCRYPTED (11ay): [status][state][prefix 3] (both lives)
    /// Requests whose body crosses encrypted, with the command byte in the
    /// answer byte's place in the keystream (11ax: PW_SAVE only).
    // 11bf (issue #36): import in VAULT mode (VaultImport.swift).
    static let cImportBegin: UInt8 = 0x4B   // none -> rAck [status]
    static let cImportItem: UInt8 = 0x4C    // ENCRYPTED [kind][...] -> rAck [status]
    static let cImportStatus: UInt8 = 0x4D  // none -> rAck [state][reason][saved u16][failed u16][last]
    static let cImportEnd: UInt8 = 0x4E     // none -> rAck [status][saved u16][failed u16]
    // 11bi (issue #38): a password made by the KEY for a new-password field.
    static let cGenPw: UInt8 = 0x4F         // [kind][minLen][maxLen][required][allowed][sLen][specials] -> rGenPw
    static let rGenPw: UInt8 = 0xC1         // encrypted: [status][pLen][password]
    static let encryptedRequests: Set<UInt8> = [cPwSave, cImportItem]
    static let rErr: UInt8 = 0xBF

    /// Answers whose body is encrypted.
    static let encrypted: Set<UInt8> = [rLogin, rCtap, rList, rOtp, rApi, rHealth, rGenPw, rFind, rListState, rListAnswer]

    // The account list cache (KEY 11gm, issues #92 and #93). VAULT mode, VAULT
    // PIN in; none of the three shows anything on the KEY.
    static let cListState: UInt8 = 0x52    // none -> rListState [status][state 16]
    static let cFind: UInt8 = 0x53         // [sLen][site] -> rFind [status][flags][count] entries
    static let cListAnswer: UInt8 = 0x54   // [challenge 32] -> rListAnswer [status][answer 32]
    static let rFind: UInt8 = 0xC2
    static let rListState: UInt8 = 0xC3
    static let rListAnswer: UInt8 = 0xC4

    struct FindPage: Equatable {
        var flags: UInt8
        var hits: [ListEntry]
        var scores: [UInt8]                 // 3 exact, 2 same domain, 1 close name
        var loading: Bool { flags & 0x01 != 0 }   // some names are still loading on the KEY
        var more: Bool { flags & 0x02 != 0 }      // more matches than fit
    }

    /// 0xC2 body: [0x00][flags][count], then per entry
    /// [0x02][sLen][site][uLen][user][health][id 8][score].
    static func parseFind(_ body: Data) throws -> FindPage {
        let b = [UInt8](body)
        guard let st = b.first else { throw BodyFailure.malformed }
        guard st == 0x00 else { throw BodyFailure.status(st) }
        guard b.count >= 3 else { throw BodyFailure.malformed }
        var i = 3
        func take(_ n: Int) throws -> [UInt8] {
            guard n >= 0, i + n <= b.count else { throw BodyFailure.malformed }
            defer { i += n }
            return Array(b[i..<i + n])
        }
        func text() throws -> String { String(decoding: try take(Int(try take(1)[0])), as: UTF8.self) }
        var page = FindPage(flags: b[1], hits: [], scores: [])
        for _ in 0..<Int(b[2]) {
            guard try take(1)[0] == 0x02 else { throw BodyFailure.malformed }
            let site = try text(), user = try text()
            let h = try take(1)[0]
            let id = Data(try take(8))
            page.scores.append(try take(1)[0])
            page.hits.append(ListEntry(passkey: false, site: site, user: user, health: Health(raw: h), id: id))
        }
        return page
    }

    // MARK: - Reports

    /// One message as 64-byte reports: [0x10][len lo][len hi][61] then [0x11][i][62], zero padded.
    /// The index counts up from 1 and wraps from 255 to 0 (9k).
    static func reports(_ msg: Data, limit: Int = msgMax) -> [Data] {
        let m = [UInt8](msg)
        precondition(!m.isEmpty && m.count <= min(limit, 0xFFFF), "message size")
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
    static func writes(_ msg: Data, perWrite: Int, limit: Int = msgMax) -> [Data] {
        let rs = reports(msg, limit: limit), k = max(1, perWrite)
        return stride(from: 0, to: rs.count, by: k).map { rs[$0..<min($0 + k, rs.count)].reduce(Data(), +) }
    }

    /// Reassembles reports (a notification may carry several) into whole messages.
    struct Reassembler {
        private var want = 0
        private var buf: [UInt8] = []
        private var next: UInt8 = 0
        private let limit: Int

        init(limit: Int = AppChannel.msgMax) { self.limit = limit }

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
                    guard len > 0, len <= limit else { reset(); throw Failure.length }
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

        /// For the log: bytes held of the message being put together, and its length (0, 0 when idle).
        var progress: (have: Int, want: Int) { (buf.count, want) }
    }

    // MARK: - MACs and the keystream

    static func h(_ key: Data, _ msg: Data) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: msg, using: SymmetricKey(data: key)))
    }

    static func le32(_ v: UInt32) -> Data { Data([UInt8(v & 0xFF), UInt8((v >> 8) & 0xFF), UInt8((v >> 16) & 0xFF), UInt8(v >> 24)]) }
    static func be64(_ v: UInt64) -> Data { Data((0..<8).map { UInt8((v >> (56 - 8 * UInt64($0))) & 0xFF) }) }

    /// [cmd][clientId 8][ctr 4 LE][body][mac16], mac16 = H(K, "REQ" || everything before it)[0..15].
    static func request(_ cmd: UInt8, _ creds: Credentials, ctr: UInt32, body: Data = Data()) -> Data {
        var m = Data([cmd]); m.append(creds.clientId); m.append(le32(ctr))
        m.append(encryptedRequests.contains(cmd) ? keystream(body, rsp: cmd, ctr: ctr, creds) : body)
        m.append(h(creds.key, Data("REQ".utf8) + m).prefix(16))
        return m
    }

    /// XOR with the keystream: Ke = H(K, "FAVILLA-CHAN-ENC-1"),
    /// block i = H(Ke, rsp || clientId || ctr || index). The same call decrypts.
    /// The index is one byte for blocks 0 to 254; from block 255 it is
    /// 0xFF || i u16 LE (KEY 11ad, issue #9 / #20), so a body can be as long as
    /// the 40 KB message cap allows. Bodies up to 8160 bytes are unchanged.
    static func keystream(_ body: Data, rsp: UInt8, ctr: UInt32, _ creds: Credentials) -> Data {
        let ke = h(creds.key, Data("FAVILLA-CHAN-ENC-1".utf8))
        var out = [UInt8](body)
        var i = 0
        while i < out.count {
            let blk = i / 32
            var seed = Data([rsp]); seed.append(creds.clientId); seed.append(le32(ctr))
            if blk < 255 { seed.append(UInt8(blk)) } else { seed.append(contentsOf: [0xFF, UInt8(blk & 0xFF), UInt8(blk >> 8)]) }
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
        if encrypted.contains(b[0]) {
            body = keystream(body, rsp: b[0], ctr: ctr, creds)
        }
        return Answer(rsp: b[0], ctr: ctr, body: body)
    }

    /// Requests whose 0xB1 answer comes back encrypted (11ay: ASSESS_ONE only;
    /// every other 0xB1 is plain, so `open` cannot tell by the answer byte).
    static let encryptedAcks: Set<UInt8> = [cAssessOne]

    /// The 0xB1 answer to one of `encryptedAcks`, decrypted: 0xB1 stands in the
    /// answer byte's place in the keystream, as for HEALTH (firmware issue #66).
    /// Anything else (another command, the KEY's plain 0xBF refusal) is returned as it is.
    static func unsealAck(_ a: Answer, for cmd: UInt8, _ creds: Credentials) -> Answer {
        guard encryptedAcks.contains(cmd), a.rsp == rAck else { return a }
        return Answer(rsp: a.rsp, ctr: a.ctr, body: keystream(a.body, rsp: rAck, ctr: a.ctr, creds))
    }

    /// ASSESS_ONE's answer, decrypted: [status][state][prefix 3]. state 0 refused
    /// (see status), 1 the KEY is opening the entry (ask again), 2 the prefix is
    /// ready (five hex digits, as HEALTH packs it), 3 the verdict is already known.
    struct AssessOne: Equatable { var status: UInt8; var state: UInt8; var prefix: String }
    static func parseAssessOne(_ body: Data) -> AssessOne? {
        let b = [UInt8](body)
        guard b.count == 5 else { return nil }
        return AssessOne(status: b[0], state: b[1], prefix: String(b[2..<5].map { String(format: "%02X", $0) }.joined().dropLast()))
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

    /// LIST: [start hi][start lo]; with health (11s): a third byte, flags bit0.
    static func listBody(start: Int, health: Bool = false) -> Data {
        Data([UInt8((start >> 8) & 0xFF), UInt8(start & 0xFF)] + (health ? [0x01] : []))
    }

    /// The KEY's health byte on a password entry (11s).
    struct Health: Equatable {
        let raw: UInt8
        var strength: Int { Int(raw & 0x03) }          // 0 unknown, 1 weak, 2 fair, 3 strong
        var origin: Int { Int((raw >> 2) & 0x03) }     // 0 unknown, 1 made on this KEY, 2 the owner's own, 3 imported
        var reused: Bool { raw & 0x10 != 0 }
        var breached: Bool { raw & 0x20 != 0 }
        var checked: Bool { raw & 0x40 != 0 }
        var hasCode: Bool { raw & 0x80 != 0 }        // 11v: a one-time code is linked to this entry
    }

    /// 0xC0 body: [status][pending u16 LE][count][prefix 3 x count]. Each prefix is
    /// 5 hex digits packed high nibble first, the last nibble 0.
    struct HealthPage: Equatable { var pending: Int; var prefixes: [String] }
    static func parseHealth(_ body: Data) throws -> HealthPage {
        let b = [UInt8](body)
        guard let st = b.first else { throw BodyFailure.malformed }
        guard st == 0x00 else { throw BodyFailure.status(st) }
        guard b.count >= 4, b.count == 4 + 3 * Int(b[3]) else { throw BodyFailure.malformed }
        let pending = Int(b[1]) | Int(b[2]) << 8
        var out: [String] = []
        for k in 0..<Int(b[3]) {
            let p = b[(4 + 3 * k)..<(7 + 3 * k)]
            out.append(p.map { String(format: "%02X", $0) }.joined().dropLast().uppercased())
        }
        return HealthPage(pending: pending, prefixes: out)
    }

    /// HEALTH body for one bucket: [prefix 3][n u16 LE][suffix 18 x n]; a suffix is
    /// 35 hex digits packed high nibble first, the trailing nibble 0. 11bc: a
    /// bucket over `healthPart` lines goes as parts, bit 15 of n (`more`) set on
    /// all but the last; the KEY records the verdict when the last arrives.
    static let healthPart = 1000
    /// A real Have I Been Pwned range holds hundreds of lines. Fewer than this
    /// means the fetch failed; the KEY (11eb) refuses such a bucket with 0x07,
    /// and the app never sends one (firmware issue #73).
    static let healthMin = 100
    static let hibpUnreached = "Couldn't reach Have I Been Pwned, nothing was checked."

    /// The lines of a Have I Been Pwned range answer, "SUFFIX:count": the
    /// 35-hex-digit suffixes seen at least once (padding lines have count 0).
    /// The answer's lines end in CR LF, which Swift reads as ONE Character:
    /// splitting on "\n" or "\r" alone found no line ends, so the whole body
    /// was one unreadable line and every bucket came back empty (issue #73).
    static func parseHibp(_ text: String) -> (suffixes: [String], lines: Int) {
        let lines = text.split(whereSeparator: \.isNewline)
        let kept: [String] = lines.compactMap { line in
            let parts = line.split(separator: ":")
            guard parts.count == 2, let n = Int(parts[1].trimmingCharacters(in: .whitespaces)), n > 0 else { return nil }
            let sfx = String(parts[0]).trimmingCharacters(in: .whitespaces).uppercased()
            return sfx.count == 35 && sfx.allSatisfy(\.isHexDigit) ? sfx : nil
        }
        return (kept, lines.count)
    }

    /// The HEALTH bodies for one whole bucket, in parts of `healthPart`. nil
    /// for a bucket under `healthMin` suffixes (or one that will not pack):
    /// nothing is sent for a fetch that failed, so the KEY never records
    /// "clean" from an empty list.
    static func healthParts(prefix: String, suffixes: [String]) -> [Data]? {
        guard suffixes.count >= healthMin else { return nil }
        var out: [Data] = [], sent = 0
        while sent < suffixes.count {
            let end = min(sent + healthPart, suffixes.count)
            guard let body = healthBody(prefix: prefix, suffixes: Array(suffixes[sent..<end]), more: end < suffixes.count) else { return nil }
            out.append(body); sent = end
        }
        return out
    }
    static func healthBody(prefix: String, suffixes: [String], more: Bool = false) -> Data? {
        guard prefix.count == 5, let p = packHex(prefix + "0"), suffixes.count <= healthPart else { return nil }
        var d = Data(p)
        let n = suffixes.count | (more ? 0x8000 : 0)
        d.append(UInt8(n & 0xFF)); d.append(UInt8(n >> 8))
        for s in suffixes { guard s.count == 35, let x = packHex(s + "0") else { return nil }; d.append(contentsOf: x) }
        return d
    }

    // MARK: 11ax: vault edits (issue #30)

    /// The KEY's own field limits: site 1..199 bytes, the others up to 128, and
    /// 415 bytes in all (431 sealed less 16 of lengths and dates; the PWA's LIM).
    static let pwSiteMax = 199, pwFieldMax = 128, pwAllMax = 415

    enum PwFieldProblem: Error, Equatable { case siteEmpty, siteTooLong, tooLong(String), tooLongInAll, control(String), needsPassword }

    /// UTF-8 with no control characters (U+0000..U+001F, DEL, U+0080..U+009F):
    /// what the KEY accepts.
    static func pwTextOK(_ s: String) -> Bool {
        !s.unicodeScalars.contains { $0.value < 0x20 || (0x7F...0x9F).contains($0.value) }
    }

    /// PW_SAVE body, before encryption. `id` nil: a new entry (needs a
    /// password). An edit: empty `pass` keeps the password, empty `note` keeps
    /// the note; site and user are replaced as sent.
    static func pwSaveBody(id: Data?, site: String, user: String, pass: String, note: String, flags: UInt8? = nil) -> Result<Data, PwFieldProblem> {
        let s = Data(site.utf8), u = Data(user.utf8), p = Data(pass.utf8), n = Data(note.utf8)
        if s.isEmpty { return .failure(.siteEmpty) }
        if s.count > pwSiteMax { return .failure(.siteTooLong) }
        for (name, f) in [("username", u), ("password", p), ("note", n)] where f.count > pwFieldMax { return .failure(.tooLong(name)) }
        if s.count + u.count + p.count + n.count > pwAllMax { return .failure(.tooLongInAll) }
        for (name, f) in [("site", site), ("username", user), ("password", pass), ("note", note)] where !pwTextOK(f) { return .failure(.control(name)) }
        if id == nil && p.isEmpty { return .failure(.needsPassword) }
        var d = id ?? Data(count: 8)
        guard d.count == 8 else { return .failure(.siteEmpty) }
        for f in [s, u, p, n] { d.append(UInt8(f.count)); d.append(f) }
        if let f = flags { d.append(f) }   // 11bi: bit0 keeps the old password as "<site> (old)"
        return .success(d)
    }

    static func pwProblemText(_ p: PwFieldProblem) -> String {
        switch p {
        case .siteEmpty: return "The site can't be empty."
        case .siteTooLong: return "The site is too long for the KEY: 199 bytes at most."
        case .tooLong(let f): return "The \(f) is too long for the KEY: 128 bytes at most."
        case .tooLongInAll: return "Too long for the KEY: site, username, password and note come to 415 bytes at most together."
        case .control(let f): return "The \(f) has a character the KEY can't store (a line break or other control character)."
        case .needsPassword: return "A new entry needs a password."
        }
    }

    /// PW_DELETE body: [n][id 8 x n], n 1..20.
    static func pwDeleteBody(_ ids: [Data]) -> Data? {
        guard (1...20).contains(ids.count), ids.allSatisfy({ $0.count == 8 }) else { return nil }
        var d = Data([UInt8(ids.count)])
        for i in ids { d.append(i) }
        return d
    }

    struct PwResult: Equatable {
        var state: UInt8      // 0 asking, 1 done, 2 declined, 3 timed out, 4 changed meanwhile, 5 failed, 6 no job
        var id: Data
        var reason: UInt8
    }
    static func parsePwResult(_ b: Data) -> PwResult? {
        let v = [UInt8](b)
        guard v.count >= 10 else { return nil }
        return PwResult(state: v[0], id: Data(v[1..<9]), reason: v[9])
    }

    /// Why a save ended as failed (PW_RESULT state 5). 11eo (issue #75): the
    /// KEY asks for the PIN itself when the vault limit stops a save, so 0x11
    /// here means it still could not go through.
    static func pwFailedText(_ reason: UInt8) -> String {
        reason == 0x11 ? "The vault limit needs your PIN. Lock and unlock the KEY, then save again." : pwStatusText(reason)
    }

    /// PW_SAVE / PW_DELETE / ASSESS_ONE statuses (at once) and PW_RESULT reasons.
    static func pwStatusText(_ s: UInt8) -> String {
        switch s {
        case 0x03: return "The KEY has no entry with that id any more. The list has been read again."
        case 0x04: return "Your KEY is in NOSTR mode. Editing accounts needs its VAULT side: on the KEY choose VAULT, enter the VAULT PIN, and leave it on its home screen."
        case 0x05: return "Your KEY is locked. Enter the VAULT PIN on the KEY, then try again."
        case 0x06: return "The KEY is already asking about another entry. Answer it on the KEY first."
        case 0x10: return "The KEY is full, passkeys and passwords together."
        case 0x11: return "The KEY has used its record opens for this sitting. Lock and unlock the KEY, then try again."
        case 0x12: return "Too long for the KEY: site, username, password and note come to 415 bytes at most together."
        case 0x0E: return "The KEY couldn't write the entry. Try again."
        default: return statusText(s)
        }
    }

    static func packHex(_ s: String) -> [UInt8]? {
        let c = Array(s.uppercased().utf8)
        guard c.count % 2 == 0 else { return nil }
        var out: [UInt8] = []
        var i = 0
        while i < c.count {
            guard let h = hexVal(c[i]), let l = hexVal(c[i + 1]) else { return nil }
            out.append(h << 4 | l); i += 2
        }
        return out
    }
    private static func hexVal(_ c: UInt8) -> UInt8? {
        switch c { case 0x30...0x39: return c - 0x30; case 0x41...0x46: return c - 0x41 + 10; case 0x61...0x66: return c - 0x61 + 10; default: return nil }
    }

    // MARK: - Answer bodies

    /// A status byte instead of the asked-for thing (0x02 refused or timed out,
    /// 0x03 nothing saved, 0x05 locked), or a body that doesn't parse.
    enum BodyFailure: Error, Equatable { case status(UInt8), malformed }

    /// 0xB7 body: [0x00][n][n ASCII digits].
    static func parseOtp(_ body: Data) throws -> String {
        let b = [UInt8](body)
        guard let st = b.first else { throw BodyFailure.malformed }
        guard st == 0x00 else { throw BodyFailure.status(st) }
        guard b.count >= 2, (4...10).contains(Int(b[1])), b.count == 2 + Int(b[1]),
              b[2...].allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }) else { throw BodyFailure.malformed }
        return String(decoding: b[2...], as: UTF8.self)
    }

    struct ListEntry: Equatable {
        var passkey: Bool
        var site: String
        var user: String
        var credentialID: Data?
        var userHandle: Data?
        var health: Health?      // 11s, on a LIST with health
        var id: Data?            // 11s: what SHOW takes
    }

    struct ListPage: Equatable {
        var total: Int
        var entries: [ListEntry]
        var more: Bool
    }

    /// 0xB6 body: [0x00][total hi][total lo][count] entries [more].
    /// Password [0x00][sLen][site][uLen][user]; passkey
    /// [0x01][sLen][site][uLen][name][0x22][credential id 34][hLen][handle].
    static func parseList(_ body: Data) throws -> ListPage {
        let b = [UInt8](body)
        guard let st = b.first else { throw BodyFailure.malformed }
        guard st == 0x00 else { throw BodyFailure.status(st) }
        guard b.count >= 5 else { throw BodyFailure.malformed }
        let total = Int(b[1]) << 8 | Int(b[2]), count = Int(b[3])
        var i = 4
        func take(_ n: Int) throws -> [UInt8] {
            guard n >= 0, i + n <= b.count else { throw BodyFailure.malformed }
            defer { i += n }
            return Array(b[i..<i + n])
        }
        func text() throws -> String { String(decoding: try take(Int(try take(1)[0])), as: UTF8.self) }
        var out: [ListEntry] = []
        for _ in 0..<count {
            let kind = try take(1)[0]
            let site = try text(), user = try text()
            switch kind {
            case 0x00:
                out.append(ListEntry(passkey: false, site: site, user: user))
            case 0x02:
                let h = try take(1)[0]
                let id = Data(try take(8))
                out.append(ListEntry(passkey: false, site: site, user: user, health: Health(raw: h), id: id))
            case 0x01:
                let idLen = Int(try take(1)[0])
                let id = Data(try take(idLen))
                let handle = Data(try take(Int(try take(1)[0])))
                out.append(ListEntry(passkey: true, site: site, user: user, credentialID: id, userHandle: handle))
            default:
                throw BodyFailure.malformed
            }
        }
        let more = try take(1)[0]
        guard i == b.count else { throw BodyFailure.malformed }
        return ListPage(total: total, entries: out, more: more == 1)
    }

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
        case 0x0A: return "The KEY doesn't know this iPhone. On the KEY: Settings > Network > Pair a phone, then PAIR THE APP in Favilla (Settings > This iPhone)."
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
        withCounter { $0 = 0 }      // a new pairing starts its counter afresh (issue #22)
    }

    static var isPaired: Bool { load() != nil }

    /// The next counter (strictly rising across the app and the extension).
    /// The app and the notification extension are two processes, and app-group
    /// UserDefaults don't sync between them at once: each could hand out the same
    /// counter and the KEY refuses the second as a replay (issue #9, 9 Nov). So the
    /// counter lives in a file in the app group, read and written under a lock.
    static func nextCounter() -> UInt32 {
        var n = 0
        withCounter { $0 += 1; n = $0 }
        return UInt32(clamping: n)
    }

    /// After a replay refusal: continue above the KEY's floor.
    static func raiseCounter(above floor: UInt32) {
        withCounter { if $0 <= Int(floor) { $0 = Int(floor) } }
    }

    private static func withCounter(_ f: (inout Int) -> Void) {
        guard let url = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: "group.io.favillakey.app")?
                .appendingPathComponent("app-channel-counter") else {
            var v = defaults.integer(forKey: ctrKey); f(&v); defaults.set(v, forKey: ctrKey); return
        }
        let fd = Darwin.open(url.path, O_RDWR | O_CREAT, 0o600)
        guard fd >= 0 else { var v = defaults.integer(forKey: ctrKey); f(&v); defaults.set(v, forKey: ctrKey); return }
        defer { Darwin.close(fd) }
        flock(fd, LOCK_EX)
        defer { flock(fd, LOCK_UN) }
        var buf = [UInt8](repeating: 0, count: 24)
        let got = Darwin.read(fd, &buf, buf.count)
        let text = got > 0 ? String(decoding: buf.prefix(got), as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines) : ""
        var v = max(Int(text) ?? 0, defaults.integer(forKey: ctrKey))     // the defaults value: the counter before 9 Nov
        f(&v)
        let out = Array(String(v).utf8)
        _ = ftruncate(fd, 0)
        _ = lseek(fd, 0, SEEK_SET)
        _ = out.withUnsafeBufferPointer { Darwin.write(fd, $0.baseAddress, $0.count) }
        defaults.set(v, forKey: ctrKey)
    }
}

// MARK: - The KEY's pairing identity (issue #22, KEY 11ah)

/// HELLO's answer carries the first 8 bytes of the KEY's pairing key
/// (`[status][life][drop 8][pair id 8]`, 18 bytes from 11ah). When it changes,
/// the KEY was wiped and set up again, and the Nostr client's pinned device
/// key and session are stale: they are cleared before the client's next
/// session (NostrClientView), and after every successful app pairing.
/// Which KEY is this iPhone's (firmware issue #81, 26 Nov 2026).
///
/// Any KEY advertises the same service and a name that starts the same way, so
/// a neighbour's KEY used to win the race for a connection, and its identifier
/// was saved as "the KEY". Now a peripheral is this iPhone's KEY only once an
/// answer from it has passed the app channel's MAC, which needs the key made
/// at pairing. A paired iPhone stays with that one; another KEY is looked at
/// only after the trusted one has been silent for `wait`, is never saved until
/// it proves itself the same way, and is dropped for the rest of the request
/// when it cannot.
enum KeyTrust {
    static let wait: TimeInterval = 10
    private static let store = UserDefaults(suiteName: "group.io.favillakey.app")
    private static let key = "keyTrustedId"
    /// Before issue #81 the last peripheral connected was saved here, proven or
    /// not. Used only as a first guess while no KEY has proved itself yet.
    private static let oldKey = "keyPeripheralId"

    /// The peripheral whose answers have passed the MAC.
    static var id: UUID? { store?.string(forKey: key).flatMap { UUID(uuidString: $0) } }
    /// A first guess for an iPhone that has no trusted KEY yet.
    static var guess: UUID? { id == nil ? store?.string(forKey: oldKey).flatMap { UUID(uuidString: $0) } : nil }

    /// An answer from this peripheral passed the MAC. True when that is news.
    @discardableResult
    static func trust(_ p: UUID) -> Bool {
        heard()
        if id == p { return false }
        store?.set(p.uuidString, forKey: key)
        store?.removeObject(forKey: oldKey)
        return true
    }

    static func forget() {
        store?.removeObject(forKey: key)
        store?.removeObject(forKey: oldKey)
    }

    // How long the trusted KEY has been silent, across requests (issue #83).
    // Measured per request, a tap that cancelled and started again set the
    // clock back to nothing, so with the paired KEY gone (reset, restored) no
    // other KEY was ever reached: nothing connected however long the owner
    // tapped. The clock now runs from the first request that found it silent,
    // and starts over only when the KEY answers or nothing has asked for 30 s.
    private static let clock = NSLock()
    private static var silentSince: Date?
    private static var lastAsked = Date.distantPast

    /// Seconds the trusted KEY has been silent, as of this ask.
    static func silentFor(now: Date = Date()) -> TimeInterval {
        clock.lock(); defer { clock.unlock() }
        if silentSince == nil || now.timeIntervalSince(lastAsked) > 30 { silentSince = now }
        lastAsked = now
        return now.timeIntervalSince(silentSince ?? now)
    }

    /// The trusted KEY connected: it is not silent.
    static func heard() {
        clock.lock(); defer { clock.unlock() }
        silentSince = nil
    }

    enum Verdict: Equatable { case mine, wait, tryIt, never }

    /// What to do with a KEY that was found. `paired`: this iPhone holds
    /// app-channel credentials. `waited`: seconds since this request began.
    static func verdict(candidate: UUID, trusted: UUID?, paired: Bool, waited: TimeInterval, rejected: Set<UUID>) -> Verdict {
        if rejected.contains(candidate) { return .never }
        guard paired, let t = trusted else { return .tryIt }   // nothing to stay with yet
        if candidate == t { return .mine }
        // 27 Nov (issue #83): never, however long the paired KEY is silent.
        // A KEY at another address has no bond with this iPhone, so nothing
        // can be asked of it without bonding first, and the check itself (one
        // encrypted read or write) made iOS start a bond when that KEY had
        // PAIR A PHONE open. The app then let the link go 3 s later, in the
        // middle of it. Only a pairing run the owner starts may do that.
        return .wait
    }
}

/// A pairing run has the KEY to itself (issue #83, bench 27 Nov: the Nostr
/// link dialled the KEY on the same Bluetooth link while iOS was bonding, and
/// the KEY dropped the bond). While this is set nothing else in the app, the
/// AutoFill sheet or the notification extension connects, scans or reads.
enum PairingRun {
    private static let store = UserDefaults(suiteName: "group.io.favillakey.app")
    private static let key = "pairingRunUntil"
    /// Set for at most this long, so a run that died cannot block the app.
    static let longest: TimeInterval = 240

    static func begin() { store?.set(Date().addingTimeInterval(longest).timeIntervalSince1970, forKey: key) }
    static func end() { store?.removeObject(forKey: key) }
    static var active: Bool { (store?.double(forKey: key) ?? 0) > Date().timeIntervalSince1970 }
}

enum PairIdentity {
    private static let store = UserDefaults(suiteName: "group.io.favillakey.app")!
    private static let idKey = "keyPairId"
    private static let resetKey = "clientResetNeeded"

    /// The pair id in a HELLO body, when the KEY sends one.
    static func pairId(in helloBody: Data) -> Data? {
        helloBody.count >= 18 ? Data(helloBody[10..<18]) : nil
    }

    /// Note the pair id a HELLO carried. A first id is kept. One that differs
    /// from the kept one means the KEY was wiped and set up again: everything
    /// the app holds for it is cleared (resetAll) and true is returned, so the
    /// caller shows the pairing page.
    @discardableResult
    static func note(helloBody: Data) -> Bool {
        guard let id = pairId(in: helloBody) else { return false }
        let old = store.data(forKey: idKey)
        if old == id { return false }
        if old == nil { store.set(id, forKey: idKey); return false }
        KeyLife.forget("the KEY's pair id changed")
        resetAll(why: "HELLO pair id changed")
        store.set(id, forKey: idKey)
        return true
    }

    /// Everything the app holds for the KEY goes: the channel key and client id
    /// (Keychain), the counter, the pair id, and the Nostr client's device
    /// pairing (cleared before its next load). Issue #22 ruling, 11 Nov.
    static func resetAll(why: String) {
        Credentials.forget()
        KeyTrust.forget()
        store.removeObject(forKey: idKey)
        store.set(true, forKey: resetKey)
        Bunker.log("pairing: cleared everything kept for the KEY (\(why))")
        NotificationCenter.default.post(name: PairIdentity.cleared, object: nil)
    }

    /// After an app pairing: the client enrols afresh with this KEY. A client
    /// that is already running does so at once (issue #63: it used to keep the
    /// old pairing's device key and session until the app was opened again),
    /// and the Nostr link starts over with the new pairing.
    /// The pair id on record belongs to the pairing before. A new pairing takes
    /// the id from its own first HELLO: without this, that HELLO read as "the
    /// KEY was set up again" and cleared the pairing just made (issue #83).
    static func forgetId() { store.removeObject(forKey: idKey) }

    static func pairedAgain() {
        store.set(true, forKey: resetKey)
        NotificationCenter.default.post(name: PairIdentity.paired, object: nil)
    }
    /// Posted on the main queue when PAIR THE APP has just succeeded.
    static let paired = Notification.Name("PairIdentity.paired")

    /// Posted by resetAll: the Nostr client clears its device pairing and reloads; the settings page shows Not paired.
    static let cleared = Notification.Name("PairIdentity.cleared")

    static var resetNeeded: Bool { store.bool(forKey: resetKey) }
    static func resetDone() { store.removeObject(forKey: resetKey) }

    /// The keys the client keeps for its device pairing.
    static let clientKeys = ["kv_device_pub", "kv_session", "kv_phone_id", "kv_pair_eph"]
    static var clearScript: String {
        "try{" + clientKeys.map { "localStorage.removeItem('\($0)');" }.joined() + "}catch(e){};'cleared'"
    }
}
