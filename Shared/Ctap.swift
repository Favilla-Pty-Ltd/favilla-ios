// Ctap.swift - passkeys with the KEY: CTAP2 over the FIDO Bluetooth framing.
// Built against favilla-key-firmware docs/BLE_PASSKEY_PROTOCOL.md (drop 9a).
// No Bluetooth here, so it can be tested on its own (Tests/ctap_tests.swift).

import Foundation

enum Ctap {
    // Commands (protocol doc, Framing)
    static let cmdPing: UInt8 = 0x81
    static let cmdKeepalive: UInt8 = 0x82
    static let cmdMsg: UInt8 = 0x83
    static let cmdCancel: UInt8 = 0xBE
    static let cmdError: UInt8 = 0xBF
    static let maxBody = 1024

    // MARK: - Framing

    /// Split one command into writes of at most `max` bytes:
    /// first [cmd][len hi][len lo][data...], then [seq][data...] with seq from 0.
    static func frames(cmd: UInt8, payload: Data, max: Int) -> [Data] {
        precondition(max >= 4, "control point length too small")
        let p = [UInt8](payload)
        var out: [Data] = []
        var first = Data([cmd, UInt8((p.count >> 8) & 0xFF), UInt8(p.count & 0xFF)])
        let n0 = min(p.count, max - 3)
        first.append(contentsOf: p[0..<n0])
        out.append(first)
        var off = n0
        var seq: UInt8 = 0
        while off < p.count {
            let n = min(p.count - off, max - 1)
            var f = Data([seq])
            f.append(contentsOf: p[off..<off + n])
            out.append(f)
            off += n
            seq &+= 1
        }
        return out
    }

    enum Event: Equatable {
        case keepalive(UInt8)   // 0x01 processing, 0x02 waiting for the user on the KEY
        case message(Data)      // a whole MSG body: status byte + CBOR
        case ping(Data)
        case error(UInt8)       // the KEY's framing error code
    }

    /// Reassembles notifications into whole replies.
    struct Reassembler {
        private var cmd: UInt8 = 0
        private var want = 0
        private var buf = Data()
        private var nextSeq: UInt8 = 0
        private var open = false

        enum Failure: Error, Equatable { case badSequence, badLength, unexpected(UInt8) }

        /// Feed one notification. Returns an event when a reply is complete.
        mutating func feed(_ d: Data) throws -> Event? {
            let b = [UInt8](d)
            guard let h = b.first else { return nil }
            if h & 0x80 != 0 {                     // a first frame
                guard b.count >= 3 else { throw Failure.badLength }
                let len = Int(b[1]) << 8 | Int(b[2])
                guard len <= Ctap.maxBody else { throw Failure.badLength }
                cmd = h; want = len; buf = Data(b[3...].prefix(len)); nextSeq = 0; open = true
            } else {                               // a continuation
                guard open else { throw Failure.badSequence }
                guard h == nextSeq else { open = false; throw Failure.badSequence }
                nextSeq &+= 1
                buf.append(contentsOf: b[1...].prefix(want - buf.count))
            }
            guard buf.count >= want else { return nil }
            open = false
            switch cmd {
            case Ctap.cmdKeepalive: return .keepalive(buf.first ?? 0)
            case Ctap.cmdMsg: return .message(buf)
            case Ctap.cmdPing: return .ping(buf)
            case Ctap.cmdError: return .error(buf.first ?? 0x7F)
            default: throw Failure.unexpected(cmd)
            }
        }
    }

    // MARK: - Requests (CTAP2 bodies, protocol doc "CTAP2 bodies")

    static let getInfo = Data([0x04])

    static func getAssertion(rpId: String, clientDataHash: Data, allow: [Data], uv: Bool) -> Data {
        var m: [(CBOR, CBOR)] = [
            (.int(1), .text(rpId)),
            (.int(2), .bytes(clientDataHash)),
        ]
        if !allow.isEmpty {
            m.append((.int(3), .array(allow.map { .map([(.text("type"), .text("public-key")), (.text("id"), .bytes($0))]) })))
        }
        m.append((.int(5), .map([(.text("up"), .bool(true)), (.text("uv"), .bool(uv))])))
        var d = Data([0x02]); d.append(CBOR.map(m).encoded()); return d
    }

    static func makeCredential(rpId: String, clientDataHash: Data, userHandle: Data, userName: String, algorithms: [Int]) -> Data {
        let algs = algorithms.isEmpty ? [-7] : algorithms
        let m: [(CBOR, CBOR)] = [
            (.int(1), .bytes(clientDataHash)),
            (.int(2), .map([(.text("id"), .text(rpId))])),
            (.int(3), .map([(.text("id"), .bytes(userHandle)), (.text("name"), .text(userName)), (.text("displayName"), .text(userName))])),
            (.int(4), .array(algs.map { .map([(.text("alg"), .int($0)), (.text("type"), .text("public-key"))]) })),
            (.int(7), .map([(.text("rk"), .bool(true))])),
        ]
        var d = Data([0x01]); d.append(CBOR.map(m).encoded()); return d
    }

    // MARK: - Responses

    enum Failure: Error, Equatable {
        case status(UInt8)        // a CTAP2 error status from the KEY
        case malformed(String)
    }

    struct Assertion { let credentialID: Data; let authenticatorData: Data; let signature: Data; let userHandle: Data }
    struct Registration { let credentialID: Data; let attestationObject: Data }

    private static func body(_ resp: Data) throws -> CBOR {
        guard let st = resp.first else { throw Failure.malformed("empty reply") }
        guard st == 0x00 else { throw Failure.status(st) }
        do { return try CBOR.decode(resp.dropFirst()) } catch { throw Failure.malformed("CBOR: \(error)") }
    }

    static func parseAssertion(_ resp: Data) throws -> Assertion {
        let m = try body(resp)
        guard let auth = m[2]?.data, let sig = m[3]?.data else { throw Failure.malformed("no authData or signature") }
        // Credential id from 1, else from the authenticator data is not available in
        // an assertion, so it must be there.
        guard let cred = m[1]?["id"]?.data else { throw Failure.malformed("no credential id") }
        let handle = m[4]?["id"]?.data ?? Data()
        return Assertion(credentialID: cred, authenticatorData: auth, signature: sig, userHandle: handle)
    }

    static func parseRegistration(_ resp: Data) throws -> Registration {
        let m = try body(resp)
        guard let fmt = m[1]?.string, let auth = m[2]?.data, let att = m[3] else { throw Failure.malformed("no fmt, authData or attStmt") }
        guard let cred = credentialID(fromAuthData: auth) else { throw Failure.malformed("no attested credential in authData") }
        // WebAuthn attestation object: {"fmt", "attStmt", "authData"} (canonical order by the encoder).
        let obj = CBOR.map([(.text("fmt"), .text(fmt)), (.text("attStmt"), att), (.text("authData"), .bytes(auth))]).encoded()
        return Registration(credentialID: cred, attestationObject: obj)
    }

    /// authData: rpIdHash 32 | flags 1 | signCount 4 | [AAGUID 16 | credIdLen 2 BE | credId | pubKey]
    static func credentialID(fromAuthData a: Data) -> Data? {
        let b = [UInt8](a)
        guard b.count >= 37, b[32] & 0x40 != 0, b.count >= 55 else { return nil }   // AT flag
        let n = Int(b[53]) << 8 | Int(b[54])
        guard n > 0, b.count >= 55 + n else { return nil }
        return Data(b[55..<55 + n])
    }

    /// What a CTAP2 status means, in plain words.
    static func message(forStatus s: UInt8, creating: Bool) -> String {
        switch s {
        case 0x27: return creating ? "You said no on the KEY. No passkey was made." : "You said no on the KEY."
        case 0x2F: return "Nobody pressed the KEY in time. Try again."
        case 0x2E: return "There's no passkey on your KEY for this site."
        case 0x19: return "Your KEY already has a passkey for this account."
        case 0x31, 0x36: return "Enter the passkey PIN on your KEY, then try again."
        case 0x28: return "Your KEY has no room for another passkey."
        default: return String(format: "The KEY couldn't do it (CTAP status 0x%02X).", s)
        }
    }

    /// The KEY's framing error codes (0xBF), in plain words.
    static func message(forFramingError e: UInt8) -> String {
        switch e {
        case 0x05: return "The request timed out on the KEY. Try again."
        case 0x06: return "Your KEY is busy with a request over USB. Finish that first."
        default: return String(format: "The KEY couldn't read the request (error 0x%02X).", e)
        }
    }
}
