// CBOR.swift - the small part of CBOR (RFC 8949) that CTAP2 uses.
//
// Encoding is CTAP2 canonical: shortest lengths, definite lengths only, map
// keys sorted by their encoded bytes (shorter first, then byte order). That is
// what an authenticator expects in a request, and what WebAuthn expects in an
// attestation object.

import Foundation

indirect enum CBOR: Equatable {
    case uint(UInt64)
    case negative(Int64)      // the value itself, always < 0
    case bytes(Data)
    case text(String)
    case array([CBOR])
    case map([(CBOR, CBOR)])
    case bool(Bool)
    case null

    static func == (a: CBOR, b: CBOR) -> Bool { a.encoded() == b.encoded() }

    static func int(_ v: Int) -> CBOR { v >= 0 ? .uint(UInt64(v)) : .negative(Int64(v)) }

    // MARK: - Reading values

    subscript(_ key: Int) -> CBOR? { lookup(.int(key)) }
    subscript(_ key: String) -> CBOR? { lookup(.text(key)) }

    private func lookup(_ k: CBOR) -> CBOR? {
        guard case .map(let pairs) = self else { return nil }
        let want = k.encoded()
        return pairs.first(where: { $0.0.encoded() == want })?.1
    }

    var data: Data? { if case .bytes(let d) = self { return d }; return nil }
    var string: String? { if case .text(let s) = self { return s }; return nil }

    // MARK: - Encoding

    func encoded() -> Data {
        var out = Data()
        encode(into: &out)
        return out
    }

    private static func head(_ major: UInt8, _ n: UInt64, into out: inout Data) {
        let m = major << 5
        switch n {
        case 0..<24: out.append(m | UInt8(n))
        case 24...0xFF: out.append(m | 24); out.append(UInt8(n))
        case 0x100...0xFFFF: out.append(m | 25); out.append(contentsOf: [UInt8(n >> 8), UInt8(n & 0xFF)])
        case 0x10000...0xFFFF_FFFF:
            out.append(m | 26)
            for s in stride(from: 24, through: 0, by: -8) { out.append(UInt8((n >> UInt64(s)) & 0xFF)) }
        default:
            out.append(m | 27)
            for s in stride(from: 56, through: 0, by: -8) { out.append(UInt8((n >> UInt64(s)) & 0xFF)) }
        }
    }

    private func encode(into out: inout Data) {
        switch self {
        case .uint(let v): CBOR.head(0, v, into: &out)
        case .negative(let v): CBOR.head(1, UInt64(-1 - v), into: &out)
        case .bytes(let d): CBOR.head(2, UInt64(d.count), into: &out); out.append(d)
        case .text(let s): let u = Data(s.utf8); CBOR.head(3, UInt64(u.count), into: &out); out.append(u)
        case .array(let a): CBOR.head(4, UInt64(a.count), into: &out); a.forEach { $0.encode(into: &out) }
        case .map(let pairs):
            let enc = pairs.map { ($0.0.encoded(), $0.1.encoded()) }
                .sorted { a, b in a.0.count != b.0.count ? a.0.count < b.0.count : a.0.lexicographicallyPrecedes(b.0) }
            CBOR.head(5, UInt64(enc.count), into: &out)
            for (k, v) in enc { out.append(k); out.append(v) }
        case .bool(let b): out.append(b ? 0xF5 : 0xF4)
        case .null: out.append(0xF6)
        }
    }

    // MARK: - Decoding

    enum DecodeError: Error { case truncated, unsupported(UInt8), tooDeep, trailing }

    /// Decode exactly one item that fills `data`.
    static func decode(_ data: Data) throws -> CBOR {
        var r = Reader(bytes: [UInt8](data))
        let v = try r.item(depth: 0)
        if r.pos != r.bytes.count { throw DecodeError.trailing }
        return v
    }

    private struct Reader {
        let bytes: [UInt8]
        var pos = 0

        mutating func byte() throws -> UInt8 {
            guard pos < bytes.count else { throw DecodeError.truncated }
            defer { pos += 1 }
            return bytes[pos]
        }

        mutating func take(_ n: Int) throws -> [UInt8] {
            guard n >= 0, pos + n <= bytes.count else { throw DecodeError.truncated }
            defer { pos += n }
            return Array(bytes[pos..<pos + n])
        }

        mutating func arg(_ info: UInt8) throws -> UInt64 {
            switch info {
            case 0..<24: return UInt64(info)
            case 24: return UInt64(try byte())
            case 25, 26, 27:
                let n = info == 25 ? 2 : info == 26 ? 4 : 8
                return try take(n).reduce(0) { ($0 << 8) | UInt64($1) }
            default: throw DecodeError.unsupported(info)   // indefinite lengths: CTAP2 never sends them
            }
        }

        mutating func item(depth: Int) throws -> CBOR {
            guard depth < 16 else { throw DecodeError.tooDeep }
            let ib = try byte()
            let major = ib >> 5, info = ib & 0x1F
            switch major {
            case 0: return .uint(try arg(info))
            case 1:
                let n = try arg(info)
                guard n < UInt64(Int64.max) else { throw DecodeError.unsupported(ib) }
                return .negative(-1 - Int64(n))
            case 2: return .bytes(Data(try take(Int(try arg(info)))))
            case 3:
                guard let s = String(bytes: try take(Int(try arg(info))), encoding: .utf8) else { throw DecodeError.unsupported(ib) }
                return .text(s)
            case 4:
                let n = try arg(info)
                guard n <= UInt64(bytes.count) else { throw DecodeError.truncated }
                return .array(try (0..<Int(n)).map { _ in try item(depth: depth + 1) })
            case 5:
                let n = try arg(info)
                guard n <= UInt64(bytes.count) else { throw DecodeError.truncated }
                return .map(try (0..<Int(n)).map { _ in (try item(depth: depth + 1), try item(depth: depth + 1)) })
            case 7:
                switch info {
                case 20: return .bool(false)
                case 21: return .bool(true)
                case 22: return .null
                default: throw DecodeError.unsupported(ib)
                }
            default: throw DecodeError.unsupported(ib)   // tags (6) are not used in CTAP2
            }
        }
    }
}
