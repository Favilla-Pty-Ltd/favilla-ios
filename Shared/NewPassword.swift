// NewPassword.swift - new passwords from iPhone AutoFill (KEY 11bi, issue #38).
//
// iOS 26.2 asks a credential manager for a strong password when the owner taps
// a new-password field, and hands it the site, username and password to save
// when the form is sent. The password is made by the KEY (GEN_PW 0x4F, its
// random source, no press, nothing stored) and saved on the KEY with a held
// ENTER (PW_SAVE 0x47, flags bit0 keeping the old one as "<site> (old)").

import CryptoKit
import Foundation

enum NewPassword {

    // MARK: Apple's password rules -> GEN_PW bytes

    static let lower: UInt8 = 0x01, upper: UInt8 = 0x02, digit: UInt8 = 0x04, special: UInt8 = 0x08

    struct Rules: Equatable {
        var minLen: UInt8 = 20
        var maxLen: UInt8 = 20
        var required: UInt8 = 0x0F
        var allowed: UInt8 = 0x0F
        var specials = ""            // "" = the KEY's default set
        var allowsSpecial: Bool { allowed & special != 0 }
    }

    /// Apple's `passwordrules` text ("required: upper; allowed: ascii-printable;
    /// minlength: 12; max-consecutive: 2"), as far as GEN_PW can say it. A
    /// `required` naming several classes ("upper, lower") means one of them;
    /// the first is required and the rest only allowed. nil or empty: the
    /// KEY's default (20 characters, all four classes).
    static func rules(_ text: String?) -> Rules {
        guard let text, !text.trimmingCharacters(in: .whitespaces).isEmpty else { return Rules() }
        var r = Rules(minLen: 0, maxLen: 0, required: 0, allowed: 0)
        var specials = Set<Character>(), anyPrintable = false
        for part in text.split(separator: ";") {
            let kv = part.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
            guard kv.count == 2 else { continue }
            let key = kv[0].lowercased(), value = kv[1]
            switch key {
            case "minlength": if let n = Int(value) { r.minLen = UInt8(clamping: max(Int(r.minLen), n)) }
            case "maxlength": if let n = Int(value) { r.maxLen = r.maxLen == 0 ? UInt8(clamping: n) : min(r.maxLen, UInt8(clamping: n)) }
            case "required", "allowed":
                var first = true
                for cls in classes(value) {
                    var bits: UInt8 = 0
                    switch cls {
                    case "lower": bits = lower
                    case "upper": bits = upper
                    case "digit": bits = digit
                    case "special": bits = special
                    case "ascii-printable", "unicode": bits = 0x0F; anyPrintable = true
                    default:
                        if cls.hasPrefix("[") {
                            for ch in cls.dropFirst().dropLast() {
                                if ch.isLowercase { bits |= lower } else if ch.isUppercase { bits |= upper }
                                else if ch.isNumber { bits |= digit }
                                else if ch.isASCII, ch != " " { bits |= special; specials.insert(ch) }
                            }
                        }
                    }
                    r.allowed |= bits
                    if key == "required", first { r.required |= (bits == 0x0F ? 0 : bits) }
                    first = false
                }
            default: break
            }
        }
        if r.allowed == 0 { r.allowed = 0x0F }
        if r.allowed & (lower | upper | digit) == 0 { r.allowed |= lower | upper | digit }
        r.required &= r.allowed
        if r.required == 0 { r.required = r.allowed & (lower | upper | digit) }
        // The range the site allows; the KEY makes 20, or the nearest in range.
        let lo = r.minLen == 0 ? 8 : max(8, min(64, Int(r.minLen)))
        let hi = max(lo, r.maxLen == 0 ? 64 : max(8, min(64, Int(r.maxLen))))
        r.minLen = UInt8(lo); r.maxLen = UInt8(hi)
        // Only the site's own specials when it named some and not "any printable".
        if r.allowed & special != 0, !anyPrintable, !specials.isEmpty {
            r.specials = String(specials.sorted().prefix(32))
        }
        return r
    }

    /// The comma-separated classes of one rule, keeping `[...]` sets whole.
    private static func classes(_ s: String) -> [String] {
        var out: [String] = [], cur = "", inSet = false
        for ch in s {
            if ch == "[" { inSet = true }
            if ch == "]" { inSet = false }
            if ch == ",", !inSet { out.append(cur.trimmingCharacters(in: .whitespaces)); cur = ""; continue }
            cur.append(ch)
        }
        if !cur.trimmingCharacters(in: .whitespaces).isEmpty { out.append(cur.trimmingCharacters(in: .whitespaces)) }
        return out.map { $0.hasPrefix("[") ? $0 : $0.lowercased() }
    }

    /// GEN_PW body: kind 0x01 strong, 0x02 letters and digits only.
    static func genBody(_ r: Rules, kind: UInt8) -> Data {
        var d = Data([kind, r.minLen, r.maxLen, r.required, r.allowed])
        let sp = Data(r.specials.utf8.prefix(32))
        d.append(UInt8(sp.count)); d.append(sp)
        return d
    }

    /// R_GEN_PW (decrypted): the password, or the KEY's status.
    static func parseGen(_ b: Data) -> Result<String, GenFailure> {
        let v = [UInt8](b)
        guard v.count >= 2 else { return .failure(.status(0xFF)) }
        guard v[0] == 0x00 else { return .failure(.status(v[0])) }
        let n = Int(v[1])
        guard v.count >= 2 + n, n > 0, let s = String(bytes: v[2..<(2 + n)], encoding: .utf8) else { return .failure(.status(0xFF)) }
        return .success(s)
    }
    enum GenFailure: Error, Equatable { case status(UInt8) }

    static func genText(_ st: UInt8) -> String {
        switch st {
        case 0x04: return "Strong passwords come from the KEY in VAULT mode."
        case 0x05: return "Your KEY is locked."
        case 0x06: return "The KEY made 10 passwords in the last minute. Try again in a moment."
        case 0x07: return "The KEY couldn't follow this site's password rules."
        case 0x0E: return "The KEY's random generator didn't answer. Try again."
        default: return String(format: "The KEY answered 0x%02X.", st)
        }
    }

    // MARK: A login the KEY just sent

    /// iOS's save after the KEY's own NEW LOGIN or NEW PASSWORD (or any fill)
    /// would ask the owner to save what the KEY already holds. For two minutes
    /// after a fill, a keyed hash of what was filled (never the password) is
    /// kept in the app group so that save can be skipped. Key and hash go
    /// together after the two minutes or the first check.
    private static let store = UserDefaults(suiteName: "group.io.favillakey.app") ?? .standard
    private static let memoKey = "fillMemo"

    static func recordFill(site: String, user: String, password: String) {
        var key = Data(count: 32)
        _ = key.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        let mac = tag(key, site, user, password)
        store.set(["k": key, "m": mac, "at": Date().timeIntervalSince1970], forKey: memoKey)
        // The site and username (not secret) for a retype box filled next.
        store.set(["site": site, "user": user, "at": Date().timeIntervalSince1970], forKey: lastKey)
    }

    private static let lastKey = "lastFill"

    /// The site and username filled from the KEY in the last minute (the KEY's
    /// "Send again?" window), for the retype box.
    static func lastFill() -> (site: String, user: String)? {
        guard let m = store.dictionary(forKey: lastKey), let site = m["site"] as? String, let user = m["user"] as? String,
              let at = m["at"] as? Double, Date().timeIntervalSince1970 - at < 60 else { return nil }
        return (site, user)
    }

    /// True when this exact login was filled from the KEY in the last two minutes.
    static func justFilled(site: String, user: String, password: String) -> Bool {
        defer { store.removeObject(forKey: memoKey) }
        guard let m = store.dictionary(forKey: memoKey), let k = m["k"] as? Data, let mac = m["m"] as? Data,
              let at = m["at"] as? Double, Date().timeIntervalSince1970 - at < 120 else { return false }
        return tag(k, site, user, password) == mac
    }

    private static func tag(_ k: Data, _ site: String, _ user: String, _ pass: String) -> Data {
        var h = HMAC<SHA256>(key: SymmetricKey(data: k))
        for part in [site.lowercased(), user.lowercased(), pass] { h.update(data: Data(part.utf8)); h.update(data: Data([0])) }
        return Data(h.finalize())
    }

    /// The host the KEY lists a site under: lower case, no scheme, no "www.".
    static func host(_ s: String) -> String {
        var h = s.trimmingCharacters(in: .whitespaces).lowercased()
        if let u = URL(string: h.contains("://") ? h : "https://" + h), let hh = u.host { h = hh }
        if h.hasPrefix("www.") { h.removeFirst(4) }
        return h
    }
}
