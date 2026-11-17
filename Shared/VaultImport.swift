// VaultImport.swift - another manager's export onto the KEY in VAULT mode
// (KEY 11bf, firmware issue #36, 16 Nov 2026).
//
// From G0 v19 the G0 seals an import only in a VAULT life, which has no Wi-Fi,
// so the PWA's import no longer works and the app drives the KEY's import
// window over the app channel instead:
//   0x4B IMPORT_BEGIN   none                 -> 0xB1 [status]
//   0x4C IMPORT_ITEM    ENCRYPTED [kind][..] -> 0xB1 [status]
//   0x4D IMPORT_STATUS  none                 -> 0xB1 [state][reason][saved u16][failed u16][last]
//   0x4E IMPORT_END     none                 -> 0xB1 [status][saved u16][failed u16]
//
// This file is the phone-side reading: CSV exports (1Password, Bitwarden,
// Apple Passwords, Chrome and friends, the same columns the PWA's import
// knew), otpauth fields turned into one-time code items, sites normalised as
// the PWA did, duplicates of what LIST v2 shows skipped (the KEY doesn't
// merge), and each item packed as the KEY wants it. Nothing here is written to
// disk; the plan lives in memory until the import ends or is discarded.

import Foundation

enum VaultImport {

    // MARK: Items

    enum Kind: Equatable { case password, code }

    struct Item: Equatable {
        var kind: Kind
        var site: String
        var user: String          // the account name, for a code
        var pass = ""
        var note = ""
        var digits: UInt8 = 6
        var period: UInt8 = 30
        var secret = Data()       // raw bytes, for a code
        var noteCut = false

        var label: String { user.isEmpty ? site : "\(site) (\(user))" }

        /// The IMPORT_ITEM body before encryption.
        var body: Data {
            var d = Data()
            func put(_ s: String) { let b = Data(s.utf8); d.append(UInt8(b.count)); d.append(b) }
            switch kind {
            case .password:
                d.append(0x01); put(site); put(user); put(pass); put(note)
            case .code:
                d.append(0x02); put(site); put(user)
                d.append(digits); d.append(period)
                d.append(UInt8(secret.count)); d.append(secret)
            }
            return d
        }
    }

    struct Skipped: Equatable { var label: String; var why: String }

    struct Plan {
        var source = ""                  // "Bitwarden CSV", "Apple Passwords"...
        var items: [Item] = []
        var skipped: [Skipped] = []
        var passwords: Int { items.filter { $0.kind == .password }.count }
        var codes: Int { items.filter { $0.kind == .code }.count }
        var cutNotes: Int { items.filter { $0.noteCut }.count }
    }

    /// A row from any source, before fitting: what one login looked like there.
    struct Row {
        var url = ""
        var name = ""
        var user = ""
        var pass = ""
        var note = ""
        var otp = ""                    // otpauth:// URI or a bare base32 secret
    }

    static let maxItems = 300           // the G0's import budget per window

    // MARK: Building the plan

    /// What's already on the KEY, from LIST v2: site and username, and whether
    /// the site has a code linked.
    struct OnKey {
        var pairs = Set<String>()
        var codeSites = Set<String>()
        init(_ entries: [AppChannel.ListEntry]) {
            for e in entries {
                pairs.insert(key(e.site, e.user))
                if e.health?.hasCode == true { codeSites.insert(e.site.lowercased()) }
            }
        }
        init() {}
    }

    static func key(_ site: String, _ user: String) -> String { site.lowercased() + "\u{1}" + user.lowercased() }

    static func plan(_ rows: [Row], source: String, onKey: OnKey) -> Plan {
        var p = Plan(source: source)
        var seen = onKey.pairs, codeSeen = onKey.codeSites
        for r in rows {
            let site = normSite(r.url, r.name)
            let label = r.user.isEmpty ? (site.isEmpty ? "(no name)" : site) : "\(site.isEmpty ? "(no name)" : site) (\(r.user))"
            // The password.
            var passwordSite: String?
            if r.pass.isEmpty {
                if r.otp.isEmpty { p.skipped.append(Skipped(label: label, why: "no password")) }
            } else if let why = fitWhy(site: site, user: r.user, pass: r.pass) {
                p.skipped.append(Skipped(label: label, why: why))
            } else if seen.contains(key(site, r.user)) {
                p.skipped.append(Skipped(label: label, why: "already on the KEY"))
                passwordSite = site      // a code can still link to the existing entry
            } else {
                var it = Item(kind: .password, site: site, user: r.user, pass: r.pass)
                (it.note, it.noteCut) = fitNote(r.note.replacingOccurrences(of: "\r\n", with: "\n").replacingOccurrences(of: "\r", with: "\n"),
                                                 room: min(AppChannel.pwFieldMax, AppChannel.pwAllMax - bytes(site) - bytes(r.user) - bytes(r.pass)))
                p.items.append(it)
                seen.insert(key(site, r.user))
                passwordSite = site
            }
            // The one-time code, saved under the same site so the login links to it.
            let otp = r.otp.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !otp.isEmpty else { continue }
            let codeLabel = label + ", code"
            switch parseOtp(otp) {
            case .failure(let why):
                p.skipped.append(Skipped(label: codeLabel, why: why))
            case .success(let c):
                let s = passwordSite ?? site
                let account = r.user.isEmpty ? c.account : r.user
                if s.isEmpty { p.skipped.append(Skipped(label: codeLabel, why: "no site")); continue }
                if bytes(s) > AppChannel.pwSiteMax || bytes(account) > AppChannel.pwFieldMax || !AppChannel.pwTextOK(s) || !AppChannel.pwTextOK(account) {
                    p.skipped.append(Skipped(label: codeLabel, why: "too long for the KEY")); continue
                }
                if codeSeen.contains(s.lowercased()) { p.skipped.append(Skipped(label: codeLabel, why: "a code for this site is already on the KEY")); continue }
                p.items.append(Item(kind: .code, site: s, user: account, digits: c.digits, period: c.period, secret: c.secret))
                codeSeen.insert(s.lowercased())
            }
        }
        if p.items.count > maxItems {
            for it in p.items[maxItems...] { p.skipped.append(Skipped(label: it.label + (it.kind == .code ? ", code" : ""), why: "over the 300 the KEY takes in one import")) }
            p.items.removeSubrange(maxItems...)
        }
        return p
    }

    static func bytes(_ s: String) -> Int { s.utf8.count }

    /// Why one password can't go in, or nil (the PWA's fitEntry).
    static func fitWhy(site: String, user: String, pass: String) -> String? {
        if site.isEmpty { return "no site" }
        if bytes(site) > AppChannel.pwSiteMax { return "site too long" }
        if bytes(user) > AppChannel.pwFieldMax { return "username too long" }
        if bytes(pass) > AppChannel.pwFieldMax { return "password too long (128 bytes at most)" }
        if bytes(site) + bytes(user) + bytes(pass) > AppChannel.pwAllMax { return "too long for the KEY" }
        if !AppChannel.pwTextOK(site) || !AppChannel.pwTextOK(user) || !AppChannel.pwTextOK(pass) { return "has a character the KEY can't store" }
        return nil
    }

    /// A note that fits in `room` bytes with no control characters: line breaks
    /// become " / ", a long one is cut on a character with "...".
    static func fitNote(_ n: String, room: Int) -> (String, Bool) {
        var t = n.replacingOccurrences(of: "\n", with: " / ")
        t = String(t.unicodeScalars.filter { $0.value >= 0x20 && !(0x7F...0x9F).contains($0.value) }.map(Character.init))
        if bytes(t) <= room { return (t, false) }
        guard room >= 3 else { return ("", true) }
        while bytes(t) > room - 3 { t.removeLast() }
        return (t + "...", true)
    }

    /// The host of a login's URL, lower case, without "www." (the PWA's
    /// normSite); else the item's name; else the URL as written.
    static func normSite(_ url: String, _ name: String) -> String {
        let u = url.trimmingCharacters(in: .whitespacesAndNewlines).split(whereSeparator: { $0 == " " || $0 == "," || $0 == "\n" || $0 == "\t" }).first.map(String.init) ?? ""
        if !u.isEmpty {
            let full = u.range(of: #"^[a-zA-Z][a-zA-Z0-9+.-]*://"#, options: .regularExpression) != nil ? u : "https://" + u
            if let c = URLComponents(string: full), let scheme = c.scheme?.lowercased(), scheme == "http" || scheme == "https", let h = c.host, !h.isEmpty {
                var host = h.lowercased()
                if host.hasPrefix("www.") { host.removeFirst(4) }
                return host
            }
        }
        let n = name.trimmingCharacters(in: .whitespacesAndNewlines)
        return n.isEmpty ? u : n
    }

    // MARK: One-time codes

    struct Totp: Equatable { var digits: UInt8; var period: UInt8; var secret: Data; var account: String }
    enum Otp: Equatable { case success(Totp), failure(String) }

    /// An otpauth://totp URI, or a bare base32 secret (Bitwarden's login_totp
    /// may be either): TOTP with SHA1 only, 6 to 8 digits, 1 to 255 s.
    static func parseOtp(_ s: String) -> Otp {
        if s.lowercased().hasPrefix("otpauth://") {
            guard let c = URLComponents(string: s) else { return .failure("one-time code link couldn't be read") }
            guard c.host?.lowercased() == "totp" else { return .failure(c.host?.lowercased() == "hotp" ? "counter-based (HOTP) code: the KEY takes time-based codes only" : "one-time code of an unknown type") }
            var q: [String: String] = [:]
            for i in c.queryItems ?? [] { q[i.name.lowercased()] = i.value ?? "" }
            let alg = (q["algorithm"] ?? "SHA1").uppercased()
            guard alg == "SHA1" else { return .failure("\(alg) code: the KEY takes SHA1 codes only") }
            let digits = Int(q["digits"] ?? "6") ?? -1, period = Int(q["period"] ?? "30") ?? -1
            guard (6...8).contains(digits) else { return .failure("\(digits)-digit code: the KEY takes 6 to 8") }
            guard (1...255).contains(period) else { return .failure("code period of \(period) s: the KEY takes 1 to 255") }
            guard let sec = base32(q["secret"] ?? ""), (1...64).contains(sec.count) else { return .failure("one-time code secret couldn't be read") }
            var label = c.path.hasPrefix("/") ? String(c.path.dropFirst()) : c.path
            if let colon = label.firstIndex(of: ":") { label = String(label[label.index(after: colon)...]) }
            return .success(Totp(digits: UInt8(digits), period: UInt8(period), secret: sec, account: label.trimmingCharacters(in: .whitespaces)))
        }
        if s.lowercased().hasPrefix("steam://") { return .failure("Steam code: the KEY takes standard codes only") }
        guard let sec = base32(s), (1...64).contains(sec.count) else { return .failure("one-time code secret couldn't be read") }
        return .success(Totp(digits: 6, period: 30, secret: sec, account: ""))
    }

    /// RFC 4648 base32, any case, spaces, dashes and padding ignored.
    static func base32(_ s: String) -> Data? {
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".utf8)
        var map = [UInt8: UInt8]()
        for (i, c) in alphabet.enumerated() { map[c] = UInt8(i) }
        var out = Data(), buf: UInt32 = 0, bits = 0
        for ch in s.uppercased().utf8 {
            if ch == UInt8(ascii: "=") || ch == UInt8(ascii: " ") || ch == UInt8(ascii: "-") { continue }
            guard let v = map[ch] else { return nil }
            buf = (buf << 5) | UInt32(v); bits += 5
            if bits >= 8 { bits -= 8; out.append(UInt8((buf >> UInt32(bits)) & 0xFF)) }
        }
        return out.isEmpty ? nil : out
    }

    // MARK: CSV

    /// RFC 4180: quoted fields with "" for a quote, CR, LF or CRLF rows.
    static func csv(_ text: String) -> [[String]] {
        var rows: [[String]] = [], row: [String] = [], f = "", q = false, fresh = true
        let cs = Array(text.hasPrefix("\u{FEFF}") ? String(text.dropFirst()) : text)
        var i = 0
        while i < cs.count {
            let c = cs[i]
            if q {
                if c == "\"" { if i + 1 < cs.count, cs[i + 1] == "\"" { f.append("\""); i += 1 } else { q = false } }
                else { f.append(c) }
            } else if c == "\"" && fresh { q = true; fresh = false }
            else if c == "," { row.append(f); f = ""; fresh = true }
            else if c == "\n" || c == "\r" || c == "\r\n" {
                row.append(f); f = ""; fresh = true
                if row.count > 1 || row.first != "" { rows.append(row) }
                row = []
            } else { f.append(c); fresh = false }
            i += 1
        }
        if !f.isEmpty || !row.isEmpty { row.append(f); if row.count > 1 || row.first != "" { rows.append(row) } }
        return rows
    }

    /// Header names as the managers write them, lower case; first match wins.
    static let columns: [String: [String]] = [
        "url": ["url", "login_uri", "web site", "website", "login url", "uri", "urls"],
        "name": ["name", "title", "account", "item name"],
        "user": ["username", "login_username", "login name", "user name", "email", "login"],
        "pass": ["password", "login_password"],
        "note": ["note", "notes", "comments", "extra"],
        "otp": ["otpauth", "login_totp", "totp", "otp", "one-time password", "otp auth"],
    ]

    /// Rows from a CSV export, and what made it. nil: no password column.
    static func rows(csv text: String) -> (source: String, rows: [Row])? {
        let all = csv(text)
        guard let head = all.first else { return nil }
        let h = head.map { $0.trimmingCharacters(in: .whitespaces).lowercased() }
        func col(_ k: String) -> Int { for n in columns[k] ?? [] { if let i = h.firstIndex(of: n) { return i } }; return -1 }
        let ci = (url: col("url"), name: col("name"), user: col("user"), pass: col("pass"), note: col("note"), otp: col("otp"))
        guard ci.pass >= 0 else { return nil }
        let em = h.firstIndex(of: "email") ?? -1
        let source = h.contains("login_uri") ? "Bitwarden" : h.contains("otpauth") && h.contains("title") ? (h.contains("archived") ? "1Password" : "Apple Passwords")
            : h.contains("httprealm") ? "Firefox" : h.contains("group") && h.contains("title") ? "KeePassXC" : h.contains("name") && h.contains("url") ? "Chrome" : "a CSV file"
        let typeCol = h.firstIndex(of: "type") ?? -1
        var out: [Row] = []
        for r in all.dropFirst() {
            func g(_ i: Int) -> String { i >= 0 && i < r.count ? r[i] : "" }
            if source == "Bitwarden", typeCol >= 0, !g(typeCol).isEmpty, g(typeCol) != "login" { continue }   // cards, notes, identities
            var row = Row(url: g(ci.url), name: g(ci.name), user: g(ci.user), pass: g(ci.pass), note: g(ci.note), otp: g(ci.otp))
            if em >= 0, em != ci.user, !g(em).isEmpty, g(em) != row.user {
                if row.user.isEmpty { row.user = g(em) } else { row.note = "Email: " + g(em) + (row.note.isEmpty ? "" : "\n" + row.note) }
            }
            out.append(row)
        }
        return (source, out)
    }

    // MARK: The KEY's answers

    /// IMPORT_STATUS. 11bh adds `[queued][kept u16][done u16][n][n results]`:
    /// `done` items finished in the order sent, the results those of items
    /// done-n .. done-1. `ext` false: an 11bf KEY (7 bytes).
    struct Status: Equatable {
        var state: UInt8; var reason: UInt8; var saved: Int; var failed: Int; var last: UInt8
        var ext = false
        var queued = 0
        var kept = 0
        var done = 0
        var results: [UInt8] = []
    }

    static func parseStatus(_ b: Data) -> Status? {
        let v = [UInt8](b)
        guard v.count >= 7 else { return nil }
        var s = Status(state: v[0], reason: v[1], saved: Int(v[2]) | Int(v[3]) << 8, failed: Int(v[4]) | Int(v[5]) << 8, last: v[6])
        if v.count >= 13 {
            let n = Int(v[12])
            if v.count >= 13 + n {
                s.ext = true
                s.queued = Int(v[7]); s.kept = Int(v[8]) | Int(v[9]) << 8; s.done = Int(v[10]) | Int(v[11]) << 8
                s.results = Array(v[13..<(13 + n)])
            }
        }
        return s
    }

    static let keptResult: UInt8 = 0x17   // already on the KEY: kept, not replaced (11bh)

    /// Why the window didn't open (state 5) or closed (state 4).
    static func reasonText(_ r: UInt8, closed: Bool) -> String {
        switch r {
        case 0x00: return closed ? "The import was ended." : "The KEY didn't open the import."
        case 0x02: return closed ? "Closed with BACK on the KEY." : "Cancelled on the KEY (BACK, or 90 s on the PIN screen)."
        case 0x05: return "The KEY locked."
        case 0x06: return "A sign-in on a website took the KEY's screen. Try again."
        case 0x0E: return "The KEY's signer chip refused to open the import."
        case 0x13: return "The KEY allows one import per power-on. Restart the KEY, then try again."
        case 0x15: return "Three wrong PINs on the KEY. Restart the KEY, then try again."
        case 0x16: return "Closed after 10 minutes with nothing sent."
        default: return String(format: "The KEY answered 0x%02X.", r)
        }
    }

    /// An item's result (`last`) or an at-once IMPORT_ITEM status.
    static func itemText(_ s: UInt8) -> String {
        switch s {
        case 0x00: return "saved"
        case 0x17: return "already on the KEY (kept)"
        case 0x04: return "the KEY's signer chip is too old for one-time codes"
        case 0x07: return "the KEY couldn't read it"
        case 0x0E: return "the KEY couldn't seal or store it"
        case 0x10: return "the KEY is full (200 records)"
        case 0x12: return "too long for the KEY"
        case 0x14: return "the import window had closed"
        default: return String(format: "the KEY answered 0x%02X", s)
        }
    }

    /// IMPORT_BEGIN's status.
    static func beginText(_ s: UInt8) -> String {
        switch s {
        case 0x04: return "This KEY can't import: it needs signer chip firmware v19 and a vault set up."
        case 0x05: return "Your KEY is locked. Enter the VAULT PIN on the KEY, then try again."
        case 0x06: return "The KEY is busy with a save, a delete or another import. Finish it on the KEY first."
        case 0x13: return "The KEY allows one import per power-on. Restart the KEY, then try again."
        default: return String(format: "The KEY answered 0x%02X.", s)
        }
    }
}
