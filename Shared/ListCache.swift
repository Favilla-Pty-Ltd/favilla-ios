import Foundation
import CryptoKit

// The app's copy of the account list (KEY 11gm, firmware issues #92 and #93;
// protocol doc, "The account list cache"). VAULT opens at once from this copy,
// the KEY is asked only whether its list changed (LIST_STATE), and the AutoFill
// flows ask for one site (FIND) instead of the whole list.
//
// What is kept: the LIST v2 pages as the KEY sent them (sites, usernames,
// health, ids; never a password), AES-GCM under a random cache key. The cache
// key is kept only wrapped, AES-GCM under SHA-256(answer), where the answer is
// the KEY's LIST_ANSWER to a random challenge kept beside it. The KEY can give
// that answer only with the VAULT PIN in, and a restore or a new setup makes
// it give a different one: then the wrap does not open, the copy is deleted
// without a word, and the list is read as on first use.
enum ListCache {
    struct Stored: Codable, Equatable {
        var v = 1
        var challenge: Data      // 32 random bytes
        var wrap: Data           // the cache key, sealed under SHA-256(answer)
        var state: Data          // LIST_STATE when the pages were read
        var box: Data            // the pages, sealed under the cache key
    }

    enum State: Equatable {
        case state(Data)         // 16 bytes
        case locked              // no VAULT PIN: the list leaves memory
        case old                 // a KEY before 11gm: behave as before
        case refused(UInt8)
    }

    enum Found: Equatable {
        case hits([AppChannel.ListEntry])
        case old                 // a KEY before 11gm, or a name FIND can't take: page LIST as before
        case refused(UInt8)
    }

    // MARK: - Sealing (no KEY bytes; tested)

    static func pack(_ pages: [Data]) -> Data {
        var d = Data()
        for p in pages { d.append(UInt8(p.count >> 8)); d.append(UInt8(p.count & 0xFF)); d.append(p) }
        return d
    }

    static func unpack(_ d: Data) -> [Data]? {
        let b = [UInt8](d)
        var out: [Data] = [], i = 0
        while i < b.count {
            guard i + 2 <= b.count else { return nil }
            let n = Int(b[i]) << 8 | Int(b[i + 1])
            i += 2
            guard i + n <= b.count else { return nil }
            out.append(Data(b[i..<i + n]))
            i += n
        }
        return out
    }

    static func entries(_ pages: [Data]) -> [AppChannel.ListEntry] {
        pages.flatMap { (try? AppChannel.parseList($0))?.entries ?? [] }
    }

    private static func wrapKey(_ answer: Data) -> SymmetricKey { SymmetricKey(data: Data(SHA256.hash(data: answer))) }

    static func make(pages: [Data], state: Data, challenge: Data, answer: Data, key: SymmetricKey = SymmetricKey(size: .bits256)) -> Stored? {
        let raw = key.withUnsafeBytes { Data($0) }
        guard challenge.count == 32, answer.count == 32,
              let wrap = try? AES.GCM.seal(raw, using: wrapKey(answer), authenticating: challenge).combined,
              let box = try? AES.GCM.seal(pack(pages), using: key, authenticating: state).combined else { return nil }
        return Stored(challenge: challenge, wrap: wrap, state: state, box: box)
    }

    /// nil when the answer does not open the wrap (a restore, a new setup,
    /// another KEY) or the copy is damaged.
    static func open(_ s: Stored, answer: Data) -> (key: SymmetricKey, pages: [Data])? {
        guard let w = try? AES.GCM.SealedBox(combined: s.wrap),
              let raw = try? AES.GCM.open(w, using: wrapKey(answer), authenticating: s.challenge), raw.count == 32 else { return nil }
        let key = SymmetricKey(data: raw)
        guard let b = try? AES.GCM.SealedBox(combined: s.box),
              let plain = try? AES.GCM.open(b, using: key, authenticating: s.state),
              let pages = unpack(plain) else { return nil }
        return (key, pages)
    }

    /// The same pages and cache key under a fresh challenge (after each unlock).
    static func rewrapped(_ s: Stored, key: SymmetricKey, challenge: Data, answer: Data) -> Stored? {
        let raw = key.withUnsafeBytes { Data($0) }
        guard challenge.count == 32, answer.count == 32,
              let wrap = try? AES.GCM.seal(raw, using: wrapKey(answer), authenticating: challenge).combined else { return nil }
        var out = s
        out.challenge = challenge; out.wrap = wrap
        return out
    }

    static func newChallenge() -> Data { Data((0..<32).map { _ in UInt8.random(in: 0...255) }) }

    // MARK: - On disk (the shared container: the AutoFill sheets read it too)

    private static var url: URL? {
        FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: "group.io.favillakey.app")?.appendingPathComponent("accountlist.cache")
    }

    static func load() -> Stored? {
        guard let u = url, let d = try? Data(contentsOf: u) else { return nil }
        return try? JSONDecoder().decode(Stored.self, from: d)
    }

    static func save(_ s: Stored) {
        guard let u = url, let d = try? JSONEncoder().encode(s) else { return }
        try? d.write(to: u, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
    }

    static func delete() {
        if let u = url { try? FileManager.default.removeItem(at: u) }
    }

    // MARK: - The KEY

    /// LIST_STATE. "Names not open yet" (0x06) is asked again, about a second apart.
    static func state(_ s: KeySession) async throws -> State {
        for _ in 0..<8 {
            let a = try await s.request(AppChannel.cListState, Data(), timeout: 6)
            if a.rsp == AppChannel.rErr {
                let st = a.body.first ?? 0xFF
                return st == 0x07 ? .old : st == 0x05 ? .locked : .refused(st)
            }
            guard a.rsp == AppChannel.rListState, let st = a.body.first else { return .old }
            if st == 0x00, a.body.count >= 17 { return .state(Data([UInt8](a.body)[1..<17])) }
            if st == 0x05 { return .locked }
            guard st == 0x06 else { return .refused(st) }
            try await Task.sleep(nanoseconds: 1_000_000_000)
        }
        return .refused(0x06)
    }

    /// LIST_ANSWER for a challenge; nil when the KEY gave none (locked, busy, older).
    static func answer(_ s: KeySession, _ challenge: Data) async throws -> Data? {
        let a = try await s.request(AppChannel.cListAnswer, challenge, timeout: 6)
        guard a.rsp == AppChannel.rListAnswer, a.body.first == 0x00, a.body.count >= 33 else { return nil }
        return Data([UInt8](a.body)[1..<33])
    }

    /// Keep these pages: a new cache key, a new challenge, the KEY's answer to it.
    static func store(_ s: KeySession, pages: [Data], state: Data) async {
        let c = newChallenge()
        guard let ans = try? await answer(s, c), let made = make(pages: pages, state: state, challenge: c, answer: ans) else { return }
        save(made)
    }

    /// After an unlock: the same copy under a fresh challenge.
    static func rewrap(_ s: KeySession, _ kept: Stored, key: SymmetricKey) async {
        let c = newChallenge()
        guard let ans = try? await answer(s, c), let next = rewrapped(kept, key: key, challenge: c, answer: ans) else { return }
        save(next)
    }

    /// FIND for one site. With "names still loading" and nothing matched, once
    /// more about a second later.
    static func find(_ s: KeySession, site: String, isApp: Bool) async throws -> Found {
        guard let name = KeyLink.siteBytes(site: site, appName: isApp), !name.isEmpty, name.count <= 100 else { return .old }
        for attempt in 0..<2 {
            let a = try await s.request(AppChannel.cFind, Data([UInt8(name.count)]) + name, timeout: 8)
            if a.rsp == AppChannel.rErr {
                let st = a.body.first ?? 0xFF
                return st == 0x07 ? .old : .refused(st)
            }
            guard a.rsp == AppChannel.rFind else { return .old }
            let page: AppChannel.FindPage
            do { page = try AppChannel.parseFind(a.body) } catch AppChannel.BodyFailure.status(let st) { return .refused(st) }
            // The KEY matches as FILL does; a close name alone (score 1) is not this site.
            var hits: [AppChannel.ListEntry] = []
            for (e, score) in zip(page.hits, page.scores) where !e.site.hasSuffix(" (old)") && (score >= 2 || NewPassword.same(e.site, site, isApp: isApp)) { hits.append(e) }
            if hits.isEmpty, page.loading, attempt == 0 {
                try await Task.sleep(nanoseconds: 1_000_000_000)
                continue
            }
            return .hits(hits)
        }
        return .hits([])
    }

    /// How often each username is used, for the suggestions in the AutoFill
    /// sheets: from this iPhone's copy when the KEY opens it. Empty otherwise.
    static func usernames(_ s: KeySession) async -> [String: Int] {
        guard let kept = load(), let ans = try? await answer(s, kept.challenge), let opened = open(kept, answer: ans) else { return [:] }
        var seen: [String: Int] = [:]
        for e in entries(opened.pages) where !e.passkey && !e.user.isEmpty && !e.site.hasSuffix(" (old)") { seen[e.user, default: 0] += 1 }
        return seen
    }
}
