// Bunker.swift - the Bluetooth bunker (9 Nov 2026, firmware issue #11).
//
// The KEY in Bluetooth mode runs its own NIP-46 bunker but has no internet. The
// phone carries it: the push bridge on relay.favillakey.io (server/push-bridge)
// wakes the notification extension when a request arrives; the extension
// fetches the waiting requests, hands each to the KEY over the paired app
// channel, collects the KEY's replies and publishes them to the relays.
//
// Bytes as proposed in issue #11 (the firmware chat's doc is final):
//   0x3B NIP46       body: one kind-24133 event, JSON          -> 0xB9
//   0x3C NIP46_POLL  empty                                     -> 0xB9
//   0x3D BUNKER_INFO empty                                     -> 0xBA
//   0xB9 (MAC'd, not encrypted): [flags 1: bit0 more to come][count 1] per reply [len u16 LE][relay message]
//   0xBA (not encrypted): [pubkey 32][relay count 1] per relay [len 1][host]

import Foundation

/// Something that can send one app-channel request and return the answer:
/// KeySession in the notification extension, NostrLink in the app.
protocol ChannelCaller {
    func request(_ cmd: UInt8, _ body: Data, timeout: TimeInterval) async throws -> AppChannel.Answer
}

extension KeySession: ChannelCaller {}

enum Bunker {
    static let cNip46: UInt8 = 0x3B
    static let cPoll: UInt8 = 0x3C
    static let cInfo: UInt8 = 0x3D
    static let rNip46: UInt8 = 0xB9
    static let rInfo: UInt8 = 0xBA

    static let bridge = URL(string: "https://relay.favillakey.io/push")!
    private static let group = "group.io.favillakey.app"
    static var store: UserDefaults { UserDefaults(suiteName: group) ?? .standard }

    // MARK: - Bytes

    struct Replies: Equatable {
        var more: Bool
        var messages: [Data]      // relay messages: ["EVENT",{...}]
    }

    static func decodeReplies(_ b: Data) -> Replies? {
        let v = [UInt8](b)
        guard v.count >= 2 else { return nil }
        var off = 2, out: [Data] = []
        for _ in 0..<Int(v[1]) {
            guard off + 2 <= v.count else { return nil }
            let n = Int(v[off]) | Int(v[off + 1]) << 8
            off += 2
            guard n > 0, off + n <= v.count else { return nil }
            out.append(Data(v[off..<(off + n)]))
            off += n
        }
        guard off == v.count else { return nil }
        return Replies(more: v[0] & 1 != 0, messages: out)
    }

    struct Info: Codable, Equatable {
        var pubkey: String        // hex
        var relays: [String]      // wss:// URLs

        static let key = "bunkerInfo"
        static func load() -> Info? { store.data(forKey: key).flatMap { try? JSONDecoder().decode(Info.self, from: $0) } }
        func save() { Bunker.store.set(try? JSONEncoder().encode(self), forKey: Info.key) }
    }

    static func decodeInfo(_ b: Data) -> Info? {
        let v = [UInt8](b)
        guard v.count >= 33 else { return nil }
        let pk = v[0..<32].map { String(format: "%02x", $0) }.joined()
        var off = 33, relays: [String] = []
        for _ in 0..<Int(v[32]) {
            guard off < v.count else { return nil }
            let n = Int(v[off]); off += 1
            guard n > 0, off + n <= v.count, let h = String(bytes: v[off..<(off + n)], encoding: .utf8),
                  h.range(of: #"^[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?$"#, options: .regularExpression) != nil else { return nil }
            relays.append("wss://" + h)
            off += n
        }
        guard off == v.count, !relays.isEmpty else { return nil }
        return Info(pubkey: pk, relays: relays)
    }

    // MARK: - Requests already handled (app and extension share this)

    static func seen(_ id: String) -> Bool { (store.dictionary(forKey: "bunkerSeen") as? [String: Double])?[id] != nil }

    static func markSeen(_ ids: [String]) {
        var d = (store.dictionary(forKey: "bunkerSeen") as? [String: Double]) ?? [:]
        let now = Date().timeIntervalSince1970
        for id in ids { d[id] = now }
        d = d.filter { now - $0.value < 600 }          // requests live 2 minutes at the bridge
        store.set(d, forKey: "bunkerSeen")
    }

    // MARK: - Who handles a request

    /// The app, while open with the bunker on, listens to the relays itself and
    /// beats this every few seconds; the extension then leaves the KEY to it.
    static func beat() { store.set(Date().timeIntervalSince1970, forKey: "bunkerAppAt") }
    static func stopBeat() { store.removeObject(forKey: "bunkerAppAt") }
    static var appActive: Bool { Date().timeIntervalSince1970 - store.double(forKey: "bunkerAppAt") < 8 }

    static var on: Bool {
        get { store.bool(forKey: "bunkerOn") }
        set { store.set(newValue, forKey: "bunkerOn") }
    }

    /// One line for the log the app shows (Settings > This iPhone > Bunker).
    static func log(_ line: String) {
        var all = store.stringArray(forKey: "bunkerLog") ?? []
        all.append(ISO8601DateFormatter().string(from: Date()) + " " + line)
        store.set(Array(all.suffix(40)), forKey: "bunkerLog")
    }

    /// The 0xB9 answer, or a sentence saying why not.
    static func replies(_ a: AppChannel.Answer) -> Result<Replies, KeySession.Failure> {
        if a.rsp == rNip46, let r = decodeReplies(a.body) { return .success(r) }
        if a.rsp == AppChannel.rErr { return .failure(KeySession.Failure(refusal(a.body.first ?? 0xFF))) }
        return .failure(KeySession.Failure(String(format: "The KEY answered type %02x (needs the bunker drop, issue #11).", a.rsp)))
    }

    static func refusal(_ st: UInt8) -> String {
        switch st {
        case 0x04: return "Your KEY isn't in Bluetooth mode. On the KEY: Settings > Network > Change mode > Bluetooth."   // S_NOT_HERE
        case 0x05: return "Your KEY is locked. Enter the NOSTR PIN on the KEY."                                              // S_LOCKED
        case 0x06: return "An approval is on the KEY's screen, or it has 8 requests waiting. Trying again shortly."   // S_BUSY
        case 0x07: return "The KEY couldn't read that request."                                                         // S_BAD_REQUEST
        default: return AppChannel.statusText(st)
        }
    }

    // MARK: - Serving requests through the KEY

    struct Outcome: Equatable {
        var taken = 0          // requests the KEY took
        var sent = 0           // replies a relay accepted
        var replies = 0        // replies the KEY gave
        var waiting = false    // the KEY still had more to come (an approval on the KEY) when time ran out
        var error: String?
        var later: [(String, Data)] = []   // refused busy (S_BUSY): not taken, try again

        static func == (a: Outcome, b: Outcome) -> Bool {
            a.taken == b.taken && a.sent == b.sent && a.replies == b.replies && a.waiting == b.waiting && a.error == b.error && a.later.map { $0.0 } == b.later.map { $0.0 }
        }
    }

    static let sBusy: UInt8 = 0x06, sBadRequest: UInt8 = 0x07

    /// Hand each request to the KEY, publish its replies as they come, and poll
    /// while the KEY says more is coming (a request waiting for approval on the
    /// KEY, or encrypt/decrypt on its worker), until `deadline`.
    static func serve(_ reqs: [(String, Data)], via k: ChannelCaller, relays: [String], until deadline: Date,
                      poll: Bool = false, note: ((Outcome) -> Void)? = nil) async -> Outcome {
        var o = Outcome()
        var more = poll
        func take(_ a: AppChannel.Answer) async -> Bool {
            switch replies(a) {
            case .failure(let e): o.error = e.description; return false
            case .success(let r):
                more = r.more
                o.replies += r.messages.count
                if !r.messages.isEmpty {
                    let n = await publish(r.messages, to: relays, timeout: max(1, min(5, deadline.timeIntervalSinceNow)))
                    o.sent += n
                    log("published \(r.messages.count) repl\(r.messages.count == 1 ? "y" : "ies"), \(n) accepted")
                }
                note?(o)
                return true
            }
        }
        var pending = reqs
        while true {
            o.later = []
            for (i, (id, ev)) in pending.enumerated() {
                guard ev.count <= 32_768 else { log("request \(id.prefix(8)) too large, skipped"); markSeen([id]); continue }
                do {
                    let a = try await k.request(cNip46, ev, timeout: 12)
                    if a.rsp == AppChannel.rErr, let st = a.body.first, st == sBusy {
                        // An approval on the KEY's screen, or its queue is full: this and the rest wait.
                        o.later = Array(pending[i...])
                        more = true
                        log("KEY busy: \(o.later.count) request\(o.later.count == 1 ? "" : "s") wait")
                        break
                    }
                    if a.rsp == AppChannel.rErr, let st = a.body.first, st == sBadRequest {
                        markSeen([id]); log("request \(id.prefix(8)) refused as unreadable"); continue
                    }
                    guard await take(a) else { break }
                    markSeen([id])
                    o.taken += 1
                    log("request \(id.prefix(8)) taken by the KEY")
                } catch {
                    o.error = "\(error)"; break
                }
            }
            // Replies the KEY finishes later (an approval, encrypt/decrypt on its worker).
            while more, o.error == nil, deadline.timeIntervalSinceNow > 0.6 {
                try? await Task.sleep(nanoseconds: 500_000_000)
                do { guard await take(try await k.request(cPoll, Data(), timeout: 12)) else { break } } catch { o.error = "\(error)"; break }
            }
            // The KEY is free again: the requests it was too busy for, once more.
            guard !o.later.isEmpty, !more, o.error == nil, deadline.timeIntervalSinceNow > 2 else { break }
            pending = o.later
        }
        o.waiting = more && o.error == nil
        return o
    }

    // MARK: - The push bridge

    static func register(token: String, env: String, info: Info) async throws {
        var q = URLRequest(url: bridge.appendingPathComponent("register"), timeoutInterval: 15)
        q.httpMethod = "POST"
        q.setValue("application/json", forHTTPHeaderField: "Content-Type")
        q.httpBody = try JSONSerialization.data(withJSONObject: ["pubkey": info.pubkey, "token": token, "env": env, "relays": info.relays])
        let (d, r) = try await URLSession.shared.data(for: q)
        guard (r as? HTTPURLResponse)?.statusCode == 200 else {
            throw NSError(domain: "bunker", code: (r as? HTTPURLResponse)?.statusCode ?? 0,
                          userInfo: [NSLocalizedDescriptionKey: "The push bridge refused the registration: " + (String(data: d, encoding: .utf8) ?? "")])
        }
    }

    static func unregister(token: String, pubkey: String) async {
        var q = URLRequest(url: bridge.appendingPathComponent("unregister"), timeoutInterval: 10)
        q.httpMethod = "POST"
        q.setValue("application/json", forHTTPHeaderField: "Content-Type")
        q.httpBody = try? JSONSerialization.data(withJSONObject: ["pubkey": pubkey, "token": token])
        _ = try? await URLSession.shared.data(for: q)
    }

    /// The requests waiting at the bridge that haven't been handled here yet: (id, event JSON).
    static func pending(pubkey: String) async throws -> [(String, Data)] {
        var c = URLComponents(url: bridge.appendingPathComponent("pending"), resolvingAgainstBaseURL: false)!
        c.queryItems = [URLQueryItem(name: "pubkey", value: pubkey)]
        let (d, r) = try await URLSession.shared.data(for: URLRequest(url: c.url!, timeoutInterval: 8))
        guard (r as? HTTPURLResponse)?.statusCode == 200,
              let j = try? JSONSerialization.jsonObject(with: d) as? [String: Any],
              let evs = j["events"] as? [[String: Any]] else { return [] }
        return evs.compactMap { e in
            guard let id = e["id"] as? String, !seen(id), let data = try? JSONSerialization.data(withJSONObject: e) else { return nil }
            return (id, data)
        }
    }

    // MARK: - Publishing replies

    /// Send each relay message to every relay; true if at least one relay took each.
    /// NIP-46 replies are ephemeral: the client is subscribed and waiting, so one
    /// relay accepting is enough.
    static func publish(_ messages: [Data], to relays: [String], timeout: TimeInterval = 6) async -> Int {
        guard !messages.isEmpty else { return 0 }
        return await withTaskGroup(of: Int.self) { g in
            for r in relays {
                guard let url = URL(string: r) else { continue }
                g.addTask { await publish(messages, to: url, timeout: timeout) }
            }
            var best = 0
            for await n in g { best = max(best, n) }
            return best
        }
    }

    private static func publish(_ messages: [Data], to url: URL, timeout: TimeInterval) async -> Int {
        let ws = URLSession.shared.webSocketTask(with: url)
        ws.resume()
        defer { ws.cancel(with: .goingAway, reason: nil) }
        var ids = Set<String>()
        for m in messages {
            guard let s = String(data: m, encoding: .utf8) else { continue }
            if let j = try? JSONSerialization.jsonObject(with: m) as? [Any], j.count >= 2,
               let ev = j[1] as? [String: Any], let id = ev["id"] as? String { ids.insert(id) }
            do { try await ws.send(.string(s)) } catch { return 0 }
        }
        // Count the OKs that come back in time.
        var accepted = 0
        let deadline = Date().addingTimeInterval(timeout)
        while accepted < ids.count, Date() < deadline {
            let msg: URLSessionWebSocketTask.Message? = await withTaskGroup(of: URLSessionWebSocketTask.Message?.self) { g in
                g.addTask { try? await ws.receive() }
                g.addTask { try? await Task.sleep(nanoseconds: UInt64(max(0.1, deadline.timeIntervalSinceNow) * 1e9)); return nil }
                let first = await g.next() ?? nil
                g.cancelAll()
                return first
            }
            guard let msg, case .string(let s) = msg else { break }
            if let j = try? JSONSerialization.jsonObject(with: Data(s.utf8)) as? [Any], j.count >= 3,
               j[0] as? String == "OK", let id = j[1] as? String, ids.contains(id), j[2] as? Bool == true {
                accepted += 1
            }
        }
        return accepted
    }
}
