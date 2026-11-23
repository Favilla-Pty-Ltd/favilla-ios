// VaultCourier.swift - the vault's backup and restore through the app over
// Bluetooth (KEY 11q, firmware issue #14, 10 Nov 2026).
//
// The KEY's passkey and password records back up to vault.favillakey.io as one
// replaceable kind-30078 event signed by the vault publishing key on the G0. In
// the NOSTR Bluetooth life the KEY has no internet, so this iPhone is the
// courier: it fetches the relay's copy and hands it to the KEY (VAULT_PUT), the
// KEY checks, merges, exports and signs, the iPhone collects the signed frame
// (VAULT_GET) and publishes it, and tells the KEY what the relay said
// (VAULT_DONE). The iPhone sees ciphertext only and can't alter a record.
//
// Bytes (docs/BLE_PASSKEY_PROTOCOL.md, "The vault through the phone"):
//   0x3F VAULT_INFO  -> 0xBC [status][vault pub 32][last backup u32][records u16][dirty 1][asked 1][host]
//   0x40 VAULT_GET   [offset u32] -> 0xBD [status][total u32][offset u32][bytes]
//   0x41 VAULT_DONE  [ok][relay message] -> 0xB1 [status]
//   0x42 VAULT_PUT   [total u32][offset u32][bytes] -> 0xBE [state][result][added u16][removed u16]
// The 0xBB nudge's third byte: bit0 back up now, bit1 restore now.

import Foundation

enum Vault {
    static let cInfo: UInt8 = 0x3F, cGet: UInt8 = 0x40, cDone: UInt8 = 0x41, cPut: UInt8 = 0x42
    static let rInfo: UInt8 = 0xBC, rGet: UInt8 = 0xBD, rPut: UInt8 = 0xBE
    static let putChunk = 32_000

    struct Info: Equatable {
        var status: UInt8
        var pubkey: String
        var lastBackup: Date?
        var records: Int
        var dirty: Bool
        var asked: UInt8
        var host: String
        var relay: URL? { URL(string: "wss://" + host) }
    }

    static func decodeInfo(_ b: Data) -> Info? {
        let v = [UInt8](b)
        guard v.count >= 41 else { return nil }
        let pk = v[1..<33].map { String(format: "%02x", $0) }.joined()
        let t = u32(v, 33), n = Int(v[37]) | Int(v[38]) << 8
        guard let host = String(bytes: v[41...], encoding: .utf8), host.isEmpty || host.range(of: #"^[A-Za-z0-9.-]+(:[0-9]{1,5})?$"#, options: .regularExpression) != nil else { return nil }
        return Info(status: v[0], pubkey: pk, lastBackup: t == 0 ? nil : Date(timeIntervalSince1970: Double(t)), records: n, dirty: v[39] != 0, asked: v[40], host: host)
    }

    static func u32(_ v: [UInt8], _ i: Int) -> UInt32 { UInt32(v[i]) | UInt32(v[i + 1]) << 8 | UInt32(v[i + 2]) << 16 | UInt32(v[i + 3]) << 24 }
    static func le32(_ n: Int) -> [UInt8] { [UInt8(n & 0xFF), UInt8(n >> 8 & 0xFF), UInt8(n >> 16 & 0xFF), UInt8(n >> 24 & 0xFF)] }

    /// The KEY's VBR_* result codes, in words a person can act on.
    static func words(_ code: UInt8) -> String {
        switch code {
        case 0: return "Done."
        case 1: return "This KEY was set up before vault backups existed. Set it up again to get backup keys."
        case 2: return "The vault's publishing copy is missing. Open VAULT mode on the KEY once, then unlock it in NOSTR mode and try again."
        case 3: return "The KEY's signer chip firmware is too old for vault backups."
        case 4: return "The KEY is locked. Enter the NOSTR PIN on the KEY."
        case 5: return "The KEY has no link to the phone."
        case 6: return "The KEY's clock isn't set. Keep the app connected a moment and try again."
        case 7: return "The KEY couldn't export the vault."
        case 8: return "The KEY's signer chip refused to sign the backup."
        case 9: return "The relay couldn't be reached."
        case 10: return "The relay refused the backup."
        case 11: return "No backup found on the relay."
        case 12: return "The relay's copy failed its checks and was not used."
        case 13: return "The backup on the relay belongs to a different set of words. Nothing was changed."
        case 14: return "The backup needs the vault passphrase. Enter it on the KEY, then try again."
        case 15: return "Merging the backup failed."
        case 16: return "The KEY ran out of memory."
        case 17: return "A restore from the words is pending on the KEY. Restore first."
        case 18: return "The relay's copy holds entries this KEY can't keep."
        case 19: return "That backup is older than this KEY's last one. Nothing was imported."
        default: return "The KEY answered code \(code)."
        }
    }

    struct Failure: Error, CustomStringConvertible { let description: String; init(_ s: String) { description = s } }

    // MARK: - The relay

    /// The newest kind-30078 "favilla-vault" event by the vault key, as the JSON
    /// object text between the outer braces, or nil when the relay has none.
    static func fetchBackup(relay: URL, pubkey: String, timeout: TimeInterval = 10) async throws -> String? {
        let ws = URLSession.shared.webSocketTask(with: relay)
        ws.resume()
        let killer = Task { try? await Task.sleep(nanoseconds: UInt64(timeout * 1e9)); ws.cancel(with: .goingAway, reason: nil) }
        defer { killer.cancel(); ws.cancel(with: .goingAway, reason: nil) }
        let req: [Any] = ["REQ", "v", ["kinds": [30078], "authors": [pubkey], "#d": ["favilla-vault"], "limit": 1]]
        let text = String(data: try JSONSerialization.data(withJSONObject: req), encoding: .utf8)!
        do { try await ws.send(.string(text)) } catch { throw Failure("The vault relay couldn't be reached.") }
        var best: (Int, String)?
        while true {
            guard let msg = try? await ws.receive(), case .string(let s) = msg else {
                if best == nil { throw Failure("The vault relay couldn't be reached.") }
                break
            }
            guard let j = try? JSONSerialization.jsonObject(with: Data(s.utf8)) as? [Any], let kind = j.first as? String else { continue }
            if kind == "EOSE" { break }
            if kind == "CLOSED" || kind == "NOTICE" { throw Failure("The vault relay refused the request: " + ((j.count > 2 ? j[2] : j.last) as? String ?? "")) }
            if kind == "EVENT", j.count >= 3, let ev = j[2] as? [String: Any], ev["kind"] as? Int == 30078,
               (ev["pubkey"] as? String)?.lowercased() == pubkey, let at = ev["created_at"] as? Int {
                // The KEY verifies the signature itself; the text it gets is the
                // event exactly as the relay sent it, so re-encoding must not
                // change a byte: take the object out of the raw frame.
                if let obj = objectText(in: s), at >= (best?.0 ?? -1) { best = (at, obj) }
            }
        }
        return best?.1
    }

    /// The `{...}` of the event inside a `["EVENT","sub",{...}]` frame, verbatim.
    static func objectText(in frame: String) -> String? {
        guard let start = frame.firstIndex(of: "{"), let end = frame.lastIndex(of: "}") , start < end else { return nil }
        return String(frame[start...end])
    }

    /// Publish the KEY's signed frame as is; the relay's OK (accepted, message).
    static func publish(frame: String, relay: URL, timeout: TimeInterval = 10) async -> (ok: Bool, message: String)? {
        let ws = URLSession.shared.webSocketTask(with: relay)
        ws.resume()
        let killer = Task { try? await Task.sleep(nanoseconds: UInt64(timeout * 1e9)); ws.cancel(with: .goingAway, reason: nil) }
        defer { killer.cancel(); ws.cancel(with: .goingAway, reason: nil) }
        guard (try? await ws.send(.string(frame))) != nil else { return nil }
        let id: String? = (try? JSONSerialization.jsonObject(with: Data(frame.utf8)) as? [Any]).flatMap { $0.count > 1 ? $0[1] as? [String: Any] : nil }?["id"] as? String
        while true {
            guard let msg = try? await ws.receive(), case .string(let s) = msg else { return nil }
            guard let j = try? JSONSerialization.jsonObject(with: Data(s.utf8)) as? [Any], j.count >= 3, j[0] as? String == "OK" else { continue }
            if let id, j[1] as? String != id { continue }
            return (j[2] as? Bool == true, j.count > 3 ? (j[3] as? String ?? "") : "")
        }
    }

    // MARK: - Through the KEY

    enum Outcome {
        case backedUp(Info?)            // the relay took the signed frame
        case restored(added: Int, removed: Int, result: UInt8)
        case failed(String)
    }

    static func refusal(_ a: AppChannel.Answer) -> String? {
        guard a.rsp == AppChannel.rErr else { return nil }
        switch a.body.first ?? 0xFF {
        case 0x04: return "Your KEY isn't in Bluetooth mode. On the KEY: Settings > Network > Change mode > Bluetooth."
        case 0x05: return "Your KEY is locked. Enter the NOSTR PIN on the KEY."
        case 0x06: return "busy"
        default: return AppChannel.statusText(a.body.first ?? 0xFF)
        }
    }

    static func info(_ k: ChannelCaller) async throws -> Info {
        let a = try await k.request(cInfo, Data(), timeout: 6)
        if let why = refusal(a) { throw Failure(why) }
        guard a.rsp == rInfo, let i = decodeInfo(a.body) else { throw Failure("The KEY doesn't have vault backup over Bluetooth yet (firmware 11q).") }
        return i
    }

    /// Where a run is, for the page to show (issue #59): the same steps the KEY shows.
    enum Step: Equatable {
        case checking(Double)   // the relay's copy on its way into the KEY, 0 to 1
        case merging            // the KEY checks and merges it
        case sealing(Double)    // the KEY's signed backup on its way out, 0 to 1
        case relay              // handed to the relay, waiting for its answer
    }

    /// Steps 1 and 2: the relay's copy into the KEY. Returns the KEY's verdict.
    static func restore(_ k: ChannelCaller, info: Info, log: (String) -> Void, step: (Step) -> Void = { _ in }) async throws -> (result: UInt8, added: Int, removed: Int) {
        guard let relay = info.relay else { throw Failure("The KEY named no vault relay.") }
        guard info.status == 0 || info.status == 11 else { throw Failure(words(info.status)) }
        step(.checking(0))
        let copy = try await fetchBackup(relay: relay, pubkey: info.pubkey)
        let bytes = Data((copy ?? "").utf8)
        log(copy == nil ? "relay \(info.host): no backup there" : "relay \(info.host): backup of \(bytes.count) bytes")
        var offset = 0
        var last: AppChannel.Answer?
        repeat {
            let n = min(putChunk, bytes.count - offset)
            var body = Data(le32(bytes.count) + le32(offset))
            body.append(bytes.subdata(in: offset..<(offset + n)))
            let a = try await k.request(cPut, body, timeout: 12)
            if let why = refusal(a) { throw Failure(why) }
            guard a.rsp == rPut, a.body.count >= 6 else { throw Failure("The KEY's answer to the vault copy couldn't be read.") }
            last = a
            offset += n
            step(.checking(bytes.isEmpty ? 1 : Double(offset) / Double(bytes.count)))
        } while offset < bytes.count
        step(.merging)
        // The KEY checks and merges on its main loop: state 2 means "still working".
        var polls = 0
        while let a = last, a.body[0] == 2, polls < 60 {
            try? await Task.sleep(nanoseconds: 1_000_000_000)
            polls += 1
            let a2 = try await k.request(cPut, Data(le32(bytes.count) + le32(bytes.count)), timeout: 8)
            if let why = refusal(a2) { throw Failure(why) }
            guard a2.rsp == rPut, a2.body.count >= 6 else { throw Failure("The KEY's answer to the vault copy couldn't be read.") }
            last = a2
        }
        guard let a = last, a.body[0] == 1 else { throw Failure("The KEY didn't finish checking the relay's copy.") }
        let v = [UInt8](a.body)
        return (v[1], Int(v[2]) | Int(v[3]) << 8, Int(v[4]) | Int(v[5]) << 8)
    }

    /// The whole backup: restore (merge the relay's copy), then collect the KEY's
    /// signed frame, publish it, and tell the KEY what the relay said.
    ///
    /// Issue #35 (16 Nov): once the KEY has staged the frame it waits 90 s for
    /// VAULT_DONE. So from VAULT_GET on, a dropped link is reconnected and the
    /// step tried again, and whatever happens the KEY hears VAULT_DONE: [1] the
    /// relay took it, [0] refused, [2] not reached (also when the frame never
    /// arrived whole), never silence.
    static func backup(_ k: ChannelCaller, log: (String) -> Void, step: (Step) -> Void = { _ in }) async -> Outcome {
        let info: Info, relay: URL
        do {
            info = try await self.info(k)
            guard let r = info.relay else { return .failed("The KEY named no vault relay.") }
            relay = r
            let m = try await restore(k, info: info, log: log, step: step)
            log("KEY merged the relay's copy: result \(m.result), \(m.added) added, \(m.removed) removed")
            // 19 (KEY 11bd, issue #33): the relay's copy is older than this KEY's last
            // backup and was not merged. Carry on: the KEY's newer copy replaces it.
            if m.result == 19 { log("the relay's copy is older than the KEY's last backup: not merged, the KEY's copy replaces it") }
            guard m.result == 0 || m.result == 11 || m.result == 19 else { return .failed(words(m.result)) }
        } catch {
            return .failed("\(error)")
        }
        // 3. the signed frame, in chunks; a dropped link costs a retry, not the run.
        var frame = Data(), total = -1, offset = 0, busy = 0, drops = 0
        var problem: String?
        step(.sealing(0))
        while total < 0 || offset < total {
            let a: AppChannel.Answer
            do { a = try await k.request(cGet, Data(le32(offset)), timeout: 30) }
            catch {
                drops += 1
                log("VAULT_GET at \(offset) failed (\(error)); try \(drops) of 3")
                if drops >= 3 { problem = "The link to the KEY kept dropping while the backup came across."; break }
                // From the start: if the KEY staged the frame again, its chunks
                // must not be mixed with the first copy's.
                frame = Data(); total = -1; offset = 0
                try? await Task.sleep(nanoseconds: 1_000_000_000)
                continue
            }
            if a.rsp == AppChannel.rErr, a.body.first == 0x06 {
                busy += 1
                if busy >= 15 { problem = "The KEY didn't finish signing the backup."; break }
                try? await Task.sleep(nanoseconds: 1_000_000_000)
                continue
            }
            if let why = refusal(a) { problem = why; break }
            guard a.rsp == rGet, a.body.count >= 9 else { problem = "The KEY's backup chunk couldn't be read."; break }
            let v = [UInt8](a.body)
            guard v[0] == 0 else { return .failed(words(v[0])) }   // the KEY refused: nothing staged, no DONE owed
            let t = Int(u32(v, 1)), o = Int(u32(v, 5))
            guard o == offset, t > 0, t <= 400_000 else { problem = "The KEY's backup chunks came out of order."; break }
            if v.count == 9 { problem = "The KEY sent an empty backup chunk."; break }
            total = t
            frame.append(contentsOf: v[9...])
            offset = frame.count
            step(.sealing(Double(offset) / Double(total)))
        }
        var text: String?
        if problem == nil {
            text = String(data: frame, encoding: .utf8)
            if text?.hasPrefix("[\"EVENT\"") != true { problem = "The KEY's backup frame isn't a relay message."; text = nil }
            else { log("signed backup from the KEY: \(frame.count) bytes") }
        }
        // 4. publish
        var ok: (ok: Bool, message: String)?
        if let text { step(.relay); ok = await publish(frame: text, relay: relay) }
        // 5. report, always: [1] taken, [0] refused, [2] not reached or never sent.
        var done = Data([ok == nil ? 2 : (ok!.ok ? 1 : 0)])
        if let ok, !ok.ok { done.append(Data(ok.message.prefix(200).utf8)) }
        if let problem { done.append(Data(("app: " + problem).prefix(200).utf8)) }
        var told = false
        for attempt in 1...3 where !told {
            do {
                let d = try await k.request(cDone, done, timeout: 10)
                if let why = refusal(d) { log("VAULT_DONE refused: \(why)") }
                told = true
            } catch {
                log("VAULT_DONE try \(attempt) failed: \(error)")
                try? await Task.sleep(nanoseconds: 1_500_000_000)
            }
        }
        log(String(format: "VAULT_DONE [%d] %@", done[0], told ? "sent" : "NOT delivered"))
        if let problem { return .failed(problem) }
        guard let ok else { return .failed("The vault relay couldn't be reached. The KEY keeps the backup pending.") }
        guard ok.ok else { return .failed("The relay refused the backup: " + ok.message) }
        log("relay \(info.host): OK")
        return .backedUp(try? await self.info(k))
    }

    static func restoreOnly(_ k: ChannelCaller, log: (String) -> Void, step: (Step) -> Void = { _ in }) async -> Outcome {
        do {
            let info = try await info(k)
            let r = try await restore(k, info: info, log: log, step: step)
            return .restored(added: r.added, removed: r.removed, result: r.result)
        } catch {
            return .failed("\(error)")
        }
    }
}
