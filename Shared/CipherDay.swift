// CipherDay.swift - CIPHER's daily block over Bluetooth (KEY 11bt, issue #48).
//
// CIPHER's DAILY board is seeded by the first block of each 144-block Bitcoin
// day. In the NOSTR Bluetooth life the KEY has no internet, so the app fetches
// the block from favillakey.io and hands the text over unchanged (CIPHER_DAY
// 0x50). The app is only a courier: the KEY checks the block itself. Sent once
// after each connect (after TIME) and whenever a nudge has bit2 set.

import Foundation

enum CipherDay {
    static let cDay: UInt8 = 0x50
    static let askBit: UInt8 = 0x04          // R_NUDGE third byte, bit2: "send me today's CIPHER block"
    static let source = URL(string: "https://favillakey.io/api/cipher/day")!

    /// The body for CIPHER_DAY: the source's text as it came, whitespace around
    /// it dropped, 1 to 199 bytes. nil: nothing to send.
    static func body(_ text: String) -> Data? {
        let d = Data(text.trimmingCharacters(in: .whitespacesAndNewlines).utf8)
        return (1...199).contains(d.count) ? d : nil
    }

    /// R_ACK to CIPHER_DAY: [status][height u32 LE].
    static func parse(_ b: Data) -> (status: UInt8, height: UInt32)? {
        let v = [UInt8](b)
        guard v.count >= 5 else { return nil }
        return (v[0], UInt32(v[1]) | UInt32(v[2]) << 8 | UInt32(v[3]) << 16 | UInt32(v[4]) << 24)
    }

    // What the courier remembers between sends (main actor only).
    @MainActor private static var busy = false
    @MainActor private static var cached: (Data, Date)?      // the last text fetched
    @MainActor private static var refused: Data?             // a text the KEY turned down: not sent again
    @MainActor private static var failedAt = Date.distantPast
    @MainActor private static var loggedHeight: UInt32 = 0   // the last height written to the log

    /// Fetch and hand over. `fresh`: the KEY asked (it holds no current block),
    /// so a text fetched earlier is not good enough. One line in the bunker log.
    @MainActor
    static func send(via k: ChannelCaller, fresh: Bool, why: String) async {
        guard !busy, Date().timeIntervalSince(failedAt) > 10 else { return }
        busy = true
        defer { busy = false }
        var text: Data?
        if !fresh, let (d, at) = cached, Date().timeIntervalSince(at) < 600 { text = d }
        if text == nil {
            var q = URLRequest(url: source, timeoutInterval: 6)
            q.cachePolicy = .reloadIgnoringLocalCacheData
            guard let (d, r) = try? await URLSession.shared.data(for: q) else {
                failedAt = Date(); Bunker.log("CIPHER day block (\(why)): favillakey.io didn't answer, nothing sent"); return
            }
            let code = (r as? HTTPURLResponse)?.statusCode ?? 0
            guard code == 200, let s = String(data: d, encoding: .utf8), let b = body(s) else {
                failedAt = Date(); Bunker.log("CIPHER day block (\(why)): favillakey.io answered \(code), nothing sent"); return
            }
            cached = (b, Date()); text = b
        }
        guard let text else { return }
        if text == refused { Bunker.log("CIPHER day block (\(why)): the KEY already refused this one, not sent again"); failedAt = Date(); return }
        do {
            let a = try await k.request(cDay, text, timeout: 6)
            if a.rsp == AppChannel.rAck, let p = parse(a.body) {
                if p.status == 0x00 {
                    refused = nil
                    // Sent on every connect; one line per block is enough in the log (21 Nov).
                    if fresh || p.height != loggedHeight { Bunker.log("CIPHER day block (\(why)): height \(p.height) taken by the KEY") }
                    loggedHeight = p.height
                }
                else { refused = text; cached = nil; Bunker.log(String(format: "CIPHER day block (\(why)): the KEY refused it (0x%02X)", p.status)) }
            } else if a.rsp == AppChannel.rErr, a.body.first == 0x04 {
                Bunker.log("CIPHER day block (\(why)): the KEY isn't in NOSTR Bluetooth mode")
            } else {
                // A KEY before 11bt doesn't know 0x50: say so once per answer, and leave it.
                failedAt = Date().addingTimeInterval(590)
                Bunker.log(String(format: "CIPHER day block (\(why)): the KEY answered %02X (a KEY before 11bt?)", a.rsp))
            }
        } catch {
            failedAt = Date(); Bunker.log("CIPHER day block (\(why)): \(error)")
        }
    }
}
