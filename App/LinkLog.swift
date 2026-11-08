// LinkLog.swift - what the Nostr client's Bluetooth link did, readable on the
// iPhone itself (8 Nov 2026, firmware issue #9). Josh has no Mac, so the iOS
// console is out of reach: the log is kept here, shown under Settings > This
// iPhone > Bluetooth log, and copied from there.
//
// It holds lengths, counters, report headers and reasons only: never a key,
// a body, a path's query or anything a request or answer carries.
// The last 600 lines are kept, in memory and in a file in Caches, so a crash
// doesn't lose them.

import Combine
import Foundation

final class LinkLog: ObservableObject, @unchecked Sendable {
    static let shared = LinkLog()
    static let max = 600

    @Published private(set) var lines: [String] = []
    private let lock = NSLock()
    private let file: URL? = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask).first?.appendingPathComponent("bluetooth-log.txt")
    private let stamp: DateFormatter = {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_AU_POSIX")
        f.dateFormat = "HH:mm:ss.SSS"
        return f
    }()

    private init() {
        if let f = file, let s = try? String(contentsOf: f, encoding: .utf8) {
            lines = Array(s.split(separator: "\n").map(String.init).suffix(LinkLog.max))
        }
    }

    /// Add one line. Any thread.
    func add(_ s: String) {
        lock.lock()
        let line = stamp.string(from: Date()) + " " + s
        var l = lines
        l.append(line)
        if l.count > LinkLog.max { l.removeFirst(l.count - LinkLog.max) }
        let text = l.joined(separator: "\n")
        lock.unlock()
        if let f = file { try? text.write(to: f, atomically: true, encoding: .utf8) }
        DispatchQueue.main.async { self.lines = l }
        #if DEBUG
        print("[BT] " + s)
        #endif
    }

    var text: String { lines.joined(separator: "\n") }

    func clear() {
        lock.lock(); lines = []; lock.unlock()
        if let f = file { try? FileManager.default.removeItem(at: f) }
    }

    /// The report headers in one notification: "start 1202, cont 1-7" style.
    static func describe(_ v: Data) -> String {
        let b = [UInt8](v)
        var parts: [String] = []
        var conts: [Int] = []
        func flush() {
            guard let f = conts.first, let l = conts.last else { return }
            parts.append(f == l ? "cont \(f)" : "cont \(f)-\(l)")
            conts = []
        }
        var off = 0
        while off < b.count {
            let r = Array(b[off..<min(off + 64, b.count)])
            off += 64
            guard let h = r.first else { continue }
            if h == AppChannel.fStart, r.count >= 3 {
                flush(); parts.append("start \(Int(r[1]) | Int(r[2]) << 8)")
            } else if h == AppChannel.fCont, r.count >= 2 {
                if let last = conts.last, Int(r[1]) != (last + 1) & 0xFF { flush() }
                conts.append(Int(r[1]))
            } else {
                flush(); parts.append(String(format: "?%02x", h))
            }
            if r.count < 64 { flush(); parts.append("short report \(r.count)") }
        }
        flush()
        return parts.joined(separator: ", ")
    }

    /// The path of an ApiWire request, without its query (no ids or values in the log).
    static func path(of body: Data) -> String {
        let b = [UInt8](body)
        guard b.count >= 3 else { return "?" }
        let n = Int(b[1]) | Int(b[2]) << 8
        guard b.count >= 3 + n, let p = String(bytes: b[3..<(3 + n)], encoding: .utf8) else { return "?" }
        let m = b[0] == 0x02 ? "POST" : "GET"
        return m + " " + (p.split(separator: "?", maxSplits: 1).first.map(String.init) ?? p)
    }
}
