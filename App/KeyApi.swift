// KeyApi.swift - carries the Nostr client's calls to the KEY (7 Nov 2026).
//
// The Nostr client is the KEY's own PWA (Nostr/pwa.html, the same file the KEY
// serves), shown in a web view. Every call it makes to the KEY,
// `fetch("http://<key>/api/...")`, is caught by Nostr/bridge.js and handed to
// KeyApi, which sends it one of two ways:
//
//  - Bluetooth (Josh, 7 Nov 2026: "New NOSTR Bluetooth life", "app channel
//    only"): the KEY in its NOSTR Bluetooth life, Wi-Fi never started. Each call
//    goes as one API request on the paired app channel (8F1A0005 write,
//    8F1A0006 notify), MAC'd with a counter; the answer comes back encrypted.
//    The bytes are in ApiWire below and in the firmware issue "NOSTR over
//    Bluetooth". Waiting on that KEY drop and on the app channel doc (issue #2).
//  - Wi-Fi: the KEY in its normal NOSTR life on the same network, as the PWA in
//    Safari does today. Works now.
//
// The PWA seals its own requests end to end (FSEC: X-Favilla-Session, sealed
// bodies), so the transport only carries bytes; it adds nothing and reads nothing.

import Foundation

struct ApiRequest: Equatable {
    var method: String          // GET or POST
    var host: String            // the host the page asked for (used on Wi-Fi only)
    var path: String            // "/api/..." with any query
    var headers: [String: String]
    var body: Data
    var timeout: TimeInterval
}

struct ApiResponse: Equatable {
    var status: Int
    var contentType: String
    var body: Data
}

enum KeyApiError: Error, Equatable {
    case notReady(String)       // shown to the page as a network failure; the reason goes to the log
    case refused(String)
    case timedOut
    case badAnswer
}

/// How this iPhone reaches the KEY for the Nostr client.
enum KeyRoute: String, CaseIterable {
    case bluetooth, wifi

    static let key = "nostrRoute"
    static var current: KeyRoute {
        get { KeyRoute(rawValue: UserDefaults.standard.string(forKey: key) ?? "") ?? .wifi }
        set { UserDefaults.standard.set(newValue.rawValue, forKey: key) }
    }

    var title: String { self == .bluetooth ? "Bluetooth" : "Wi-Fi" }
}

protocol KeyTransport {
    func send(_ r: ApiRequest) async throws -> ApiResponse
}

// MARK: - The API request over the app channel (Bluetooth)

/// The bytes of an API request and answer inside the app channel's
/// [cmd][client 8][ctr u32 LE][body][mac16], as built in KEY drop 9k
/// (docs/BLE_PASSKEY_PROTOCOL.md, "NOSTR over Bluetooth", issue #7).
///
/// Request body (cmd 0x3A API):
///   [method 1: 0x01 GET, 0x02 POST]
///   [path length u16 LE][path, printable ASCII, "/api/..." with query, at most 2048]
///   [header count 1] then per header [header id 1][value length u16 LE][value]
///       ids: 0x01 X-Favilla-Session, 0x02 X-Favilla-Auth, 0x03 X-Favilla-Ctr
///       (the headers the KEY's API reads; any other header is not sent)
///   [body length u16 LE][body]
/// Answer body (0xB8 R_API, encrypted like 0xB4):
///   [status u16 LE][content type 1: 0x00 none, 0x01 JSON, 0x02 text]
///   [body length u16 LE][body]
enum ApiWire {
    static let cmdApi: UInt8 = 0x3A
    static let rspApi: UInt8 = 0xB8
    static let bodyMax = 32_768
    static let pathMax = 2048
    static let headerIds: [(UInt8, String)] = [(0x01, "X-Favilla-Session"), (0x02, "X-Favilla-Auth"), (0x03, "X-Favilla-Ctr")]

    static func encode(_ r: ApiRequest) -> Data? {
        let m: UInt8
        switch r.method.uppercased() { case "GET": m = 0x01; case "POST": m = 0x02; default: return nil }
        let path = Data(r.path.utf8)
        guard r.path.hasPrefix("/api/"), path.count <= pathMax, r.body.count <= bodyMax else { return nil }
        var d = Data([m]); put16(&d, path.count); d.append(path)
        var hs: [(UInt8, Data)] = []
        for (id, name) in headerIds {
            if let v = r.headers.first(where: { $0.key.caseInsensitiveCompare(name) == .orderedSame })?.value {
                let b = Data(v.utf8); guard b.count <= 1024 else { return nil }
                hs.append((id, b))
            }
        }
        d.append(UInt8(hs.count))
        for (id, b) in hs { d.append(id); put16(&d, b.count); d.append(b) }
        put16(&d, r.body.count); d.append(r.body)
        return d
    }

    static func decodeAnswer(_ d: Data) -> ApiResponse? {
        let b = [UInt8](d)
        guard b.count >= 5 else { return nil }
        let status = Int(b[0]) | Int(b[1]) << 8
        let ct: String
        switch b[2] { case 0x00: ct = ""; case 0x01: ct = "application/json"; case 0x02: ct = "text/plain"; default: return nil }
        let n = Int(b[3]) | Int(b[4]) << 8
        guard (100...599).contains(status), b.count == 5 + n else { return nil }
        return ApiResponse(status: status, contentType: ct, body: Data(b[5...]))
    }

    private static func put16(_ d: inout Data, _ v: Int) { d.append(UInt8(v & 0xFF)); d.append(UInt8((v >> 8) & 0xFF)) }
}

// MARK: - Wi-Fi

/// The KEY on the local network, as the PWA in Safari reaches it.
final class WifiTransport: KeyTransport {
    static let hostKey = "nostrWifiHost"
    private let session: URLSession = {
        let c = URLSessionConfiguration.ephemeral
        c.requestCachePolicy = .reloadIgnoringLocalCacheData
        c.httpShouldSetCookies = false
        c.waitsForConnectivity = false
        return URLSession(configuration: c)
    }()

    /// The page names the KEY's host itself (the PWA's paired host). If it only
    /// has its own address (localhost, the bundled page), use the saved one.
    static func target(for pageHost: String) -> String? {
        let h = pageHost.lowercased()
        if h.isEmpty || h == "localhost" || h.hasPrefix("localhost:") {
            let saved = UserDefaults.standard.string(forKey: hostKey) ?? ""
            return saved.isEmpty ? nil : saved
        }
        if isLocal(h) { return pageHost }
        // Not a local address (e.g. key.bluetooth left by the Bluetooth route):
        // the saved Wi-Fi address, never the internet.
        let saved = UserDefaults.standard.string(forKey: hostKey) ?? ""
        return saved.isEmpty ? nil : saved
    }

    /// Only the local network: an IP in a private range, or a .local name. The
    /// page is ours, but this keeps the bridge from being a way out to the internet.
    static func isLocal(_ hostPort: String) -> Bool {
        var h = hostPort.lowercased()
        if let c = h.lastIndex(of: ":"), !h.contains("]") { h = String(h[..<c]) }
        if h.hasSuffix(".local") { return true }
        let p = h.split(separator: ".").compactMap { Int($0) }
        guard p.count == 4, p.allSatisfy({ (0...255).contains($0) }) else { return false }
        return p[0] == 10 || (p[0] == 192 && p[1] == 168) || (p[0] == 172 && (16...31).contains(p[1])) || (p[0] == 169 && p[1] == 254)
    }

    func send(_ r: ApiRequest) async throws -> ApiResponse {
        guard let host = WifiTransport.target(for: r.host) else { throw KeyApiError.notReady("No KEY address yet: pair the KEY in Settings, or enter its address under This iPhone") }
        guard let url = URL(string: "http://\(host)\(r.path)") else { throw KeyApiError.refused("bad address") }
        var q = URLRequest(url: url, timeoutInterval: r.timeout)
        q.httpMethod = r.method
        for (k, v) in r.headers { q.setValue(v, forHTTPHeaderField: k) }
        if r.method == "POST" { q.httpBody = r.body }
        do {
            let (data, resp) = try await session.data(for: q)
            guard let h = resp as? HTTPURLResponse else { throw KeyApiError.badAnswer }
            if r.host.lowercased().hasPrefix("localhost") == false, WifiTransport.isLocal(r.host) {
                UserDefaults.standard.set(r.host, forKey: WifiTransport.hostKey)   // remember the KEY the page paired with
            }
            return ApiResponse(status: h.statusCode, contentType: h.value(forHTTPHeaderField: "Content-Type") ?? "", body: data)
        } catch let e as URLError where e.code == .timedOut {
            throw KeyApiError.timedOut
        }
    }
}

// MARK: - Bluetooth

/// The KEY's NOSTR Bluetooth life (Bluetooth mode) over the paired app channel (NostrLink): each call is
/// one API request (0x3A), its answer one encrypted 0xB8 (KEY drop 9k).
final class BluetoothTransport: KeyTransport {
    /// #9 item 4: the PWA retries /api/session about every 2 s while the KEY is
    /// busy. After a 503 or a busy link, further session calls are answered here
    /// (503) without touching the KEY, for 2 s, then 4, 8 and up to 30 s.
    private let lock = NSLock()
    private var holdUntil = Date.distantPast
    private var hold: TimeInterval = 0

    func send(_ r: ApiRequest) async throws -> ApiResponse {
        guard let body = ApiWire.encode(r) else { throw KeyApiError.refused("request too large or not an /api/ call") }
        guard Credentials.isPaired else { throw KeyApiError.notReady(NostrLink.notPaired) }
        let session = r.path.hasPrefix("/api/session")
        if session, let wait = backingOff() {
            return ApiResponse(status: 503, contentType: "application/json", body: Data("{\"error\":\"busy\",\"retry_in\":\(Int(wait.rounded(.up)))}".utf8))
        }
        do {
            let a = try await NostrLink.shared.send(body)
            if session { a.status == 503 ? backOff() : clear() }
            return a
        } catch KeyApiError.notReady(let why) where session && why.contains("busy") {
            backOff()
            throw KeyApiError.notReady(why)
        }
    }

    private func backingOff() -> TimeInterval? {
        lock.lock(); defer { lock.unlock() }
        let left = holdUntil.timeIntervalSinceNow
        return left > 0 ? left : nil
    }

    private func backOff() {
        lock.lock(); defer { lock.unlock() }
        hold = min(30, max(2, hold * 2))
        holdUntil = Date().addingTimeInterval(hold)
        LinkLog.shared.add("session busy: holding session calls for \(Int(hold)) s")
    }

    private func clear() {
        lock.lock(); defer { lock.unlock() }
        hold = 0; holdUntil = .distantPast
    }
}

enum KeyApi {
    static let wifi = WifiTransport()
    static let bluetooth = BluetoothTransport()
    static var transport: KeyTransport { KeyRoute.current == .bluetooth ? bluetooth : wifi }
}
