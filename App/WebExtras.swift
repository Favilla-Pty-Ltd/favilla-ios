// WebExtras.swift - things the Nostr client gets from being an iPhone app
// rather than a page served by the KEY (9 Nov 2026).
//
//  - Link previews: the PWA, served by the KEY over plain http, can't read other
//    sites, so a link is a plain card. The iPhone reads the linked page's og:
//    tags itself (straight from the site, no proxy) and bridge.js turns the
//    card into a preview.
//  - YouTube: the embedded player needs to know the web site it's on, and the
//    page has none (favilla://), so it shows an error. Played here instead, in
//    a player page that says it is favillakey.io.
//  - Links open in an in-app browser (Safari's own view) instead of leaving the app.

import SafariServices
import UIKit
import WebKit

// MARK: - Link previews

enum LinkPreview {
    struct Card { var title: String?; var desc: String?; var image: String?; var site: String? }

    private static var cache: [String: Card?] = [:]
    private static let lock = NSLock()
    private static let session: URLSession = {
        let c = URLSessionConfiguration.ephemeral
        c.httpCookieStorage = nil
        c.timeoutIntervalForRequest = 8
        c.httpAdditionalHeaders = [
            "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
            "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.5",
        ]
        return URLSession(configuration: c)
    }()

    /// The card for a public http(s) page, or nil. Never a local address: a note
    /// is written by anyone, and its links must not reach into your network.
    static func card(for raw: String) async -> Card? {
        guard let url = URL(string: raw), let scheme = url.scheme?.lowercased(), scheme == "https" || scheme == "http",
              let host = url.host?.lowercased(), !isPrivate(host) else { return nil }
        lock.lock(); let hit = cache[raw]; lock.unlock()
        if let hit { return hit }
        let c = await fetch(url)
        lock.lock(); if cache.count > 300 { cache.removeAll() }; cache[raw] = c; lock.unlock()
        return c
    }

    static func isPrivate(_ host: String) -> Bool {
        if host == "localhost" || host.hasSuffix(".local") || host.hasSuffix(".internal") || !host.contains(".") { return true }
        if host.contains(":") { return true }                       // IPv6 literals: not worth the risk
        let p = host.split(separator: ".").compactMap { Int($0) }
        guard p.count == 4 else { return false }
        return p[0] == 10 || p[0] == 127 || p[0] == 0 || (p[0] == 192 && p[1] == 168) || (p[0] == 172 && (16...31).contains(p[1])) || (p[0] == 169 && p[1] == 254) || (p[0] == 100 && (64...127).contains(p[1]))
    }

    private static func fetch(_ url: URL) async -> Card? {
        do {
            let (bytes, resp) = try await session.bytes(from: url)
            guard let h = resp as? HTTPURLResponse, (200..<300).contains(h.statusCode),
                  (h.value(forHTTPHeaderField: "Content-Type") ?? "text/html").lowercased().contains("html") else { return nil }
            // The tags are in the head: read until </head>, at most 512 KB.
            var data = Data()
            for try await b in bytes {
                data.append(b)
                if data.count > 524_288 { break }
                if b == UInt8(ascii: ">"), data.count > 7, String(decoding: data.suffix(7), as: UTF8.self).lowercased() == "</head>" { break }
            }
            let html = String(decoding: data, as: UTF8.self)
            return parse(html, base: h.url ?? url)
        } catch { return nil }
    }

    static func parse(_ html: String, base: URL) -> Card? {
        var metas: [String: String] = [:]
        let tag = try! NSRegularExpression(pattern: "<meta\\b[^>]*>", options: [.caseInsensitive])
        let attr = try! NSRegularExpression(pattern: "([a-zA-Z:_-]+)\\s*=\\s*(\"[^\"]*\"|'[^']*'|[^\\s>]+)", options: [])
        let ns = html as NSString
        for m in tag.matches(in: html, range: NSRange(location: 0, length: ns.length)) {
            let t = ns.substring(with: m.range)
            var a: [String: String] = [:]
            for x in attr.matches(in: t, range: NSRange(location: 0, length: (t as NSString).length)) {
                let k = (t as NSString).substring(with: x.range(at: 1)).lowercased()
                var v = (t as NSString).substring(with: x.range(at: 2))
                if v.hasPrefix("\"") || v.hasPrefix("'") { v = String(v.dropFirst().dropLast()) }
                a[k] = v
            }
            if let key = (a["property"] ?? a["name"])?.lowercased(), let v = a["content"], !v.isEmpty, metas[key] == nil { metas[key] = v }
        }
        var title = metas["og:title"] ?? metas["twitter:title"]
        if title == nil, let r = html.range(of: "<title[^>]*>([^<]{1,300})</title>", options: [.regularExpression, .caseInsensitive]) {
            title = String(html[r]).replacingOccurrences(of: "<[^>]+>", with: "", options: .regularExpression)
        }
        let desc = metas["og:description"] ?? metas["twitter:description"] ?? metas["description"]
        var image = metas["og:image:secure_url"] ?? metas["og:image"] ?? metas["og:image:url"] ?? metas["twitter:image"] ?? metas["twitter:image:src"]
        if let i = image, let u = URL(string: entities(i), relativeTo: base)?.absoluteURL, ["https", "http"].contains(u.scheme ?? ""),
           let h = u.host?.lowercased(), !isPrivate(h) { image = u.absoluteString } else { image = nil }
        let site = metas["og:site_name"]
        func clean(_ s: String?, _ n: Int) -> String? {
            guard let s else { return nil }
            let t = entities(s).trimmingCharacters(in: .whitespacesAndNewlines).replacingOccurrences(of: "\\s+", with: " ", options: .regularExpression)
            return t.isEmpty ? nil : String(t.prefix(n))
        }
        let c = Card(title: clean(title, 200), desc: clean(desc, 300), image: image, site: clean(site, 60))
        return (c.title == nil && c.image == nil) ? nil : c
    }

    static func entities(_ s: String) -> String {
        guard s.contains("&") else { return s }
        var out = s
        for (k, v) in [("&amp;", "&"), ("&lt;", "<"), ("&gt;", ">"), ("&quot;", "\""), ("&#39;", "'"), ("&apos;", "'"), ("&nbsp;", " ")] {
            out = out.replacingOccurrences(of: k, with: v)
        }
        let re = try! NSRegularExpression(pattern: "&#(x?)([0-9a-fA-F]{1,6});")
        let ns = out as NSString
        var res = "", last = 0
        for m in re.matches(in: out, range: NSRange(location: 0, length: ns.length)) {
            res += ns.substring(with: NSRange(location: last, length: m.range.location - last))
            let hex = ns.substring(with: m.range(at: 1)) == "x"
            let n = UInt32(ns.substring(with: m.range(at: 2)), radix: hex ? 16 : 10)
            res += n.flatMap(Unicode.Scalar.init).map { String(Character($0)) } ?? ""
            last = m.range.location + m.range.length
        }
        return res + ns.substring(from: last)
    }
}

// MARK: - YouTube

final class YouTubePlayer: UIViewController {
    private let id: String
    init(id: String) { self.id = id; super.init(nibName: nil, bundle: nil) }
    required init?(coder: NSCoder) { nil }

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        let cfg = WKWebViewConfiguration()
        cfg.allowsInlineMediaPlayback = true
        cfg.allowsPictureInPictureMediaPlayback = true
        cfg.mediaTypesRequiringUserActionForPlayback = []
        cfg.websiteDataStore = .nonPersistent()
        let wv = WKWebView(frame: .zero, configuration: cfg)
        wv.isOpaque = false
        wv.backgroundColor = .black
        wv.scrollView.isScrollEnabled = false
        wv.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(wv)

        let close = UIButton(type: .system)
        close.setTitle("Done", for: .normal)
        close.titleLabel?.font = UIFont(name: "ArchivoRoman-SemiBold", size: 17) ?? .systemFont(ofSize: 17, weight: .semibold)
        close.tintColor = UIColor(red: 0xC9 / 255, green: 0xA4 / 255, blue: 0x5C / 255, alpha: 1)
        close.addAction(UIAction { [weak self] _ in self?.dismiss(animated: true) }, for: .touchUpInside)
        let open = UIButton(type: .system)
        open.setTitle("Open in YouTube", for: .normal)
        open.titleLabel?.font = UIFont(name: "ArchivoRoman-Regular", size: 15) ?? .systemFont(ofSize: 15)
        open.tintColor = UIColor(red: 0xF4 / 255, green: 0xF2 / 255, blue: 0xEE / 255, alpha: 0.7)
        let vid = id
        open.addAction(UIAction { _ in
            if let u = URL(string: "https://www.youtube.com/watch?v=\(vid)") { UIApplication.shared.open(u) }
        }, for: .touchUpInside)
        for b in [close, open] { b.translatesAutoresizingMaskIntoConstraints = false; view.addSubview(b) }

        NSLayoutConstraint.activate([
            close.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 8),
            close.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -16),
            open.bottomAnchor.constraint(equalTo: view.safeAreaLayoutGuide.bottomAnchor, constant: -12),
            open.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            wv.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            wv.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            wv.centerYAnchor.constraint(equalTo: view.centerYAnchor),
            wv.heightAnchor.constraint(equalTo: wv.widthAnchor, multiplier: 9.0 / 16.0),
        ])
        // The player page claims https://favillakey.io as its site, which is what
        // YouTube's embed checks (it refuses pages with no web origin).
        let html = """
        <!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1">
        <meta name="referrer" content="strict-origin-when-cross-origin">
        <style>html,body{margin:0;height:100%;background:#000}iframe{border:0;width:100%;height:100%}</style></head>
        <body><iframe src="https://www.youtube-nocookie.com/embed/\(id)?autoplay=1&playsinline=1&rel=0&origin=https://favillakey.io"
        allow="autoplay; encrypted-media; picture-in-picture; fullscreen" allowfullscreen
        referrerpolicy="strict-origin-when-cross-origin"></iframe></body></html>
        """
        wv.loadHTMLString(html, baseURL: URL(string: "https://favillakey.io/"))
    }
}

// MARK: - Presenting

enum WebExtras {
    static func top(from v: UIView?) -> UIViewController? {
        guard var t = v?.window?.rootViewController else { return nil }
        while let p = t.presentedViewController { t = p }
        return t
    }

    static func playYouTube(_ id: String, from v: UIView?) {
        guard id.range(of: "^[A-Za-z0-9_-]{6,20}$", options: .regularExpression) != nil, let t = top(from: v) else { return }
        let p = YouTubePlayer(id: id)
        p.modalPresentationStyle = .fullScreen
        t.present(p, animated: true)
    }

    /// http(s) in an in-app browser (Safari's own view: your Safari sign-ins,
    /// Reader, share); anything else to the app that handles it.
    static func open(_ url: URL, from v: UIView?) {
        let s = url.scheme?.lowercased() ?? ""
        guard s == "https" || s == "http", let t = top(from: v) else { UIApplication.shared.open(url); return }
        let cfg = SFSafariViewController.Configuration()
        cfg.entersReaderIfAvailable = false
        let sf = SFSafariViewController(url: url, configuration: cfg)
        sf.preferredBarTintColor = UIColor(red: 0x11 / 255, green: 0x11 / 255, blue: 0x11 / 255, alpha: 1)
        sf.preferredControlTintColor = UIColor(red: 0xC9 / 255, green: 0xA4 / 255, blue: 0x5C / 255, alpha: 1)
        sf.dismissButtonStyle = .done
        t.present(sf, animated: true)
    }
}

// MARK: - The call window (video and voice calls)
//
// The PWA runs calls through a separate "media satellite" page (favillakey.io/call)
// that it opens with window.open and drives with postMessage: the PWA does the
// signalling with the KEY, the satellite does the camera, microphone and WebRTC.
// In Safari that window is a second tab. In the app it has to be a second web
// view made from the configuration WebKit hands us, so the opener link (and with
// it postMessage) survives; sending it to Safari cut the link and no call could
// connect. Shown full screen over the client; the satellite's own hang-up closes it.

final class CallWindow: UIViewController {
    let web: WKWebView
    var onClose: (() -> Void)?

    init(_ web: WKWebView) { self.web = web; super.init(nibName: nil, bundle: nil) }
    required init?(coder: NSCoder) { nil }

    static func isCall(_ url: URL) -> Bool {
        guard url.scheme?.lowercased() == "https" else { return false }
        let p = url.path.lowercased()
        return p == "/call" || p == "/call.html" || p.hasSuffix("/call") || p.hasSuffix("/call.html")
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        isModalInPresentation = true
        web.isOpaque = false
        web.backgroundColor = .black
        web.scrollView.backgroundColor = .black
        web.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(web)
        NSLayoutConstraint.activate([
            web.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor),
            web.bottomAnchor.constraint(equalTo: view.bottomAnchor),
            web.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            web.trailingAnchor.constraint(equalTo: view.trailingAnchor),
        ])
    }

    override var preferredStatusBarStyle: UIStatusBarStyle { .lightContent }

    /// The satellite ran window.close() (hang-up), or the call ended.
    func closed() {
        guard presentingViewController != nil else { onClose?(); return }
        dismiss(animated: true) { [weak self] in self?.onClose?() }
    }
}
