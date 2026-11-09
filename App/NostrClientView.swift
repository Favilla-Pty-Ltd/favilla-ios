// NostrClientView.swift - the Nostr client: the KEY's own PWA in a web view (7 Nov 2026).
//
// The page is Nostr/pwa.html, a copy of favilla-key-firmware src/pwa.html (see
// Nostr/PWA_SOURCE.txt and scripts/sync_pwa.sh), served from the app bundle at
// favilla://localhost/. Nostr/bridge.js catches its calls to the KEY and hands
// them to KeyApi (Bluetooth or Wi-Fi). Relays, media and everything else go out
// over the phone's own internet, exactly as in Safari.
//
// Rules for the web view:
//  - only the bundled page is ever loaded in it; links open in Safari;
//  - camera and microphone (pairing QR, calls) are granted to the bundled page only;
//  - the page's storage (localStorage) persists in the app's default data store.

import SwiftUI
import WebKit

struct NostrClientView: UIViewRepresentable {
    var onOpenSettings: () -> Void
    /// The page's background colour (status bar strip) as it changes with the theme.
    var onPageColour: (UIColor) -> Void = { _ in }
    @Binding var routeText: String

    static let scheme = "favilla"
    static let origin = "favilla://localhost"

    func makeCoordinator() -> Coordinator { Coordinator(self) }

    func makeUIView(context: Context) -> WKWebView {
        let cfg = WKWebViewConfiguration()
        cfg.setURLSchemeHandler(context.coordinator.files, forURLScheme: Self.scheme)
        cfg.websiteDataStore = .default()
        cfg.allowsInlineMediaPlayback = true
        cfg.mediaTypesRequiringUserActionForPlayback = []
        let uc = cfg.userContentController
        context.coordinator.installScripts(uc)
        uc.addScriptMessageHandler(context.coordinator, contentWorld: .page, name: "favillaKey")
        uc.addScriptMessageHandler(context.coordinator, contentWorld: .page, name: "favillaPreview")
        uc.add(context.coordinator, name: "favillaKeyCancel")
        uc.add(context.coordinator, name: "favillaApp")

        let wv = WKWebView(frame: .zero, configuration: cfg)
        wv.navigationDelegate = context.coordinator
        wv.uiDelegate = context.coordinator
        wv.isOpaque = false
        wv.backgroundColor = .black
        wv.scrollView.backgroundColor = .black
        wv.scrollView.contentInsetAdjustmentBehavior = .never   // below the status bar to the bottom edge, no insets: as the home-screen PWA
        wv.allowsBackForwardNavigationGestures = false
        #if DEBUG
        if #available(iOS 16.4, *) { wv.isInspectable = true }
        #endif
        context.coordinator.webView = wv
        wv.load(URLRequest(url: URL(string: Self.origin + "/")!))
        return wv
    }

    func updateUIView(_ wv: WKWebView, context: Context) {
        context.coordinator.parent = self
        // A new route: start the page again with it, so the PWA's launch (saved
        // host, reconnect) runs against the right link from its first call.
        if context.coordinator.loadedRoute != KeyRoute.current {
            context.coordinator.installScripts(wv.configuration.userContentController)
            wv.reload()
            return
        }
        context.coordinator.pushRoute(routeText)
    }

    static func dismantleUIView(_ wv: WKWebView, coordinator: Coordinator) {
        let uc = wv.configuration.userContentController
        uc.removeAllScriptMessageHandlers()
    }

    // MARK: - Coordinator

    final class Coordinator: NSObject, WKScriptMessageHandlerWithReply, WKScriptMessageHandler, WKNavigationDelegate, WKUIDelegate {
        var parent: NostrClientView
        weak var webView: WKWebView?
        let files = BundleFiles()
        private var tasks: [Int: Task<Void, Never>] = [:]
        private var lastRoute = ""

        private(set) var loadedRoute = KeyRoute.current

        init(_ p: NostrClientView) { parent = p }

        /// The route goes in ahead of bridge.js, so the bridge knows it before the
        /// PWA's own scripts run (its launch reconnect happens at parse time).
        func installScripts(_ uc: WKUserContentController) {
            uc.removeAllUserScripts()
            loadedRoute = KeyRoute.current
            uc.addUserScript(WKUserScript(source: "window.__favillaInitialRoute = '\(loadedRoute.rawValue)';", injectionTime: .atDocumentStart, forMainFrameOnly: true))
            if let url = Bundle.main.url(forResource: "bridge", withExtension: "js"), let js = try? String(contentsOf: url, encoding: .utf8) {
                uc.addUserScript(WKUserScript(source: js, injectionTime: .atDocumentStart, forMainFrameOnly: true))
            }
        }

        func pushRoute(_ text: String) {
            let route = KeyRoute.current.rawValue
            let bunker = Bunker.on ? "on" : "off"         // the Connect apps note (bridge.js)
            guard text + route + bunker != lastRoute, let wv = webView else { return }
            lastRoute = text + route + bunker
            let arg = (try? String(data: JSONSerialization.data(withJSONObject: [text, route, bunker]), encoding: .utf8)) ?? "[\"\", \"wifi\", \"off\"]"
            wv.evaluateJavaScript("window.__favillaSetRoute && window.__favillaSetRoute(\(arg)[0], \(arg)[1], \(arg)[2])")
        }

        // The page has loaded: give it the route (the Settings row and the Bluetooth Connect).
        func webView(_ wv: WKWebView, didFinish navigation: WKNavigation!) {
            lastRoute = ""
            pushRoute(parent.routeText)
        }

        // A call to the KEY from the page (bridge.js). Answered with
        // {status, contentType, body (base64)} or an error string.
        func userContentController(_ uc: WKUserContentController, didReceive message: WKScriptMessage, replyHandler: @escaping (Any?, String?) -> Void) {
            if message.name == "favillaPreview" {
                // A link card's preview (bridge.js): the page's og: tags, read by the iPhone.
                guard message.frameInfo.isMainFrame, message.frameInfo.securityOrigin.protocol == NostrClientView.scheme,
                      let m = message.body as? [String: Any], let url = m["url"] as? String else { replyHandler(nil, "refused"); return }
                Task {
                    let c = await LinkPreview.card(for: url)
                    let out: [String: Any]? = c.map { c in
                        var d: [String: Any] = [:]
                        if let v = c.title { d["title"] = v }; if let v = c.desc { d["desc"] = v }
                        if let v = c.image { d["image"] = v }; if let v = c.site { d["site"] = v }
                        return d
                    }
                    await MainActor.run { replyHandler(out, nil) }
                }
                return
            }
            guard message.frameInfo.isMainFrame, message.frameInfo.securityOrigin.protocol == NostrClientView.scheme,
                  let m = message.body as? [String: Any],
                  let id = m["id"] as? Int,
                  let method = m["method"] as? String,
                  let path = m["path"] as? String, path.hasPrefix("/api/") else {
                replyHandler(nil, "refused"); return
            }
            let host = m["host"] as? String ?? ""
            let headers = (m["headers"] as? [String: String]) ?? [:]
            let body = Data(base64Encoded: m["body"] as? String ?? "") ?? Data()
            let ms = (m["timeoutMs"] as? Double) ?? 30000
            let req = ApiRequest(method: method.uppercased(), host: host, path: path, headers: headers, body: body, timeout: max(1, min(ms / 1000, 120)))
            let transport = KeyApi.transport
            tasks[id] = Task { [weak self] in
                let reply: (Any?, String?)
                do {
                    let r = try await transport.send(req)
                    reply = (["status": r.status, "contentType": r.contentType, "body": r.body.base64EncodedString()], nil)
                } catch KeyApiError.notReady(let why) {
                    reply = (nil, why)
                } catch {
                    reply = (nil, "\(error)")
                }
                await MainActor.run {
                    self?.tasks[id] = nil
                    replyHandler(reply.0, reply.1)
                }
            }
        }

        // Cancels (the page's AbortSignal fired) and app requests from the page.
        func userContentController(_ uc: WKUserContentController, didReceive message: WKScriptMessage) {
            guard message.frameInfo.isMainFrame, message.frameInfo.securityOrigin.protocol == NostrClientView.scheme,
                  let m = message.body as? [String: Any] else { return }
            if message.name == "favillaKeyCancel", let id = m["id"] as? Int {
                tasks[id]?.cancel(); tasks[id] = nil
            } else if message.name == "favillaApp", m["open"] as? String == "settings" {
                parent.onOpenSettings()
            } else if message.name == "favillaApp", let id = m["youtube"] as? String {
                WebExtras.playYouTube(id, from: webView)
            } else if message.name == "favillaApp", let bg = m["bg"] as? String, let c = Coordinator.colour(css: bg) {
                webView?.backgroundColor = c
                webView?.scrollView.backgroundColor = c
                parent.onPageColour(c)
            }
        }

        /// "rgb(r, g, b)" or "rgba(r, g, b, a)" from getComputedStyle.
        static func colour(css: String) -> UIColor? {
            let n = css.components(separatedBy: CharacterSet(charactersIn: "0123456789.").inverted).compactMap(Double.init)
            guard css.hasPrefix("rgb"), n.count >= 3 else { return nil }
            return UIColor(red: n[0] / 255, green: n[1] / 255, blue: n[2] / 255, alpha: 1)
        }

        // Only the bundled page loads here. Links open in the in-app browser; the PWA's one
        // allowed frame (YouTube embeds, frame-src in its CSP) loads in place.
        func webView(_ wv: WKWebView, decidePolicyFor a: WKNavigationAction, decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
            guard let url = a.request.url else { decisionHandler(.cancel); return }
            if url.scheme == NostrClientView.scheme { decisionHandler(.allow); return }
            if a.targetFrame?.isMainFrame == false, url.host?.hasSuffix("youtube.com") == true { decisionHandler(.allow); return }
            if a.targetFrame?.isMainFrame == false, url.scheme == "about" { decisionHandler(.allow); return }
            if ["http", "https", "lightning", "bitcoin", "nostr", "mailto"].contains(url.scheme ?? "") {
                WebExtras.open(url, from: wv)
            }
            decisionHandler(.cancel)
        }

        func webViewWebContentProcessDidTerminate(_ wv: WKWebView) { wv.reload() }

        // window.open / target=_blank: the in-app browser.
        func webView(_ wv: WKWebView, createWebViewWith c: WKWebViewConfiguration, for a: WKNavigationAction, windowFeatures f: WKWindowFeatures) -> WKWebView? {
            if let url = a.request.url { WebExtras.open(url, from: wv) }
            return nil
        }

        // Camera (scanning the KEY's pairing code) and microphone (calls), bundled page only.
        func webView(_ wv: WKWebView, requestMediaCapturePermissionFor origin: WKSecurityOrigin, initiatedByFrame frame: WKFrameInfo, type: WKMediaCaptureType, decisionHandler: @escaping (WKPermissionDecision) -> Void) {
            decisionHandler(origin.protocol == NostrClientView.scheme && frame.isMainFrame ? .grant : .deny)
        }

        func webView(_ wv: WKWebView, runJavaScriptAlertPanelWithMessage msg: String, initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping () -> Void) {
            present(UIAlertController(title: nil, message: msg, preferredStyle: .alert), actions: [("OK", .default, completionHandler)])
        }

        func webView(_ wv: WKWebView, runJavaScriptConfirmPanelWithMessage msg: String, initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping (Bool) -> Void) {
            present(UIAlertController(title: nil, message: msg, preferredStyle: .alert),
                    actions: [("Cancel", .cancel, { completionHandler(false) }), ("OK", .default, { completionHandler(true) })])
        }

        func webView(_ wv: WKWebView, runJavaScriptTextInputPanelWithPrompt prompt: String, defaultText: String?, initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping (String?) -> Void) {
            let a = UIAlertController(title: nil, message: prompt, preferredStyle: .alert)
            a.addTextField { $0.text = defaultText }
            present(a, actions: [("Cancel", .cancel, { completionHandler(nil) }), ("OK", .default, { completionHandler(a.textFields?.first?.text) })])
        }

        private func present(_ a: UIAlertController, actions: [(String, UIAlertAction.Style, () -> Void)]) {
            for (t, s, f) in actions { a.addAction(UIAlertAction(title: t, style: s) { _ in f() }) }
            guard let root = webView?.window?.rootViewController else { actions.first?.2(); return }
            var top = root; while let p = top.presentedViewController { top = p }
            top.present(a, animated: true)
        }
    }
}

/// Serves the bundled page at favilla://localhost/. Only pwa.html; anything else
/// the page asks for from its own origin (launch images, icons) is a 404.
final class BundleFiles: NSObject, WKURLSchemeHandler {
    private lazy var page: Data? = Bundle.main.url(forResource: "pwa", withExtension: "html").flatMap { try? Data(contentsOf: $0) }

    func webView(_ wv: WKWebView, start task: WKURLSchemeTask) {
        guard let url = task.request.url else { return }
        let path = url.path
        if (path == "/" || path == "/index.html" || path == "/pwa.html"), let d = page {
            let r = HTTPURLResponse(url: url, statusCode: 200, httpVersion: "HTTP/1.1",
                                    headerFields: ["Content-Type": "text/html; charset=utf-8", "Content-Length": "\(d.count)", "Cache-Control": "no-store"])!
            task.didReceive(r); task.didReceive(d); task.didFinish()
        } else {
            let r = HTTPURLResponse(url: url, statusCode: 404, httpVersion: "HTTP/1.1", headerFields: ["Content-Length": "0"])!
            task.didReceive(r); task.didFinish()
        }
    }

    func webView(_ wv: WKWebView, stop task: WKURLSchemeTask) {}
}
