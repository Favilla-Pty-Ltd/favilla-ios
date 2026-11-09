// bridge.js - runs in the Nostr client page before any of its own scripts
// (WKUserScript, document start). Injected scripts are not bound by the page's
// Content-Security-Policy, so the PWA itself is unchanged.
//
// 1. Every fetch to "http://<anything>/api/..." (the PWA's calls to the KEY) is
//    handed to the app (window.webkit.messageHandlers.favillaKey), which carries
//    it over Bluetooth or Wi-Fi (App/KeyApi.swift). Everything else (relays,
//    media, NIP-05, zaps) goes out as normal over the phone's own internet.
//    A transport failure looks to the page exactly like a network failure
//    (TypeError), which the PWA already handles.
// 2. The page is told it runs installed (navigator.standalone), as on the home
//    screen. Like the home-screen app, the web view starts below the status bar
//    and runs to the bottom edge, with the page's viewport left as it is (no
//    viewport-fit=cover): the home-screen PWA gets no safe-area insets, so its
//    bottom bar sits over the home indicator, and the app must match. The page's background colour is sent to the app, which paints the status
//    bar strip with it and picks light or dark status bar text.
// 3. A "This iPhone" row is added to the PWA's Settings hub; it opens the app's
//    own settings (how the phone reaches the KEY, pairing, AutoFill).
(function () {
  'use strict';
  if (window.__favillaBridge) return;
  window.__favillaBridge = true;
  var mh = window.webkit && window.webkit.messageHandlers;
  if (!mh || !mh.favillaKey) return;

  // ---- 1. fetch ------------------------------------------------------------
  var realFetch = window.fetch.bind(window);
  var seq = 0;

  function keyUrl(input) {
    var raw = typeof input === 'string' ? input : (input && input.url) || String(input);
    var u;
    try { u = new URL(raw, location.href); } catch (e) { return null; }
    return (u.protocol === 'http:' && u.pathname.indexOf('/api/') === 0) ? u : null;
  }

  function toB64(bytes) {
    var s = '', CH = 0x8000;
    for (var i = 0; i < bytes.length; i += CH) s += String.fromCharCode.apply(null, bytes.subarray(i, i + CH));
    return btoa(s);
  }
  function fromB64(b64) {
    var s = atob(b64 || ''), out = new Uint8Array(s.length);
    for (var i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
    return out;
  }

  async function bodyBytes(body) {
    if (body == null) return new Uint8Array(0);
    if (typeof body === 'string') return new TextEncoder().encode(body);
    if (body instanceof ArrayBuffer) return new Uint8Array(body);
    if (ArrayBuffer.isView(body)) return new Uint8Array(body.buffer, body.byteOffset, body.byteLength);
    if (typeof Blob !== 'undefined' && body instanceof Blob) return new Uint8Array(await body.arrayBuffer());
    if (typeof URLSearchParams !== 'undefined' && body instanceof URLSearchParams) return new TextEncoder().encode(body.toString());
    return new TextEncoder().encode(String(body));
  }

  function abortError() {
    try { return new DOMException('The operation was aborted.', 'AbortError'); }
    catch (e) { var er = new Error('The operation was aborted.'); er.name = 'AbortError'; return er; }
  }

  window.fetch = async function (input, init) {
    var u = keyUrl(input);
    if (!u) return realFetch(input, init);
    init = init || {};
    var isReq = typeof Request !== 'undefined' && input instanceof Request;
    var method = String(init.method || (isReq ? input.method : 'GET')).toUpperCase();
    var hdrs = {};
    try { new Headers(init.headers || (isReq ? input.headers : undefined)).forEach(function (v, k) { hdrs[k] = v; }); } catch (e) {}
    var body = await bodyBytes(init.body != null ? init.body : (isReq && method !== 'GET' ? await input.clone().arrayBuffer() : null));
    var signal = init.signal || (isReq ? input.signal : null);
    if (signal && signal.aborted) throw abortError();
    var id = ++seq;
    var ask = mh.favillaKey.postMessage({
      id: id, method: method, host: u.host, path: u.pathname + u.search,
      headers: hdrs, body: toB64(body), timeoutMs: 30000
    });
    var answer = await new Promise(function (resolve, reject) {
      var done = false;
      function onAbort() {
        if (done) return; done = true;
        try { mh.favillaKeyCancel && mh.favillaKeyCancel.postMessage({ id: id }); } catch (e) {}
        reject(abortError());
      }
      if (signal) signal.addEventListener('abort', onAbort, { once: true });
      ask.then(function (a) {
        if (done) return; done = true;
        if (signal) signal.removeEventListener('abort', onAbort);
        resolve(a);
      }, function (err) {
        if (done) return; done = true;
        if (signal) signal.removeEventListener('abort', onAbort);
        reject(new TypeError('Failed to fetch (' + (err && err.message || err) + ')'));
      });
    });
    var status = answer.status | 0;
    var headers = new Headers();
    if (answer.contentType) headers.set('Content-Type', answer.contentType);
    var nullBody = status === 204 || status === 205 || status === 304;
    return new Response(nullBody ? null : fromB64(answer.body), { status: status, headers: headers });
  };

  // ---- 2. installed, full screen ------------------------------------------------
  try { Object.defineProperty(navigator, 'standalone', { value: true, configurable: true }); } catch (e) {}

  // ---- 3. "This iPhone" in Settings ---------------------------------------------
  function addSettingsRow() {
    var hub = document.getElementById('set-hub');
    if (!hub || document.getElementById('fv-iphone')) return;
    var grp = document.createElement('div');
    grp.className = 'set-grp';
    grp.textContent = 'This iPhone';
    var list = document.createElement('div');
    list.className = 'set-list';
    var b = document.createElement('button');
    b.type = 'button'; b.className = 'set-row'; b.id = 'fv-iphone';
    b.innerHTML = '<span class="set-ico"><svg viewBox="0 0 24 24"><rect x="6" y="2" width="12" height="20" rx="2"/><line x1="11" y1="18" x2="13" y2="18"/></svg></span>' +
      '<span class="set-rt"><b>Link to the KEY</b><small id="fv-iphone-sub">Bluetooth or Wi-Fi, pairing, passwords and passkeys</small></span>' +
      '<svg class="set-chev" viewBox="0 0 24 24"><path d="M9 6l6 6-6 6"/></svg>';
    b.addEventListener('click', function (ev) {
      ev.preventDefault(); ev.stopPropagation();
      try { mh.favillaApp.postMessage({ open: 'settings' }); } catch (e) {}
    });
    list.appendChild(b);
    var first = hub.querySelector('.set-grp');
    hub.insertBefore(list, first);
    hub.insertBefore(grp, list);
  }
  // The app sets the row's subtitle ("Bluetooth" / "Wi-Fi: 192.168.1.20") and the route.
  var route = window.__favillaInitialRoute === 'bluetooth' ? 'bluetooth' : 'wifi';
  var bunkerOn = false;
  window.__favillaSetRoute = function (text, r, bunker) {
    if (r) route = r;
    if (bunker) bunkerOn = bunker === 'on';
    var s = document.getElementById('fv-iphone-sub');
    if (s && text) s.textContent = text;
    paintBunkerNote();
  };

  // Connect apps (the KEY's NIP-46 bunker) works the same on Bluetooth, but the
  // KEY has no internet there: this iPhone carries the requests, once "Sign for
  // other apps" is on in This iPhone > Bunker. Say so at the top of the page.
  function paintBunkerNote() {
    var sec = document.getElementById('section-bunker');
    if (!sec) return;
    var n = document.getElementById('fv-bunker-note');
    if (route !== 'bluetooth') { if (n) n.remove(); return; }
    if (!n) {
      n = document.createElement('div');
      n.id = 'fv-bunker-note'; n.className = 'bk-card';
      n.style.cssText = 'display:flex;align-items:center;gap:12px;margin:0 0 12px;padding:12px 14px;';
      n.innerHTML = '<div style="flex:1;min-width:0"><b style="display:block;font-size:14px">Through this iPhone</b>' +
        '<small id="fv-bunker-line" style="display:block;color:var(--muted);font-size:12px;line-height:1.45"></small></div>' +
        '<button type="button" class="bk-pill" id="fv-bunker-open" style="cursor:pointer">Set up</button>';
      n.querySelector('#fv-bunker-open').addEventListener('click', function (ev) {
        ev.preventDefault(); ev.stopPropagation();
        try { mh.favillaApp.postMessage({ open: 'settings' }); } catch (e) {}
      });
      var hero = sec.querySelector('.bk-hero');
      if (hero && hero.nextSibling) sec.insertBefore(n, hero.nextSibling); else sec.appendChild(n);
    }
    n.querySelector('#fv-bunker-line').textContent = bunkerOn
      ? 'Favilla reaches your KEY over Bluetooth, and passes each app\'s request to it and sends the answer back, even when Favilla is closed.'
      : 'On Bluetooth your KEY has no internet, so other apps reach it through Favilla on this iPhone. Turn on This iPhone > Bunker > Sign for other apps.';
    n.querySelector('#fv-bunker-open').textContent = bunkerOn ? 'On' : 'Set up';
  }

  // On Bluetooth the KEY's address means nothing (the app sends every /api call
  // to the paired KEY), and the PWA's Connect with an empty address box scans
  // ~1,270 network addresses at once. So on Bluetooth, Connect gets a fixed
  // name first and goes straight to the KEY.
  var BT_HOST = 'key.bluetooth';
  // On Bluetooth the PWA needs a saved host for its launch reconnect to run at
  // all (it skips with none). Any name reaches the paired KEY; give it one.
  if (route === 'bluetooth') {
    try { if (!localStorage.getItem('kv_host')) localStorage.setItem('kv_host', BT_HOST); } catch (e) {}
  }
  document.addEventListener('click', function (ev) {
    if (route !== 'bluetooth') return;
    var btn = ev.target && ev.target.closest && ev.target.closest('#pair-connect-btn');
    if (!btn) return;
    var inp = document.getElementById('pair-host-input');
    if (inp && !inp.value.trim()) inp.value = BT_HOST;
  }, true);
  document.addEventListener('focusin', function (ev) {
    if (route === 'bluetooth' && ev.target && ev.target.id === 'pair-host-input') ev.target.placeholder = 'Bluetooth: leave blank and tap Connect';
  }, true);

  // ---- 4. status bar strip follows the page's theme ------------------------------
  var lastBg = '';
  function sendBg() {
    try {
      var bg = getComputedStyle(document.body || document.documentElement).backgroundColor;
      if (!bg || bg === 'rgba(0, 0, 0, 0)' || bg === 'transparent') bg = getComputedStyle(document.documentElement).backgroundColor;
      if (bg && bg !== lastBg) { lastBg = bg; mh.favillaApp.postMessage({ bg: bg }); }
    } catch (e) {}
  }
  function watchTheme() {
    sendBg();
    try {
      var mo = new MutationObserver(function () { setTimeout(sendBg, 50); });
      var opts = { attributes: true, attributeFilter: ['class', 'data-theme', 'style'] };
      mo.observe(document.documentElement, opts);
      if (document.body) mo.observe(document.body, opts);
    } catch (e) {}
  }

  function onReady() { addSettingsRow(); watchTheme(); paintBunkerNote(); }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', onReady);
  else onReady();
})();
