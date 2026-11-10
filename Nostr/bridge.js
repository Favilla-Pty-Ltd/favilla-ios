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

  // ---- 5. YouTube ---------------------------------------------------------------
  // YouTube's embedded player needs to know the web site it is embedded on, and
  // this page has none (favilla://), so the in-page player shows an error. A tap
  // on a YouTube card plays it in the app's own player instead.
  document.addEventListener('click', function (ev) {
    var box = ev.target && ev.target.closest && ev.target.closest('[data-ytid]');
    if (!box) return;
    var id = box.getAttribute('data-ytid');
    if (!/^[A-Za-z0-9_-]{6,20}$/.test(id || '')) return;
    ev.preventDefault(); ev.stopPropagation(); ev.stopImmediatePropagation();
    try { mh.favillaApp.postMessage({ youtube: id }); } catch (e) {}
  }, true);

  // ---- 6. link previews --------------------------------------------------------
  // The PWA draws a plain card for a link (icon, site, path): served by the KEY
  // over plain http it can't read other sites. The app can: when a link card
  // scrolls into view the iPhone reads the page's og: tags itself (straight from
  // the site, no proxy) and the card becomes a preview with picture, title and
  // summary, in the PWA's own .link-preview style.
  var previews = {};          // url -> {title, desc, image, site} | null
  var waiting = [], running = 0;
  function el(tag, cls, text) { var e = document.createElement(tag); if (cls) e.className = cls; if (text) e.textContent = text; return e; }
  function fill(a, p) {
    if (!p || !(p.title || p.image) || !a.isConnected) return;
    var host = '';
    try { host = new URL(a.href).hostname.replace(/^www\./, ''); } catch (e) {}
    a.className = 'link-preview fv-lp';
    a.style.display = 'block';
    a.textContent = '';
    if (p.image) {
      var img = el('img', 'link-preview-img'); img.loading = 'lazy'; img.alt = ''; img.referrerPolicy = 'no-referrer';
      img.onerror = function () { img.remove(); };
      img.src = p.image; a.appendChild(img);
    }
    var b = el('div', 'link-preview-body');
    b.appendChild(el('div', 'link-preview-domain', p.site || host));
    if (p.title) b.appendChild(el('div', 'link-preview-title', p.title));
    if (p.desc) b.appendChild(el('div', 'link-preview-desc', p.desc));
    a.appendChild(b);
  }
  function next() {
    while (running < 3 && waiting.length) {
      var a = waiting.shift(), url = a.href;
      if (!a.isConnected) continue;
      if (url in previews) { fill(a, previews[url]); continue; }
      running++;
      mh.favillaPreview.postMessage({ url: url }).then(function (a, url) { return function (p) {
        previews[url] = p || null; fill(a, p);
        document.querySelectorAll('a.link-card[data-fv-lp="1"]').forEach(function (o) { if (o.href === url) fill(o, p); });
      }; }(a, url), function (url) { return function () { previews[url] = null; }; }(url)).then(function () { running--; next(); });
    }
  }
  var seen = typeof IntersectionObserver === 'function' ? new IntersectionObserver(function (es) {
    es.forEach(function (e) { if (e.isIntersecting) { seen.unobserve(e.target); waiting.push(e.target); } });
    next();
  }, { rootMargin: '400px 0px' }) : null;
  function scan(root) {
    if (!seen || !mh.favillaPreview || !root.querySelectorAll) return;
    var list = Array.prototype.slice.call(root.querySelectorAll('a.link-card:not(.lc-nostr):not([data-fv-lp])'));
    if (root.matches && root.matches('a.link-card:not(.lc-nostr):not([data-fv-lp])')) list.push(root);
    list.forEach(function (a) {
      if (!/^https?:/i.test(a.href || '')) return;
      a.setAttribute('data-fv-lp', '1');
      seen.observe(a);
    });
  }
  new MutationObserver(function (ms) {
    ms.forEach(function (m) { m.addedNodes.forEach(function (n) { if (n.nodeType === 1) scan(n); }); });
  }).observe(document.documentElement, { childList: true, subtree: true });

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

  // ---- 7. calls ring like phone calls ---------------------------------------------
  // The app reports an incoming call to iOS (CallKit) and runs the PWA's own
  // accept / decline when you answer on the lock screen. Here: who you are and
  // where calls arrive (for the push bridge), the PWA's incoming banner (the
  // caller's name), its call state, and the commands back.
  var lastIdentity = '', lastPhase = '';
  function reportIdentity() {
    try {
      var pk = (typeof state === 'object' && state && state.pubkeyHex) || '';
      var rl = (typeof CALL_RELAYS !== 'undefined' && Array.isArray(CALL_RELAYS)) ? CALL_RELAYS.slice(0, 8) : [];
      if (!/^[0-9a-f]{64}$/i.test(pk)) return;
      var key = pk + '|' + rl.join(',');
      if (key === lastIdentity) return;
      lastIdentity = key;
      mh.favillaApp.postMessage({ identity: pk.toLowerCase(), callRelays: rl });
    } catch (e) {}
  }
  function reportCallState() {
    try {
      var st = (typeof pwacState === 'object' && pwacState) ? pwacState : null;
      if (!st) return;
      var phase = st.phase || 'idle';
      if (phase === lastPhase) return;
      var first = lastPhase === '';
      lastPhase = phase;
      if (first && phase === 'idle') return;     // nothing has happened yet
      if (phase === 'incoming') {
        var name = (document.getElementById('pwacall-name') || {}).textContent || 'Nostr call';
        mh.favillaApp.postMessage({ callIncoming: name, video: !!st.video });
      } else {
        mh.favillaApp.postMessage({ callPhase: phase });
      }
    } catch (e) {}
  }
  setInterval(function () { reportIdentity(); reportCallState(); }, 500);
  // The app's command (from the lock-screen call UI): the PWA's own functions.
  window.__favillaCall = function (cmd) {
    try {
      if (cmd === 'accept' && typeof callsAccept === 'function') callsAccept();
      else if (cmd === 'decline' && typeof callsReject === 'function') callsReject();
      else if (cmd === 'hangup') {
        var st = (typeof pwacState === 'object' && pwacState) ? pwacState : null;
        if (st && st.phase === 'incoming' && typeof callsReject === 'function') callsReject();
        else if (st && st.phase !== 'idle') {
          if (st.peer && typeof pwacSend === 'function' && typeof CALLS_K !== 'undefined') pwacSend(CALLS_K.HANGUP, st.peer, 'hangup').catch(function () {});
          if (typeof satEnd === 'function') satEnd('Call ended');
          if (typeof callsTeardown === 'function') callsTeardown('Call ended');
        }
      }
    } catch (e) {}
    reportCallState();
  };

  // Call wraps the bridge kept while this client wasn't connected (ephemeral
  // events: a relay never replays them). Into the PWA's own receive path.
  window.__favillaCallWraps = function (evs) {
    try {
      if (!Array.isArray(evs) || typeof callsIngestWrap !== 'function') return;
      var st = (typeof pwacState === 'object' && pwacState) ? pwacState : null;
      evs.forEach(function (ev) {
        if (!ev || ev.kind !== 21059) return;
        // Handed over again while nothing is ringing in the client: a wrap it
        // dropped earlier (KEY not ready yet) gets another go.
        if (st && st.phase === 'idle' && st.seenWraps && st.seenWraps.delete) st.seenWraps.delete(ev.id);
        ev._live = true;
        callsIngestWrap(ev);
      });
    } catch (e) {}
  };

  // ---- 7b. passwords handed over by another manager (issue #16) -----------------
  // Apple Passwords > Export Data to Another App: iOS gives the app the logins
  // (CredentialImport.swift). They come here as the CSV the Passwords page
  // already imports (Safari's columns), through its own file box, so the same
  // code runs: the pick list, the dup check, the KEY's import window and the
  // seal of each entry. The text lives in this page's memory only and is
  // dropped with the picks.
  var cxfImport = false;
  function csvCell(s) { return '"' + String(s == null ? '' : s).replace(/"/g, '""') + '"'; }
  window.__favillaImport = function (logins, from, note) {
    try {
      if (!Array.isArray(logins) || !logins.length) return 'nothing to import';
      var csv = 'Title,URL,Username,Password,Notes,OTPAuth\n' + logins.map(function (l) {
        return [l.title, l.url, l.user, l.pass, l.note, ''].map(csvCell).join(',');
      }).join('\n');
      logins.length = 0;
      if (typeof window.settingsOpen === 'function') window.settingsOpen('passwords');
      var input = document.getElementById('pw-file');
      if (!input) return 'no import box on this page';
      cxfImport = true;
      // The block is hidden until the list has loaded; show it so the picks and
      // the status are on screen even while the KEY is still being reached.
      var blk = document.getElementById('pw-import-blk'); if (blk) blk.hidden = false;
      var dt = new DataTransfer();
      dt.items.add(new File([csv], (from || 'passwords') + '.csv', { type: 'text/csv' }));
      csv = '';
      input.files = dt.files;
      input.dispatchEvent(new Event('change', { bubbles: true }));
      setTimeout(function () {
        var st = document.getElementById('pw-import-status');
        if (st && note) st.textContent = (st.textContent ? st.textContent + ' ' : '') + note + '.';
        if (blk) blk.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }, 150);
      return 'handed to the Passwords page';
    } catch (e) { return 'failed: ' + (e && e.message || e); }
  };
  // The page's reminder after an import is about the export file. There is no
  // file here: say what is true, and point at the breach check.
  function watchImportReminder() {
    var r = document.getElementById('pw-import-remind');
    if (!r || !window.MutationObserver) return;
    var fileText = r.textContent;
    new MutationObserver(function () {
      if (r.hidden) return;
      if (!cxfImport) { r.textContent = fileText; return; }   // a real CSV file: the page's own words
      cxfImport = false;
      r.textContent = 'Nothing was written on this iPhone: the copy the other app handed over is gone. ' +
        'To score what you just imported, run Check breaches: Settings > This iPhone > Accounts. ' +
        'Then delete those logins from the other app if the KEY is to be the only place they live.';
    }).observe(r, { attributes: true, attributeFilter: ['hidden'] });
  }

  // ---- 8. no "update ready" loop ------------------------------------------------
  // The client compares its build with the one the KEY serves and reloads to
  // pick the newer one up. In the app the client is a bundled copy, and a
  // reload only brings the same copy back, so the check would loop. The app's
  // copy is refreshed with each app update (scripts/sync_pwa.sh).
  function noUpdateLoop() {
    try { if (typeof checkPwaVersion === 'function') window.checkPwaVersion = function () {}; } catch (e) {}
    try { if (typeof pwaForceUpdate === 'function') window.pwaForceUpdate = function () {}; } catch (e) {}
    var card = document.getElementById('pair-update-notice');
    if (card) card.style.display = 'none';
    var pill = document.getElementById('upd-pill');
    if (pill) pill.remove();
  }

  function onReady() { addSettingsRow(); watchTheme(); paintBunkerNote(); reportIdentity(); noUpdateLoop(); watchImportReminder(); }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', onReady);
  else onReady();
})();
