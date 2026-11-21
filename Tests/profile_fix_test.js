// The profile-notes fix in Nostr/bridge.js (firmware issue #50), run under node
// against a pretend page and pretend relays:  node Tests/profile_fix_test.js
const fs = require('fs'), path = require('path');
const src = fs.readFileSync(path.join(__dirname, '..', 'Nostr', 'bridge.js'), 'utf8');
const m = src.match(/\/\/ <profile-fix>([\s\S]*?)\/\/ <\/profile-fix>/);
if (!m) { console.log('FAIL: no <profile-fix> block in bridge.js'); process.exit(1); }
const ProfileFix = new Function(m[1] + '\nreturn ProfileFix;')();

let failures = 0;
function check(ok, what) { if (!ok) { failures++; console.log('FAIL: ' + what); } else console.log('ok: ' + what); }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---- pretend relays: behaviour by address ----
const relays = {};   // url -> { events: [...], end: 'EOSE' | 'CLOSED:reason' | 'hang' | 'refuse' }
let dialled = [];
class FakeWS {
  constructor(url) {
    if (/\s/.test(url)) throw new Error('bad url');
    this.url = url; this.readyState = 0; dialled.push(url);
    const r = relays[url] || { end: 'refuse' };
    setTimeout(() => {
      if (r.end === 'refuse') { this.readyState = 3; this.onerror && this.onerror({}); return; }
      this.readyState = 1; this.onopen && this.onopen();
    }, 5);
    this._r = r;
  }
  send(text) {
    const q = JSON.parse(text);
    if (q[0] !== 'REQ') return;
    const sub = q[1], r = this._r;
    setTimeout(() => {
      (r.events || []).forEach((ev) => this.onmessage && this.onmessage({ data: JSON.stringify(['EVENT', sub, ev]) }));
      if (r.end === 'EOSE') this.onmessage && this.onmessage({ data: JSON.stringify(['EOSE', sub]) });
      else if (r.end && r.end.startsWith('CLOSED:')) this.onmessage && this.onmessage({ data: JSON.stringify(['CLOSED', sub, r.end.slice(7)]) });
    }, 5);
  }
  close() { this.readyState = 3; }
}
const ev = (id, t) => ({ id, created_at: t, kind: 1, tags: [] });
const A = 'ab'.repeat(32);
const OURS = ['wss://relay.favillakey.io', 'wss://nos.lol', 'wss://nostr.mom', 'wss://relay.primal.net', 'wss://relay.nostr.band', 'wss://relay.damus.io'];

(async () => {
  // 1. addresses
  check(ProfileFix.norm('wss://Relay.FavillaKey.io/') === 'wss://relay.favillakey.io', 'norm: host lower case, no trailing slash');
  check(ProfileFix.norm('wss://nostr.lu.ke/%0A') === 'wss://nostr.lu.ke' && ProfileFix.norm(' wss://nos.lol \n') === 'wss://nos.lol', 'norm: a stray line break or space is dropped');
  check(ProfileFix.norm('ws://nos.lol') === null && ProfileFix.norm('https://nos.lol') === null && ProfileFix.norm('wss://') === null && ProfileFix.norm('wss://u:p@nos.lol') === null && ProfileFix.norm(null) === null, 'norm: only plain wss addresses');
  check(ProfileFix.norm('wss://relay.example.com:4848/nostr/inbox') === 'wss://relay.example.com:4848/nostr/inbox', 'norm: port and path kept');

  // 2. the list (the two lists from the 21 Nov bench)
  const theirs = ['wss://xxmmrr.shogatsu.ovh', 'wss://purplepag.es', 'wss://nostr.eluc.ch', 'wss://nostr.lu.ke/%0A', 'wss://nostr.fmt.wiz.biz'];
  const p1 = ProfileFix.plan(['wss://relay.primal.net', ...theirs], OURS, theirs, ['wss://nos.lol', 'wss://relay.primal.net']);
  check(p1.length === 9 && p1.slice(0, 3).join() === 'wss://xxmmrr.shogatsu.ovh,wss://nostr.eluc.ch,wss://nostr.lu.ke', 'plan: three of the author\'s relays first, cleaned, no profile-only relay');
  check(OURS.every((u) => p1.includes(u)), 'plan: every one of ours is asked');
  const p2 = ProfileFix.plan(['wss://relay.primal.net', 'wss://nos.lol', 'wss://relay.favillakey.io/', 'wss://relay.favillakey.io', 'wss://nostr.mom', 'wss://relay.nostr.band'],
    ['wss://relay.favillakey.io/', ...OURS.slice(1)], ['wss://relay.primal.net', 'wss://nos.lol', 'wss://relay.favillakey.io'], ['wss://relay.favillakey.io/', 'wss://nos.lol']);
  check(p2.filter((u) => /favillakey/.test(u)).length === 1 && p2.includes('wss://relay.favillakey.io/'), 'plan: one relay once, named the way the open socket is filed');
  check(p2.length === 6, 'plan: nothing invented when ours already cover the hubs');
  check(ProfileFix.plan(['wss://a.example', 'wss://nos.lol'], OURS, [], [])[0] === 'wss://a.example', 'plan: no relay list known for the author: what the page asked, minus ours, stands in');

  // 3. other fetches are left alone
  let got = null;
  const passthrough = ProfileFix.wrap(function () { got = Array.from(arguments); return Promise.resolve(['x']); }, {});
  const f3 = { kinds: [0], authors: [A] }, r3 = ['wss://nos.lol'];
  const o3 = await passthrough(f3, r3, 4000, null);
  check(got[0] === f3 && got[1] === r3 && got[2] === 4000 && o3[0] === 'x', 'wrap: a fetch that is not a profile\'s notes goes straight through');
  check(!ProfileFix.isProfile({ kinds: [1], authors: [A], '#e': ['x'] }) && !ProfileFix.isProfile({ kinds: [1], authors: [A, A] }) && ProfileFix.isProfile({ kinds: [1], authors: [A], limit: 40, until: 5 }), 'isProfile: one author, kind 1, not a thread');

  const envFor = (open, log) => ({ ours: () => OURS, theirs: () => [], openKeys: () => open, log: (s) => log.push(s), WebSocket: FakeWS, hint: () => {} });

  // 4. healthy: the page's own sockets answer, no new connections
  dialled = [];
  let log = [], seen = [];
  const forty = Array.from({ length: 40 }, (_, i) => ev('h' + i, 1000 + i));
  let askedList = null;
  const healthy = ProfileFix.wrap((f, list, ms, on) => { askedList = list; forty.forEach((e) => on(e, 'wss://nos.lol')); return sleep(20).then(() => forty); }, envFor(['wss://nos.lol', 'wss://nostr.mom'], log));
  const o4 = await healthy({ kinds: [1], authors: [A], limit: 40 }, OURS.slice(0, 6), 8000, (e) => seen.push(e.id));
  check(o4.length === 40 && seen.length === 40 && dialled.length === 0, 'healthy: 40 notes, each handed on once, no new connection');
  check(o4[0].created_at === 1039 && askedList.length === 6, 'healthy: newest first, the cleaned list went to the page\'s fetch');
  check(log.length === 1 && /40 from 6 relays/.test(log[0]) && /\*nos\.lol/.test(log[0]), 'healthy: one line in the log');

  // 5. the open sockets return nothing: asked again on new connections
  dialled = []; log = []; seen = [];
  relays['wss://nos.lol'] = { events: [ev('n1', 50), ev('n2', 40), ev('both', 30)], end: 'EOSE' };
  relays['wss://nostr.mom'] = { events: [ev('both', 30), ev('m1', 20)], end: 'CLOSED:rate-limited: slow down' };
  relays['wss://relay.primal.net'] = { end: 'refuse' };
  const dead = ProfileFix.wrap(() => sleep(30).then(() => []), envFor(['wss://nos.lol', 'wss://nostr.mom', 'wss://relay.primal.net'], log));
  const o5 = await dead({ kinds: [1], authors: [A], limit: 40 }, OURS, 8000, (e) => seen.push(e.id));
  check(o5.length === 4 && seen.length === 4 && o5.map((e) => e.id).join() === 'n1,n2,both,m1', 'dead sockets: the notes come over new connections, merged, no note twice');
  check(dialled.sort().join() === 'wss://nos.lol,wss://nostr.mom,wss://relay.primal.net', 'dead sockets: only the relays that were on open sockets are dialled again');
  check(/4 \(4 over new connections\)/.test(log[0]) && log.some((l) => /nostr\.mom: 2 notes, CLOSED rate-limited/.test(l)) && log.some((l) => /relay\.primal\.net: no connection/.test(l)), 'dead sockets: the log says what each relay answered');

  // 6. nothing for 1.5 s: new connections start before the page's fetch gives up
  dialled = []; log = []; seen = [];
  let t0 = Date.now(), firstAt = 0;
  const slow = ProfileFix.wrap(() => sleep(2300).then(() => []), envFor(['wss://nos.lol'], log));
  const o6 = await slow({ kinds: [1], authors: [A], limit: 40 }, OURS, 8000, () => { if (!firstAt) firstAt = Date.now() - t0; });
  check(o6.length === 3 && firstAt >= 1400 && firstAt < 2200, 'silent sockets: the first notes arrive at about 1.5 s, not at the end');
  check(dialled.length === 1, 'silent sockets: dialled once, not again when the page\'s fetch ends');

  // 6b. a short page, all of it from a freshly dialled relay, none from the open sockets
  dialled = []; log = []; seen = [];
  const six = Array.from({ length: 6 }, (_, i) => ev('s' + i, 500 + i));
  const partial = ProfileFix.wrap((f, list, ms, on) => { six.forEach((e) => on(e, 'wss://relay.damus.io')); return sleep(20).then(() => six); }, envFor(['wss://nos.lol'], log));
  const o6b = await partial({ kinds: [1], authors: [A], limit: 40 }, OURS, 8000, (e) => seen.push(e.id));
  check(o6b.length === 9 && dialled.join() === 'wss://nos.lol', 'partial: six notes but none from the open socket, so it is asked again');
  dialled = [];
  const fine = ProfileFix.wrap((f, list, ms, on) => { six.forEach((e) => on(e, 'wss://nos.lol')); return sleep(20).then(() => six); }, envFor(['wss://nos.lol'], []));
  check((await fine({ kinds: [1], authors: [A], limit: 40 }, OURS, 8000, null)).length === 6 && dialled.length === 0, 'partial: six notes from the open socket is an author with six notes, left alone');

  // 6c. one relay never answers: the fetch ends when the others have gone quiet, not at the page's 8 s
  dialled = []; log = []; seen = [];
  t0 = Date.now();
  const hang = ProfileFix.wrap((f, list, ms, on) => { forty.forEach((e) => on(e, 'wss://nos.lol')); return sleep(6000).then(() => forty); }, envFor(['wss://nos.lol'], log));
  const o6c = await hang({ kinds: [1], authors: [A], limit: 40 }, OURS, 8000, (e) => seen.push(e.id));
  const took = Date.now() - t0;
  check(o6c.length === 40 && seen.length === 40 && took >= 2900 && took < 3600 && dialled.length === 0, 'a relay that never answers: a full page of 40 and done at about 3 s (' + took + ' ms)');
  t0 = Date.now();
  const twenty = forty.slice(0, 20);
  const hang2 = ProfileFix.wrap((f, list, ms, on) => { twenty.forEach((e) => on(e, 'wss://nos.lol')); return sleep(7000).then(() => twenty); }, envFor(['wss://nos.lol'], []));
  const o6d = await hang2({ kinds: [1], authors: [A], limit: 40 }, OURS, 8000, null);
  const took2 = Date.now() - t0;
  check(o6d.length === 20 && took2 >= 5400 && took2 < 6100, 'a relay that never answers: a short page waits longer for a slow relay, about 5.5 s (' + took2 + ' ms)');
  check(/ended when the relays went quiet/.test(log[0]), 'a relay that never answers: the log says it ended early');
  check(ProfileFix.plan(['wss://nwc.primal.net/abc', 'wss://relay.mostr.pub'], OURS, ['wss://nwc.primal.net/abc', 'wss://relay.mostr.pub'], [])[0] === 'wss://relay.mostr.pub', 'plan: a wallet relay in an author\'s list is not asked for notes');

  // 7. no open socket to fall back on, and a fetch that throws
  dialled = []; log = [];
  const none = ProfileFix.wrap(() => Promise.resolve([ev('x', 1)]), envFor([], log));
  check((await none({ kinds: [1], authors: [A] }, OURS, 8000, null)).length === 1 && dialled.length === 0, 'no open sockets: nothing to ask again, the page\'s answer stands');
  const boom = ProfileFix.wrap(() => { throw new Error('boom'); }, envFor(['wss://nos.lol'], []));
  check((await boom({ kinds: [1], authors: [A] }, OURS, 8000, null)).length === 3, 'a failing fetch: the new connections still deliver');

  console.log(failures === 0 ? 'ALL PASSED' : failures + ' FAILED');
  process.exit(failures === 0 ? 0 : 1);
})();
