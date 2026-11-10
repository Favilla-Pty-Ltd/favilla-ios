#!/usr/bin/env python3
"""Favilla push bridge (9 Nov 2026): wakes the Favilla iPhone app when a Nostr
app sends a NIP-46 request to a Favilla KEY in Bluetooth mode.

The KEY has no internet in Bluetooth mode. Its bunker requests (kind 24133,
p-tagged to the KEY's key) go to the relays in its bunker:// link. This bridge
listens on those relays for each registered key. When a request arrives it:
  1. keeps the event for 120 s (24133 is ephemeral: relays don't store it, so
     the iPhone can't fetch it later from them), and
  2. sends a wake-up push to the registered iPhone(s). The app's notification
     extension then fetches the waiting requests from here, hands each to the
     KEY over Bluetooth and publishes the KEY's replies to the relays.

It sees nothing a relay subscriber couldn't: requests are NIP-44 encrypted to
the KEY, and anyone may subscribe to them on a public relay. Registration needs
no login for that reason; it only decides which phone gets woken.

HTTP (behind nginx at https://relay.favillakey.io/push/):
  POST /push/register    {"pubkey": hex64, "token": hex, "env": "production"|"development",
                          "relays": ["wss://...", ...]}   -> {"ok": true}
  POST /push/unregister  {"pubkey": hex64, "token": hex}  -> {"ok": true}
  GET  /push/pending?pubkey=hex64                         -> {"events": [event, ...]}
  GET  /push/health                                       -> {"ok": true, ...}

Config: /etc/favilla-push/config.json (see config.example.json).
"""
import asyncio
import collections
import json
import logging
import os
import re
import sys
import time

import aiohttp
from aiohttp import web
import websockets

log = logging.getLogger("favilla-push")

HEX64 = re.compile(r"^[0-9a-f]{64}$")
TOKEN = re.compile(r"^[0-9a-f]{64,200}$")
RELAY = re.compile(r"^wss://[A-Za-z0-9.-]{1,100}(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]{0,100})?$")
KEEP_S = 120            # how long a request waits here for the phone
MAX_PER_KEY = 64        # requests kept per KEY
MAX_RELAYS = 8          # relays per registration
MAX_TOKENS = 4          # phones per KEY
PUSH_GAP_S = 1.0        # at most one push per phone per second (a trailing one follows)
AGAIN_MAX = 6           # follow-up pushes per request chain (about 3 minutes of waiting for an approval)
AGAIN_DELAY_S = 2       # after the extension asks (it has just stopped)
AGAIN_GAP_S = 3         # at most one follow-up per phone per 3 s


# ---------------------------------------------------------------- state ------

class Store:
    """Registrations, persisted as JSON: {pubkey: {token: {"env", "relays", "at"}}}."""

    def __init__(self, path):
        self.path = path
        try:
            with open(path) as f:
                self.reg = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            self.reg = {}

    def save(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.reg, f)
        os.replace(tmp, self.path)

    def add(self, pubkey, token, env, relays, voip=None):
        toks = self.reg.setdefault(pubkey, {})
        old = toks.get(token) or {}
        toks[token] = {"env": env, "relays": relays, "at": int(time.time()),
                       "voip": voip if voip is not None else old.get("voip")}
        if len(toks) > MAX_TOKENS:   # keep the newest phones
            for t, _ in sorted(toks.items(), key=lambda kv: kv[1]["at"])[:len(toks) - MAX_TOKENS]:
                del toks[t]
        self.save()

    def remove(self, pubkey, token):
        if self.reg.get(pubkey, {}).pop(token, None) is not None:
            if not self.reg[pubkey]:
                del self.reg[pubkey]
            self.save()
            return True
        return False

    def relay_map(self):
        """relay url -> set of pubkeys to listen for there."""
        m = collections.defaultdict(set)
        for pk, toks in self.reg.items():
            for info in toks.values():
                for r in info["relays"]:
                    m[r].add(pk)
        return m


class Pending:
    """Requests waiting for the phone, per KEY, for KEEP_S seconds."""

    def __init__(self):
        self.by_key = collections.defaultdict(collections.deque)
        self.seen = collections.OrderedDict()

    def add(self, pubkey, ev):
        if ev["id"] in self.seen:
            return False
        self.seen[ev["id"]] = time.time()
        while len(self.seen) > 4000:
            self.seen.popitem(last=False)
        q = self.by_key[pubkey]
        q.append((time.time(), ev))
        while len(q) > MAX_PER_KEY:
            q.popleft()
        return True

    def get(self, pubkey):
        q = self.by_key.get(pubkey)
        if not q:
            return []
        cut = time.time() - KEEP_S
        while q and q[0][0] < cut:
            q.popleft()
        return [ev for _, ev in q]


CALL_KIND = 21059         # the NIP-AC call wrap (OFFER, ANSWER, ICE, HANGUP, all look alike from outside)
CALL_GAP_S = 20           # at most one ring push per phone per 20 s (ICE wraps come in bursts)
CALL_KEEP_S = 90          # call wraps kept for the phone to fetch (offers go stale at 60 s)
CALL_OVER_S = 10          # no ring for this long after the app says a call ended (late candidates from the other side)
CALL_MIN_CONTENT = 2000   # a wrap smaller than this can't hold an offer (SDP): a hang-up, reject or candidate. Kept for the phone, never rung.
CALL_WRAP_MAX = 48


def valid_call(ev, pubkeys):
    """A kind-21059 wrap p-tagged to one of our keys. The bridge can't read it
    (NIP-44 to the owner's key); the phone finds out what it is."""
    if not isinstance(ev, dict) or ev.get("kind") != CALL_KIND:
        return None
    if not isinstance(ev.get("id"), str) or not HEX64.match(ev["id"]):
        return None
    for t in ev.get("tags") or []:
        if isinstance(t, list) and len(t) >= 2 and t[0] == "p" and t[1] in pubkeys:
            return t[1]
    return None


def valid_request(ev, pubkeys):
    """A kind-24133 event p-tagged to one of our keys. Signatures are not checked
    here: the KEY checks everything, and a forged event costs the phone one wake."""
    if not isinstance(ev, dict) or ev.get("kind") != 24133:
        return None
    if not isinstance(ev.get("id"), str) or not HEX64.match(ev["id"]):
        return None
    if not isinstance(ev.get("content"), str) or len(ev["content"]) > 65536:
        return None
    for t in ev.get("tags") or []:
        if isinstance(t, list) and len(t) >= 2 and t[0] == "p" and t[1] in pubkeys:
            return t[1]
    return None


# ---------------------------------------------------------------- APNs -------

class Apns:
    def __init__(self, team_id, key_id, key_path, topic):
        self.team_id, self.key_id, self.topic = team_id, key_id, topic
        with open(key_path) as f:
            self.key = f.read()
        self._jwt, self._jwt_at = None, 0
        import httpx
        self.http = httpx.AsyncClient(http2=True, timeout=10)

    def token(self):
        import jwt
        if not self._jwt or time.time() - self._jwt_at > 40 * 60:   # APNs wants a fresh one within the hour
            self._jwt_at = int(time.time())
            self._jwt = jwt.encode({"iss": self.team_id, "iat": self._jwt_at}, self.key,
                                   algorithm="ES256", headers={"kid": self.key_id})
        return self._jwt

    async def ring(self, device, env, pubkey, ev):
        """A VoIP push (PushKit): topic <bundle>.voip, delivered at once or not at all."""
        host = "api.sandbox.push.apple.com" if env == "development" else "api.push.apple.com"
        body = {"fv": {"call": 1, "pk": pubkey, "id": ev["id"], "at": ev.get("created_at", 0)}}
        if len(json.dumps(ev, separators=(",", ":"))) <= PUSH_BUDGET:
            body["fv"]["ev"] = ev
        r = await self.http.post(f"https://{host}/3/device/{device}", json=body, headers={
            "authorization": "bearer " + self.token(), "apns-topic": self.topic + ".voip",
            "apns-push-type": "voip", "apns-priority": "10", "apns-expiration": str(int(time.time()) + 45)})
        return r.status_code, r.text

    async def send(self, device, env, pubkey, waiting, round_=0, events=None):
        host = "api.sandbox.push.apple.com" if env == "development" else "api.push.apple.com"
        text = "Signing request from a Nostr app"
        # time-sensitive: iOS delivers it at once, through Focus and summaries.
        # The requests themselves ride along when they fit (APNs allows 4 KB), so
        # the phone has nothing to fetch before it talks to the KEY.
        body = {"aps": {"alert": {"title": "Favilla", "body": text},
                        "mutable-content": 1, "thread-id": "bunker", "interruption-level": "time-sensitive"},
                "fv": {"pk": pubkey, "n": waiting, "r": round_}}
        if events:
            body["fv"]["evs"] = events
        r = await self.http.post(f"https://{host}/3/device/{device}", json=body, headers={
            "authorization": "bearer " + self.token(), "apns-topic": self.topic,
            "apns-push-type": "alert", "apns-priority": "10", "apns-expiration": "0",
            "apns-collapse-id": "bunker-" + pubkey[:16]})
        reason = ""
        if r.status_code != 200:
            try:
                reason = r.json().get("reason", "")
            except ValueError:
                reason = r.text[:100]
        return r.status_code, reason


LINKED_S = 15           # a phone that asked over its Bluetooth link this recently is "linked" (path B)
LINK_GRACE_S = 9        # how long a linked phone gets to take a request before the push goes anyway
PUSH_BUDGET = 3700      # bytes of request events carried in a push (APNs max payload 4096)


def fit_events(evs, budget=PUSH_BUDGET):
    """The newest waiting requests that fit in a push, oldest first."""
    out, used = [], 0
    for ev in reversed(evs):
        n = len(json.dumps(ev, separators=(",", ":")))
        if used + n + 1 > budget:
            break
        out.insert(0, ev)
        used += n + 1
    return out


# ---------------------------------------------------------------- bridge -----

class Bridge:
    def __init__(self, store, pending, sender, ringer=None):
        self.store, self.pending, self.sender = store, pending, sender
        self.ringer = ringer          # async (voip_token, env, pubkey, wrap) -> (status, reason)
        self.listeners = {}          # relay url -> task
        self.wanted = {}             # relay url -> set of pubkeys
        self.changed = {}            # relay url -> asyncio.Event (resubscribe)
        self.last_push = {}          # token -> time
        self.trailing = set()        # tokens with a trailing push scheduled
        self.last_again = {}         # token -> time of the last follow-up
        self.last_link = {}          # pubkey -> time the app last asked on a KEY nudge (path B)
        self.last_ring = {}          # pubkey -> time of the last VoIP push
        self.in_call = {}            # pubkey -> time the app last said it is in a call
        self.call_over = {}          # pubkey -> time the app said the call (or ring) ended
        self.seen_calls = set()
        self.call_wraps = collections.defaultdict(list)   # pubkey -> recent 21059 wraps (the phone fetches them: ephemeral, so no relay replays them)
        self.fetched = collections.defaultdict(set)   # pubkey -> request ids handed out
        self.stats = collections.Counter()

    # relays

    def sync(self):
        m = self.store.relay_map()
        for url, pks in m.items():
            if self.wanted.get(url) != pks:
                self.wanted[url] = pks
                self.changed.setdefault(url, asyncio.Event()).set()
            if url not in self.listeners or self.listeners[url].done():
                self.listeners[url] = asyncio.create_task(self.listen(url))
        for url in list(self.listeners):
            if url not in m:
                self.wanted.pop(url, None)
                self.listeners.pop(url).cancel()

    async def listen(self, url):
        backoff = 2
        while url in self.wanted:
            try:
                async with websockets.connect(url, open_timeout=10, ping_interval=30, max_size=2**20) as ws:
                    log.info("relay %s: connected", url)
                    backoff = 2
                    while url in self.wanted:
                        ev_changed = self.changed.setdefault(url, asyncio.Event())
                        ev_changed.clear()
                        pks = sorted(self.wanted.get(url, ()))
                        await ws.send(json.dumps(["REQ", "fvpush", {"kinds": [24133, CALL_KIND], "#p": pks,
                                                                     "since": int(time.time()) - 10}]))
                        while not ev_changed.is_set():
                            recv = asyncio.ensure_future(ws.recv())
                            wait = asyncio.ensure_future(ev_changed.wait())
                            done, _ = await asyncio.wait({recv, wait}, return_when=asyncio.FIRST_COMPLETED)
                            if recv not in done:
                                recv.cancel()
                                break
                            wait.cancel()
                            await self.on_message(url, recv.result(), set(pks))
                        await ws.send(json.dumps(["CLOSE", "fvpush"]))
            except asyncio.CancelledError:
                return
            except Exception as e:  # noqa: BLE001 - any relay failure: retry
                log.warning("relay %s: %s; retry in %d s", url, e, backoff)
                await asyncio.sleep(backoff)
                backoff = min(120, backoff * 2)

    async def on_message(self, url, raw, pks):
        try:
            msg = json.loads(raw)
        except ValueError:
            return
        if not isinstance(msg, list) or len(msg) < 3 or msg[0] != "EVENT":
            return
        ev = msg[2]
        cpk = valid_call(ev, pks)
        if cpk:
            await self.ring(cpk, ev, url)
            return
        pk = valid_request(ev, pks)
        if not pk or not self.pending.add(pk, ev):
            return
        self.stats["requests"] += 1
        log.info("request %s… for %s… via %s", ev["id"][:12], pk[:12], url)
        # Path B (issue #11, 9 Nov): the KEY nudges the app over Bluetooth every
        # few seconds and the app asks here. While it does, give it a moment to
        # take the request itself; push only if it doesn't.
        if time.time() - self.last_link.get(pk, 0) < LINKED_S:
            asyncio.ensure_future(self._push_unless_taken(pk, ev["id"]))
            return
        await self.push_all(pk)

    # Calls (10 Nov 2026): a 21059 wrap for the owner means a call is starting,
    # or in progress (ICE, answer, hang-up all travel the same way). The phone
    # gets a VoIP push, which iOS must turn into a ringing call or an immediate
    # end; while a call is live the app tells us so and nothing is sent.
    async def ring(self, pk, ev, url):
        if ev["id"] in self.seen_calls:
            return
        self.seen_calls.add(ev["id"])
        wraps = self.call_wraps[pk]
        wraps.append(ev)
        cutoff = time.time() - CALL_KEEP_S
        self.call_wraps[pk] = [w for w in wraps if w.get("created_at", 0) >= cutoff][-CALL_WRAP_MAX:]
        if len(ev.get("content") or "") < CALL_MIN_CONTENT:
            log.info("call wrap %s… for %s…: %d bytes, too small for an offer; kept, no ring", ev["id"][:12], pk[:12], len(ev.get("content") or ""))
            return
        if len(self.seen_calls) > 5000:
            self.seen_calls.clear()
        now = time.time()
        if now - self.in_call.get(pk, 0) < 90:
            return
        if now - self.call_over.get(pk, 0) < CALL_OVER_S:
            return
        if now - self.last_ring.get(pk, 0) < CALL_GAP_S:
            return
        self.last_ring[pk] = now
        self.stats["calls"] = self.stats.get("calls", 0) + 1
        log.info("call wrap %s… for %s… via %s", ev["id"][:12], pk[:12], url)
        for token, info in list(self.store.reg.get(pk, {}).items()):
            if not info.get("voip"):
                continue
            try:
                if not self.ringer:
                    log.warning("no VoIP sender configured; can't ring %s…", token[:8])
                    return
                status, reason = await self.ringer(info["voip"], info["env"], pk, ev)
            except Exception as e:  # noqa: BLE001
                log.warning("VoIP push to %s…: %s", token[:8], e)
                continue
            if status == 410 or (status == 400 and "BadDeviceToken" in reason):
                log.info("VoIP token for %s… is gone (%s); dropping the ring token", token[:8], reason)
                info["voip"] = None
                self.store.save()
            elif status != 200:
                log.warning("VoIP push to %s…: HTTP %s %s", token[:8], status, reason)

    async def push_all(self, pk):
        for token, info in list(self.store.reg.get(pk, {}).items()):
            await self.push(pk, token, info["env"])

    async def _push_unless_taken(self, pk, ev_id):
        await asyncio.sleep(LINK_GRACE_S)
        if ev_id in self.fetched.get(pk, ()):
            self.stats["taken_over_link"] = self.stats.get("taken_over_link", 0) + 1
            log.info("request %s… taken over the Bluetooth link, no push", ev_id[:12])
            return
        log.info("request %s… not taken over the link in %d s: push", ev_id[:12], LINK_GRACE_S)
        await self.push_all(pk)

    def handed_out(self, pk, evs, link):
        if link:
            self.last_link[pk] = time.time()
        ids = self.fetched[pk]
        ids.update(e["id"] for e in evs)
        if len(ids) > 2000:
            ids.clear()
            ids.update(e["id"] for e in evs)

    # pushes

    async def push(self, pk, token, env):
        gap = time.time() - self.last_push.get(token, 0)
        if gap < PUSH_GAP_S:
            if token not in self.trailing:     # one trailing push covers a burst
                self.trailing.add(token)
                asyncio.get_running_loop().call_later(PUSH_GAP_S - gap, lambda: asyncio.ensure_future(self._trail(pk, token, env)))
            return
        await self._send(pk, token, env)

    async def _trail(self, pk, token, env):
        self.trailing.discard(token)
        await self._send(pk, token, env)

    async def _send(self, pk, token, env):
        self.last_push[token] = time.time()
        try:
            evs = self.pending.get(pk)
            status, reason = await self.sender(token, env, pk, len(evs), 0, fit_events(evs))
        except Exception as e:  # noqa: BLE001
            log.warning("push to %s…: %s", token[:8], e)
            self.stats["push_errors"] += 1
            return
        if status == 200:
            self.stats["pushes"] += 1
            return
        self.stats["push_errors"] += 1
        log.warning("push to %s…: HTTP %s %s", token[:8], status, reason)
        if status == 410 or reason in ("BadDeviceToken", "Unregistered", "DeviceTokenNotForTopic"):
            if self.store.remove(pk, token):
                log.info("removed phone %s… (%s)", token[:8], reason or status)
                self.sync()


    # A follow-up push (9 Nov 2026). The phone's extension lives about 30 s; a
    # request waiting for a button press on the KEY can take longer. When the
    # extension runs out with the KEY still busy, it asks for another push a few
    # seconds later, and the next run collects the reply. At most AGAIN_MAX rounds.
    async def again(self, pk, token, round_, delay=None):
        env = self.store.reg.get(pk, {}).get(token, {}).get("env")
        if not env:
            return False
        if time.time() - self.last_again.get(token, 0) < AGAIN_GAP_S:
            return False
        self.last_again[token] = time.time()

        wait = AGAIN_DELAY_S if delay is None else delay

        async def later():
            await asyncio.sleep(wait)
            try:
                evs = self.pending.get(pk)
                status, reason = await self.sender(token, env, pk, len(evs), round_, fit_events(evs))
                if status != 200:
                    log.warning("follow-up push to %s…: HTTP %s %s", token[:8], status, reason)
            except Exception as e:  # noqa: BLE001
                log.warning("follow-up push to %s…: %s", token[:8], e)
        asyncio.ensure_future(later())
        log.info("follow-up push %d for %s… in %s s", round_, token[:8], wait)
        return True


# ---------------------------------------------------------------- HTTP -------

def make_app(bridge):
    hits = collections.defaultdict(collections.deque)

    def limited(req, n=20):
        ip = req.headers.get("X-Real-IP") or req.remote or "?"
        q = hits[ip]
        now = time.time()
        while q and q[0] < now - 60:
            q.popleft()
        q.append(now)
        return len(q) > n

    async def body(req):
        try:
            b = await req.json()
            return b if isinstance(b, dict) else None
        except (ValueError, aiohttp.ContentTypeError):
            return None

    async def register(req):
        if limited(req):
            return web.json_response({"error": "slow down"}, status=429)
        b = await body(req)
        if not b:
            return web.json_response({"error": "json body needed"}, status=400)
        pk, tok = str(b.get("pubkey", "")).lower(), str(b.get("token", "")).lower()
        env = b.get("env", "production")
        relays = b.get("relays") or []
        voip = b.get("voip")
        if voip is not None and (not isinstance(voip, str) or not TOKEN.match(voip.lower())):
            return web.json_response({"error": "bad voip token"}, status=400)
        if not HEX64.match(pk) or not TOKEN.match(tok) or env not in ("production", "development"):
            return web.json_response({"error": "bad pubkey, token or env"}, status=400)
        if not isinstance(relays, list) or not relays or len(relays) > MAX_RELAYS or not all(isinstance(r, str) and RELAY.match(r) for r in relays):
            return web.json_response({"error": f"relays: 1 to {MAX_RELAYS} wss:// URLs"}, status=400)
        bridge.store.add(pk, tok, env, sorted(set(relays)), voip.lower() if voip else None)
        bridge.sync()
        log.info("registered phone %s… for %s… on %d relay(s)", tok[:8], pk[:12], len(set(relays)))
        return web.json_response({"ok": True})

    async def unregister(req):
        if limited(req):
            return web.json_response({"error": "slow down"}, status=429)
        b = await body(req) or {}
        pk, tok = str(b.get("pubkey", "")).lower(), str(b.get("token", "")).lower()
        if bridge.store.remove(pk, tok):
            bridge.sync()
        return web.json_response({"ok": True})

    async def pending(req):
        if limited(req, 120):
            return web.json_response({"error": "slow down"}, status=429)
        pk = req.query.get("pubkey", "").lower()
        if not HEX64.match(pk):
            return web.json_response({"error": "bad pubkey"}, status=400)
        evs = bridge.pending.get(pk)
        bridge.handed_out(pk, evs, req.query.get("via") == "link")
        return web.json_response({"events": evs})

    async def calls(req):
        """The recent call wraps for a pubkey: the phone feeds them to the client
        (they are ephemeral, so a client that wasn't connected never sees them)."""
        if limited(req, 120):
            return web.json_response({"error": "slow down"}, status=429)
        pk = req.query.get("pubkey", "").lower()
        if not HEX64.match(pk):
            return web.json_response({"error": "bad pubkey"}, status=400)
        cutoff = time.time() - CALL_KEEP_S
        return web.json_response({"events": [w for w in bridge.call_wraps.get(pk, []) if w.get("created_at", 0) >= cutoff]})

    async def incall(req):
        """The app is in a call (or just left one): no VoIP pushes meanwhile."""
        if limited(req):
            return web.json_response({"error": "slow down"}, status=429)
        b = await body(req) or {}
        pk = str(b.get("pubkey", "")).lower()
        if not HEX64.match(pk):
            return web.json_response({"error": "bad pubkey"}, status=400)
        if b.get("live", True):
            bridge.in_call[pk] = time.time()
        else:
            bridge.in_call.pop(pk, None)
            bridge.call_over[pk] = time.time()
        return web.json_response({"ok": True})

    async def again(req):
        if limited(req):
            return web.json_response({"error": "slow down"}, status=429)
        b = await body(req) or {}
        pk, tok = str(b.get("pubkey", "")).lower(), str(b.get("token", "")).lower()
        try:
            rnd = int(b.get("round", 0))
        except (TypeError, ValueError):
            rnd = 0
        if not HEX64.match(pk) or not TOKEN.match(tok) or not 1 <= rnd <= AGAIN_MAX:
            return web.json_response({"error": f"bad pubkey, token or round (1 to {AGAIN_MAX})"}, status=400)
        try:
            delay = min(5.0, max(0.0, float(b.get("delay", AGAIN_DELAY_S))))
        except (TypeError, ValueError):
            delay = AGAIN_DELAY_S
        ok = await bridge.again(pk, tok, rnd, delay)
        return web.json_response({"ok": ok})

    async def health(req):
        return web.json_response({"ok": True, "keys": len(bridge.store.reg),
                                  "relays": sorted(bridge.wanted), **bridge.stats})

    app = web.Application(client_max_size=16 * 1024)
    app.router.add_post("/push/register", register)
    app.router.add_post("/push/unregister", unregister)
    app.router.add_get("/push/pending", pending)
    app.router.add_get("/push/health", health)
    app.router.add_post("/push/again", again)
    app.router.add_post("/push/incall", incall)
    app.router.add_get("/push/calls", calls)
    return app


async def main(cfg_path):
    with open(cfg_path) as f:
        cfg = json.load(f)
    apns = Apns(cfg["team_id"], cfg["key_id"], cfg["key_path"], cfg.get("topic", "io.favillakey.app"))
    bridge = Bridge(Store(cfg.get("db", "/var/lib/favilla-push/devices.json")), Pending(), apns.send, apns.ring)
    bridge.sync()
    runner = web.AppRunner(make_app(bridge))
    await runner.setup()
    host, port = cfg.get("listen", "127.0.0.1:8787").rsplit(":", 1)
    await web.TCPSite(runner, host, int(port)).start()
    log.info("listening on %s:%s, %d key(s) registered", host, port, len(bridge.store.reg))
    await asyncio.Event().wait()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s", stream=sys.stdout)
    asyncio.run(main(sys.argv[1] if len(sys.argv) > 1 else "/etc/favilla-push/config.json"))
