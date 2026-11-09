#!/usr/bin/env python3
"""Tests for bridge.py with a fake relay and a fake APNs sender. No network.
Run: python3 server/push-bridge/test_bridge.py"""
import asyncio
import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import websockets  # noqa: E402
from aiohttp.test_utils import TestClient, TestServer  # noqa: E402

import bridge as B  # noqa: E402

KEY = "dc" * 32          # the KEY's pubkey
OTHER = "ab" * 32
TOK = "20ff43ed267737978f8071cccdfc9711b874e473ad105b39c2fdd205dae12dc7"
fails = 0


def ok(c, name):
    global fails
    print(("ok   " if c else "FAIL ") + name)
    if not c:
        fails += 1


def ev(i, kind=24133, p=KEY):
    return {"id": f"{i:064x}", "pubkey": "11" * 32, "created_at": int(time.time()), "kind": kind,
            "tags": [["p", p]], "content": "nip44-ciphertext", "sig": "00" * 64}


async def main():
    reqs = []            # filters the fake relay was asked for
    clients = []

    async def relay(ws):
        clients.append(ws)
        async for raw in ws:
            m = json.loads(raw)
            if m[0] == "REQ":
                reqs.append(m[2])

    srv = await websockets.serve(relay, "127.0.0.1", 0)
    url = f"ws://127.0.0.1:{srv.sockets[0].getsockname()[1]}"

    pushes = []

    async def sender(token, env, pk, n, round_=0):
        pushes.append((token, env, pk, n, time.time(), round_))
        return 200, ""

    d = tempfile.mkdtemp()
    store = B.Store(os.path.join(d, "devices.json"))
    br = B.Bridge(store, B.Pending(), sender)

    # register straight in the store (the HTTP route only allows wss://)
    store.add(KEY, TOK, "production", [url])
    br.sync()
    for _ in range(50):
        if reqs:
            break
        await asyncio.sleep(0.05)
    ok(reqs and reqs[0]["kinds"] == [24133] and reqs[0]["#p"] == [KEY], "subscribes for kind 24133 #p the KEY")

    ws = clients[0]
    await ws.send(json.dumps(["EVENT", "fvpush", ev(1)]))
    await ws.send(json.dumps(["EVENT", "fvpush", ev(1)]))            # duplicate
    await ws.send(json.dumps(["EVENT", "fvpush", ev(2, kind=1)]))    # not a request
    await ws.send(json.dumps(["EVENT", "fvpush", ev(3, p=OTHER)]))   # not our KEY
    await asyncio.sleep(0.3)
    ok([e["id"] for e in br.pending.get(KEY)] == [f"{1:064x}"], "keeps one request; drops duplicate, other kinds, other keys")
    ok(len(pushes) == 1 and pushes[0][:4] == (TOK, "production", KEY, 1), "one push to the phone with the waiting count")

    # a burst: one trailing push after the gap, not one per request
    for i in range(10, 15):
        await ws.send(json.dumps(["EVENT", "fvpush", ev(i)]))
    await asyncio.sleep(1.5)
    ok(len(pushes) == 2 and pushes[1][3] == 6, "a burst of 5 gives one trailing push, counting 6 waiting")
    ok(pushes[1][4] - pushes[0][4] >= B.PUSH_GAP_S - 0.05, "pushes at least a second apart")

    # a second KEY on the same relay: resubscribes with both
    n0 = len(reqs)
    store.add(OTHER, "aa" * 32, "development", [url])
    br.sync()
    await asyncio.sleep(0.5)
    ok(len(reqs) > n0 and sorted(reqs[-1]["#p"]) == sorted([KEY, OTHER]), "resubscribes when a KEY registers")

    # expiry
    B.KEEP_S, keep = 0, B.KEEP_S
    ok(br.pending.get(KEY) == [], "requests expire")
    B.KEEP_S = keep

    # a dead token is dropped
    async def gone(token, env, pk, n, round_=0):
        return 410, "Unregistered"
    br.sender = gone
    br.last_push.clear()
    await ws.send(json.dumps(["EVENT", "fvpush", ev(99)]))
    await asyncio.sleep(0.3)
    ok(TOK not in store.reg.get(KEY, {}), "an unregistered phone is removed")
    br.sender = sender

    # HTTP
    client = TestClient(TestServer(B.make_app(br)))
    await client.start_server()
    r = await client.post("/push/register", json={"pubkey": "nothex", "token": TOK, "relays": [url]})
    ok(r.status == 400, "register: bad pubkey refused")
    r = await client.post("/push/register", json={"pubkey": KEY, "token": TOK, "relays": ["http://evil"]})
    ok(r.status == 400, "register: non-wss relay refused")
    r = await client.post("/push/register", json={"pubkey": KEY, "token": TOK, "env": "production",
                                                  "relays": ["wss://relay.favillakey.io", "wss://nos.lol"]})
    ok(r.status == 200 and TOK in store.reg[KEY], "register: ok")
    ok(json.load(open(os.path.join(d, "devices.json")))[KEY][TOK]["relays"] == ["wss://nos.lol", "wss://relay.favillakey.io"], "registration saved to disk")
    r = await client.get("/push/pending", params={"pubkey": KEY})
    evs = (await r.json())["events"]
    ok(r.status == 200 and [e["id"] for e in evs] == [f"{99:064x}"], "pending returns what is still waiting (the earlier ones expired above)")
    r = await client.get("/push/health")
    h = await r.json()
    ok(h["ok"] and h["requests"] >= 7, "health reports counts")
    # follow-up push: only for a registered phone, rounds 1..AGAIN_MAX, at most one per 10 s
    B.AGAIN_DELAY_S = 0
    n0 = len(pushes)
    r = await client.post("/push/again", json={"pubkey": KEY, "token": TOK, "round": 1})
    ok((await r.json())["ok"] is True, "again: accepted for a registered phone")
    await asyncio.sleep(0.2)
    ok(len(pushes) == n0 + 1 and pushes[-1][5] == 1, "again: one follow-up push, round 1")
    r = await client.post("/push/again", json={"pubkey": KEY, "token": TOK, "round": 2})
    ok((await r.json())["ok"] is False, "again: a second within 10 s is refused")
    r = await client.post("/push/again", json={"pubkey": KEY, "token": "ab" * 32, "round": 1})
    ok((await r.json())["ok"] is False, "again: an unknown phone gets nothing")
    r = await client.post("/push/again", json={"pubkey": KEY, "token": TOK, "round": 99})
    ok(r.status == 400, "again: round out of range refused")

    r = await client.post("/push/unregister", json={"pubkey": KEY, "token": TOK})
    ok(r.status == 200 and TOK not in store.reg.get(KEY, {}), "unregister")
    await client.close()

    for t in br.listeners.values():
        t.cancel()
    srv.close()
    print("ALL PASSED" if not fails else f"{fails} FAILED")
    return fails


if __name__ == "__main__":
    sys.exit(1 if asyncio.run(main()) else 0)
