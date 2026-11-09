#!/usr/bin/env python3
"""Make sure every App ID the project signs exists, with the capabilities it needs.

Xcode's automatic signing in CI can make profiles for App IDs that exist, but
registering a brand-new App ID through the App Store Connect key failed on
9 Nov 2026 ("Authentication failed ... bearer token", target FavillaPushProbe).
So this registers any missing App ID first, and turns on the capabilities each
needs, through the same key. Idempotent: an App ID or capability that is
already there is left alone. Xcode still assigns the app group itself.

Env: ASC_KEY_ID, ASC_ISSUER_ID, and the .p8 path in ASC_KEY_PATH.
"""
import json
import os
import sys
import urllib.error
import urllib.request

from revoke_ci_dev_certs import API, token

# identifier -> (name shown in the developer account, capabilities)
WANTED = {
    "io.favillakey.app": ("Favilla", ["APP_GROUPS", "AUTOFILL_CREDENTIAL_PROVIDER", "PUSH_NOTIFICATIONS"]),
    "io.favillakey.app.autofill": ("Favilla AutoFill", ["APP_GROUPS", "AUTOFILL_CREDENTIAL_PROVIDER"]),
    "io.favillakey.app.pushprobe": ("Favilla Push Probe", ["APP_GROUPS"]),
}


def call(method, path, tok, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(API + path, data=data, method=method,
                                 headers={"Authorization": "Bearer " + tok, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            b = r.read()
            return r.status, (json.loads(b) if b else None)
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def errors(j):
    return "; ".join(f"{e.get('title')}: {e.get('detail')}" for e in (j or {}).get("errors", []))


def main() -> int:
    tok = token()
    ok = True
    for ident, (name, caps) in WANTED.items():
        st, j = call("GET", f"/bundleIds?filter[identifier]={ident}&include=bundleIdCapabilities&limit=20", tok)
        if st != 200:
            print(f"::error::listing {ident}: HTTP {st} {errors(j)}"); ok = False; continue
        found = [d for d in j["data"] if d["attributes"]["identifier"] == ident]
        if found:
            bid = found[0]["id"]
            print(f"{ident}: exists ({bid})")
        else:
            st, j = call("POST", "/bundleIds", tok, {"data": {"type": "bundleIds", "attributes": {
                "identifier": ident, "name": name, "platform": "IOS"}}})
            if st != 201:
                print(f"::error::registering {ident}: HTTP {st} {errors(j)}"); ok = False; continue
            bid = j["data"]["id"]
            print(f"{ident}: registered ({bid})")
        st, j = call("GET", f"/bundleIds/{bid}?include=bundleIdCapabilities", tok)
        if st != 200:
            print(f"::warning::{ident}: can't read its capabilities (HTTP {st} {errors(j)}); leaving them alone")
            continue
        have = {c["attributes"].get("capabilityType") for c in (j.get("included") or []) if c.get("type") == "bundleIdCapabilities"}
        print(f"  has: {', '.join(sorted(x for x in have if x)) or 'none listed'}")
        for cap in caps:
            if cap in have:
                continue
            st, j = call("POST", "/bundleIdCapabilities", tok, {"data": {"type": "bundleIdCapabilities",
                "attributes": {"capabilityType": cap},
                "relationships": {"bundleId": {"data": {"type": "bundleIds", "id": bid}}}}})
            if st == 201:
                print(f"  {cap}: turned on")
            elif st == 409:
                print(f"  {cap}: already on")
            else:
                print(f"::warning::{ident} {cap}: HTTP {st} {errors(j)}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
