#!/usr/bin/env python3
"""Revoke the development certificates earlier CI runs created.

Every run starts on a clean Mac, so Xcode's automatic signing makes a new
"Apple Development: Created via API" certificate each time, and Apple caps how
many an account may hold. They are only used to build the archive (the upload
is re-signed for distribution), so revoking them leaves TestFlight builds alone.

Only certificates whose name says "Created via API" are touched: anything made
by hand in the developer account is left as it is.

Env: ASC_KEY_ID, ASC_ISSUER_ID, and the .p8 path in ASC_KEY_PATH.
"""
import json
import os
import sys
import time
import urllib.request

import jwt  # PyJWT, with cryptography for ES256

API = "https://api.appstoreconnect.apple.com/v1"


def token() -> str:
    with open(os.environ["ASC_KEY_PATH"], "rb") as f:
        key = f.read()
    now = int(time.time())
    return jwt.encode(
        {"iss": os.environ["ASC_ISSUER_ID"], "iat": now, "exp": now + 600, "aud": "appstoreconnect-v1"},
        key,
        algorithm="ES256",
        headers={"kid": os.environ["ASC_KEY_ID"], "typ": "JWT"},
    )


def call(method: str, path: str, tok: str):
    req = urllib.request.Request(API + path, method=method, headers={"Authorization": "Bearer " + tok})
    with urllib.request.urlopen(req, timeout=30) as r:
        body = r.read()
        return json.loads(body) if body else None


def main() -> int:
    tok = token()
    certs = call("GET", "/certificates?filter[certificateType]=DEVELOPMENT,IOS_DEVELOPMENT&limit=200", tok)["data"]
    ours = [c for c in certs if "Created via API" in (c["attributes"].get("name") or "") + (c["attributes"].get("displayName") or "")]
    print(f"{len(certs)} development certificate(s), {len(ours)} made by CI")
    for c in ours:
        a = c["attributes"]
        call("DELETE", f"/certificates/{c['id']}", tok)
        print(f"revoked {a.get('name')} (serial {a.get('serialNumber')}, expires {a.get('expirationDate')})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
