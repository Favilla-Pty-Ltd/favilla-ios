# Favilla push bridge

Runs on the relay box next to strfry. It wakes the Favilla iPhone app when a
Nostr app sends a NIP-46 request to a Favilla KEY in Bluetooth mode (firmware
issue #11). See the top of `bridge.py` for how it works and its HTTP routes.

Install or update (on the box, as root, from a folder holding both files):

    sudo bash favilla-push.sh /path/to/AuthKey_KEYID.p8 KEYID

Check: `curl https://relay.favillakey.io/push/health` and `journalctl -u favilla-push -f`.

Tests (no network): `python3 server/push-bridge/test_bridge.py` (also run in CI).
