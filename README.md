# Favilla for iPhone

The iPhone app for the Favilla KEY: an AutoFill provider that signs you in with
passkeys and passwords held on the KEY, reached over Bluetooth. Keys never
leave the KEY; the app only relays requests and answers.

**Stage: passwords and passkeys (KEY firmware 9c).** Built against
favilla-key-firmware `docs/BLE_PASSKEY_PROTOCOL.md`.

- Passwords: pick Favilla in Safari's sign-in sheet, pick the login on the KEY;
  the KEY sends it to the sheet and iOS fills the fields (FILL on 8F1A0003,
  answer on 8F1A0004).
- Passkeys: make and sign in, CTAP2 over the FIDO Bluetooth framing on
  8F1A0010-12. The app hands iOS a "none" attestation (iOS refused "packed").
- Pairing ("App only" mode): open PAIR A PHONE on the KEY, tap FIND MY KEY in
  the app, accept the code.
- The app shows the last AutoFill request's log (SHOW LAST REQUEST).

## Build

No Mac needed. GitHub Actions builds it on macOS (`.github/workflows/ios.yml`):

- every push to `main`: unsigned simulator build (compile check);
- Actions > iOS > Run workflow, tick "Upload to TestFlight": signed build to
  TestFlight (needs the four secrets listed at the top of the workflow).

The Xcode project is generated from `project.yml` with XcodeGen.
