# Favilla for iPhone

The iPhone app for the Favilla KEY: an AutoFill provider that signs you in with
passkeys and passwords held on the KEY, reached over Bluetooth. Keys never
leave the KEY; the app only relays requests and answers.

**Stage: sign in (passwords).** Pick Favilla in Safari's sign-in sheet: the
sheet sends the site to the KEY and closes, you pick the login on the KEY, and
the KEY types it in as the phone's Bluetooth keyboard. The app never receives a
password. Needs KEY firmware drop 8z7 or later. Passkeys are not wired up yet.
The app itself still runs the link probe (FIND MY KEY).

## Build

No Mac needed. GitHub Actions builds it on macOS (`.github/workflows/ios.yml`):

- every push to `main`: unsigned simulator build (compile check);
- Actions > iOS > Run workflow, tick "Upload to TestFlight": signed build to
  TestFlight (needs the four secrets listed at the top of the workflow).

The Xcode project is generated from `project.yml` with XcodeGen.
