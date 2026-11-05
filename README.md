# Favilla for iPhone

The iPhone app for the Favilla KEY: an AutoFill provider that signs you in with
passkeys and passwords held on the KEY, reached over Bluetooth. Keys never
leave the KEY; the app only relays requests and answers.

**Stage: probe.** The AutoFill sheet and the app check that the phone can reach
the KEY over its bonded Bluetooth link (needs KEY firmware drop 8y or later).

## Build

No Mac needed. GitHub Actions builds it on macOS (`.github/workflows/ios.yml`):

- every push to `main`: unsigned simulator build (compile check);
- Actions > iOS > Run workflow, tick "Upload to TestFlight": signed build to
  TestFlight (needs the four secrets listed at the top of the workflow).

The Xcode project is generated from `project.yml` with XcodeGen.
