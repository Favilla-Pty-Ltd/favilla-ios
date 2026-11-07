# favilla-ios: notes for Claude sessions

## Working with the firmware chat (read first)
- The KEY firmware is done in a separate chat. Never change `Favilla-Pty-Ltd/favilla-key-firmware` from here, apart from issue comments.
- The interface is `docs/BLE_PASSKEY_PROTOCOL.md` in that repo. Build the app against it. Only the firmware chat edits it.
- The two chats coordinate through the firmware repo's Issues. Rules are in issue #1. At the start of every session, and before saying you're done, list the open issues:
  ```
  gh api "repos/Favilla-Pty-Ltd/favilla-key-firmware/issues?state=open" -q '.[] | "#\(.number) [\(.labels|map(.name)|join(","))] \(.title)"'
  ```
  `gh issue` doesn't work from Claude sessions; use `gh api`.
- Work the issues labelled `for-app`. Comment as you go, and close them when done (or relabel `bench` if Josh has to test first).
- When the app needs something from the KEY, open an issue labelled `for-firmware` (plus `protocol` if it changes bytes) with the exact characteristic, bytes and behaviour.
- `needs-josh` means wait for Josh. Never put secrets, passwords or personal bench logs in an issue.

## Build and ship
- No Mac here. CI (`.github/workflows/ios.yml`) runs the CBOR/CTAP/FILL tests, builds for the simulator and checks the bundled fonts on every push.
- TestFlight: dispatch the workflow with `upload=true`:
  ```
  gh api -X POST repos/Favilla-Pty-Ltd/favilla-ios/actions/workflows/ios.yml/dispatches -f ref=main -F 'inputs[upload]=true'
  ```
  The build number is the run number. Bump `MARKETING_VERSION` in `project.yml` only for user-visible releases; it must stay above 1.0 (the first upload went out as 1.0).
- Each upload revokes the previous CI development certificate (Apple caps them); Josh gets an email per build and is fine with that.

## Rulings that shape the app
- Passwords: the KEY sends the login to the AutoFill sheet (FILL 0x34, answer on 8F1A0004), which hands it to iOS and keeps nothing.
- Passkeys: CTAP2 over the FIDO Bluetooth framing on 8F1A0010-12. iOS only accepts a "none" attestation from a provider, so the app re-encodes the KEY's reply.
- The account list above the keyboard is opt-in, off by default, and never holds a password.
- Brand: Archivo, brass #C9A45C, ink #F4F2EE, the Entropy Ember and the FAVILLA KEY wordmark (Shared/Brand.swift), taken from favillakey.io.
- Josh's instructions: every step names the app or site and device first, written out in full, commands in separate code blocks, no em dashes.
