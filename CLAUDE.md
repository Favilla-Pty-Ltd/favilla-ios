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
- Nostr client (7 Nov 2026): the app opens on the KEY's own PWA, unchanged, in a web view; bridge.js tunnels its `/api/` calls. Two routes (Settings > This iPhone): Wi-Fi, or Bluetooth = the KEY's NOSTR BT life over the paired app channel only (KEY 9k: API 0x3A / R_API 0xB8, App/NostrLink.swift keeps the link up while the client runs). On Bluetooth the bridge fills the PWA's empty address box with key.bluetooth so Connect doesn't scan the network. Don't edit Nostr/pwa.html by hand: refresh it with scripts/sync_pwa.sh, or let `.github/workflows/sync-pwa.yml` do it (every 4 h and on dispatch: when the firmware main's PWA build id differs, it commits the copy and dispatches a TestFlight build; needs the FIRMWARE_READ_TOKEN secret).
- Shape (19 Nov 2026): the app opens on a home page of modes (App/AppShape.swift): VAULT, NOSTR, BITCOIN later. The owner picks the door; the KEY's mode (KeyLife, from HELLO) marks where the KEY is and finishes a hand-over page, it does not pick the screen. No banner inside a mode: in NOSTR a small chip bridge.js puts beside the client's wordmark, in VAULT a menu on the wordmark, and a MODE group in Settings. The Nostr client keeps running under Home and VAULT once opened (21 Nov), is started anew if the KEY was in VAULT mode meanwhile, and is let go after ten minutes out of sight.
- New passwords (18 Nov 2026): the app runs a change from the AutoFill sheet (Shared/NewPasswordFlow.swift, Shared/SaveToKey.swift; GEN_PW, PW_SAVE with the keep-old flag, PW_RESULT) and the KEY only asks for ENTER. iOS fills a form's first password box whichever box was tapped, so a change is copied to paste and a sign-up is filled. iOS's own strong-password suggestion is made on the iPhone (no time to reach the KEY).
- Runtime patches to the page live in Nostr/bridge.js, never in pwa.html. The profile-notes fix (21 Nov, firmware issue #50) is the block between `<profile-fix>` markers, tested by `node Tests/profile_fix_test.js`; drop it once the page does the same itself.
- Seeing the UI: CI launches the simulator with `-FavillaDemo <name>` (sample data, no KEY) and prints screenshots into the build log between SHOT-BEGIN and SHOT-END. `x-...` names show the AutoFill sheets (App/DemoGallery.swift); `nostr-profile` opens a profile page against the real relays and prints the app's log lines (FVLOG). Look at the screenshots before shipping a layout change.
- The account list above the keyboard is opt-in, off by default, and never holds a password.
- Brand: Archivo, brass #C9A45C, ink #F4F2EE, the Entropy Ember and the FAVILLA KEY wordmark (Shared/Brand.swift), taken from favillakey.io.
- Josh's instructions: every step names the app or site and device first, written out in full, commands in separate code blocks, no em dashes.
