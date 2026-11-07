#!/usr/bin/env bash
# Copy the KEY's PWA (favilla-key-firmware src/pwa.html) into the app as the
# Nostr client, and record which commit and build it came from.
# Usage: scripts/sync_pwa.sh [path to a favilla-key-firmware checkout] (default ../favilla-key-firmware)
# Reads the firmware repo only; never writes to it.
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
fw="${1:-$here/../favilla-key-firmware}"
src="$fw/src/pwa.html"
[ -f "$src" ] || { echo "no $src (clone favilla-key-firmware next to favilla-ios, or pass its path)"; exit 1; }
git -C "$fw" pull --ff-only >/dev/null 2>&1 || true
cp "$src" "$here/Nostr/pwa.html"
bid=$(grep -o 'data-pwa-build="[0-9a-f]*"' "$here/Nostr/pwa.html" | head -1 | cut -d'"' -f2)
sha=$(git -C "$fw" rev-parse HEAD)
printf 'Copied from Favilla-Pty-Ltd/favilla-key-firmware src/pwa.html\ncommit %s\npwa build %s\ncopied %s\nRefresh with scripts/sync_pwa.sh\n' \
  "$sha" "$bid" "$(date -u +%F)" > "$here/Nostr/PWA_SOURCE.txt"
echo "pwa.html build $bid from $sha"
