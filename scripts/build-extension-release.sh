#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "$0")/.." && pwd)"
extension_dir="$repo_dir/extension"
release_dir="$repo_dir/release/chrome-web-store"
archive="$release_dir/virgo-vpn-1.0.0.zip"

files=(
  manifest.json popup.html popup.css popup.js service-worker.js
  assets/icon-16.png assets/icon-32.png assets/icon-48.png assets/icon-128.png assets/virgo-logo.png
  src/api-client.js src/config.js src/discovery.js src/pairing-recovery.js
  src/proxy-controller.js src/qr.js src/safety.js src/storage.js
)

for file in "${files[@]}"; do
  test -f "$extension_dir/$file" || { echo "Missing runtime file: $file" >&2; exit 1; }
done

if rg -n "(api[_-]?key|secret|password)\\s*[:=]\\s*[\\\"']" \
  "${files[@]/#/$extension_dir/}" >/dev/null 2>&1; then
  echo "Possible embedded secret found" >&2
  exit 1
fi

mkdir -p "$release_dir"
rm -f "$archive"
(
  cd "$extension_dir"
  zip -q "$archive" "${files[@]}"
)

(
  cd "$release_dir"
  shasum -a 256 "$(basename "$archive")" > SHA256SUMS.txt
)
printf '%s\n' "${files[@]}" > "$release_dir/PACKAGE_CONTENTS.txt"
echo "$archive"
