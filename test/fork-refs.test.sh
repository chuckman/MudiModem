#!/bin/sh
# fork-refs.test.sh — the fork's LIVE install/update defaults must resolve to the fork.
#
# The owner is recorded once in .fork-owner. Historical docs (docs/history,
# docs/design, CHANGELOG) and the README's attribution line may still name the
# upstream projects; only the shipping paths are checked here.
set -eu
cd "$(dirname "$0")/.."

owner=$(tr -d ' \r\n' < .fork-owner)
[ -n "$owner" ] || { echo "FAIL: .fork-owner is empty"; exit 1; }

fail=0
need() {  # file pattern label
  grep -q "$2" "$1" || { echo "FAIL: $1 does not name the fork ($3)"; fail=1; }
}

need install.sh                        "raw.githubusercontent.com/$owner/MudiModem/"            "default install base"
need uninstall.sh                      "raw.githubusercontent.com/$owner/MudiModem/"            "default uninstall base"
need tools/deploy.sh                   "raw.githubusercontent.com/$owner/MudiModem/main"        "deploy update base"
need src/sbin/mudimodem-selfupdate     "raw.githubusercontent.com/$owner/MudiModem/main"        "self-update fallback"
need src/lib/rpc/config.lua            "raw.githubusercontent.com/$owner/MudiModem/main"        "version-check fallback"
need .gitmodules                       "github.com/$owner/mudi-emu"                             "mudi-emu submodule"
need src/lib/mudimodemd/tasks.lua      "raw.githubusercontent.com/$owner/mudi7-at-library/main/dist" "AT library feed"
need README.md                         "raw.githubusercontent.com/$owner/MudiModem/main/install.sh"  "install command"

for f in install.sh uninstall.sh tools/deploy.sh src/sbin/mudimodem-selfupdate src/lib/rpc/config.lua; do
  if grep -q 'raw.githubusercontent.com/Antiman-cmyk/MudiModem' "$f"; then
    echo "FAIL: $f still falls back to the upstream repo"
    fail=1
  fi
done

[ "$fail" -eq 0 ] && echo "  ok  - live defaults point at $owner"
exit "$fail"
