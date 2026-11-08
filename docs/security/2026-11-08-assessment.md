# Security assessment — MudiModem 3.0.3

**Date:** 2026-11-08
**Target:** `Antiman-cmyk/MudiModem` at `6a4f7ed8d7ba8ebf8aeeef64b563a4f781629083` (version 3.0.3),
the same tree this fork started from. Fork changes so far are URL defaults only.
**Platform:** GL.iNet GL-E5800 ("Mudi"), GL firmware 4.10.x, Quectel RG650V, nginx + Lua plugin,
procd daemon on lua-eco.
**Classification:** public summary; no weaponised exploit detail is included.

## 1. Executive summary

No unauthenticated remote code execution, authentication bypass, or command injection reachable
from the browser or LAN was found. The most serious risk is architectural: **the installer and
self-updater execute code fetched from a mutable Git branch as root, with no tag pinning, checksum,
or signature**. Whoever controls that branch — or the GitHub account behind it — controls every
router that installs or updates from it.

Secondary risks are the unsigned community AT-library feed (now self-hosted by this fork), one
unvalidated pass-through from RPC to GL's cell-tower API, and the absence of an on-device
CSRF/origin test for the admin session that the whole plugin relies on.

The code shows unusually careful handling of the dangerous parts: staged atomic installs,
fail-closed confirm-or-revert, integer validation of band/cell values, bounded AT input (8 steps ×
256 chars, CR/LF stripped, timeout clamped), a 1 MB cap and sanity check on the library fetch, and
no DOM HTML sinks. `gitleaks` found no secrets in 262 commits.

## 2. Scope and method

Reviewed: the installer/updater, the nginx RPC plugin (`src/rpc`, `src/lib/rpc`), `mudimodemd`
(`src/lib/mudimodemd`), shell helpers (`src/sbin`, `src/hotplug`, `src/etc`), the browser bundle
(`src/web`), the nginx location config, the websocket seed module, the baked AT-library snapshot,
and the published feed.

Methods:

| Step | Tool / action | Result |
|---|---|---|
| Secret scan, full history | `gitleaks 8.30.1` (262 commits, 5.27 MB) | no leaks |
| Shell static analysis | `shellcheck 0.11.0` (same rule set as the repo) | only SC2164 in `tools/test-local.sh` |
| Lua syntax | `luac5.1 -p` over every `*.lua` (and `luac5.4` for the daemon file) | all compile; `atport.lua` needs Lua 5.4 (bitwise/file API), which is the daemon's runtime |
| JS dependencies | `npm audit` | 0 vulnerabilities (esbuild is dev-only) |
| Unit/integration baseline | `tools/test-local.sh` (host Lua 5.1 + lua-cjson, Python, Node, dash, busybox) | all green; 2 intentional XFAILs on host cjson |
| Manual review | privileged paths, RPC surface, input→shell/ubus, web sinks, data handling | findings below |
| Firmware reference | `tools/mudi-emu/reference/e5800-4.10.0` (`gl.conf`, `oui-rpc.lua`, session) | used to verify the request path |

Not performed in this environment: full router emulation (no `qemu-user-static` and no extracted
firmware image), headless UI rendering (no Playwright/browser), a real-device install, and live
network capture. Those are listed as follow-ups in §5.

## 3. Findings

Severity is the reviewer's judgement, not a CVSS score.

| ID | Finding | Severity |
|---|---|---|
| H1 | Root install/update from a mutable branch with no integrity verification | High |
| M1 | Community AT-library feed is unsigned third-party content served to the UI | Medium |
| M2 | `set_cell_lock` forwards arbitrary `extra` keys/values to GL's `modem.set_cell_tower` | Medium |
| M3 | Update flow advertises remote root code execution without provenance or notes | Medium |
| M4 | No evidence of CSRF/Origin protection on the admin RPC the plugin depends on (test gap) | Medium |
| L1 | CSV export is vulnerable to spreadsheet formula injection | Low |
| L2 | URL allowlists accept `http://`; curl follows redirects without a protocol restriction | Low |
| L3 | Plugin static assets are served unauthenticated (intended; no secrets today) | Low |
| L4 | Browser chunks are executed with `new Function`, with no CSP | Low |
| L5 | No LICENSE, CI, CodeQL/Dependabot, or branch protection; commits mostly unsigned | Low (process) |
| L6 | `mkdir -p` built from environment-derived paths without quoting | Low (defence in depth) |
| I1 | Privacy/egress review: history stays local; outbound endpoints are GitHub, Cloudflare, user LibreSpeed | Info |
| I2 | Positive controls that should be preserved | Info |

### H1 — Root install/update from a mutable branch, no integrity check

**Evidence**

- `install.sh:21` defaults `BASE` to `https://raw.githubusercontent.com/<owner>/MudiModem/main`.
  The script downloads the installer, `manifest.txt`, `version.json` and every payload file, then
  runs the installer as root (`install.sh:41-56`).
- `src/installer/mudimodem-install:255` records that base in `/etc/mudimodem/version.json`.
- `src/lib/rpc/config.lua:13` and `src/sbin/mudimodem-selfupdate:29` follow the recorded base on
  every update check and `Update now`.
- There is no tag pinning, `SHA256SUMS`, minisign/GPG signature, or release-artifact verification
  anywhere in the tree. `version.json` contains only `{"version": "3.0.3"}`.
- The curl calls use `-fsSL` but no `--proto '=https'` / `--proto-redir '=https'`, so a redirect to
  plain HTTP would be followed.

**Impact.** A compromised GitHub account, a malicious commit on `main`, or a stolen maintainer
token yields root code execution on every router that installs or updates from that branch. The
device has no way to distinguish a legitimate release from a malicious one. This is the highest
risk in the project.

**Recommendation (P0).**

1. Publish releases with a signed hash manifest (`SHA256SUMS` + minisign/GPG, key kept offline).
2. Make `install.sh` fetch and verify that manifest before running anything; refuse on mismatch.
3. Default the installer to a release tag, not `main` (a `stable` branch is acceptable).
4. Add `--proto '=https' --proto-redir '=https'` to every curl invocation in the install/update path.
5. Require 2FA, branch protection and signed tags/commits on the publishing account/repository.
6. Show the verified signature/version in the Config tab before offering "Update now".

### M1 — Unsigned AT-library feed

**Evidence.** `src/lib/mudimodemd/tasks.lua:62` fetches `.../mudi7-at-library/main/dist` over HTTPS;
`lib_refresh` checks size (< 1 MB), decodes JSON, requires `entries`, `revision` and `version`, and
caches the body verbatim. The baked snapshot matches the published feed (`revision 14ec2ae7c7fd`,
24 entries: 16 `read`, 4 `set`, 4 `nv`). Nothing auto-executes; a library click only fills the
console prompt, and `set`/`nv` require the higher-risk toggle (`src/web/tabs/console.js`).

**Impact.** The library is trusted content that changes without review on the router. A compromised
feed could present a destructive `nv` command as routine, or silently change an existing entry's
meaning while keeping its risk badge. HTTPS protects transport, not the feed's integrity at rest.
`nv` commands survive a factory reset.

**Recommendation (P1).** Sign `dist/at-library.json` + `version.json` (minisign or a detached
sig), pin the public key in the firmware image, verify on refresh, and show provenance/revision in
the UI. Until then, treat feed updates like code updates: review the diff before syncing your fork,
and prefer the baked snapshot when offline.

### M2 — Arbitrary `extra` passthrough to GL's cell-tower API

**Evidence.** `src/lib/rpc/lock.lua:204-206`:

```lua
if type(args.extra) == "table" then
  for k, v in pairs(args.extra) do
    if payload[k] == nil then payload[k] = v end
  end
end
```

`payload` already holds `bus`, `slot`, `lock`, `network_type`, `pci`, `freq` (and `scs`, `band`),
so those cannot be overwritten, but any other key and any value type is forwarded to
`glc("modem", "set_cell_tower", payload)`.

**Impact.** An admin session (or a CSRF that reaches it) can put attacker-chosen fields into a
root-run GL API call. Today the intended use is forwarding scan-row fields (`cellid`, `carrier`,
`mcc`, `mnc`, …); the impact depends on how GL's `set_cell_tower` treats unknown keys. No evidence
of code execution was found, hence Medium rather than High.

**Recommendation (P1).** Replace the loop with a whitelist of known scan fields and validate each
type (strings with a charset/length cap, integers where numeric). Drop everything else.

### M3 — Update flow trains remote root execution

**Evidence.** `config.lua:56` (`app_version`) compares the remote `version.json` and returns
`update_available`; `config.lua:91` starts the detached updater. The Config tab surfaces this as a
one-click action (`src/web/main/config.js`), with no signature status, diff, or release notes.

**Impact.** It normalises "click to run new code as root from the internet" for a device that is
often administered remotely over cellular. Combined with H1 this is the delivery mechanism.

**Recommendation (P1).** Only offer updates that pass the H1 verification; show source URL,
version, and signature status; never auto-update. Document the trust model in the UI or README.

### M4 — CSRF/Origin protection is inherited from GL and untested here

**Evidence.** The plugin adds no auth and no CSRF token; it relies on GL's `/rpc` session
(`docs/knowledge.md` §3, `src/lib/rpc/rpc.js` sends the `Admin-Token` cookie). The shipped
reference `oui-rpc.lua` checks only the HTTP method (POST), JSON shape and the ACL; it does not
check `Origin`/`Referer`. `oui-access.lua`, which could, is not present in the reference tree, so
this cannot be verified statically. A localhost request with a `glinet` header bypasses the ACL by
GL's design (`docs/knowledge.md`).

**Impact.** If GL's access layer does not reject cross-origin requests, a malicious page on the LAN
could drive band/cell changes or the AT console in an authenticated browser. The AT console is a
root-equivalent modem channel. Browsers' JSON preflight and cookie `SameSite` may mitigate, but
that must be measured, not assumed.

**Recommendation (P1).** Test on a real box: cross-origin `POST /rpc` with and without the cookie,
with `Origin`/`Referer` set and omitted, and with a simple vs JSON content type. Record cookie
attributes. If GL does not enforce it, add an origin check in the plugin for state-changing methods
(and never rely on the `glinet` loopback header from a browser-reachable path).

### L1 — CSV formula injection

**Evidence.** `src/web/kit/csv.js:5-10` quotes values per RFC 4180 but does not neutralise cells
beginning with `=`, `+`, `-`, `@`, tab or CR. Exports include carrier names, event labels, speed-test
server names and cell/PCI values.

**Impact.** Opening an export in a spreadsheet can execute a formula (external data fetch, DDE in
older Excel). The data comes from the network/operator and the router, not from a remote attacker
directly, so this is Low.

**Recommendation (P2).** Prefix dangerous cells with `'` during CSV export (display unchanged),
and add a test with `=cmd` and leading-tab values.

### L2 — URL allowlists accept HTTP; no protocol restriction on redirects

**Evidence.** `src/lib/mudimodemd/tasks.lua:43`, `src/lib/rpc/speedtest.lua:199`,
`src/lib/mudimodemd/speedtest.lua:48` all accept `^https?://…`; `config.lua:28` accepts `http://`
for the recorded update base; curl uses `-L` without `--proto`.

**Impact.** A misconfigured or tampered base/feed could downgrade to plain HTTP. The self-update
base is root-owned (`/etc/mudimodem/version.json`, 0644) and the speed-test URL is admin-supplied,
so this is Low.

**Recommendation (P2).** Default to HTTPS-only; keep HTTP behind an explicit local-development
override. Add `--proto`/`--proto-redir` to all curl calls.

### L3 — Unauthenticated static assets

**Evidence.** `src/nginx/mudimodem.conf` serves `/views/gl-sdk4-ui-mudimodem*` and `/mudimodem/`
from `/usr/share/mudimodem/www`; GL's `gl.conf` applies auth to `/rpc`, `/ws`, `/upload`,
`/download`, `/cgi-bin/` and HTML/images, not to these locations. `docs/knowledge.md` states the
chunks are served unauthenticated and must never contain secrets.

**Impact.** None today: the chunks and the AT library are public content. It becomes a finding only
if a future change puts history, SIM identity, logs or tokens there.

**Recommendation (P2).** Add a CI/static check that nothing sensitive is introduced under
`dist/views` or the `/mudimodem/` cache; keep the rule in `docs/knowledge.md`.

### L4 — `new Function` chunk execution without CSP

**Evidence.** `src/web/kit/chunks.js:9` fetches `/views/...js` and evaluates it with
`new Function("module", res.data)`. Served same-origin; the URL carries a cache-buster.

**Impact.** A same-origin script compromise (or a malicious chunk) runs in the admin page. A router
that serves a modified chunk is already compromised, so this is Low. There is no CSP to reduce the
blast radius.

**Recommendation (P3).** If the nginx location can add headers without breaking GL's page, add a
conservative CSP (`script-src 'self'`); otherwise record the residual risk.

### L5 — Project/process posture

**Evidence.** No `LICENSE` (redistribution rights unclear), no `.github/workflows`, no CodeQL,
Dependabot or secret scanning, no `SECURITY.md` before this fork, and `git log --format=%G?` shows
267 unsigned commits (12 signed with keys not available locally). Branch protection on the fork is
not configured yet (GitHub API needs authentication to verify).

**Recommendation (P1).** Add `SECURITY.md` (done in this fork), enable 2FA, branch protection,
secret scanning and Dependabot on all three repositories; add a minimal CI (shellcheck, luacheck,
gitleaks, `npm ci && npm run check:web`, `test-local.sh`); obtain a license or keep the fork
private/personal.

### L6 — Unquoted `mkdir -p` from environment paths

**Evidence.** `src/lib/rpc/speedtest.lua:68` (`os.execute("mkdir -p " .. dir …)`) and `:227`
(single-quoted but not escaped), `src/lib/mudimodemd/collector.lua:425`, `config.lua:106-107`
(`[ -d '…' ]`). The paths come from `MUDIMODEM_*` variables set when nginx/procd starts, not from
RPC arguments.

**Impact.** Root-only environment, so not attacker-reachable. It is still a pattern worth removing
because these scripts run as root.

**Recommendation (P3).** Use the existing quoting helpers (`shq`) consistently, or avoid the shell
for directory creation.

## 4. Positive controls (preserve these)

- **Preflight guard**: the installer refuses anything that is not a GL-E5800 on firmware ≥ 4.10
  (`src/installer/mudimodem-install` preflight).
- **Staged, atomic install**: everything is downloaded to a temp dir first; files are written to
  `.mm-new`, chmodded, then renamed. A dropped connection leaves the box untouched.
- **Confirm-or-revert**: writes arm a watchdog first and refuse to proceed if it is not armed;
  the watchdog restores the previous GL snapshot on timeout (`core.lua`, `change.lua`,
  `src/sbin/mudimodem-revert`). Fail-closed is implemented in several places, including unreadable
  lock state.
- **Bounded AT console**: one step per line, max 8 × 256 chars, CR/LF stripped, timeout clamped to
  1–60 s, commands sent through GL's ubus AT service or the direct port via file I/O — **no shell
  interpolation of AT commands**.
- **RPC validation**: GL's default string allowlist applies to every string argument; only
  `at_console.cmd` is deliberately overridden (`src/validator/mudimodem.lua`). Band/cell integers
  are type- and range-checked.
- **Bounded library fetch**: 1 MB cap, 8/20 s timeouts, schema sanity check, atomic gzip+rename.
- **No DOM HTML sinks**: no `innerHTML`, `v-html`, `document.write` or attribute injection of
  untrusted data was found in `src/web`; text is rendered through `h()`/text nodes. The only
  dynamic code execution is the same-origin chunk loader (L4).
- **Secrets**: none in history or in the tree (gitleaks).
- **Privacy**: RF, battery and event history stays in `/tmp/mudimodem` or `/etc/mudimodem`; no
  telemetry. Egress is limited to GitHub (version/library), `speed.cloudflare.com` (speed test) and
  a user-configured LibreSpeed server. IMSI/ICCID are read from GL to resolve the active SIM but are
  not written to the history files.
- **Single user on the box**: files are 0644/0755 and the router's administrative model is root;
  this is consistent with GL's own plugins, not a new exposure.

## 5. Test gaps and follow-ups

1. **On-device CSRF/origin test** for `/rpc` (M4) — highest-value dynamic test. Needs a real
   Mudi or the emulator with the actual `oui-access.lua`.
2. **Real install/uninstall** from the fork's raw URL on a Mudi, then a self-update from one
   version to the next, watching for partial writes and nginx restarts.
3. **Router emulation pass**: install `qemu-user-static`, run `mudi-emu fetch && extract`, then
   `tools/test-local.sh`; it exercises GL's own Lua/busybox and the daemon under eco.
4. **UI render pass**: `npm i playwright`, `mudi-emu extract`, `tools/preview.js --matrix`, with
   XSS payloads in carrier names, AT replies and library entries.
5. **Fuzz the RPC boundary**: wrong types, 1 MB strings, NUL/Unicode, `null` fields, `extra`
   variants, huge windows/schedules.
6. **Egress capture** on the box (`tcpdump`) to confirm the endpoint list, including the LibreSpeed
   path and any firmware/GL cloud traffic that is outside this project's control.

## 6. Remediation roadmap

| Priority | Item |
|---|---|
| P0 | Signed release + hash verification; tag-pinned install; HTTPS-only curl; 2FA + branch protection + signed tags |
| P1 | Whitelist `set_cell_lock.extra`; on-device CSRF test; library feed signature/verification; update UI provenance |
| P2 | CSV formula guard; CI (shellcheck/luacheck/gitleaks/CodeQL/Dependabot); static-asset content check; HTTPS-only URL defaults |
| P3 | Consistent shell quoting; CSP; license/attribution |

Upstream-worthy fixes (small, self-contained): M2, L1, the `--proto` flags, and the HTTPS-only
defaults. Send them as focused PRs to `Antiman-cmyk/MudiModem` once the fork is stable.

## 7. Appendix — commands used

```bash
git clone https://github.com/Antiman-cmyk/MudiModem.git && cd MudiModem
gitleaks detect --source . --redact -v
shellcheck -s sh -S warning -e SC2086,SC2034,SC1090,SC2016,SC3043 \
  src/sbin/* install.sh uninstall.sh src/installer/mudimodem-install tools/deploy.sh
for f in $(git ls-files '*.lua'); do luac5.1 -p "$f"; done
npm ci && npm audit
LUA_CPATH=/path/to/cjson.so bash tools/test-local.sh
```

Tool versions: gitleaks 8.30.1, shellcheck 0.11.0, Lua 5.1/5.4, Node 26.13.0, npm 12.2.2,
Python 3. The audit clone was read-only; no router was modified.
