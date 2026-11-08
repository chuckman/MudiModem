# Security policy

This repository is a personal fork of
[Antiman-cmyk/MudiModem](https://github.com/Antiman-cmyk/MudiModem), which in turn is
based on [kevinherzig/MudiModem](https://github.com/kevinherzig/MudiModem).

## Reporting a vulnerability

Please do **not** open a public issue for a security problem.

Use GitHub's private vulnerability reporting on this repository
(**Security → Advisories → Report a vulnerability**). If that is unavailable, open a
minimal public issue asking for a private contact channel and disclose nothing else.

Include: affected version/commit, router model and GL firmware version, a description of
the impact, reproduction steps, and whether the issue also affects the upstream project.
Reports are handled on a best-effort basis, and any confirmed issue that also affects
upstream will be forwarded there.

## Scope

In scope:

- the installer and self-update path (`install.sh`, `uninstall.sh`,
  `src/installer/mudimodem-install`, `src/sbin/mudimodem-selfupdate`);
- the nginx RPC plugin (`src/rpc/`, `src/lib/rpc/`), the `mudimodemd` daemon
  (`src/lib/mudimodemd/`) and the shell helpers under `src/sbin/`, `src/hotplug/`,
  `src/etc/`;
- the browser code under `src/web/` (as served by the router);
- the community AT library feed and the baked snapshot (`src/at-library.snapshot.json`).

Out of scope: vulnerabilities in GL.iNet firmware or its own `/rpc`, `/ws`, `glc` and
admin UI; GL.iNet's `oui` framework; the fact that a root shell on the router can change
anything; and issues that require the attacker to already have router root.

## Design notes that matter for reports

- The plugin adds **no authentication of its own**. It relies on GL's admin session and
  the `root` ACL group; it exposes no no-auth RPC methods.
- The AT console is an intentionally powerful, admin-only channel. A cross-site request
  forgery that reaches it is a serious issue; report it as such.
- The installer and updater run as **root** and fetch from a Git branch. Treat any
  weakness in that path as high impact.
- The community AT library never executes automatically; entries only fill the console
  prompt. `set` and `nv` entries stay locked until the operator enables higher-risk
  commands.

## Hardening expectations for operators

- Install only from a source you trust, over HTTPS, and keep the fork in sync with
  upstream before updating the router.
- Enable 2FA and branch protection on the GitHub account and repositories that publish
  your install source: whoever controls that branch controls the routers that update
  from it.
- Do not expose the GL admin UI to the internet.
