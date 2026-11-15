# Security policy

RD Panel controls remote access to computers, so please report security problems privately
and not as a public issue.

## Versions

Fixes are released as new versions. Please check whether the problem still exists in the
[latest release](https://github.com/bropines/rdpanel/releases/latest) before reporting it.

If you are not sure whether a problem is in RD Panel or in the hbbs/hbbr binaries bundled
in the image (built from [bropines/rustdesk-server](https://github.com/bropines/rustdesk-server)),
report it here.

## Reporting a vulnerability

E-mail the maintainer at <bropines@gmail.com>. Once GitHub's private vulnerability reporting
is enabled for this repository, you can also use
[Report a vulnerability](https://github.com/bropines/rdpanel/security/advisories/new).

Please include:

- the RD Panel version (shown on the About page) and how it is deployed (image, Helm,
  binary; reverse proxy; SQLite or PostgreSQL);
- what an attacker can do, and what they need for it (network access, an account, a role);
- steps or a proof of concept to reproduce it.

Please give the maintainer time to release a fix before you publish any details.

## Before you report

Some parts are meant to stay behind a proxy or a firewall, for example the hbbs/hbbr admin
channel and the WebSocket ports 21118/21119, which trust `X-Forwarded-For`.
[docs/deploy.md](docs/deploy.md) describes the intended setup. A problem that only appears
when that setup is ignored may still be worth a report, but please say so.
