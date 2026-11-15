# Contributing to RD Panel

Thanks for helping. Bug reports, translations, docs and code are all welcome.

Before you start on something big, open an issue first so we can agree on the approach.
Security problems do not go into issues: see [SECURITY.md](SECURITY.md). Everyone here
follows the [code of conduct](CODE_OF_CONDUCT.md).

## Issues

- Search the [existing issues](https://github.com/bropines/rdpanel/issues) first.
- For a bug, use the bug report form. The RD Panel version (About page), the RustDesk client
  version and how you deploy (image, Helm, binary; reverse proxy; SQLite or PostgreSQL)
  usually decide where to look.
- For a feature, start with the problem you want solved.

## Setting up

You need Go 1.26 or newer and Node 20.19 or newer with npm. The binary is built without CGO.

```sh
make web build          # web/dist, then bin/rdpanel with the UI embedded
cd web && npm run dev:mock    # UI against in-memory mocks (admin/admin, TOTP 123456)
```

[README.md](README.md#building-from-source) has the full build instructions and
[AGENTS.md](AGENTS.md) the layout of the repository.

## Before you open a pull request

```sh
make lint     # go vet + staticcheck + web typecheck and eslint
make test     # go vet + go test -race + web tests
```

The database tests also run on PostgreSQL in CI. To run them locally (the role needs
`CREATEDB`):

```sh
RDPANEL_TEST_PG_DSN='postgres://postgres:pw@127.0.0.1:5432/postgres?sslmode=disable' go test ./...
```

## Rules of the codebase

They protect existing installations. [AGENTS.md](AGENTS.md#rules) has the details.

- RustDesk clients first. Changes under `internal/clientapi` must keep official RustDesk
  clients working: tolerate unknown fields, keep field names and types, extend the contract
  tests.
- The admin API is contract-first. Edit `api/openapi.yaml`, run `make gen`, implement the
  handler and add an MSW mock for the UI.
- Migrations are append-only. Add the next `000NN_` file for SQLite and for PostgreSQL;
  never edit one that was released.
- Security defaults stay on: hashed tokens, encrypted secrets, CSRF on cookie sessions,
  rate limits on auth endpoints, client IPs only from trusted proxies, no secrets in logs.
- hbbs/hbbr changes go to [bropines/rustdesk-server](https://github.com/bropines/rustdesk-server)
  and must be opt-in, with upstream behaviour as the default.
- UI text goes into every locale under `web/src/i18n/locales/`; a test checks that the
  keys match. Check light and dark theme and a phone-sized screen.
- New settings get an `RDPANEL_*` variable and YAML key, a row in
  `docs/configuration.md` and `docs/deploy.md`, and an entry in
  `deploy/rdpanel.env.example` when operators are likely to set them.
- The product is called RD Panel (`rdpanel`). Use "RustDesk" only to describe
  compatibility.

## Translations

To add a language to the UI:

1. Copy `web/src/i18n/locales/en.json` and translate the values. Keep the keys,
   `{{variables}}` and tags as they are.
2. Add the language's name as `language.<code>` to every locale, for the language switcher.
3. Register it in `web/src/i18n/index.ts` and in the locale test
   `web/src/i18n/i18n.test.ts`, with the plural forms the language needs.

E-mails (`internal/mail/templates.go`) and the OIDC result page (`internal/oidc/page.go`)
have their own texts per language.

## Commits and pull requests

- Commit subjects follow `type(scope): summary`, for example `feat(relays): …`,
  `fix(oidc): …`, `docs: …`, `ci: …`.
- Keep a pull request to one topic and link the issue it closes.
- Say how you tested it. For UI changes, screenshots in light and dark help a lot.

By contributing you agree that your contribution is licensed like the part of the project
it touches: MIT for the panel (see [LICENSE](LICENSE)).
