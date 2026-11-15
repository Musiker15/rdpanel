## What and why

<!-- What does this change, and which problem does it solve? -->

Closes #

## How it was tested

<!-- Commands you ran, setups you tried. For UI changes, screenshots in light and dark. -->

## Checklist

- [ ] `make lint` and `make test` pass
- [ ] RustDesk clients keep working (changes under `internal/clientapi` have contract tests)
- [ ] Admin API changes are in `api/openapi.yaml`, `make gen` ran, the UI has an MSW mock
- [ ] New migrations are new `000NN_` files for SQLite and PostgreSQL
- [ ] UI text is in every locale; light, dark and mobile checked
- [ ] Docs updated (README, `docs/`, `deploy/rdpanel.env.example` for new settings)

<!-- Not everything applies to every change; leave out what does not. -->
