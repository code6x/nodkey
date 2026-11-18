# Configs of the last release

The Release check workflow loads each config of `configs/` with the last
release (N-1) and with the release candidate, with
`nodkey broker check --files`, and the result must be the same
(docs/releasing.md, "Check a release candidate", check 4).

- `ok-*.toml`: a config that N-1 accepts. Most come from the examples in
  `docs/setup.md` of a release, with a real pin.
- `bad-*.toml`: a config that N-1 refuses.
- `known_hosts`: the host keys that the configs name, made for this
  folder only.

When a release adds a config key, add an `ok-` config with it after that
release, so the next candidate is checked with it.
