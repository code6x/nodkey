# The pullgate recipe of nodkey

These files let the broker host pull its config from a private git repo
with [pullgate](https://github.com/code6x/pullgate). The owner taps
Apply on Telegram for each commit. A config that fails goes back to the
last good one by itself.

- `nodkey-broker.toml`: the pullgate instance config.
- `check.sh`: checks a new commit, as the check user.
- `summary.sh`: the change list in the question, as the check user.
- `apply.sh`: installs the two files and reloads or restarts the broker,
  as root. It puts the old files back on a failure.
- `health.sh`: waits for the broker to say that it runs the new config,
  as root.
- `lib.sh`: the part that the scripts share, such as the one rule for
  "reload or restart".

Install them from a release of nodkey (`nodkey_VERSION_pullgate.tar.gz`),
checked as docs/setup.md says, and never from a config repo. The steps
are in [docs/setup.md](../../docs/setup.md), "Change the config from git
with pullgate".
