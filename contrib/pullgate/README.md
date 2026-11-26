# The pullgate recipe of nodkey

These files let the broker host pull its config and its host settings
from private git repos with [pullgate](https://github.com/code6x/pullgate).
The owner taps Apply on Telegram for each commit. Each release ships
them as `nodkey_VERSION_pullgate.tar.gz`, a pullgate recipe with two
instances, so one command sets up a broker host:

```sh
pullgate bootstrap --recipe https://github.com/code6x/nodkey/releases/download/vX.Y.Z/nodkey_X.Y.Z_pullgate.tar.gz \
    --instance nodkey-broker --repo ssh://git@github.com/owner/broker-config.git \
    --instance nodkey-host --repo ssh://git@github.com/owner/host-data.git
```

The steps are in [docs/setup.md](../../docs/setup.md), "Change the
config from git with pullgate" and "The host instance".

| file | runs as | what it does |
|---|---|---|
| `pullgate-recipe.toml` | - | the manifest: the two instances, their templates and their setup; the build writes the version |
| `nodkey-broker.toml.in` | - | the template of `/etc/pullgate/nodkey-broker.toml` |
| `nodkey-host.toml.in` | - | the template of `/etc/pullgate/nodkey-host.toml` |
| `setup.sh` | root | the setup of an instance at the bootstrap: the checks that were steps by hand |
| `check.sh` | check user | broker config: checks a new commit |
| `summary.sh` | check user | broker config: the change list in the question |
| `apply.sh` | root | broker config: installs the two files and reloads or restarts the broker; puts the old files back on a failure |
| `health.sh` | root | both: waits for the broker to say that it runs the new config |
| `lib.sh` | - | broker config: the shared part, such as the one rule for "reload or restart" |
| `host-check.sh` | check user | host: `check-data` on `host.yml`, only the files of the data repo layout, the rules of the host |
| `host-summary.sh` | check user | host: the `⚠` lines first, then the changed keys |
| `host-apply.sh` | root | host: the recipes of a new version first, then `broker-host.yml`, then `pullgate recipe use` |
| `host-get-recipe.sh` | root | host: gets and checks the Ansible recipe of a release (and the pullgate recipe) |
| `host-lib.sh` | - | host: the shared part |

Both `apply` commands take one lock, so the two instances never restart
the broker at the same time. A new version moves both instances to the
recipe of that version only after its playbook passed.

Tests: `contrib_pullgate_linux_test.go` and
`contrib_pullgate_host_linux_test.go` at the root of the module, and
`test/ci.sh`: `pullgate bootstrap --recipe` of a pinned pullgate
release on a test build, in a Debian 13 container with systemd, with a
real broker (a fake bot token), a fake release server, a fake gh and a
fake Telegram:

```sh
sh scripts/build-release.sh 1.2.3 /tmp/dist
sh contrib/pullgate/test/ci.sh /tmp/dist 1.2.3
```
