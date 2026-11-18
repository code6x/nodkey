# The Ansible recipe of nodkey

An Ansible role that installs nodkey on the broker host or on an agent
machine, as [docs/setup.md](../../docs/setup.md) says, with the same
checks as `install.sh`. Two fixed playbooks run it from a data file, for
a host that keeps only data in its repository. Why it works this way:
[DESIGN.md section 18](../../DESIGN.md#18-build-ci-and-releases) and
[THREAT-MODEL.md T53](../../THREAT-MODEL.md).

- `roles/nodkey/`: the role.
- `playbooks/broker-host.yml`, `playbooks/agent-host.yml`: the playbooks
  for a data file.
- `check-data`: checks a data file.
- `build.sh`: makes the recipe of one release. The release workflow runs
  it.

## What the role does

Both sides (`nodkey_side`):

- The first time, it runs the `install.sh` of the tag of
  `nodkey_version`. The role holds that file, and checks its SHA-256
  before it does anything. `install.sh` checks the SHA-256 of the
  release in `SHA256SUMS`, its build attestation with
  `gh attestation verify`, and the version of the new binary. If a check
  fails, nothing is installed.
- When nodkey is installed already, it updates it only with the
  installed binary: `nodkey update --version X.Y.Z`. That runs the
  installer that is built into the installed, checked nodkey, with the
  same checks. The role brings no check of its own for an update.
- Before it runs the installed `/usr/local/bin/nodkey`, it checks that
  only root can change it and each directory above it, and that it is no
  link, as `install.sh` does.
- **Forward only.** It refuses a version older than the installed one.
  It also refuses an installed nodkey that is not a release, such as a
  build from the source.
- After the install or the update, it checks that `nodkey version` prints
  the version.

`nodkey_side: broker` also makes:

- the system user and group `nodkey`, with the home `/var/lib/nodkey`
  and the shell `/usr/sbin/nologin` (setup.md section 3);
- `/etc/nodkey` (root, `0755`) and `/etc/nodkey/credentials` (root,
  `0700`), an empty slot for the credentials;
- `/etc/systemd/system/nodkey.service`: `contrib/systemd/nodkey.service`
  of the same tag, unchanged.

It never writes `broker.toml`, `known_hosts` or a credential. Fit the
unit to the host with a drop-in, such as
`/etc/systemd/system/nodkey.service.d/local.conf`. The role never changes
that directory. For example, to load only two credentials:

```ini
[Service]
LoadCredentialEncrypted=
LoadCredentialEncrypted=broker-tls-key:/etc/nodkey/credentials/broker-tls-key.cred
LoadCredentialEncrypted=telegram-token:/etc/nodkey/credentials/telegram-token.cred
```

The empty line removes the lines of the unit. The role does not enable or
start the broker: do that once by hand, after the setup of setup.md
sections 4 to 10. After a change of the binary or the unit, it restarts
the broker only if it runs (`systemctl try-restart`). The restart ends
all grants; `nodkey_restart: false` turns it off.

The restart is a handler at the end of the play, so a failed task, such
as a failed config check, restarts nothing. The role writes the mark
`/var/lib/nodkey-ansible/restart-due` as soon as the binary or the unit
changed, and removes it after the restart. So the next run that passes
does a restart that a failed run left due.

A broker that you set up by hand may have changes in
`/etc/systemd/system/nodkey.service`. Before the first run, move them to
a drop-in, and look at `--check --diff`. The role keeps the old unit as
a backup file next to it.

`nodkey_side: agent` with `nodkey_ssh_agent_user` also runs
`nodkey ssh-agent` as a user unit of that account (setup.md section 11).
The unit is `/etc/systemd/user/nodkey-ssh-agent.service`, owned by root,
with `ConditionUser=` set to the account, and enabled as with
`systemctl --global enable`. So the role never writes into the home
directory of the account, which the agent can change. It turns on linger
for the account, so the agent starts at boot. The role does not write
the client config (setup.md section 11). With `nodkey_ssh_agent_user`
empty, the role removes the user unit. It never turns linger off: the
account may need it for other units.

## Get the role

Each release from 0.8.0 on has the file `nodkey_<version>_ansible.tar.gz`.
It is in `SHA256SUMS` and covered by the build attestation, as the
binaries are. Download and check it on a trusted machine or on the host,
as root, with the steps of
[docs/releasing.md, "Verify a download"](../../docs/releasing.md#verify-a-download),
with the name of this file. Then unpack it into a directory that only
root can change:

```sh
VERSION=0.8.0
install -d -o root -g root -m 0755 "/opt/nodkey-ansible-$VERSION"
tar -xzf "nodkey_${VERSION}_ansible.tar.gz" -C "/opt/nodkey-ansible-$VERSION" --no-same-owner
```

The role of release X.Y.Z installs only nodkey X.Y.Z: it holds the
`install.sh` and the unit of that tag. The source of the role in the
repository has neither, and it refuses to run. To try the source, build
it: `sh contrib/ansible/build.sh X.Y.Z TAGDIR OUTDIR`, where `TAGDIR` is
a checkout of the tag `vX.Y.Z`.

## Settings

The defaults are in `roles/nodkey/defaults/main.yml`.

| setting | default | what it does |
|---|---|---|
| `nodkey_side` | `agent` | `broker` or `agent`. |
| `nodkey_version` | the version of the role | The release to install, `X.Y.Z`. It must be the version of the role. |
| `nodkey_restart` | `true` | Restart the broker (only if it runs), or the user unit, after a change of the binary or the unit. |
| `nodkey_broker_config` | `""` | Broker side: the path of the config that the host provides. The role checks it with `runuser -u nodkey -- nodkey broker check --config PATH`, and fails if the check fails. Empty: no check. A data file may name only a file in `/etc/nodkey/`. |
| `nodkey_ssh_agent_user` | `""` | Agent side: the account that runs `nodkey ssh-agent`. Never `root`. Empty: no user unit. |
| `nodkey_ssh_agent_linger` | `true` | Agent side: turn on linger for that account. |

`roles/nodkey/vars/main.yml` is written by `build.sh`: the version of the
role, and the SHA-256 of its `install.sh` and of its unit. There is no
setting to skip a check.

The role needs ansible-core 2.19 or newer. An example play, run as root
on the host:

```yaml
- name: nodkey broker
  hosts: example-host
  become: true
  roles:
    - role: /opt/nodkey-ansible-0.8.0/roles/nodkey
      vars:
        nodkey_side: broker
        nodkey_broker_config: /etc/nodkey/broker.toml
```

It works with `ansible-playbook --connection local` too, for a host that
applies its own config. `--check --diff` shows what would change. A
second run with the same version changes nothing.

## The data file

For a host that keeps only data in its repository, such as a host that
applies its config with pullgate, run a fixed playbook of the installed
recipe, with the data file of the host. As root, on the host:

```sh
cd /opt/nodkey-ansible-0.8.0
ansible-playbook -i localhost, --connection local playbooks/broker-host.yml -e nodkey_data_file=/etc/config-repo/nodkey.yml
```

Give the path with `-e nodkey_data_file=PATH`, never as `-e @PATH`. With
`@`, each key of the file would become a variable of Ansible, and a key
could change a setting that the file must not set. The playbook first
copies the file to a private temporary directory, runs `check-data` on
the copy, and reads the copy only if the check passes, into one
variable. So the file cannot change between the check and the read.
Then it runs the role with the keys of the schema.

The data file is YAML: one map, with only these keys.

| key | side | type | required |
|---|---|---|---|
| `nodkey_version` | both | text `X.Y.Z`, such as `"0.8.0"` | yes |
| `nodkey_restart` | both | `true` or `false` | no |
| `nodkey_broker_config` | broker | the path of a file in `/etc/nodkey/`, or `""` | no |
| `nodkey_ssh_agent_user` | agent | the name of an account, not `root`, or `""` | no |
| `nodkey_ssh_agent_linger` | agent | `true` or `false` | no |

`check-data` fails on another key, a key that is there twice, a wrong
type, a version that is not `X.Y.Z`, and a version older than the
installed nodkey. A text value may hold only the characters of a path
or an account name, so no value is an Ansible template. The role still
checks that the version is the version of the role. Check a file before
you commit it:

```sh
./check-data --side broker --installed 0.8.0 nodkey.yml
```

`--installed` names the installed version; `--installed none` means
that no nodkey is installed. `check-data` never runs nodkey. It prints no
value of the file, and the name of a key only if it is a plain name.
Exit codes: 0 good, 1 not good, 64 wrong usage.

An example for the broker host:

```yaml
nodkey_version: "0.8.0"
nodkey_broker_config: /etc/nodkey/broker.toml
nodkey_restart: false
```

## Update

Get the recipe of the new release, and check it, as in "Get the role".
Then set `nodkey_version` to the new version in the data file or the
play, and run it with the new recipe. It runs `nodkey update --version`
of the installed nodkey, installs the unit of the new tag, and restarts
the broker if it runs. Read the changes first: `nodkey update --notes`
(setup.md section 13).

## Tests

`contrib/ansible/test/ci.sh OLD NEW` runs the recipe in a Debian stable
container with systemd, for both sides, against two real releases. CI
runs it. `contrib_ansible_linux_test.go`, at the root of the module,
tests `check-data` and `build.sh`.
