#!/bin/sh
# ci.sh tests the Ansible recipe in a Debian stable container with
# systemd, for both sides, against real releases on GitHub:
#
#   - a first run installs the release, and nodkey version prints it;
#   - a second run, and a run with --check --diff, change nothing;
#   - the unit that the role installs is the one of the tag;
#   - a wrong SHA-256 of install.sh fails, and installs nothing;
#   - an older version is refused; a newer one installs with nodkey update;
#   - a data file with an unknown key fails before any change;
#   - the broker side makes the SSH keys of nodkey_ssh_keys, and a broker
#     signs an SSH login with a new key, through a fake ntfy server.
#
#   sh contrib/ansible/test/ci.sh OLD NEW
#
# OLD and NEW are two releases, X.Y.Z, both with a Sigstore bundle. It
# runs from the root of a git checkout with the tags vOLD and vNEW. It
# needs Docker and network access, and removes the containers and the
# image that it makes.

set -eu

[ "$#" -eq 2 ] || {
	echo 'ci.sh: give OLD and NEW, such as: sh contrib/ansible/test/ci.sh 0.6.0 0.7.0 (exit 64)' >&2
	exit 64
}
old=$1
new=$2
image=nodkey-ansible-test:$$
work=$(mktemp -d)
cts=""

cleanup() {
	for ct in $cts; do docker rm -f "$ct" >/dev/null 2>&1 || :; done
	docker rmi -f "$image" >/dev/null 2>&1 || :
	rm -rf "$work" || :
}
trap cleanup EXIT

fail() {
	printf 'FAIL: %s\n' "$*" >&2
	exit 1
}

pass() {
	printf 'PASS: %s\n' "$*"
}

# build VERSION: the recipe of that release, with the files of its tag.
build() {
	mkdir -p "$work/tag-$1"
	git archive "v$1" install.sh contrib/systemd/nodkey.service | tar -x -C "$work/tag-$1"
	sh contrib/ansible/build.sh "$1" "$work/tag-$1" "$work/recipe-$1" >/dev/null
}

# start NAME: a new container with systemd, and the recipes in /opt.
start() {
	ct="nodkey-ansible-$1-$$"
	cts="$cts $ct"
	docker run -d --name "$ct" --privileged --cgroupns=host \
		--tmpfs /run --tmpfs /run/lock \
		-v /sys/fs/cgroup:/sys/fs/cgroup:rw "$image" >/dev/null
	# systemd needs a moment before systemctl can reach it.
	state=""
	for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
		state=$(docker exec "$ct" systemctl is-system-running --wait 2>/dev/null || :)
		case $state in running | degraded) break ;; esac
		sleep 1
	done
	case $state in
	running | degraded) ;;
	*) fail "systemd in $ct did not start: $state" ;;
	esac
	# systemd mounts the credentials of a unit from a child process: the
	# mounts of the container must be shared, as on a host.
	docker exec "$ct" mount --make-rshared /
	docker cp "$work/recipe-$old" "$ct:/opt/recipe-$old"
	docker cp "$work/recipe-$new" "$ct:/opt/recipe-$new"
	docker cp "$work/data" "$ct:/opt/data"
}

# play CT VERSION SIDE DATA [ARGS...]: run the playbook of a side as
# root in the container, with --connection local. Its output is in
# $work/out.
play() {
	p_ct=$1 p_version=$2 p_side=$3 p_data=$4
	shift 4
	docker exec "$p_ct" ansible-playbook -i localhost, --connection local \
		"/opt/recipe-$p_version/playbooks/$p_side-host.yml" \
		-e "nodkey_data_file=/opt/data/$p_data" "$@" >"$work/out" 2>&1
}

recap_changed() {
	sed -n 's/.* changed=\([0-9]*\) .*/\1/p' "$work/out" | tail -n 1
}

show() {
	cat "$work/out" >&2
}

# result TASK: the result of the last run of a task in $work/out, such as
# "changed". A task runs at most once in a play here.
result() {
	# Ansible may print an error with its lines before "fatal:".
	grep -A20 -F "$1]" "$work/out" | sed -n 's/^\(ok\|changed\|skipping\|fatal\|failed\):.*/\1/p' | head -n 1
}

installed() {
	docker exec "$1" /usr/local/bin/nodkey version | head -n 1
}

docker build -q -t "$image" contrib/ansible/test >/dev/null
build "$old"
build "$new"

mkdir -p "$work/data"
printf 'nodkey_version: "%s"\nnodkey_broker_config: ""\n' "$new" >"$work/data/broker-new.yml"
printf 'nodkey_version: "%s"\n' "$old" >"$work/data/broker-old.yml"
printf 'nodkey_version: "%s"\nnodkey_ssh_agent_user: example-user\n' "$new" >"$work/data/agent-new.yml"
printf 'nodkey_version: "%s"\nnodkey_install_sh_sha256: "%s"\n' "$new" \
	0000000000000000000000000000000000000000000000000000000000000000 >"$work/data/broker-unknown-key.yml"

# --- The broker side.
start broker
ct="nodkey-ansible-broker-$$"
play "$ct" "$new" broker broker-unknown-key.yml && { show; fail "a data file with an unknown key passed"; }
grep -q 'the key nodkey_install_sh_sha256 is not a key of the broker side' "$work/out" || { show; fail "no error for the unknown key"; }
docker exec "$ct" test ! -e /usr/local/bin/nodkey || fail "the unknown key installed nodkey"
pass "broker: a data file with an unknown key fails, and installs nothing"

play "$ct" "$new" broker broker-new.yml || { show; fail "the first run of the broker side failed"; }
[ "$(installed "$ct")" = "nodkey $new" ] || fail "nodkey version is not nodkey $new"
pass "broker: the first run installs nodkey $new"

git show "v$new:contrib/systemd/nodkey.service" >"$work/unit-tag"
docker cp "$ct:/etc/systemd/system/nodkey.service" "$work/unit-host"
cmp -s "$work/unit-tag" "$work/unit-host" || fail "the unit on the host is not the unit of the tag v$new"
pass "broker: the unit is contrib/systemd/nodkey.service of the tag v$new"

for spec in "root:root:755:/etc/nodkey" "root:root:700:/etc/nodkey/credentials"; do
	path=${spec##*:}
	want=${spec%:*}
	got=$(docker exec "$ct" stat -c '%U:%G:%a' "$path")
	[ "$got" = "$want" ] || fail "$path is $got, not $want"
done
docker exec "$ct" getent passwd nodkey | grep -q ':/var/lib/nodkey:/usr/sbin/nologin$' || fail "the user nodkey is wrong"
[ -z "$(docker exec "$ct" ls -A /etc/nodkey/credentials)" ] || fail "/etc/nodkey/credentials is not empty"
docker exec "$ct" test ! -e /etc/nodkey/broker.toml || fail "the role wrote broker.toml"
pass "broker: the user, /etc/nodkey and the empty /etc/nodkey/credentials"

play "$ct" "$new" broker broker-new.yml || { show; fail "the second run failed"; }
[ "$(recap_changed)" = 0 ] || { show; fail "the second run changed something"; }
play "$ct" "$new" broker broker-new.yml --check --diff || { show; fail "the run with --check --diff failed"; }
[ "$(recap_changed)" = 0 ] || { show; fail "the run with --check --diff shows a change"; }
pass "broker: a second run, and a run with --check --diff, change nothing"

play "$ct" "$old" broker broker-old.yml && { show; fail "an older version was not refused"; }
grep -q "is older than the installed nodkey $new" "$work/out" || { show; fail "no error for the older version"; }
[ "$(installed "$ct")" = "nodkey $new" ] || fail "the older version changed nodkey"
pass "broker: an older version is refused, and nodkey $new stays"

# A restart that a failed run left due is done by the next run.
docker exec "$ct" sh -c 'install -d -m 0700 /var/lib/nodkey-ansible && touch /var/lib/nodkey-ansible/restart-due'
play "$ct" "$new" broker broker-new.yml || { show; fail "the run with a restart due failed"; }
[ "$(result 'Restart the broker')" = changed ] || { show; fail "the due restart did not run"; }
docker exec "$ct" test ! -e /var/lib/nodkey-ansible/restart-due || fail "the mark of the restart is still there"
pass "broker: a restart that is due runs at the next run"

# A broker config that the host provides: the role checks it.
docker exec "$ct" sh -c 'printf "listen = 1\n" > /etc/nodkey/broker.toml'
printf 'nodkey_version: "%s"\nnodkey_broker_config: /etc/nodkey/broker.toml\n' "$new" >"$work/broker-config.yml"
docker cp "$work/broker-config.yml" "$ct:/opt/data/broker-config.yml"
play "$ct" "$new" broker broker-config.yml && { show; fail "a bad broker.toml passed"; }
[ "$(result 'Check the config with nodkey broker check')" = fatal ] || { show; fail "the config check did not fail"; }
pass "broker: a bad broker.toml of the host fails nodkey broker check"

# --- The SSH keys of the broker (nodkey_ssh_keys).
start keys
ct="nodkey-ansible-keys-$$"
docker cp contrib/ansible/test/fake-ntfy.py "$ct:/opt/fake-ntfy.py"
docker cp contrib/ansible/test/sign-setup.sh "$ct:/opt/sign-setup.sh"
keys_data() { # FILE [KEYS...]: a data file with these keys, NAME or NAME:TYPE.
	kd_file=$1
	shift
	{
		printf 'nodkey_version: "%s"\n' "$new"
		[ -z "${KEYS_EXTRA:-}" ] || printf '%s\n' "$KEYS_EXTRA"
		printf 'nodkey_ssh_keys:'
		[ "$#" -gt 0 ] || printf ' []'
		printf '\n'
		for k in "$@"; do
			case $k in
			*:*) printf '  - name: %s\n    type: %s\n' "${k%%:*}" "${k#*:}" ;;
			*) printf '  - name: %s\n' "$k" ;;
			esac
		done
	} >"$work/$kd_file"
	docker cp "$work/$kd_file" "$ct:/opt/data/$kd_file"
}
# private_keys: the SSH private keys in files on the host, but the host
# keys of sshd, and the keys that systemd gives the running broker in
# its credentials directory, in memory.
private_keys() {
	docker exec "$ct" sh -c 'grep -rlsF -e "OPENSSH PRIVATE KEY" /run /tmp /var/tmp /etc /root /var/lib /home /opt 2>/dev/null |
		grep -v -e "^/etc/ssh/ssh_host_" -e "^/run/credentials/nodkey.service/" || :'
}
dropin=/etc/systemd/system/nodkey.service.d/ssh-keys.conf
# The search finds a key that is there.
docker exec "$ct" ssh-keygen -q -t ed25519 -N '' -f /run/canary-key
[ "$(private_keys)" = /run/canary-key ] || fail "keys: the search for private keys does not find one"
docker exec "$ct" rm -f /run/canary-key /run/canary-key.pub
line() { printf 'LoadCredentialEncrypted=ssh-%s:/etc/nodkey/credentials/ssh-%s.cred' "$1" "$1"; }

keys_data keys.yml deploy ops:ecdsa-p256
play "$ct" "$new" broker keys.yml --check --diff || { show; fail "keys: --check on a new host failed"; }
grep -q 'would make the SSH key ops (ecdsa-p256)' "$work/out" || { show; fail "keys: --check does not say what it would make"; }
docker exec "$ct" sh -c '! ls -d /etc/nodkey/credentials/* /etc/nodkey/credentials/.ssh-* /etc/nodkey/ssh-* /run/nodkey-ssh-key.* /etc/systemd/system/nodkey.service.d 2>/dev/null' ||
	fail "keys: --check made something"
pass "keys: --check makes no key and says what it would make"

play "$ct" "$new" broker keys.yml || { show; fail "keys: the first run failed"; }
for name in deploy ops; do
	got=$(docker exec "$ct" stat -c '%U:%G:%a' "/etc/nodkey/credentials/ssh-$name.cred" "/etc/nodkey/ssh-$name.pub" | tr '\n' ' ')
	[ "$got" = "root:root:600 root:root:644 " ] || fail "keys: the files of $name are $got"
	docker exec "$ct" grep -qx "$(line "$name")" "$dropin" || fail "keys: no line for $name in the drop-in"
	grep -q "made the SSH key $name, /etc/nodkey/ssh-$name.pub" "$work/out" || { show; fail "keys: the run does not show the key $name"; }
	docker exec "$ct" grep -q " nodkey-$name\$" "/etc/nodkey/ssh-$name.pub" || fail "keys: the comment of $name is wrong"
done
docker exec "$ct" grep -q '^ssh-ed25519 ' /etc/nodkey/ssh-deploy.pub || fail "keys: deploy is not ed25519"
docker exec "$ct" grep -q '^ecdsa-sha2-nistp256 ' /etc/nodkey/ssh-ops.pub || fail "keys: ops is not ECDSA P-256"
grep -q 'SHA256:.* nodkey-deploy (ED25519)' "$work/out" || { show; fail "keys: the run does not show the fingerprint"; }
[ -z "$(private_keys)" ] || fail "keys: a private key is left: $(private_keys)"
docker exec "$ct" sh -c '! ls -d /run/nodkey-ssh-key.* /etc/nodkey/credentials/.ssh-* 2>/dev/null' || fail "keys: a temporary file is left"
pass "keys: a new name makes the .cred, the .pub and the line in the drop-in, and leaves no private key"

docker exec "$ct" sha256sum /etc/nodkey/credentials/ssh-deploy.cred /etc/nodkey/ssh-deploy.pub "$dropin" >"$work/sums"
play "$ct" "$new" broker keys.yml || { show; fail "keys: the second run failed"; }
[ "$(recap_changed)" = 0 ] || { show; fail "keys: the second run changed something"; }
play "$ct" "$new" broker keys.yml --check --diff || { show; fail "keys: the run with --check failed"; }
[ "$(recap_changed)" = 0 ] || { show; fail "keys: the run with --check shows a change"; }
pass "keys: a second run, and a run with --check, change nothing"

# A broker that signs with the new key: a real SSH login, approved by
# the fake ntfy server.
docker exec "$ct" sh /opt/sign-setup.sh >"$work/out" 2>&1 || { show; fail "keys: the setup of the broker failed"; }
docker exec "$ct" systemctl is-active --quiet nodkey.service || {
	docker exec "$ct" journalctl -u nodkey --no-pager | tail -n 30 >&2
	fail "keys: the broker does not run"
}
got=$(docker exec "$ct" busctl get-property org.freedesktop.systemd1 /org/freedesktop/systemd1/unit/nodkey_2eservice \
	org.freedesktop.systemd1.Service LoadCredentialEncrypted | grep -o '"ssh-deploy"' | wc -l)
[ "$got" -eq 1 ] || fail "keys: the broker loads ssh-deploy $got times"
docker exec "$ct" systemd-analyze verify nodkey.service >"$work/out" 2>&1 || { show; fail "keys: systemd-analyze verify failed"; }
# wait_broker: wait until the broker takes connections.
wait_broker() {
	docker exec "$ct" python3 -c 'import socket, time
for _ in range(30):
    try:
        socket.create_connection(("127.0.0.1", 7743), 1).close()
        break
    except OSError:
        time.sleep(1)
else:
    raise SystemExit(1)' || fail "keys: the broker takes no connection"
}
wait_broker
login() {
	docker exec "$ct" runuser -u example-user -- env HOME=/home/example-user \
		SSH_AUTH_SOCK=/home/example-user/run/nodkey/agent.sock NODKEY_REASON="ansible test" \
		ssh -4 -o BatchMode=yes -o UserKnownHostsFile=/etc/nodkey/known_hosts \
		-o HostKeyAlgorithms=ssh-ed25519 deploy@localhost echo signed-in >"$work/out" 2>&1
}
login || {
	show
	docker exec "$ct" journalctl -u nodkey -u nodkey-test-agent --no-pager | tail -n 30 >&2
	fail "keys: the SSH login with the new key failed"
}
grep -qx signed-in "$work/out" || { show; fail "keys: the SSH login did not run the command"; }
docker exec "$ct" grep -q '"approve_once"' /var/lib/nodkey/audit.jsonl || fail "keys: the audit log has no approval"
pass "keys: the broker starts with the new key next to the ssh-deploy line of the unit, and signs with it"

# An existing credential is never replaced: not by the role, and not
# when the name has another type now.
keys_data keys-type.yml deploy:ecdsa-p521 ops:ecdsa-p256
play "$ct" "$new" broker keys-type.yml || { show; fail "keys: the run with another type failed"; }
[ "$(recap_changed)" = 0 ] || { show; fail "keys: another type changed something"; }
docker exec -i "$ct" sha256sum -c --quiet - <"$work/sums" || fail "keys: an existing key was replaced"
pass "keys: an existing .cred is never replaced"

# nodkey_restart: false: a new key, and no restart.
KEYS_EXTRA='nodkey_restart: false' keys_data keys-norestart.yml deploy ops:ecdsa-p256 backup
pid=$(docker exec "$ct" systemctl show -p MainPID --value nodkey.service)
play "$ct" "$new" broker keys-norestart.yml || { show; fail "keys: the run with nodkey_restart false failed"; }
docker exec "$ct" test -e /etc/nodkey/credentials/ssh-backup.cred || fail "keys: the key backup was not made"
[ "$(result 'Restart the broker')" = skipping ] || { show; fail "keys: nodkey_restart false restarted the broker"; }
grep -q 'nodkey_restart is false' "$work/out" || { show; fail "keys: no notice that a restart is needed"; }
[ "$(docker exec "$ct" systemctl show -p MainPID --value nodkey.service)" = "$pid" ] || fail "keys: the broker was restarted"
pass "keys: with nodkey_restart false, a new key restarts nothing"

# A name that leaves the list keeps its files, with a warning.
keys_data keys-removed.yml deploy ops:ecdsa-p256
pid=$(docker exec "$ct" systemctl show -p MainPID --value nodkey.service)
play "$ct" "$new" broker keys-removed.yml || { show; fail "keys: the run without backup failed"; }
[ "$(docker exec "$ct" systemctl show -p MainPID --value nodkey.service)" != "$pid" ] || fail "keys: a changed drop-in did not restart the broker"
grep -q 'warning: the SSH key backup is no longer in nodkey_ssh_keys' "$work/out" || { show; fail "keys: no warning for the removed name"; }
docker exec "$ct" sh -c 'test -e /etc/nodkey/credentials/ssh-backup.cred && test -e /etc/nodkey/ssh-backup.pub' || fail "keys: the files of a removed name are gone"
docker exec "$ct" grep -q 'ssh-backup' "$dropin" && fail "keys: the drop-in still loads the removed name"
pass "keys: a removed name keeps its files and gives a warning"

# A new key alone, with no change of the drop-in, restarts the broker:
# here the owner removed the key ops by hand.
docker exec "$ct" rm /etc/nodkey/credentials/ssh-ops.cred
wait_broker
pid=$(docker exec "$ct" systemctl show -p MainPID --value nodkey.service)
play "$ct" "$new" broker keys-removed.yml || { show; fail "keys: the run that makes ops again failed"; }
grep -q 'made the SSH key ops, /etc/nodkey/ssh-ops.pub' "$work/out" || { show; fail "keys: ops was not made again"; }
[ "$(docker exec "$ct" systemctl show -p MainPID --value nodkey.service)" != "$pid" ] || fail "keys: a new key did not restart the broker"
pass "keys: a new key restarts the broker"

# A run that stops before the rename: systemd-creds fails here, as
# there is no TPM2 chip. It leaves no .cred and no private key, and the
# next run makes the key.
KEYS_EXTRA='nodkey_ssh_key_with_key: host+tpm2' keys_data keys-fail.yml deploy ops:ecdsa-p256 late
play "$ct" "$new" broker keys-fail.yml && { show; fail "keys: a failing systemd-creds passed"; }
grep -q 'the SSH key late was not made' "$work/out" || { show; fail "keys: no error for the key that was not made"; }
docker exec "$ct" test ! -e /etc/nodkey/credentials/ssh-late.cred || fail "keys: a failed run left a .cred"
[ -z "$(private_keys)" ] || fail "keys: a failed run left a private key: $(private_keys)"
docker exec "$ct" sh -c '! ls -d /run/nodkey-ssh-key.* /etc/nodkey/credentials/.ssh-* 2>/dev/null' || fail "keys: a failed run left a temporary file"
# What a killed run leaves in /run: the next run removes it first.
docker exec "$ct" sh -c 'install -d -m 0700 /run/nodkey-ssh-key.killed && ssh-keygen -q -t ed25519 -N "" -f /run/nodkey-ssh-key.killed/key && touch /etc/nodkey/credentials/.ssh-late.cred.new'
keys_data keys-late.yml deploy ops:ecdsa-p256 late
play "$ct" "$new" broker keys-late.yml || { show; fail "keys: the run after the failed one failed"; }
[ -z "$(private_keys)" ] || fail "keys: the run did not remove what a killed run left: $(private_keys)"
docker exec "$ct" sh -c '! ls -d /run/nodkey-ssh-key.* /etc/nodkey/credentials/.ssh-* 2>/dev/null' || fail "keys: a temporary file of a killed run is left"
docker exec "$ct" test -e /etc/nodkey/credentials/ssh-late.cred || fail "keys: the next run did not make the key"
docker exec "$ct" grep -qx "$(line late)" "$dropin" || fail "keys: no line for late in the drop-in"
pass "keys: a run that stops before the rename leaves no .cred and no private key; the next run makes the key"

# A name that the unit loads from another file, such as a key made by
# hand: the role refuses to make a new key for it.
docker exec "$ct" sh -c 'printf "[Service]\nLoadCredentialEncrypted=ssh-hand:/etc/nodkey/credentials/hand.cred\n" >/etc/systemd/system/nodkey.service.d/hand.conf && systemctl daemon-reload'
keys_data keys-hand.yml deploy ops:ecdsa-p256 late hand
play "$ct" "$new" broker keys-hand.yml && { show; fail "keys: a name that the unit loads from another file passed"; }
grep -q 'the unit loads the credential ssh-hand from' "$work/out" || { show; fail "keys: no error for the name that the unit loads"; }
docker exec "$ct" sh -c 'test ! -e /etc/nodkey/credentials/ssh-hand.cred && test ! -e /etc/nodkey/ssh-hand.pub' || fail "keys: the role made a key for that name"
docker exec "$ct" sh -c 'rm /etc/systemd/system/nodkey.service.d/hand.conf && systemctl daemon-reload'
pass "keys: a name that the unit loads from another file is refused"

# The README's drop-in that removes the lines of the unit: the drop-in
# of the role sorts after it, so the keys stay loaded.
docker exec "$ct" sh -c 'printf "LoadCredentialEncrypted=\nLoadCredentialEncrypted=broker-tls-key:/etc/nodkey/credentials/broker-tls-key.cred\nLoadCredentialEncrypted=ntfy-token:/etc/nodkey/credentials/ntfy-token.cred\n" >>/etc/systemd/system/nodkey.service.d/local.conf && systemctl daemon-reload && systemctl restart nodkey.service'
wait_broker
login || { show; fail "keys: the SSH login after an empty LoadCredentialEncrypted= in local.conf failed"; }
pass "keys: an empty LoadCredentialEncrypted= in local.conf keeps the keys of the role"

# An empty list removes the drop-in, but no key.
keys_data keys-none.yml
play "$ct" "$new" broker keys-none.yml || { show; fail "keys: the run with no keys failed"; }
docker exec "$ct" test ! -e "$dropin" || fail "keys: the drop-in is still there"
docker exec "$ct" test -e /etc/nodkey/credentials/ssh-deploy.cred || fail "keys: an empty list removed a key"
pass "keys: an empty list removes the drop-in, and keeps the keys"

# --- A new host: --check --diff passes and changes nothing.
start sha
ct="nodkey-ansible-sha-$$"
play "$ct" "$new" broker broker-new.yml --check --diff || { show; fail "--check --diff on a new host failed"; }
docker exec "$ct" test ! -e /usr/local/bin/nodkey || fail "--check installed nodkey"
docker exec "$ct" test ! -e /etc/systemd/system/nodkey.service || fail "--check installed the unit"
pass "broker: --check --diff on a new host passes, and installs nothing"

# --- A link in place of nodkey is never run.
docker exec "$ct" sh -c 'printf "#!/bin/sh\ntouch /ran-as-root\n" > /tmp/evil && chmod 755 /tmp/evil && ln -s /tmp/evil /usr/local/bin/nodkey'
play "$ct" "$new" broker broker-new.yml && { show; fail "a link in place of nodkey passed"; }
grep -q 'is not a file that only root can' "$work/out" || { show; fail "no error for the link"; }
docker exec "$ct" test ! -e /ran-as-root || fail "the link was run as root"
docker exec "$ct" rm -f /usr/local/bin/nodkey /tmp/evil
pass "a link in place of nodkey is refused, and not run"

# --- A wrong SHA-256 of install.sh: nothing is installed.
play "$ct" "$new" broker broker-new.yml -e nodkey_install_sh_sha256=0000000000000000000000000000000000000000000000000000000000000000 &&
	{ show; fail "a wrong SHA-256 passed"; }
grep -q 'does not have the SHA-256 of' "$work/out" || { show; fail "no error for the wrong SHA-256"; }
docker exec "$ct" test ! -e /usr/local/bin/nodkey || fail "a wrong SHA-256 installed nodkey"
docker exec "$ct" test ! -e /etc/systemd/system/nodkey.service || fail "a wrong SHA-256 installed the unit"
pass "a wrong SHA-256 of install.sh fails, and installs nothing"

# --- An update: OLD first, then NEW through nodkey update.
play "$ct" "$old" broker broker-old.yml || { show; fail "the run with nodkey $old failed"; }
[ "$(installed "$ct")" = "nodkey $old" ] || fail "nodkey version is not nodkey $old"
play "$ct" "$new" broker broker-new.yml || { show; fail "the update to nodkey $new failed"; }
[ "$(result 'Update nodkey with the installed nodkey')" = changed ] || { show; fail "the update did not use nodkey update"; }
[ "$(result 'Run install.sh')" = skipping ] || { show; fail "the update ran install.sh"; }
[ "$(installed "$ct")" = "nodkey $new" ] || fail "the update did not install nodkey $new"
docker cp "$ct:/etc/systemd/system/nodkey.service" "$work/unit-host"
cmp -s "$work/unit-tag" "$work/unit-host" || fail "after the update, the unit is not the unit of the tag v$new"
pass "an update from nodkey $old to $new goes through nodkey update"

# The role in a play of its own, without the data file: its own check
# refuses the older version too.
cat >"$work/role-old.yml" <<EOF
- name: The role of nodkey $old
  hosts: all
  roles:
    - role: /opt/recipe-$old/roles/nodkey
      vars:
        nodkey_side: broker
EOF
docker cp "$work/role-old.yml" "$ct:/opt/role-old.yml"
docker exec "$ct" ansible-playbook -i localhost, --connection local /opt/role-old.yml >"$work/out" 2>&1 &&
	{ show; fail "the role took an older version"; }
grep -q "which is newer than nodkey_version $old" "$work/out" || { show; fail "no error of the role for the older version"; }
[ "$(installed "$ct")" = "nodkey $new" ] || fail "the older role changed nodkey"
pass "the role alone refuses an older version too"

# --- The agent side.
start agent
ct="nodkey-ansible-agent-$$"
play "$ct" "$new" agent agent-new.yml --check --diff || { show; fail "agent: --check --diff on a new host failed"; }
docker exec "$ct" test ! -e /usr/local/bin/nodkey || fail "agent: --check installed nodkey"
pass "agent: --check --diff on a new host passes, and installs nothing"
play "$ct" "$new" agent agent-new.yml || { show; fail "the first run of the agent side failed"; }
[ "$(installed "$ct")" = "nodkey $new" ] || fail "nodkey version is not nodkey $new"
docker exec "$ct" grep -qx 'ConditionUser=example-user' /etc/systemd/user/nodkey-ssh-agent.service || fail "the user unit is wrong"
docker exec "$ct" test -L /etc/systemd/user/default.target.wants/nodkey-ssh-agent.service || fail "the user unit is not enabled"
docker exec "$ct" test -e /var/lib/systemd/linger/example-user || fail "linger is off"
docker exec "$ct" test ! -e /etc/systemd/system/nodkey.service || fail "the agent side installed the broker unit"
docker exec "$ct" test ! -e /home/example-user/.config || fail "the role wrote into the home directory"
pass "agent: the first run installs nodkey $new and the user unit"

play "$ct" "$new" agent agent-new.yml || { show; fail "the second run of the agent side failed"; }
[ "$(recap_changed)" = 0 ] || { show; fail "the second run of the agent side changed something"; }
play "$ct" "$new" agent agent-new.yml --check --diff || { show; fail "the agent run with --check --diff failed"; }
[ "$(recap_changed)" = 0 ] || { show; fail "the agent run with --check --diff shows a change"; }
pass "agent: a second run, and a run with --check --diff, change nothing"

printf 'nodkey_version: "%s"\nnodkey_ssh_agent_user: ""\n' "$new" >"$work/agent-none.yml"
docker cp "$work/agent-none.yml" "$ct:/opt/data/agent-none.yml"
play "$ct" "$new" agent agent-none.yml || { show; fail "the agent run without an account failed"; }
[ "$(result 'Stop nodkey ssh-agent of the old account')" = changed ] || { show; fail "the agent of the old account was not stopped"; }
docker exec "$ct" test ! -e /etc/systemd/user/nodkey-ssh-agent.service || fail "the user unit is still there"
docker exec "$ct" test ! -L /etc/systemd/user/default.target.wants/nodkey-ssh-agent.service || fail "the link of the user unit is still there"
pass "agent: without an account, the agent stops and the user unit is removed"

echo "ci.sh: all tests passed"
