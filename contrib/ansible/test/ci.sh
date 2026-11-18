#!/bin/sh
# ci.sh tests the Ansible recipe in a Debian stable container with
# systemd, for both sides, against real releases on GitHub:
#
#   - a first run installs the release, and nodkey version prints it;
#   - a second run, and a run with --check --diff, change nothing;
#   - the unit that the role installs is the one of the tag;
#   - a wrong SHA-256 of install.sh fails, and installs nothing;
#   - an older version is refused; a newer one installs with nodkey update;
#   - a data file with an unknown key fails before any change.
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
