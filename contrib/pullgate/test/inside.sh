#!/bin/sh
# inside.sh VERSION: the part of contrib/pullgate/test/ci.sh that runs as
# root inside the container with systemd. ci.sh put there:
#   /opt/test/dist      the files of the test build (build-release.sh)
#   /opt/test/*         this script and faketg.py
#   /usr/local/bin/pullgate   pullgate of the pinned release
#
# A broker host as the owner has it before the setup: nodkey VERSION
# installed and set up with the Ansible recipe (a real broker with a
# fake bot token; api.telegram.org is 127.0.0.1 here), and two data
# repos. Then the one command of docs/setup.md, pullgate bootstrap
# --recipe, with a fake GitHub release server and a fake gh on
# 127.0.0.1 (pullgate's options for a test) and a fake Telegram that
# pairs and taps Apply. Both instances must be set up, and the first
# commit of each is asked and applied; the host instance's playbook
# with changed=0.
set -eu

v=$1
t=/opt/test
dist=$t/dist
tg=18444
rel=18445
ok() { echo "PASS: $*"; }
fail() {
	echo "FAIL: $*" >&2
	exit 1
}
# wait_for SECONDS CMD...: run CMD each second until it passes.
wait_for() {
	n=$1
	shift
	while [ "$n" -gt 0 ]; do
		if "$@" >/dev/null 2>&1; then
			return 0
		fi
		n=$((n - 1))
		sleep 1
	done
	return 1
}

# --- The broker host before the setup.
tar -xzf "$dist/nodkey_${v}_linux_amd64.tar.gz" -C /tmp nodkey
install -o root -g root -m 0755 /tmp/nodkey /usr/local/bin/nodkey
[ "$(nodkey version --offline)" = "nodkey $v" ] || fail "nodkey $v is not installed"

# The Ansible recipe of the release in /opt, as host-get-recipe.sh puts
# it there (it is checked there; the download is tested by the Go tests).
install -d -o root -g root -m 0755 "/opt/nodkey-ansible-$v"
tar --no-same-owner -xzf "$dist/nodkey_${v}_ansible.tar.gz" -C "/opt/nodkey-ansible-$v"
chown -R root:root "/opt/nodkey-ansible-$v"
chmod -R go-w "/opt/nodkey-ansible-$v"

# The first host.yml: the installed version, and the broker config of
# the host.
install -d -m 0755 /srv/work
printf 'nodkey_version: "%s"\nnodkey_broker_config: /etc/nodkey/broker.toml\n' "$v" >/srv/work/host.yml

# The broker config with a test key and a fake bot token. The test key
# and token are plain files of the user nodkey: the container cannot give
# the unit encrypted credentials, so a drop-in turns them off.
cd "/opt/nodkey-ansible-$v"
# The owner set up the broker with the role, before the config: the user,
# the folders and the unit. The config check of the role needs a config,
# so the first run is without one.
printf 'nodkey_version: "%s"\nnodkey_broker_config: ""\n' "$v" >/srv/work/first.yml
ansible-playbook -i localhost, --connection local playbooks/broker-host.yml \
	-e nodkey_data_file=/srv/work/first.yml >/srv/work/first.out 2>&1 || {
	cat /srv/work/first.out
	fail "the first run of the role failed"
}
install -d -o root -g root -m 0700 /etc/nodkey/test
nodkey keygen --out /etc/nodkey/test/broker-tls-key >/dev/null
pin=$(nodkey keygen --out /root/client-tls-key)
printf '123456789:%s\n' AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA >/etc/nodkey/test/telegram-token
chown -R nodkey:nodkey /etc/nodkey/test
chmod 0600 /etc/nodkey/test/*
: >/etc/nodkey/known_hosts
chmod 0644 /etc/nodkey/known_hosts
cat >/etc/nodkey/broker.toml <<EOF
listen = "127.0.0.1:7743"
tls_key = "/etc/nodkey/test/broker-tls-key"
audit_log = "/var/lib/nodkey/audit.jsonl"
known_hosts = "/etc/nodkey/known_hosts"

[telegram]
token_file = "/etc/nodkey/test/telegram-token"
user_id = 123456789

[updates]
check = false

[client.test]
pin = "$pin"
EOF
chmod 0644 /etc/nodkey/broker.toml
install -d -m 0755 /etc/systemd/system/nodkey.service.d
printf '[Service]\nLoadCredentialEncrypted=\n' >/etc/systemd/system/nodkey.service.d/test.conf
systemctl daemon-reload
systemctl restart nodkey
broker_runs() {
	pid=$(systemctl show -P MainPID nodkey) && [ "$pid" != 0 ] &&
		grep -q "^{\"pid\":$pid," /var/lib/nodkey/reload-status.json
}
wait_for 30 broker_runs || {
	journalctl -u nodkey --no-pager | tail -n 30
	fail "the broker does not run"
}
ok "a broker host: nodkey $v set up with the role, a broker that runs"

# The role with the config of the host, once by hand, as the owner did:
# from now on the host instance applies host.yml.
ansible-playbook -i localhost, --connection local playbooks/broker-host.yml \
	-e nodkey_data_file=/srv/work/host.yml >/srv/work/second.out 2>&1 || {
	cat /srv/work/second.out
	fail "the run of the role with the config failed"
}
wait_for 30 broker_runs || fail "the broker does not run after the role"

# --- The two data repos, local bare repos (pullgate reads a path too).
repo() {
	install -d -m 0755 "/srv/git/$1.git" "/srv/src/$1"
	git init -q --bare -b main "/srv/git/$1.git"
	git -C "/srv/src/$1" init -q -b main
	git -C "/srv/src/$1" remote add origin "/srv/git/$1.git"
}
commit() {
	git -C "/srv/src/$1" add -A
	git -C "/srv/src/$1" -c user.name=test -c user.email=test@example.com commit -q -m "$2"
	git -C "/srv/src/$1" push -q origin main
}
repo config
cp /etc/nodkey/broker.toml /etc/nodkey/known_hosts /srv/src/config/
commit config "the live config"
repo host-data
cp /srv/work/host.yml /srv/src/host-data/host.yml
printf '# host-data\n\nThe host settings of example-host.\n' >/srv/src/host-data/README.md
commit host-data "the host settings"

# --- The fake release of the recipe, a fake gh, a fake Telegram.
d=/srv/releases/code6x/nodkey/releases/download/v$v
install -d -m 0755 "$d"
cp "$dist/nodkey_${v}_pullgate.tar.gz" "$dist/SHA256SUMS" "$d/"
printf '{}\n' >"$d/nodkey_${v}_pullgate.sigstore.json"
install -d -o root -g root -m 0755 /usr/local/lib/nodkey-test
cat >/usr/local/lib/nodkey-test/gh <<'EOF'
#!/bin/sh
# A fake gh: it checks the flags as the real one would, and prints the
# signed statement with the name and SHA-256 of the file.
set -eu
if [ "$1" = --version ]; then echo "gh version 2.102.0 (2026-01-01)"; exit 0; fi
[ "$1 $2" = "attestation verify" ] || exit 9
f=$3
shift 3
self=0
while [ $# -gt 0 ]; do
	case $1 in
	--repo) [ "$2" = code6x/nodkey ] || exit 1; shift 2 ;;
	--cert-identity) [ "$2" = https://github.com/code6x/nodkey/.github/workflows/release.yml@refs/heads/main ] || exit 1; shift 2 ;;
	--deny-self-hosted-runners) self=1; shift ;;
	*) shift 2 ;;
	esac
done
[ "$self" = 1 ] || exit 1
printf '[{"verificationResult":{"statement":{"subject":[{"name":"%s","digest":{"sha256":"%s"}}]}}}]' "$(basename "$f")" "$(sha256sum "$f" | cut -d ' ' -f 1)"
EOF
chmod 0755 /usr/local/lib/nodkey-test/gh
texts=/srv/work/texts
python3 -I "$t/faketg.py" "$tg" /srv/work/tg.log --tap "$texts" &
python3 -I -m http.server --bind 127.0.0.1 --directory /srv/releases "$rel" >/dev/null 2>&1 &
port_open() { python3 -I -c 'import socket, sys; socket.create_connection(("127.0.0.1", int(sys.argv[1])), 1)' "$1"; }
wait_for 20 port_open "$tg" || fail "the fake Telegram did not start"
wait_for 20 port_open "$rel" || fail "the fake release server did not start"

# --- The one command of docs/setup.md, with the test options.
url=http://127.0.0.1:$rel/code6x/nodkey/releases/download/v$v/nodkey_${v}_pullgate.tar.gz
boot=/srv/work/bootstrap.out
printf '123:a-test-token-made-by-the-test\n' |
	pullgate bootstrap --token-stdin --api-url "http://127.0.0.1:$tg" \
		--recipe "$url" --gh /usr/local/lib/nodkey-test/gh \
		--instance nodkey-broker --repo /srv/git/config.git \
		--instance nodkey-host --repo /srv/git/host-data.git >"$boot" 2>&1 &
bpid=$!
code=
n=0
while [ -z "$code" ]; do
	code=$(sed -n 's/^    \([0-9]\{4\}\) \([0-9]\{4\}\)$/\1\2/p' "$boot")
	[ -z "$code" ] || break
	n=$((n + 1))
	[ "$n" -lt 240 ] || {
		cat "$boot"
		fail "pullgate bootstrap printed no pairing code"
	}
	sleep 0.5
done
python3 -I -c 'import json, sys, urllib.request
urllib.request.urlopen(urllib.request.Request("http://127.0.0.1:%s/test/say" % sys.argv[1], data=json.dumps({"text": sys.argv[2]}).encode(), method="POST"), timeout=5)' "$tg" "$code"
wait "$bpid" || {
	cat "$boot"
	fail "pullgate bootstrap --recipe failed"
}
cat "$boot"
grep -q 'a-test-token' "$boot" && fail "bootstrap printed the token"
for name in nodkey-broker nodkey-host; do
	grep -q "^nodkey setup ($name): every check passed" "$boot" || fail "the setup of $name did not pass"
	grep -q "^version = \"$v\"$" "/etc/pullgate/$name.recipe" || fail "no recipe record for $name"
	grep -q -F "/usr/local/lib/pullgate/recipes/code6x/nodkey/$v/" "/etc/pullgate/$name.toml" ||
		fail "/etc/pullgate/$name.toml does not name the scripts of the recipe"
	grep -q -E '"/usr/bin/flock", "-w", "[0-9]+", "/run/nodkey-broker-apply.lock", "/usr/local/lib/pullgate/recipes/' "/etc/pullgate/$name.toml" ||
		fail "the apply of $name does not take the shared lock"
	systemctl is-enabled --quiet "pullgate-run@$name.timer" || fail "pullgate-run@$name.timer is not enabled"
	systemctl is-enabled --quiet "pullgate-apply@$name.path" || fail "pullgate-apply@$name.path is not enabled"
done
ok "pullgate bootstrap --recipe set up nodkey-broker and nodkey-host, each setup passed"

# --- The first commit of each repo: asked, tapped, applied.
for name in nodkey-broker nodkey-host; do
	case $name in
	nodkey-broker) tip=$(git -C /srv/src/config rev-parse HEAD) ;;
	nodkey-host) tip=$(git -C /srv/src/host-data rev-parse HEAD) ;;
	esac
	applied() { pullgate status "$name" | grep -q "^applied: *$tip\$"; }
	n=0
	until applied; do
		systemctl start "pullgate-run@$name.service" || :
		n=$((n + 1))
		[ "$n" -lt 90 ] || {
			pullgate status "$name" || :
			journalctl -t pullgate --no-pager | tail -n 60
			cat "$texts" 2>/dev/null || :
			fail "the first commit of $name was not applied"
		}
		sleep 2
	done
	ok "$name: the first commit was asked and applied"
done
grep -q -F 'First apply: the values in host.yml.' "$texts" || fail "the question of nodkey-host has no summary of host.yml"
# The output of an apply goes to the journal.
journalctl --no-pager >/srv/work/journal
grep -E 'localhost +: ok=[0-9]+ +changed=0 +unreachable=0 +failed=0' /srv/work/journal >/dev/null || {
	grep -E 'localhost +: ok=' /srv/work/journal || :
	tail -n 80 /srv/work/journal
	fail "the playbook of the host instance did not run with changed=0"
}
grep -q -F 'nodkey host apply: done, nodkey '"$v" /srv/work/journal || fail "host-apply.sh did not finish"
ok "nodkey-host: broker-host.yml ran with changed=0"
wait_for 30 broker_runs || fail "the broker does not run after the applies"

# --- A commit with a file outside the layout of the data repo: the check
# refuses it, so no question comes, only a notice, and nothing is applied.
good=$(git -C /srv/src/host-data rev-parse HEAD)
printf 'not a file of the layout\n' >/srv/src/host-data/notes.txt
commit host-data "a file outside the layout"
refused() { grep -q -F 'notes.txt is not an allowed file of the data repo' "$texts"; }
n=0
until refused; do
	systemctl start pullgate-run@nodkey-host.service || :
	n=$((n + 1))
	[ "$n" -lt 30 ] || {
		cat "$texts"
		fail "no notice for the commit with a file outside the layout"
	}
	sleep 2
done
pullgate status nodkey-host | grep -q "^applied: *$good\$" || fail "the refused commit changed the applied commit"
ok "nodkey-host: a commit with a file outside the layout gets a notice, no question, and is not applied"

pullgate doctor || fail "pullgate doctor found a problem"
ok "pullgate doctor finds no problem"
