#!/bin/sh
# setup.sh broker|host: the setup of an instance of the pullgate recipe of
# nodkey (docs/setup.md, "Change the config from git with pullgate").
# pullgate bootstrap --recipe runs it once, as root, in the folder of the
# recipe, before it writes the config of the instance. It runs the checks
# that were steps by hand before. On a failure it says how to fix it, and
# bootstrap writes no config and enables no unit; run bootstrap again
# after the fix.
#
#   broker  the broker config instance (nodkey-broker)
#   host    the host instance (nodkey-host); it also gets the Ansible
#           recipe of the installed nodkey into /opt
#
# It changes nothing on the host, but the Ansible recipe in /opt.
set -u
dir=${0%/*}
. "$dir/lib.sh"
. "$dir/host-lib.sh"

role=${1:-}
case $role in
broker | host) ;;
*)
	echo "setup.sh: give broker or host, such as: setup.sh host (exit 64)"
	exit 64
	;;
esac
name=${PULLGATE_INSTANCE:?PULLGATE_INSTANCE is not set; pullgate bootstrap sets it}
failed=0
ok() { echo "nodkey setup ($name): ok: $*"; }
bad() {
	echo "nodkey setup ($name): PROBLEM: $*"
	failed=1
}

if [ "$(id -u)" != 0 ] && [ "$NKH_ROOT_UID" = 0 ]; then
	echo "nodkey setup: run it as root (pullgate bootstrap runs it so)"
	exit 1
fi

# The version of this recipe, from its manifest (pullgate checked that it
# is the version of the release).
recipe_v=$(sed -n 's/^version = "\([0-9.]*\)"$/\1/p' "$dir/pullgate-recipe.toml" | head -n 1)

# 1. The installed nodkey is the version of this recipe: a script of a
# new version never runs with an older nodkey.
if inst=$(nkh_installed); then
	if [ "$inst" = "$recipe_v" ]; then
		ok "nodkey $inst is installed, the version of this recipe"
	else
		bad "this is the recipe of nodkey $recipe_v, but nodkey $inst is installed. Fix: give the recipe of the installed version, https://github.com/code6x/nodkey/releases/download/v$inst/nodkey_${inst}_pullgate.tar.gz (or update nodkey first, docs/setup.md \"Upgrades\")"
	fi
else
	bad "$inst"
	inst=
fi

# 2. The live config: both files, and the two lines at its top that the
# scripts read.
if why=$(nkp_files_ok "$NKP_ETC"); then
	ok "$NKP_ETC/broker.toml and $NKP_ETC/known_hosts are plain files"
	kh=$(nkp_top_key "$NKP_ETC/broker.toml" known_hosts) || kh=
	if [ "$kh" = "$NKP_ETC/known_hosts" ]; then
		ok "broker.toml has known_hosts = \"$NKP_ETC/known_hosts\" at its top"
	else
		bad "broker.toml needs the line known_hosts = \"$NKP_ETC/known_hosts\" before its first [section], once, as one plain line. Fix: change it as root (docs/setup.md, \"The config repo\")"
	fi
	if nkp_top_key "$NKP_ETC/broker.toml" audit_log >/dev/null; then
		ok "broker.toml has one audit_log line at its top"
	else
		bad "broker.toml needs one line audit_log = \"...\" before its first [section], as one plain line: health.sh reads the status file next to the audit log. Fix: change it as root (docs/setup.md section 7)"
	fi
else
	bad "$why. Fix: set up the broker config first (docs/setup.md section 7)"
fi

# 3. The check user: pullgate runs check and summary as it, with no
# other groups. It is in the config, or pullgate-check-NAME for a new one.
user=
if [ -f "$NKH_PGETC/$name.toml" ]; then
	user=$(sed -n 's/^[[:space:]]*check_user[[:space:]]*=[[:space:]]*"\([a-z_][a-z0-9_-]*\)".*/\1/p' "$NKH_PGETC/$name.toml" | head -n 1)
fi
[ -n "$user" ] || user=pullgate-check-$name
# as_user CMD...: run CMD as the check user, as pullgate does: its own
# group only.
as_user() {
	if [ "$NKH_ROOT_UID" != 0 ]; then
		"$@"
	else
		setpriv --reuid="$user" --regid="$(id -g "$user")" --clear-groups -- "$@"
	fi
}
if ! id -u "$user" >/dev/null 2>&1; then
	bad "the check user $user does not exist. Fix: run pullgate bootstrap again; it makes the user"
elif [ "$role" = broker ]; then
	# check.sh compares the commit with the live config.
	if as_user test -r "$NKP_ETC/broker.toml" && as_user test -r "$NKP_ETC/known_hosts"; then
		ok "the check user $user can read $NKP_ETC/broker.toml and known_hosts"
	else
		bad "the check user $user cannot read $NKP_ETC/broker.toml and known_hosts (it has no other group). Fix: as root, chmod 0644 $NKP_ETC/broker.toml $NKP_ETC/known_hosts and check each folder above them (docs/setup.md section 7)"
	fi
else
	# host-check.sh runs the installed nodkey as the check user.
	if [ -n "$inst" ] && as_user "$NKH_NODKEY" version --offline >/dev/null 2>&1; then
		ok "the check user $user can run $NKH_NODKEY"
	else
		bad "the check user $user cannot run $NKH_NODKEY version --offline. Fix: install nodkey as root with install.sh (docs/setup.md section 2)"
	fi
fi

# 4. The host instance: the Ansible recipe of the installed nodkey, and
# the unit of its role.
if [ "$role" = host ] && [ -n "$inst" ]; then
	if out=$("$dir/host-get-recipe.sh" "$inst" 2>&1); then
		ok "the Ansible recipe of nodkey $inst is checked and in $NKH_OPT/nodkey-ansible-$inst"
		rec=$NKH_OPT/nodkey-ansible-$inst
		if cmp -s "$rec/roles/nodkey/files/nodkey.service" "$NKH_UNIT_FILE"; then
			ok "$NKH_UNIT_FILE is the unit of the role of nodkey $inst"
		else
			bad "$NKH_UNIT_FILE is not the unit of nodkey $inst (contrib/systemd/nodkey.service). Fix: as root, install $rec/roles/nodkey/files/nodkey.service as $NKH_UNIT_FILE, keep your changes in a drop-in, run systemctl daemon-reload and systemctl restart nodkey (docs/setup.md section 9)"
		fi
	else
		printf '%s\n' "$out"
		bad "host-get-recipe.sh $inst failed (above). Fix what it says, then run pullgate bootstrap again"
	fi
fi

# 5. The broker runs the live config: the health check of both instances.
if [ "$failed" = 0 ]; then
	if out=$("$dir/health.sh" 2>&1); then
		ok "health.sh: ${out#nodkey health: }"
	else
		bad "health.sh: ${out#nodkey health: }. Fix: start the broker with the live config (systemctl restart nodkey, as root), and read journalctl -u nodkey"
	fi
fi

if [ "$failed" != 0 ]; then
	echo "nodkey setup ($name): a check failed; pullgate wrote no config and enabled no unit. Fix each PROBLEM above, then run the same pullgate bootstrap again."
	exit 1
fi
echo "nodkey setup ($name): every check passed"
