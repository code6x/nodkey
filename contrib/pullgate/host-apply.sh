#!/bin/sh
# The apply of the host instance of the pullgate recipe of nodkey
# (docs/setup.md, "The host instance"). pullgate runs it as root after the
# owner tapped Apply, under the lock that the two instances of the recipe
# share (flock in their configs). It runs only checked code: the playbook
# broker-host.yml of the Ansible recipe of a release, with --connection
# local and host.yml as data. Forward only: check-data and the role refuse
# an older nodkey_version, and the instance has on_failure = "pause".
#
# For a new nodkey_version it first gets the recipes of that release and
# checks them (host-get-recipe.sh: the Ansible recipe into /opt, and
# pullgate recipe fetch for this recipe). The pullgate instances move to
# the new recipe (pullgate recipe use) only after the playbook passed: a
# script of a new version never runs with an older nodkey.
set -u
umask 022
. "${0%/*}/host-lib.sh"

new=${PULLGATE_TREE:?PULLGATE_TREE is not set; pullgate sets it}
self=${PULLGATE_INSTANCE:?PULLGATE_INSTANCE is not set; pullgate sets it}
report() {
	[ -z "${PULLGATE_REPORT_FILE:-}" ] || printf '%s\n' "$*" >>"$PULLGATE_REPORT_FILE" 2>/dev/null || :
}
fail() {
	echo "nodkey host apply: $*"
	report "nodkey host apply failed: $*"
	exit 1
}

[ "$(id -u)" = 0 ] || [ "$NKH_ROOT_UID" != 0 ] || fail "run it as root (pullgate runs it so)"
work=$(mktemp -d /tmp/nodkey-host-apply.XXXXXX) || fail "cannot make a temporary directory in /tmp"
trap 'rm -rf "$work"' EXIT
mkdir "$work/ansible" || fail "cannot make $work/ansible"

# A private copy: the playbook copies it again, and checks that copy.
nkh_plain "$new/host.yml" || fail "fix the data repo"
cp "$new/host.yml" "$work/host.yml" || fail "cannot copy host.yml"
data=$work/host.yml

inst=$(nkh_installed) || fail "$inst"
cur=$(nkh_recipe "$inst") || fail "$cur"
nkh_check_data "$cur" "$inst" "$data" || fail "host.yml did not pass check-data of nodkey $inst; fix it with a new commit"
why=$(nkh_rules "$data") || fail "$why"
want=$(nkh_version "$data") || fail "$want"

# The pullgate instances of this recipe, and those of them that do not
# run the recipe of $want yet: they move to it after the playbook. Also
# when the version stays: an apply of a new version that failed after
# nodkey update left them on the recipe before.
ours=$(nkh_our_instances) || fail "$ours"
move=$(printf '%s\n' "$ours" | awk -v w="$want" 'NF == 2 && $2 != w { print $1 }')
if [ "$want" != "$inst" ]; then
	# This instance must move too: else it would keep running the scripts
	# of the old version. Checked before any change.
	printf '%s\n' "$move" | grep -Fqx "$self" ||
		fail "the pullgate instance $self does not run the recipe of nodkey (no $NKH_PGETC/$self.recipe that names it), so it cannot move to the recipe of $want; set it up with pullgate bootstrap --recipe (docs/setup.md, \"The host instance\"). Nothing was changed"
	echo "nodkey host apply: nodkey $inst → $want"
fi
if [ -n "$move" ]; then
	echo "nodkey host apply: getting the recipes of nodkey $want"
	"${0%/*}/host-get-recipe.sh" "$want" --with-pullgate ||
		fail "the recipes of nodkey $want did not pass their checks; nothing was changed"
fi
recipe=$(nkh_recipe "$want") || fail "$recipe"

# Never in the tree: ansible-playbook reads ansible.cfg from the working
# directory. The config is ours, and every Ansible path is in $work.
printf '[defaults]\nretry_files_enabled = False\n' >"$work/ansible.cfg"
cd "$recipe" || fail "cannot enter $recipe"
echo "nodkey host apply: ansible-playbook -i localhost, --connection local --diff $recipe/playbooks/broker-host.yml"
env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
	HOME="$work/ansible" LANG=C.UTF-8 \
	ANSIBLE_CONFIG="$work/ansible.cfg" ANSIBLE_HOME="$work/ansible" \
	ANSIBLE_LOCAL_TEMP="$work/ansible/tmp" ANSIBLE_REMOTE_TEMP="$work/ansible/tmp" \
	ANSIBLE_NOCOLOR=1 \
	"$NKH_ANSIBLE_PLAYBOOK" -i localhost, --connection local --diff \
	"$recipe/playbooks/broker-host.yml" -e "nodkey_data_file=$data" ||
	fail "the playbook failed; the instance pauses at this commit, and the pullgate instances stay on the recipe they had. Read the lines above (journalctl -t pullgate), then fix it with a new commit"

# The recipe of the pullgate instances goes with the binary. Only after
# the playbook passed, so the scripts never run ahead of it. pullgate
# checks the folder again, and the new configs count from the next run.
if [ -n "$move" ]; then
	for name in $move; do
		"$NKH_PULLGATE" recipe use "$name" "$want" ||
			fail "nodkey $want is installed, but pullgate recipe use $name $want failed; as root, run it again (journalctl -t pullgate)"
		echo "nodkey host apply: the pullgate instance $name now runs the recipe of nodkey $want"
	done
fi
echo "nodkey host apply: done, nodkey $want"
report "nodkey host apply: done, nodkey $want"
