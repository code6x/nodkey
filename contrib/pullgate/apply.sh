#!/bin/sh
# The apply of the pullgate recipe of nodkey. pullgate runs it as root
# after the owner tapped Apply, and again with the last good commit in a
# rollback. It is safe to run again: it installs two files and reloads or
# restarts the broker.
#
# On a failure it puts the old files back, reloads or restarts the broker
# again, and exits with 1. Then pullgate rolls back, or pauses.
set -u
umask 077
. "${0%/*}/lib.sh"

new=${PULLGATE_TREE:?PULLGATE_TREE is not set; pullgate sets it}
stage=$NKP_ETC/pullgate-new
keep=$NKP_ETC/pullgate-old

# moved is set once the new files are in $NKP_ETC. Before that, a failure
# removes the stage and the copy: the live files did not change.
moved=
fail() {
	echo "nodkey apply: $*"
	[ -n "$moved" ] || rm -rf "$stage" "$keep"
	exit 1
}

nkp_files_ok "$new" || fail "fix the config repo"
nkp_files_ok "$NKP_ETC" || fail "set up $NKP_ETC by hand first (docs/setup.md section 7)"
# known_hosts goes to $NKP_ETC/known_hosts. check.sh refuses a commit that
# moves it, so the live config must name that path.
kh=$(nkp_top_key "$NKP_ETC/broker.toml" known_hosts) ||
	fail "cannot read known_hosts = \"...\" at the top of $NKP_ETC/broker.toml; write it as one plain line"
[ "$kh" = "$NKP_ETC/known_hosts" ] ||
	fail "the live config has known_hosts = \"$kh\"; this recipe needs \"$NKP_ETC/known_hosts\""

# Stage the new files with the owner and mode of the live ones, and keep
# a copy of the live ones. A stage or a copy from an earlier run that was
# cut off is removed first.
# $keep is left only when an earlier apply could not put the old files
# back. It may hold the only copy of a good config: never remove it here.
[ ! -e "$keep" ] || {
	moved=1
	fail "$keep is left from an earlier apply; compare it with $NKP_ETC, put back what is right, remove it, then run pullgate status \$PULLGATE_INSTANCE --resume"
}
rm -rf "$stage" || fail "cannot remove $stage; remove it by hand, as root"
mkdir -m 0700 "$stage" "$keep" || fail "cannot make $stage and $keep"
for f in $NKP_FILES; do
	cur=$NKP_ETC/$f
	install -m "$(stat -c %a "$cur")" -o "$(stat -c %u "$cur")" -g "$(stat -c %g "$cur")" "$new/$f" "$stage/$f" ||
		fail "cannot install $stage/$f; read the error above, and check the space and the modes in $NKP_ETC"
	cp -p "$cur" "$keep/$f" || fail "cannot copy $cur to $keep; read the error above, and check the space in $NKP_ETC"
done

# The checks of a start again, as root, with the names of the credentials.
if [ -d "$NKP_CREDENTIALS" ]; then
	nodkey broker check --files "$stage" --credentials "$NKP_CREDENTIALS" || fail "nodkey broker check refused the new config"
else
	nodkey broker check --files "$stage" || fail "nodkey broker check refused the new config"
fi

# The same rule as check.sh, again as root: also a rollback, which runs no
# check, must not change the gate.
nkp_host_parts "$NKP_ETC" "$stage" ||
	fail "refused: the commit changes a part that only root on the host may change (docs/setup.md, \"What stays a step on the host\")"

action=$(nkp_action "$NKP_ETC" "$stage")
# A broker that does not run cannot reload. So apply.sh also starts a
# broker that was stopped: pause the instance first to keep it stopped.
systemctl is-active --quiet "$NKP_UNIT" || action=restart
echo "nodkey apply: the change needs a $action"

moved=1
for f in $NKP_FILES; do
	mv -f "$stage/$f" "$NKP_ETC/$f" || fail "cannot move $stage/$f to $NKP_ETC; the old files are in $keep"
done
rmdir "$stage"

if nkp_run "$action"; then
	rm -rf "$keep"
	echo "nodkey apply: done, with a $action"
	exit 0
fi

if [ "${PULLGATE_ROLLBACK:-}" = 1 ]; then
	# The files that are live now are of the commit that failed: keep the
	# last good ones in place, and try a restart.
	rm -rf "$keep"
	if [ "$action" = reload ] && nkp_run restart; then
		echo "nodkey apply: the rollback reload failed, the restart worked"
		exit 0
	fi
	echo "nodkey apply: the rollback failed; the last good files are in $NKP_ETC; read journalctl -u $NKP_UNIT"
	exit 1
fi

echo "nodkey apply: the $action failed; the old files go back"
for f in $NKP_FILES; do
	mv -f "$keep/$f" "$NKP_ETC/$f" || fail "cannot put $keep/$f back; put it in $NKP_ETC by hand, as root"
done
rmdir "$keep"
if nkp_run "$action"; then
	echo "nodkey apply: the old config runs again"
else
	echo "nodkey apply: the $action with the old config failed too; read journalctl -u $NKP_UNIT"
fi
exit 1
