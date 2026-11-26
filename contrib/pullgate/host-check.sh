#!/bin/sh
# The check of the host instance of the pullgate recipe of nodkey
# (docs/setup.md, "The host instance"). pullgate runs it as the check user
# on each new commit, before it asks. It reads host.yml only as data, with
# check-data of the Ansible recipe of the installed nodkey. A failure means
# no question: the owner gets the end of this output.
set -u
. "${0%/*}/host-lib.sh"

new=${PULLGATE_TREE:?PULLGATE_TREE is not set; pullgate sets it}
old=${PULLGATE_OLD_TREE:-}
data=$new/host.yml
fix_files() {
	echo "Fix: remove it from the data repo. The data repo holds only these files:"
	echo "$NKH_ALLOWED_FILES"
	exit 1
}

nkh_plain "$data" || {
	echo "Fix: put host.yml at the root of the data repo, as a plain file."
	exit 1
}
# Only the known files: a long list of files would push the summary out
# of the question.
nkh_only_allowed "$new" || fix_files
# The same for the changed paths that pullgate lists: a submodule is not
# in the tree, but it is in this list, and in the question.
changed=${PULLGATE_CHANGED_FILES:?PULLGATE_CHANGED_FILES is not set; pullgate sets it}
first=0
[ -n "$old" ] || first=1
nkh_changed_allowed "$changed" "$first" || fix_files
inst=$(nkh_installed) || {
	echo "$inst"
	exit 1
}
recipe=$(nkh_recipe "$inst") || {
	echo "$recipe"
	exit 1
}

# check-data of the installed release: only its keys, each with its type,
# and no nodkey_version older than the installed one.
if ! nkh_check_data "$recipe" "$inst" "$data"; then
	echo "Fix host.yml in the data repo. Only the keys of nodkey $inst are allowed;"
	echo "change nodkey_version alone, never to an older version than $inst."
	exit 1
fi
# The rules of the host: the config path of the broker, and a new version
# alone. Against the last applied commit, when there is one.
if [ -n "$old" ] && [ -f "$old/host.yml" ] && [ ! -L "$old/host.yml" ]; then
	nkh_rules "$data" "$inst" "$old/host.yml" || {
		echo "Fix host.yml in the data repo."
		exit 1
	}
else
	nkh_rules "$data" || {
		echo "Fix host.yml in the data repo."
		exit 1
	}
fi
want=$(nkh_version "$data") || {
	echo "$want"
	exit 1
}
echo "host.yml passed check-data of nodkey $inst (nodkey_version $want)."
