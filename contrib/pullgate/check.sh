#!/bin/sh
# The check of the pullgate recipe of nodkey. pullgate runs it as the
# check user, on the new commit, before it asks the owner. It reads the
# tree only as data and runs nothing from it. A failure means no question:
# the owner gets the end of this output instead.
set -u
. "${0%/*}/lib.sh"

new=${PULLGATE_TREE:?PULLGATE_TREE is not set; pullgate sets it}

if ! nkp_files_ok "$new"; then
	echo "Fix: put broker.toml and known_hosts at the root of the config repo, as plain files."
	exit 1
fi

# The checks of a start, without the files of the host.
if ! nodkey broker check --files "$new"; then
	echo "Fix the config in the repo; run nodkey broker check --files DIR on a copy of it first."
	exit 1
fi

kh=$(nkp_top_key "$NKP_ETC/broker.toml" known_hosts)
if [ "$kh" != "$NKP_ETC/known_hosts" ]; then
	echo "The live config in $NKP_ETC/broker.toml needs known_hosts = \"$NKP_ETC/known_hosts\" on one plain line for this recipe."
	echo "Fix: change it on the host, as root (docs/setup.md, \"The config repo\")."
	exit 1
fi

# A commit may not change the parts of the gate itself (lib.sh,
# nkp_host_parts), such as the approval channel or a store, or the paths
# of known_hosts and the audit log: apply.sh installs known_hosts in
# $NKP_ETC, and health.sh reads the status file next to the audit log.
if ! nkp_host_parts "$NKP_ETC" "$new"; then
	echo "Refused: a commit may not change listen, tls_key, the paths of known_hosts or audit_log,"
	echo "[telegram], [ntfy] or a [store.*] (or the compare with $NKP_ETC failed)."
	echo "Fix: make such a change on the host, as root (docs/setup.md, \"What stays a step on the host\"),"
	echo "then commit the same files. The check user must be able to read $NKP_ETC/broker.toml and known_hosts."
	exit 1
fi
echo "The config passed nodkey broker check."
