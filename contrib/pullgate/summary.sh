#!/bin/sh
# The summary of the pullgate recipe of nodkey. pullgate runs it as the
# check user and puts its output into the question. The lines with ⚠ come
# first; read each one before you tap Apply.
set -u
. "${0%/*}/lib.sh"

new=${PULLGATE_TREE:?PULLGATE_TREE is not set; pullgate sets it}
old=${PULLGATE_OLD_TREE:-}
first=
if [ -z "$old" ]; then
	# The first apply: compare with the config that runs now.
	old=$NKP_ETC
	first=1
fi

if [ "$(nkp_action "$old" "$new")" = restart ]; then
	echo "⚠ needs a broker restart: all grants end"
fi
if [ -n "$first" ]; then
	echo "First apply: the changes from the live config in $NKP_ETC."
elif ! nodkey broker config-diff "$NKP_ETC" "$old" >/dev/null 2>&1; then
	echo "⚠ the live config in $NKP_ETC is not the applied commit (a change by hand?); the list is from the applied commit"
fi
nodkey broker config-diff --short --max-chars 1200 "$old" "$new" 2>&1
# config-diff exits 1 when the configs differ: that is not a failure.
[ $? -le 1 ]
