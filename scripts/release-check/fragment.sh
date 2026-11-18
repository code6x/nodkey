#!/bin/sh
# fragment.sh writes the result of one check of the Release check workflow
# as JSON (docs/releasing.md, "Read the result").
#
#   sh scripts/release-check/fragment.sh CHECK RESULT EVIDENCE_FILE OUT
#
# RESULT is pass, fail or report (the timing report, which never fails).
# The last 200 lines of EVIDENCE_FILE (it may be missing) go in as the
# evidence. It needs jq.

set -eu
[ "$#" -eq 4 ] || {
	echo "fragment.sh: give CHECK RESULT EVIDENCE_FILE OUT" >&2
	exit 2
}
case $2 in
pass | fail | report) ;;
*)
	echo "fragment.sh: RESULT must be pass, fail or report, not '$2'" >&2
	exit 2
	;;
esac
# The evidence goes to jq as a file: a long log does not fit in one
# argument.
tmp=$(mktemp)
trap 'rm -f -- "$tmp"' EXIT
if [ -f "$3" ]; then
	tail -n 200 -- "$3" | tail -c 65536 >"$tmp"
fi
jq -n --arg check "$1" --arg result "$2" --rawfile evidence "$tmp" \
	'{check: $check, result: $result, evidence: $evidence}' >"$4"
