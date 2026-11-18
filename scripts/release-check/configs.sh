#!/bin/sh
# configs.sh checks that the release candidate loads the configs of the
# last release in the same way (check 4 of the Release check workflow,
# docs/releasing.md).
#
#   sh scripts/release-check/configs.sh OLD_BIN NEW_BIN [CORPUS_DIR]
#
# CORPUS_DIR (default test/compat/configs) holds broker configs, each
# checked with "nodkey broker check --files". An ok-*.toml must pass the
# old nodkey, and a bad-*.toml must fail it: so the corpus itself is
# right. Then the new nodkey must give the same result for each. Other
# files in the folder are the files that the configs name (known_hosts).
#
# It prints one line per config, "ok: FILE" or "FAILED: FILE: why", and
# exits with 1 when one failed.

set -eu

die() {
	echo "configs.sh: $*" >&2
	exit 2
}

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
	die "give OLD_BIN NEW_BIN [CORPUS_DIR]"
fi
old=$1
new=$2
corpus=${3:-test/compat/configs}
if [ ! -x "$old" ] || [ ! -x "$new" ]; then
	die "OLD_BIN and NEW_BIN must be nodkey binaries that can run"
fi
[ -d "$corpus" ] || die "$corpus is not a folder; run it at the root of the repository"

# nodkey refuses a config in a folder that others can write to, also
# /tmp, so the corpus goes to a private folder in $HOME first. The ok-*
# configs prove that nodkey accepts that folder.
work=$(mktemp -d "${HOME:?}/nodkey-configs.XXXXXX")
trap 'rm -rf -- "$work"' EXIT
chmod 700 "$work"
cp "$corpus"/* "$work/"
chmod -R go-w "$work"

# result BIN FILE prints the exit code of nodkey broker check.
result() {
	code=0
	"$1" broker check --files "$work" --config "$2" >/dev/null 2>&1 || code=$?
	echo "$code"
}

failed=0
n=0
for f in "$work"/*.toml; do
	name=${f##*/}
	n=$((n + 1))
	a=$(result "$old" "$f")
	b=$(result "$new" "$f")
	case $name in
	ok-*) want=0 ;;
	bad-*) want=1 ;;
	*)
		echo "FAILED: $name: the name must start with ok- or bad-"
		failed=1
		continue
		;;
	esac
	if [ "$a" != "$want" ]; then
		echo "FAILED: $name: the old nodkey exits with $a, want $want; fix the corpus"
		failed=1
	elif [ "$b" != "$a" ]; then
		echo "FAILED: $name: the old nodkey exits with $a, the new one with $b"
		failed=1
	else
		echo "ok: $name (exit $a with both)"
	fi
done
[ "$n" -gt 0 ] || {
	echo "FAILED: no config in $corpus"
	failed=1
}
exit "$failed"
