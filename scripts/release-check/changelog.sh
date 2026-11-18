#!/bin/sh
# changelog.sh checks the release notes of a release pull request (check 8
# of the Release check workflow, docs/releasing.md).
#
#   sh scripts/release-check/changelog.sh PREV_VERSION VERSION
#
# Run it at the root of the repository, on the head of the release pull
# request, with the full history and the tags. PREV_VERSION is the last
# release (N-1), VERSION the one of the release pull request.
#
# For every commit since vPREV_VERSION (each is one squash merged pull
# request), it checks:
#   - the subject names its pull request: "(#N)" at the end;
#   - a type that the notes show (see release-please-config.json) has #N
#     in the section of VERSION in CHANGELOG.md;
#   - a "!" title also has a section "## Updating from PREV_VERSION" (or
#     "... or older") in docs/updating.md, and that file names #N.
# Commits of a hidden type (chore, ci, test, refactor, build, style) need
# no line.
#
# It prints one line per commit, "ok: ..." or "FAILED: ...", and exits
# with 1 when one failed.

set -eu

die() {
	echo "changelog.sh: $*" >&2
	exit 2
}

[ "$#" -eq 2 ] || die "give PREV_VERSION VERSION, for example 0.7.0 0.8.0"
prev=$1
version=$2
for v in "$prev" "$version"; do
	case $v in *'
'*) die "a version has a line break" ;;
	esac
	printf '%s\n' "$v" | grep -Eqx '[0-9]+\.[0-9]+\.[0-9]+' || die "'$v' is not X.Y.Z"
done
git rev-parse -q --verify "refs/tags/v$prev^{commit}" >/dev/null ||
	die "no tag v$prev; fetch the tags (actions/checkout with fetch-depth: 0)"

# The section of VERSION in CHANGELOG.md: from its heading to the next one.
notes=$(awk -v v="$version" '
	/^## / { if (on) exit; if (index($0, "[" v "]") || index($0, " " v " ")) on = 1; next }
	on' CHANGELOG.md)
[ -n "$notes" ] || die "CHANGELOG.md has no section for $version; run it on the release pull request"

failed=0
n=0
log=$(mktemp)
trap 'rm -f -- "$log"' EXIT
git log --no-merges --format='%H %s' "v$prev..HEAD" >"$log"
while read -r sha subject; do
	case $subject in
	"chore(main): release "*) continue ;; # the release pull request itself
	esac
	n=$((n + 1))
	short=$(printf '%.12s' "$sha")
	pr=$(printf '%s\n' "$subject" | sed -n 's/.*(#\([0-9][0-9]*\))$/\1/p')
	type=$(printf '%s\n' "$subject" | sed -n 's/^\([a-z][a-z]*\)\(([^)]*)\)\{0,1\}\(!\{0,1\}\): .*/\1/p')
	bang=$(printf '%s\n' "$subject" | sed -n 's/^[a-z][a-z]*\(([^)]*)\)\{0,1\}!: .*/!/p')
	if [ -z "$pr" ]; then
		echo "FAILED: $short has no (#N) at the end of its subject; was it merged without a pull request?"
		failed=1
		continue
	fi
	if [ -z "$type" ]; then
		echo "FAILED: #$pr: the subject is not a Conventional Commit title"
		failed=1
		continue
	fi
	if [ -n "$bang" ]; then
		if ! grep -Eq "^## Updating from ${prev}( or older)?\$" docs/updating.md; then
			echo "FAILED: #$pr has ! but docs/updating.md has no section \"## Updating from $prev\""
			failed=1
		elif ! grep -q "#$pr\\b" docs/updating.md; then
			echo "FAILED: #$pr has ! but docs/updating.md does not name #$pr"
			failed=1
		else
			echo "ok: #$pr has its section in docs/updating.md"
		fi
	fi
	case $type in
	chore | ci | test | refactor | build | style)
		[ -n "$bang" ] || echo "ok: #$pr ($type) is a hidden type"
		[ -z "$bang" ] || printf '%s\n' "$notes" | grep -q "#$pr\\b" || {
			echo "FAILED: #$pr has ! but is not in the notes of $version"
			failed=1
		}
		;;
	*)
		if printf '%s\n' "$notes" | grep -q "#$pr\\b"; then
			echo "ok: #$pr ($type) is in the notes of $version"
		else
			echo "FAILED: #$pr ($type) is not in the notes of $version in CHANGELOG.md"
			failed=1
		fi
		;;
	esac
done <"$log"
[ "$n" -gt 0 ] || {
	echo "FAILED: no commit since v$prev"
	failed=1
}
exit "$failed"
