#!/bin/sh
# previous.sh prints N-1 and N-2 for a release candidate (check 2 of the
# Release check workflow, docs/releasing.md): the two highest published
# releases below VERSION. A draft, a prerelease, or a tag without a
# release do not count: a failed release can leave a tag or a draft.
#
#   sh scripts/release-check/previous.sh VERSION < releases.json
#
# The input is the list of releases of the GitHub API, one JSON array per
# page (gh api --paginate repos/OWNER/REPO/releases). It needs jq. It
# prints "N1 N2" (N2 can be missing), and fails when there is no N-1.

set -eu

die() {
	echo "previous.sh: $*" >&2
	exit 1
}

[ "$#" -eq 1 ] || die "give the VERSION of the candidate, for example 0.8.0"
version=$1
case $version in *'
'*) die "the version has a line break" ;;
esac
printf '%s\n' "$version" | grep -Eqx '[0-9]+\.[0-9]+\.[0-9]+' || die "'$version' is not X.Y.Z"

tags=$(jq -r '.[] | select(.draft == false and .prerelease == false and .published_at != null) | .tag_name') ||
	die "cannot read the list of releases"
# grep exits with 1 when no tag matches: that is not an error here.
list=$(printf '%s\n' "$tags" | grep -Ex 'v[0-9]+\.[0-9]+\.[0-9]+' | sed 's/^v//') || [ "$?" -eq 1 ] ||
	die "cannot filter the list of releases"
below=$(printf '%s\n%s\n' "$list" "$version" | grep -v '^$' | sort -u -t. -k1,1n -k2,2n -k3,3n |
	awk -v v="$version" '$0 == v { exit } { print }')
[ -n "$below" ] || die "no published release below $version"
printf '%s\n' "$below" | tail -n 2 | sort -t. -k1,1nr -k2,2nr -k3,3nr | tr '\n' ' ' | sed 's/ $/\n/'
