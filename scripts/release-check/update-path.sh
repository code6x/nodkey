#!/bin/sh
# update-path.sh checks the update path of a release candidate (check 3
# of the Release check workflow, docs/releasing.md): a real older nodkey
# runs "nodkey update", and the install.sh of its own release runs, and
# both install the candidate from a local HTTPS server that plays GitHub.
# A broken release is refused, and the old nodkey stays.
#
#   sh scripts/release-check/update-path.sh DIST VERSION OLD...
#
# DIST holds the files of the candidate (scripts/build-release.sh), and
# VERSION is its version. Each OLD is VERSION:BIN:INSTALL_SH of an older
# release: its version, its nodkey binary for linux/amd64, and its
# install.sh. It needs Docker and openssl, and runs all in a container of
# debian:trixie, as root, where github.com and api.github.com are the
# local server.
#
# The candidate has no attestation: only the Release workflow on main can
# sign one. So a fake gh stands for "gh attestation verify" here: it
# passes when the bundle file was downloaded, and fails when the file
# /root/gh-fail exists (install.sh clears the environment of gh). The real check of the attestation is in the
# verify job of release.yml.
#
# It prints one line per case, "ok: CASE" or "FAILED: CASE: why", and
# exits with 1 when a case failed.

set -eu

die() {
	echo "update-path.sh: $*" >&2
	exit 2
}

# is_version: X.Y.Z, digits only, on one line.
is_version() {
	case $1 in *'
'*) return 1 ;;
	esac
	printf '%s\n' "$1" | grep -Eqx '[0-9]+\.[0-9]+\.[0-9]+'
}

[ "$#" -ge 3 ] || die "give DIST VERSION and at least one OLD as VERSION:BIN:INSTALL_SH"
dist=$1
version=$2
shift 2
is_version "$version" || die "the version '$version' is not X.Y.Z"
[ -f "$dist/SHA256SUMS" ] || die "$dist has no SHA256SUMS; build the candidate with scripts/build-release.sh first"

work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
mkdir -p "$work/web/code6x/nodkey/releases/download/v$version" "$work/web/repos/code6x/nodkey/releases" "$work/old"
cp "$dist"/nodkey_*_linux_amd64.tar.gz "$dist/SHA256SUMS" "$work/web/code6x/nodkey/releases/download/v$version/"
# A made-up bundle: only the fake gh reads it.
echo '{"fake": "bundle of the release check"}' >"$work/web/code6x/nodkey/releases/download/v$version/nodkey_${version}.sigstore.json"
printf '{\n  "tag_name": "v%s",\n  "draft": false\n}\n' "$version" >"$work/web/repos/code6x/nodkey/releases/latest"

olds=
for old in "$@"; do
	v=${old%%:*}
	rest=${old#*:}
	bin=${rest%%:*}
	script=${rest#*:}
	if ! is_version "$v" || [ ! -f "$bin" ] || [ ! -f "$script" ]; then
		die "OLD $old: give VERSION:BIN:INSTALL_SH, with X.Y.Z and files that exist"
	fi
	cp "$bin" "$work/old/nodkey-$v"
	cp "$script" "$work/old/install-$v.sh"
	olds="$olds $v"
done

# A CA of this run only, and the certificate of the server.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
	-subj "/CN=nodkey release check CA" -keyout "$work/ca.key" -out "$work/ca.crt" 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=github.com" \
	-keyout "$work/server.key" -out "$work/server.csr" 2>/dev/null
printf 'subjectAltName=DNS:github.com,DNS:api.github.com\n' >"$work/ext"
openssl x509 -req -in "$work/server.csr" -CA "$work/ca.crt" -CAkey "$work/ca.key" -CAcreateserial \
	-days 1 -extfile "$work/ext" -out "$work/server.crt" 2>/dev/null
rm -f "$work/ca.key"

cat >"$work/inside.sh" <<'INSIDE'
#!/bin/sh
# Runs in the container, as root.
set -eu
version=$1
shift
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -y -qq --no-install-recommends curl ca-certificates openssl >/dev/null
cp /work/ca.crt /usr/local/share/ca-certificates/release-check.crt
update-ca-certificates >/dev/null 2>&1
web=/srv/web
cp -r /work/web "$web"
(cd "$web" && openssl s_server -quiet -accept 443 -WWW -cert /work/server.crt -key /work/server.key \
	>/var/log/fixture.log 2>&1) &
sleep 1

# The fake gh: see update-path.sh.
cat >/usr/local/bin/gh <<'GH'
#!/bin/sh
if [ "$1" = --version ]; then
	echo "gh version 2.102.0 (2026-09-30)"
	exit 0
fi
[ "$1 $2" = "attestation verify" ] || exit 2
[ ! -e /root/gh-fail ] || exit 1
bundle=
while [ "$#" -gt 0 ]; do
	[ "$1" = --bundle ] && bundle=$2
	shift
done
[ -s "$bundle" ]
GH
chmod 755 /usr/local/bin/gh

rel=$web/code6x/nodkey/releases/download/v$version
cp "$rel/SHA256SUMS" /root/SHA256SUMS.good
tarball=nodkey_${version}_linux_amd64.tar.gz
cp "$rel/$tarball" /root/tarball.good
failed=0
pass() { echo "ok: $1"; }
fail() {
	echo "FAILED: $1: $2"
	failed=1
}
put_old() {
	install -m 755 "/work/old/nodkey-$1" /usr/local/bin/nodkey
}
restore() {
	cp /root/SHA256SUMS.good "$rel/SHA256SUMS"
	cp /root/tarball.good "$rel/$tarball"
}
# want_new CASE: the candidate is installed.
want_new() {
	got=$(/usr/local/bin/nodkey version --offline 2>&1) || true
	if [ "$got" = "nodkey $version" ]; then pass "$1"; else fail "$1" "nodkey version says '$got'"; fi
}
# want_refused CASE OLD CODE: the update failed, and the old file stays.
want_refused() {
	if [ "$3" -eq 0 ]; then
		fail "$1" "it exited with 0"
	elif cmp -s "/work/old/nodkey-$2" /usr/local/bin/nodkey; then
		pass "$1"
	else
		fail "$1" "the old nodkey is gone"
	fi
}

for old in "$@"; do
	put_old "$old"
	if /usr/local/bin/nodkey update --gh /usr/local/bin/gh >"/root/log-$old" 2>&1; then
		want_new "nodkey $old: nodkey update installs $version"
	else
		fail "nodkey $old: nodkey update installs $version" "it failed: $(tail -n 3 "/root/log-$old" | tr '\n' ' ')"
	fi
	put_old "$old"
	if sh "/work/old/install-$old.sh" --version "$version" --bin-dir /usr/local/bin --gh /usr/local/bin/gh >"/root/log-$old-sh" 2>&1; then
		want_new "nodkey $old: its install.sh installs $version"
	else
		fail "nodkey $old: its install.sh installs $version" "it failed: $(tail -n 3 "/root/log-$old-sh" | tr '\n' ' ')"
	fi

	put_old "$old"
	sed "s/^[0-9a-f]\{64\}  $tarball\$/$(printf '%064d' 0)  $tarball/" /root/SHA256SUMS.good >"$rel/SHA256SUMS"
	code=0
	/usr/local/bin/nodkey update --gh /usr/local/bin/gh >/dev/null 2>&1 || code=$?
	want_refused "nodkey $old: a wrong checksum is refused" "$old" "$code"
	restore

	put_old "$old"
	grep -v " $tarball\$" /root/SHA256SUMS.good >"$rel/SHA256SUMS" || true
	code=0
	/usr/local/bin/nodkey update --gh /usr/local/bin/gh >/dev/null 2>&1 || code=$?
	want_refused "nodkey $old: a missing checksum is refused" "$old" "$code"
	restore

	put_old "$old"
	rm -f "$rel/$tarball"
	code=0
	/usr/local/bin/nodkey update --gh /usr/local/bin/gh >/dev/null 2>&1 || code=$?
	want_refused "nodkey $old: a missing file is refused" "$old" "$code"
	restore

	put_old "$old"
	printf 'x' >>"$rel/$tarball"
	code=0
	/usr/local/bin/nodkey update --gh /usr/local/bin/gh >/dev/null 2>&1 || code=$?
	want_refused "nodkey $old: a changed file is refused" "$old" "$code"
	restore

	put_old "$old"
	code=0
	: >/root/gh-fail
	/usr/local/bin/nodkey update --gh /usr/local/bin/gh >/dev/null 2>&1 || code=$?
	rm -f /root/gh-fail
	want_refused "nodkey $old: a failed attestation check is refused" "$old" "$code"
done
exit "$failed"
INSIDE

# debian:trixie, pinned. Update the digest by hand, with
# docker buildx imagetools inspect debian:trixie.
image=debian:trixie@sha256:9c6e381421d0f48d1b8133e573f33c185ee16cbf505eda9c4a8a4791b25ea8a6

# Only root may change the files that the script runs (install.sh checks).
chmod -R go-w "$work"
# $olds is a list of checked versions: digits and dots, split on purpose.
# shellcheck disable=SC2086
docker run --rm --network bridge \
	--add-host github.com:127.0.0.1 --add-host api.github.com:127.0.0.1 \
	-v "$work:/work:ro" "$image" sh /work/inside.sh "$version" $olds
