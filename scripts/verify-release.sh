#!/bin/sh
# verify-release.sh checks the files of a draft release before it is
# published (the verify job of release.yml, docs/releasing.md "The
# verify gate"). The release stays a draft unless every check passes.
#
#   sh scripts/verify-release.sh DIR VERSION GH_TARBALL
#
# Run it at the root of the repository, at the commit of the release.
# DIR holds the files of the draft. GH_TARBALL is
# gh_2.102.0_linux_amd64.tar.gz of cli/cli (install.sh checks its
# SHA-256). It needs Docker, openssl, jq, gh and go. The checks:
#   1. the names of the files are exactly the expected ones;
#   2. SHA256SUMS names each tarball once, and each matches;
#   3. the attestation in the bundle verifies, offline, with the identity
#      of the release workflow on main, and names exactly these tarballs;
#   4. each binary is built for its CPU and says this version (the build
#      info, and amd64 also runs "nodkey version --offline");
#   5. install.sh of this commit installs the draft's tarball in a clean
#      debian:trixie container, as root, with the same checks that a
#      user runs: the real gh of install.sh and the real bundle. Only
#      github.com and api.github.com are a local HTTPS server there,
#      because the files of a draft are not public yet;
#   6. the pullgate tarball is a pullgate recipe of this version
#      (scripts/release-check/recipe.sh), and the release has the bundle
#      also as nodkey_VERSION_pullgate.sigstore.json, the same bytes:
#      pullgate looks for the bundle under that name.
#
# NODKEY_VERIFY_COMMIT (default: HEAD) is the commit that the binaries
# must name.
# NODKEY_VERIFY_KINDS (default "ansible linux_amd64 linux_arm64 pullgate
# pullgate_recipe") names the tarballs that must be there; only the dry
# run sets it. pullgate_recipe is not a tarball: it says that the
# pullgate tarball is a recipe, with its own bundle name (check 6).
#
# It prints "ok: ..." or "FAILED: ..." for each check, and exits with 1
# when one failed.

set -eu

die() {
	echo "verify-release.sh: $*" >&2
	exit 2
}

[ "$#" -eq 3 ] || die "give DIR VERSION GH_TARBALL"
dir=$1
version=$2
gh_tarball=$3
case $version in *'
'*) die "the version has a line break" ;;
esac
printf '%s\n' "$version" | grep -Eqx '[0-9]+\.[0-9]+\.[0-9]+' || die "'$version' is not X.Y.Z"
version_re=$(printf '%s' "$version" | sed 's/\./\\./g')
[ -d "$dir" ] || die "$dir is not a folder"
[ -f "$gh_tarball" ] || die "$gh_tarball does not exist"
[ -f install.sh ] || die "run it at the root of the repository"
repo=${GITHUB_REPOSITORY:-code6x/nodkey}
# The commit of the release: this checkout, or NODKEY_VERIFY_COMMIT (only
# the dry run sets it, for an older release).
commit=${NODKEY_VERIFY_COMMIT:-$(git rev-parse HEAD)}
printf '%s\n' "$commit" | grep -Eqx '[0-9a-f]{40}' || die "the commit '$commit' is not a full SHA-1"
identity="https://github.com/${repo}/.github/workflows/release.yml@refs/heads/main"

failed=0
ok() { echo "ok: $*"; }
fail() {
	echo "FAILED: $*"
	failed=1
}

# The kinds of tarballs. Only the dry run of verify-release.yml sets
# NODKEY_VERIFY_KINDS, for an older release that has fewer kinds.
kinds=${NODKEY_VERIFY_KINDS:-ansible linux_amd64 linux_arm64 pullgate pullgate_recipe}
tarballs=
recipe=
for k in $kinds; do
	case $k in
	ansible | linux_amd64 | linux_arm64 | pullgate) tarballs="$tarballs nodkey_${version}_${k}.tar.gz" ;;
	pullgate_recipe) recipe=1 ;;
	*) die "NODKEY_VERIFY_KINDS: unknown kind '$k'" ;;
	esac
done
case " $kinds " in *" linux_amd64 "*) ;; *) die "NODKEY_VERIFY_KINDS must have linux_amd64" ;; esac
case " $kinds " in *" pullgate_recipe "*) case " $kinds " in *" pullgate "*) ;; *) die "NODKEY_VERIFY_KINDS: pullgate_recipe needs pullgate" ;; esac ;; esac
bundle=nodkey_${version}.sigstore.json
recipe_bundle=nodkey_${version}_pullgate.sigstore.json

# 1. The names.
tarball_lines=$(for t in $tarballs; do echo "$t"; done | LC_ALL=C sort)
want=$(printf '%s\n%s\n%s\n' "$tarball_lines" SHA256SUMS "$bundle" | LC_ALL=C sort)
if [ -n "$recipe" ]; then
	want=$(printf '%s\n%s\n' "$want" "$recipe_bundle" | LC_ALL=C sort)
fi
have=$(find "$dir" -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort)
if [ "$have" = "$want" ]; then
	ok "1 the draft has exactly the expected files"
else
	fail "1 the files of the draft are not the expected ones: have [$(printf '%s' "$have" | tr '\n' ' ')], want [$(printf '%s' "$want" | tr '\n' ' ')]"
fi

# 2. SHA256SUMS.
names=$(awk '{ sub(/^\*/, "", $2); print $2 }' "$dir/SHA256SUMS" 2>/dev/null | LC_ALL=C sort)
if [ "$names" != "$tarball_lines" ]; then
	fail "2 SHA256SUMS does not name each tarball exactly once"
elif (cd "$dir" && sha256sum --strict --quiet -c SHA256SUMS); then
	ok "2 each tarball matches SHA256SUMS"
else
	fail "2 a tarball does not match SHA256SUMS"
fi

# 3. The attestation: each tarball, offline with the bundle, and the
# bundle names exactly the four tarballs with their SHA-256.
att=ok
for t in $tarballs; do
	if [ ! -f "$dir/$t" ] || ! gh attestation verify "$dir/$t" --bundle "$dir/$bundle" --repo "$repo" \
		--cert-identity "$identity" --deny-self-hosted-runners --source-digest "$commit" >/dev/null 2>&1; then
		fail "3 the attestation does not verify $t"
		att=
	fi
done
subjects=$(jq -r '.dsseEnvelope.payload' "$dir/$bundle" 2>/dev/null | base64 -d 2>/dev/null |
	jq -r '.subject[] | "\(.digest.sha256)  \(.name)"' 2>/dev/null | LC_ALL=C sort -k2) || subjects=
sums=$(LC_ALL=C sort -k2 "$dir/SHA256SUMS" 2>/dev/null | sed 's/  \*/  /')
if [ -z "$subjects" ] || [ "$subjects" != "$sums" ]; then
	fail "3 the bundle does not name exactly the tarballs of SHA256SUMS"
	att=
fi
[ -z "$att" ] || ok "3 the attestation verifies each tarball, with the identity $identity and the commit $commit"

# 4. The version in each binary.
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
for arch in amd64 arm64; do
	t=nodkey_${version}_linux_${arch}.tar.gz
	case " $kinds " in *" linux_$arch "*) ;; *) continue ;; esac
	mkdir -p "$work/$arch"
	if ! tar -xzf "$dir/$t" -C "$work/$arch" nodkey 2>/dev/null; then
		fail "4 $t has no file nodkey"
		continue
	fi
	# With -trimpath the build info has no -ldflags, but Go puts in the
	# version of the tag of a clean checkout, and the commit.
	info=$(go version -m "$work/$arch/nodkey" 2>/dev/null) || info=
	if printf '%s\n' "$info" | grep -Eq "^[[:space:]]+mod[[:space:]]+github\.com/code6x/nodkey[[:space:]]+v${version_re}([[:space:]]|\$)" &&
		printf '%s\n' "$info" | grep -Eq "^[[:space:]]+build[[:space:]]+GOARCH=${arch}\$" &&
		printf '%s\n' "$info" | grep -Eq "^[[:space:]]+build[[:space:]]+vcs.revision=${commit}\$" &&
		printf '%s\n' "$info" | grep -Eq "^[[:space:]]+build[[:space:]]+vcs.modified=false\$"; then
		ok "4 $t: the build info says v$version, $arch, commit $commit, a clean checkout"
	else
		fail "4 $t: the build info does not say v$version, $arch, commit $commit and a clean checkout"
	fi
done
got=$("$work/amd64/nodkey" version --offline 2>&1) || got="(it does not run)"
if [ "$got" = "nodkey $version" ]; then
	ok "4 the amd64 binary says: $got"
else
	fail "4 the amd64 binary says '$got', want 'nodkey $version'"
fi

# 5. install.sh in a clean container.
web=$work/web
mkdir -p "$web/code6x/nodkey/releases/download/v$version" "$web/repos/code6x/nodkey/releases" \
	"$web/cli/cli/releases/download/v2.102.0"
cp "$dir"/* "$web/code6x/nodkey/releases/download/v$version/"
cp "$gh_tarball" "$web/cli/cli/releases/download/v2.102.0/"
printf '{\n  "tag_name": "v%s"\n}\n' "$version" >"$web/repos/code6x/nodkey/releases/latest"
cp install.sh "$work/install.sh"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
	-subj "/CN=nodkey verify CA" -keyout "$work/ca.key" -out "$work/ca.crt" 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=github.com" \
	-keyout "$work/server.key" -out "$work/server.csr" 2>/dev/null
printf 'subjectAltName=DNS:github.com,DNS:api.github.com\n' >"$work/ext"
openssl x509 -req -in "$work/server.csr" -CA "$work/ca.crt" -CAkey "$work/ca.key" -CAcreateserial \
	-days 1 -extfile "$work/ext" -out "$work/server.crt" 2>/dev/null
rm -f "$work/ca.key"
cat >"$work/inside.sh" <<'INSIDE'
set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -y -qq --no-install-recommends curl ca-certificates openssl >/dev/null
cp /work/ca.crt /usr/local/share/ca-certificates/verify.crt
update-ca-certificates >/dev/null 2>&1
cp -r /work/web /srv/web
(cd /srv/web && openssl s_server -quiet -accept 443 -WWW -cert /work/server.crt -key /work/server.key >/dev/null 2>&1) &
sleep 1
sh /work/install.sh --version "$1"
/usr/local/bin/nodkey version --offline
INSIDE
chmod -R go-w "$work"
# debian:trixie, pinned, as in scripts/release-check/update-path.sh.
image=debian:trixie@sha256:9c6e381421d0f48d1b8133e573f33c185ee16cbf505eda9c4a8a4791b25ea8a6
if out=$(docker run --rm --add-host github.com:127.0.0.1 --add-host api.github.com:127.0.0.1 \
	-v "$work:/work:ro" "$image" sh /work/inside.sh "$version" 2>&1) &&
	[ "$(printf '%s\n' "$out" | tail -n 1)" = "nodkey $version" ]; then
	ok "5 install.sh installs the draft's tarball in a clean container, as root"
else
	fail "5 install.sh does not install the draft's tarball: $(printf '%s\n' "$out" | tail -n 5 | tr '\n' ' ')"
fi

# 6. The pullgate recipe, and its bundle name.
if [ -n "$recipe" ]; then
	if out=$(sh scripts/release-check/recipe.sh "$dir/nodkey_${version}_pullgate.tar.gz" "$version" 2>&1); then
		ok "6 $(printf '%s\n' "$out" | tail -n 1 | sed 's/^ok: //')"
	else
		fail "6 the pullgate tarball is not a good recipe: $(printf '%s\n' "$out" | grep -v '^ok:' | head -n 5 | tr '\n' ' ')"
	fi
	if [ -f "$dir/$recipe_bundle" ] && cmp -s "$dir/$bundle" "$dir/$recipe_bundle"; then
		ok "6 $recipe_bundle is the bundle $bundle"
	else
		fail "6 $recipe_bundle is missing, or is not the same file as $bundle"
	fi
fi
exit "$failed"
