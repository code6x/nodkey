#!/bin/sh
# build-release.sh builds the files of a release of nodkey: the tarballs
# of the binary for Linux amd64 and arm64, of the pullgate recipe and of
# the Ansible recipe, and SHA256SUMS.
#
#   sh scripts/build-release.sh VERSION OUT_DIR
#
# Run it at the root of the repository, at the commit to build, with the
# Go of the release (docs/releasing.md). The Release workflow builds the
# files of each release with it, and the Release check workflow builds a
# candidate with it, so both make the same files. A rebuild of the same
# commit with the same Go version gives the same bytes: the binaries are
# built with -trimpath and without cgo, and the tarballs have a fixed
# owner, mode, order and time (the time of the last commit).
#
# OUT_DIR must not exist yet. Signing and publishing are not done here:
# only the Release workflow does them.

set -eu

die() {
	echo "build-release.sh: $*" >&2
	exit 1
}

[ "$#" -eq 2 ] || die "give VERSION and OUT_DIR, for example: sh scripts/build-release.sh 1.2.3 dist"
version=$1
out=$2
case $version in *'
'*) die "the version has a line break; give one line, for example 1.2.3" ;;
esac
if ! printf '%s\n' "$version" | grep -Eqx '(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)'; then
	die "the version '$version' is not X.Y.Z; give the version without the v, for example 1.2.3"
fi
if [ ! -f go.mod ] || [ ! -d cmd/nodkey ]; then
	die "run it at the root of the nodkey repository"
fi
if [ -e "$out" ] || [ -L "$out" ]; then
	die "$out exists already; remove it or give a new directory"
fi

# LC_ALL=C: the same order of the names in a tarball on every runner.
LC_ALL=C
export LC_ALL

work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
mkdir -p -- "$out"

# Fixed owner, mode and time in the tarball, so a rebuild of the same
# commit with the same Go version gives the same file.
mtime="@$(git log -1 --format=%ct)"

# -w drops the debug data. The symbol table stays (no -s): govulncheck
# needs it to check the published binaries (see ci.yml).
for arch in amd64 arm64; do
	name="nodkey_${version}_linux_${arch}"
	stage="${work}/${name}"
	mkdir -p -- "$stage"
	CGO_ENABLED=0 GOOS=linux GOARCH="$arch" \
		go build -trimpath -ldflags "-w -X main.version=${version}" \
		-o "${stage}/nodkey" ./cmd/nodkey
	cp LICENSE README.md "$stage/"
	tar --owner=0 --group=0 --numeric-owner --mode=go-w --mtime="$mtime" \
		-C "$stage" -cf - nodkey LICENSE README.md | gzip -9n >"${out}/${name}.tar.gz"
done

# The pullgate recipe (contrib/pullgate, docs/setup.md): the files of
# contrib/pullgate (not its test folder), with the version of this
# release in the manifest pullgate-recipe.toml. pullgate bootstrap
# --recipe and pullgate recipe fetch install it from here, checked by
# SHA256SUMS and the attestation as the binaries are, never from a
# config repo. The release also has the bundle under the name that
# pullgate looks for, nodkey_VERSION_pullgate.sigstore.json (release.yml).
name="nodkey_${version}_pullgate"
stage="${work}/${name}"
mkdir -p -- "$stage"
find contrib/pullgate -maxdepth 1 -type f -exec cp -- {} "$stage/" \;
cp LICENSE "$stage/"
[ "$(grep -c '^version = "0\.0\.0"$' "$stage/pullgate-recipe.toml")" = 1 ] ||
	die "contrib/pullgate/pullgate-recipe.toml needs one line version = \"0.0.0\"; the build writes the version there"
sed "s/^version = \"0\.0\.0\"\$/version = \"${version}\"/" "$stage/pullgate-recipe.toml" >"$work/manifest"
mv -- "$work/manifest" "$stage/pullgate-recipe.toml"
chmod 0644 "$stage/pullgate-recipe.toml"
(cd "$stage" && tar --sort=name --owner=0 --group=0 --numeric-owner --mode=go-w --mtime="$mtime" \
	-cf - -- *) | gzip -9n >"${out}/${name}.tar.gz"

# The Ansible recipe (contrib/ansible): the role, the playbooks and
# check-data. build.sh puts the install.sh and the unit of this commit into
# the role, and pins their SHA-256 in it. A host installs it from here,
# checked as the binaries are.
name="nodkey_${version}_ansible"
stage="${work}/${name}"
sh contrib/ansible/build.sh "$version" . "$stage"
(cd "$stage" && tar --sort=name --owner=0 --group=0 --numeric-owner --mode=go-w --mtime="$mtime" \
	-cf - -- *) | gzip -9n >"${out}/${name}.tar.gz"

(cd "$out" && sha256sum -- *.tar.gz >SHA256SUMS && cat SHA256SUMS)
