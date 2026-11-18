#!/bin/sh
# build.sh makes the Ansible recipe of one nodkey release: the role, the
# playbooks and check-data, with the install.sh and the unit of the tag
# in the role, and their SHA-256 in roles/nodkey/vars/main.yml.
#
#   sh contrib/ansible/build.sh VERSION TAGDIR OUTDIR
#
# VERSION is X.Y.Z. TAGDIR holds install.sh and
# contrib/systemd/nodkey.service of the tag vX.Y.Z: the release workflow
# passes the checkout of the tag. OUTDIR must not exist; build.sh makes it.
# The release workflow packs OUTDIR into nodkey_VERSION_ansible.tar.gz
# (DESIGN.md section 18).
#
# Exit codes: 0 done, 1 failure, 64 wrong usage.

set -eu

usage_error() {
	printf 'build.sh: %s; usage: sh contrib/ansible/build.sh VERSION TAGDIR OUTDIR (exit 64)\n' "$1" >&2
	exit 64
}

die() {
	printf 'build.sh: %s (exit 1)\n' "$1" >&2
	exit 1
}

[ "$#" -eq 3 ] || usage_error "give VERSION, TAGDIR and OUTDIR"
version=$1
tagdir=$2
out=$3

# X.Y.Z, without leading zeros: the same rule as install.sh.
printf '%s\n' "$version" | grep -Eqx '(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)' ||
	usage_error "VERSION \"$version\" is not X.Y.Z"
[ -f "$tagdir/install.sh" ] || die "$tagdir/install.sh is not there; give the checkout of the tag v$version as TAGDIR"
[ -f "$tagdir/contrib/systemd/nodkey.service" ] ||
	die "$tagdir/contrib/systemd/nodkey.service is not there; give the checkout of the tag v$version as TAGDIR"
[ ! -e "$out" ] || die "$out is there already; give a new directory as OUTDIR"

src=$(cd "$(dirname "$0")" && pwd)

mkdir -p "$out"
cp "$src/README.md" "$src/check-data" "$out/"
cp -R "$src/playbooks" "$src/roles" "$out/"
cp "$src/../../LICENSE" "$out/"
mkdir -p "$out/roles/nodkey/files" "$out/roles/nodkey/vars"
cp "$tagdir/install.sh" "$out/roles/nodkey/files/install.sh"
cp "$tagdir/contrib/systemd/nodkey.service" "$out/roles/nodkey/files/nodkey.service"

install_sh_sha256=$(sha256sum <"$out/roles/nodkey/files/install.sh" | cut -d' ' -f1)
unit_sha256=$(sha256sum <"$out/roles/nodkey/files/nodkey.service" | cut -d' ' -f1)

cat >"$out/roles/nodkey/vars/main.yml" <<EOF
---
# Written by contrib/ansible/build.sh for nodkey $version. The role
# installs only this release, with these two files of the tag v$version.
nodkey_role_version: "$version"
nodkey_install_sh_sha256: "$install_sh_sha256"
nodkey_unit_sha256: "$unit_sha256"
EOF

chmod 0755 "$out/check-data"
printf 'build.sh: the Ansible recipe of nodkey %s is in %s\n' "$version" "$out"
