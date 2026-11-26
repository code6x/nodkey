#!/bin/sh
# host-get-recipe.sh X.Y.Z [--with-pullgate]: get the recipes of a nodkey
# release, check them, and unpack them (docs/setup.md, "The host
# instance"). Run as root: setup.sh runs it at the bootstrap, and
# host-apply.sh when host.yml names a new version.
#
# - The Ansible recipe, nodkey_X.Y.Z_ansible.tar.gz, goes to
#   /opt/nodkey-ansible-X.Y.Z. The checks are those of docs/releasing.md,
#   "Verify a download": the SHA-256 in SHA256SUMS, and the build
#   attestation: gh attestation verify says that the release workflow of
#   code6x/nodkey on main built the file, on a runner that GitHub hosts,
#   and its signed statement names the file with its SHA-256. Nothing is
#   unpacked unless every check passes. A recipe that is there already is
#   kept as it is (after the check that only root can change it).
# - With --with-pullgate, the pullgate recipe of the release too:
#   pullgate recipe fetch checks it in the same way and unpacks it into
#   its own folder. It does not switch an instance to it: host-apply.sh
#   runs pullgate recipe use after the playbook passed.
#
# gh is downloaded and checked against the SHA-256 below, as install.sh
# does (the same version and the same SHA-256; a test checks that).
set -eu
umask 022
. "${0%/*}/host-lib.sh"

v=${1:-}
printf '%s\n' "$v" | grep -Eq "$NKH_VERSION_RE" || {
	echo "host-get-recipe.sh: give the version X.Y.Z, such as: host-get-recipe.sh 1.2.3 [--with-pullgate] (exit 64)" >&2
	exit 64
}
with_pullgate=
case ${2:-} in
"") ;;
--with-pullgate) with_pullgate=1 ;;
*)
	echo "host-get-recipe.sh: unknown option '${2:-}'; the only option is --with-pullgate (exit 64)" >&2
	exit 64
	;;
esac
if [ "$(id -u)" != 0 ] && [ "$NKH_ROOT_UID" = 0 ]; then
	echo "host-get-recipe.sh: run it as root" >&2
	exit 1
fi

# The gh of install.sh, with the lines of gh_2.102.0_checksums.txt.
gh_version=2.102.0
gh_sha256_amd64=bb766f710eef8ede859c18578c72c327597cd4c8a85b06001b1f3843c6019386
gh_sha256_arm64=7862c86c72f43df3a2d93ddde6f473285b4e2af61b494849846827e513ef6484
identity=https://github.com/code6x/nodkey/.github/workflows/release.yml@refs/heads/main
base=$NKH_RELEASES/v$v
ansible=nodkey_${v}_ansible.tar.gz

# role_ok DIR: the role in DIR is the one of release $v.
role_ok() { grep -qx "nodkey_role_version: \"$v\"" "$1/roles/nodkey/vars/main.yml"; }
have() {
	a=$(nkh_recipe "$v" 2>/dev/null) && role_ok "$a"
}

# The work folder: only root can change it or any folder above it, so
# pullgate takes the gh in it (pullgate checks the folders of --gh).
install -d -m 0700 "$NKH_WORK"
tmp=$(mktemp -d "$NKH_WORK/get-recipe.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
cd "$tmp"
get() { curl -q --proto '=https' --tlsv1.2 -fsSL --max-filesize "$2" -o "$1" "$3"; }

gh=
# get_gh: download gh and check its SHA-256, once.
get_gh() {
	[ -z "$gh" ] || return 0
	if [ -n "${NKH_GH:-}" ]; then
		# Only the tests set it: a fake gh.
		gh=$NKH_GH
		return 0
	fi
	case $(uname -m) in
	x86_64) arch=amd64 gh_sha=$gh_sha256_amd64 ;;
	aarch64 | arm64) arch=arm64 gh_sha=$gh_sha256_arm64 ;;
	*)
		echo "host-get-recipe.sh: no gh for the CPU $(uname -m); nodkey runs on amd64 and arm64"
		exit 1
		;;
	esac
	gh_tar=gh_${gh_version}_linux_${arch}.tar.gz
	get "$gh_tar" 67108864 "https://github.com/cli/cli/releases/download/v$gh_version/$gh_tar" || {
		echo "host-get-recipe.sh: cannot download gh $gh_version; check the network of the host"
		exit 1
	}
	echo "$gh_sha  $gh_tar" | sha256sum -c --quiet - || {
		echo "host-get-recipe.sh: the SHA-256 of $gh_tar is wrong; nothing was changed"
		exit 1
	}
	mkdir -m 0700 gh home
	tar --no-same-owner -xzf "$gh_tar" -C gh "gh_${gh_version}_linux_${arch}/bin/gh"
	gh=$tmp/gh/gh_${gh_version}_linux_${arch}/bin/gh
}

if have; then
	echo "host-get-recipe.sh: the Ansible recipe of nodkey $v is there already"
else
	get "$ansible" 67108864 "$base/$ansible" || {
		echo "host-get-recipe.sh: cannot download $ansible of v$v; is $v a release of nodkey?"
		exit 1
	}
	get SHA256SUMS 1048576 "$base/SHA256SUMS" || {
		echo "host-get-recipe.sh: cannot download SHA256SUMS of v$v"
		exit 1
	}
	get bundle.json 1048576 "$base/nodkey_${v}.sigstore.json" || {
		echo "host-get-recipe.sh: cannot download the bundle of v$v"
		exit 1
	}
	[ "$(grep -c "  $ansible\$" SHA256SUMS)" = 1 ] || {
		echo "host-get-recipe.sh: SHA256SUMS has no single line for $ansible; nothing was changed"
		exit 1
	}
	grep "  $ansible\$" SHA256SUMS | sha256sum -c --quiet - || {
		echo "host-get-recipe.sh: the SHA-256 of $ansible is not the one in SHA256SUMS; nothing was changed"
		exit 1
	}
	get_gh
	mkdir -p -m 0700 home
	env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME="$tmp/home" XDG_CONFIG_HOME="$tmp/home" \
		XDG_CACHE_HOME="$tmp/home" XDG_DATA_HOME="$tmp/home" XDG_STATE_HOME="$tmp/home" \
		GH_NO_UPDATE_NOTIFIER=1 GH_PROMPT_DISABLED=1 \
		"$gh" attestation verify "$ansible" --bundle bundle.json --repo code6x/nodkey \
		--cert-identity "$identity" --deny-self-hosted-runners --format json >att.json || {
		echo "host-get-recipe.sh: gh attestation verify failed for $ansible: it is not proven that the release workflow built it; nothing was changed"
		exit 1
	}
	# The signed statement must name this file, with the version in its
	# name, and its SHA-256. So a tarball of another release, signed too,
	# cannot pass as the one of $v.
	nkh_statement_names att.json "$ansible" "$ansible" || {
		echo "host-get-recipe.sh: the signed statement does not name $ansible with its SHA-256; nothing was changed"
		exit 1
	}

	# Unpack into a new folder next to the final one, then rename it.
	d=$NKH_OPT/nodkey-ansible-$v
	if [ -e "$d" ] || [ -L "$d" ]; then
		echo "host-get-recipe.sh: $d is there but not safe; look at it, remove it as root, and run host-get-recipe.sh $v again"
		exit 1
	fi
	rm -rf "$d.new"
	install -d -m 0755 "$d.new"
	tar --no-same-owner --no-same-permissions -xzf "$ansible" -C "$d.new"
	if [ "$NKH_ROOT_UID" = 0 ]; then
		chown -R root:root "$d.new"
	fi
	chmod -R go-w "$d.new"
	if ! role_ok "$d.new"; then
		rm -rf "$d.new"
		echo "host-get-recipe.sh: the role in $ansible is not the one of $v; nothing was changed"
		exit 1
	fi
	mv "$d.new" "$d"
	have || {
		echo "host-get-recipe.sh: the Ansible recipe of $v is not safe after the unpack; look at $d"
		exit 1
	}
	echo "host-get-recipe.sh: the Ansible recipe of nodkey $v is checked and in $d"
fi

if [ -n "$with_pullgate" ]; then
	get_gh
	# pullgate prints the folder last. It checks the SHA-256 and the
	# attestation, and that the manifest names version $v.
	"$NKH_PULLGATE" recipe fetch "$base/nodkey_${v}_pullgate.tar.gz" --gh "$gh" || {
		echo "host-get-recipe.sh: pullgate recipe fetch of nodkey_${v}_pullgate.tar.gz failed (above); no pullgate instance was changed"
		exit 1
	}
	echo "host-get-recipe.sh: the pullgate recipe of nodkey $v is checked; pullgate recipe use switches an instance to it"
fi
