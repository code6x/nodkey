#!/bin/sh
# ci.sh tests the pullgate recipe of nodkey end to end, in a Debian 13
# container with systemd, with pullgate of a pinned release:
#
#   - a broker host set up with the Ansible recipe of the test build, with
#     a real broker (a fake bot token; api.telegram.org is 127.0.0.1);
#   - pullgate bootstrap --recipe on the recipe of the test build, the one
#     command of docs/setup.md, with a fake GitHub release server, a fake
#     gh and a fake Telegram on 127.0.0.1 (pullgate's options for a test);
#   - both instances are set up, each setup passes, and the first commit
#     of each data repo is asked, tapped and applied; the playbook of the
#     host instance with changed=0; pullgate doctor finds no problem.
#
#   sh contrib/pullgate/test/ci.sh DIST VERSION
#
# DIST holds the files of a test build of VERSION:
#   sh scripts/build-release.sh VERSION DIST
# It runs from the root of the repository, needs Docker, curl and network
# access (for the image and pullgate), and removes the container and the
# image that it makes.

set -eu

# pullgate of a pinned release, checked against the SHA-256 of its
# SHA256SUMS. Update both together, by hand.
pullgate_version=0.4.0
pullgate_sha256=3ec1f734771cad4c0622879a2623e14340164e903d05d6006361b0a3b95350f4

[ "$#" -eq 2 ] || {
	echo 'ci.sh: give DIST and VERSION, such as: sh contrib/pullgate/test/ci.sh dist 1.2.3 (exit 64)' >&2
	exit 64
}
dist=$1
v=$2
printf '%s\n' "$v" | grep -Eqx '[0-9]+\.[0-9]+\.[0-9]+' || {
	echo "ci.sh: the version '$v' is not X.Y.Z (exit 64)" >&2
	exit 64
}
[ -f "$dist/nodkey_${v}_pullgate.tar.gz" ] || {
	echo "ci.sh: $dist has no nodkey_${v}_pullgate.tar.gz; build it first: sh scripts/build-release.sh $v $dist" >&2
	exit 1
}
image=nodkey-pullgate-test:$$
ct=nodkey-pullgate-test-$$
work=$(mktemp -d)
cleanup() {
	docker rm -f "$ct" >/dev/null 2>&1 || :
	docker rmi -f "$image" >/dev/null 2>&1 || :
	rm -rf "$work" || :
}
trap cleanup EXIT
fail() {
	printf 'FAIL: %s\n' "$*" >&2
	exit 1
}

tarball=pullgate_${pullgate_version}_linux_amd64.tar.gz
curl --proto '=https' --tlsv1.2 -fsSL --retry 3 -o "$work/$tarball" \
	"https://github.com/code6x/pullgate/releases/download/v$pullgate_version/$tarball"
echo "$pullgate_sha256  $work/$tarball" | sha256sum -c --quiet - || fail "the SHA-256 of $tarball is wrong"
tar -xzf "$work/$tarball" -C "$work" pullgate

docker build -q -t "$image" contrib/pullgate/test >/dev/null
docker run -d --name "$ct" --privileged --cgroupns=host \
	--tmpfs /run --tmpfs /run/lock \
	-v /sys/fs/cgroup:/sys/fs/cgroup:rw \
	--add-host api.telegram.org:127.0.0.1 "$image" >/dev/null
state=""
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
	state=$(docker exec "$ct" systemctl is-system-running --wait 2>/dev/null || :)
	case $state in running | degraded) break ;; esac
	sleep 1
done
case $state in
running | degraded) ;;
*) fail "systemd in the container did not start: $state" ;;
esac
# systemd mounts the credentials of a unit from a child process: the
# mounts of the container must be shared, as on a host.
docker exec "$ct" mount --make-rshared /
docker exec "$ct" install -d -o root -g root -m 0755 /opt/test
docker cp "$dist" "$ct:/opt/test/dist"
docker cp contrib/pullgate/test/inside.sh "$ct:/opt/test/inside.sh"
docker cp contrib/pullgate/test/faketg.py "$ct:/opt/test/faketg.py"
docker cp "$work/pullgate" "$ct:/usr/local/bin/pullgate"
docker exec "$ct" sh -c 'chown -R root:root /opt/test /usr/local/bin/pullgate && chmod -R go-w /opt/test && chmod 0755 /usr/local/bin/pullgate'
docker exec "$ct" pullgate --version
docker exec "$ct" sh /opt/test/inside.sh "$v"
