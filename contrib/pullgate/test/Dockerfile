# A Debian 13 host with systemd as PID 1, for the test of the pullgate
# recipe of nodkey (contrib/pullgate/test/ci.sh): pullgate bootstrap
# --recipe sets up both instances, as on a broker host. The same base as
# contrib/ansible/test/Dockerfile.
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2

RUN apt-get update \
 && apt-get install --yes --no-install-recommends \
      systemd systemd-sysv dbus \
      ansible-core python3-yaml \
      ca-certificates curl git gzip tar util-linux \
 && rm -rf /var/lib/apt/lists/*

STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
