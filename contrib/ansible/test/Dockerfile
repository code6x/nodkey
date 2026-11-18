# A Debian stable host with systemd as PID 1, for the test of the
# Ansible role (contrib/ansible/test/ci.sh). Ansible runs inside it with
# --connection local, as on a host that applies its own config.
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2

RUN apt-get update \
 && apt-get install --yes --no-install-recommends \
      systemd systemd-sysv dbus libpam-systemd \
      ansible-core python3-yaml \
      ca-certificates curl gzip tar \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --create-home --shell /bin/bash example-user

STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
