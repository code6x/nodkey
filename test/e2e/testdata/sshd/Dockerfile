# The SSH targets of the end-to-end test of nodkey (test/e2e): OpenSSH's
# sshd and git, from Debian. The image holds no key: the host keys that
# the openssh-server package makes are removed. Before the container
# starts, the test copies its own throwaway keys to /e2e (see
# entrypoint.sh). The same image runs the root-only test of
# internal/client.
#
# The base image is pinned by the digest of its multi-platform index.
FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587

# deploy and ops are the remote users. Their password is "*": no password
# works, and the account is not locked, so sshd lets the key in (sshd
# refuses a locked account when UsePAM is off). The bare repository is
# the target of git over SSH.
RUN apt-get update \
 && apt-get install --yes --no-install-recommends openssh-server git \
 && rm -rf /var/lib/apt/lists/* /etc/ssh/ssh_host_* \
 && useradd --create-home --shell /bin/sh --password '*' deploy \
 && useradd --create-home --shell /bin/sh --password '*' ops \
 && su deploy -c 'git init --quiet --bare --initial-branch=main /home/deploy/repo.git' \
 && mkdir -p /run/sshd /e2e /etc/ssh/authorized_keys

COPY sshd_config /etc/ssh/sshd_config.e2e
COPY entrypoint.sh /usr/local/bin/e2e-entrypoint.sh
ENTRYPOINT ["/bin/sh", "/usr/local/bin/e2e-entrypoint.sh"]
