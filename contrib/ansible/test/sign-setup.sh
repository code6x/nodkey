#!/bin/sh
# sign-setup.sh runs as root in the test container of ci.sh, after the
# role made the SSH key deploy. It sets up what a broker needs to sign
# with that key, as docs/setup.md does by hand, but for a test:
#
#   - fake-ntfy.py, a fake ntfy server on 127.0.0.1:8443, with a test CA
#     that only the broker trusts (SSL_CERT_FILE in a drop-in);
#   - sshd on 127.0.0.1, with the account deploy, which accepts
#     /etc/nodkey/ssh-deploy.pub;
#   - the broker's TLS key, its ntfy token and broker.toml, and an empty
#     credential for each other line of the stock unit;
#   - the client of the account example-user, with nodkey ssh-agent.
#
# Then it starts the broker. The keys and tokens are made here, for the
# test only.
#
#   sh /opt/sign-setup.sh

set -eu

creds=/etc/nodkey/credentials
setup=/run/nodkey-test
install -d -m 0700 "$setup"

# The test CA and the certificate of the fake ntfy server.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
	-subj /CN=nodkey-test-ca -keyout "$setup/ca.key" -out /etc/nodkey/test-ca.pem 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=localhost \
	-keyout "$setup/ntfy.key" -out "$setup/ntfy.csr" 2>/dev/null
printf 'subjectAltName=DNS:localhost\n' >"$setup/ext"
openssl x509 -req -in "$setup/ntfy.csr" -CA /etc/nodkey/test-ca.pem -CAkey "$setup/ca.key" \
	-CAcreateserial -days 2 -extfile "$setup/ext" -out "$setup/ntfy.pem" 2>/dev/null
systemd-run --quiet --unit fake-ntfy python3 /opt/fake-ntfy.py \
	"$setup/ntfy.pem" "$setup/ntfy.key" 8443 nodkey-answers

# sshd and the account deploy.
ssh-keygen -A >/dev/null
useradd --create-home --shell /bin/sh deploy
install -d -o deploy -g deploy -m 0700 /home/deploy/.ssh
install -o deploy -g deploy -m 0600 /etc/nodkey/ssh-deploy.pub /home/deploy/.ssh/authorized_keys
printf 'ListenAddress 127.0.0.1\nPasswordAuthentication no\n' >/etc/ssh/sshd_config.d/test.conf
systemctl start ssh.service
printf 'localhost %s\n' "$(cut -d' ' -f1,2 /etc/ssh/ssh_host_ed25519_key.pub)" >/etc/nodkey/known_hosts
chmod 0644 /etc/nodkey/known_hosts

# The client of example-user.
home=/home/example-user
runuser -u example-user -- install -d -m 0700 "$home/.config" "$home/.config/nodkey" "$home/run"
client_pin=$(runuser -u example-user -- /usr/local/bin/nodkey keygen --out "$home/.config/nodkey/client.key")

# The broker.
broker_pin=$(/usr/local/bin/nodkey keygen --out "$setup/broker-tls-key")
systemd-creds encrypt --with-key=host --name=broker-tls-key "$setup/broker-tls-key" "$creds/broker-tls-key.cred" 2>/dev/null
rm -f "$setup/broker-tls-key"
printf 'tk_test%s' "$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')" |
	systemd-creds encrypt --with-key=host --name=ntfy-token - "$creds/ntfy-token.cred" 2>/dev/null
# The other lines of the stock unit need a file each. ssh-deploy is the
# key that the role made.
for name in telegram-token bws-token bws-token-backup bw-master-password op-token infisical-secret; do
	printf 'unused' | systemd-creds encrypt --with-key=host --name="$name" - "$creds/$name.cred" 2>/dev/null
done
chmod 0600 "$creds"/*.cred

cat >/etc/nodkey/broker.toml <<EOF
listen = "127.0.0.1:7743"
tls_key = "\${CREDENTIALS_DIRECTORY}/broker-tls-key"
audit_log = "/var/lib/nodkey/audit.jsonl"
known_hosts = "/etc/nodkey/known_hosts"

[ntfy]
server = "https://localhost:8443"
request_topic = "nodkey-requests"
answer_topic = "nodkey-answers"
token_file = "\${CREDENTIALS_DIRECTORY}/ntfy-token"
timeout = "60s"
ssh_timeout = "60s"

[client.laptop]
pin = "$client_pin"

[key.deploy]
file = "\${CREDENTIALS_DIRECTORY}/ssh-deploy"
clients = ["laptop"]
ask = "always"
EOF
chmod 0644 /etc/nodkey/broker.toml

# Only the broker trusts the test CA. The owner's own drop-in: it sorts
# before ssh-keys.conf of the role.
install -d -m 0755 /etc/systemd/system/nodkey.service.d
printf '[Service]\nEnvironment=SSL_CERT_FILE=/etc/nodkey/test-ca.pem\n' >/etc/systemd/system/nodkey.service.d/local.conf
systemctl daemon-reload
systemctl start nodkey.service

cat >"$home/.config/nodkey/client.toml" <<EOF
broker = "127.0.0.1:7743"
broker_pin = "$broker_pin"
tls_key = "~/.config/nodkey/client.key"
EOF
chown example-user:example-user "$home/.config/nodkey/client.toml"
systemd-run --quiet --unit nodkey-test-agent --uid=example-user \
	--setenv=HOME="$home" --setenv=XDG_RUNTIME_DIR="$home/run" \
	/usr/local/bin/nodkey ssh-agent
for _ in 1 2 3 4 5 6 7 8 9 10; do
	[ -S "$home/run/nodkey/agent.sock" ] && break
	sleep 1
done
[ -S "$home/run/nodkey/agent.sock" ] || {
	echo 'sign-setup.sh: nodkey ssh-agent did not start (exit 1)' >&2
	exit 1
}
