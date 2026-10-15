#!/bin/sh
# The entrypoint of the SSH targets of the end-to-end test of nodkey.
#
# Before the container starts, the test copies these files to /e2e:
#   authorized_keys  the public half of the broker's SSH key
#   targets          one line for each target: its name and its port
#   NAME.key         the host key of the target NAME, such as web-1.key
#
# Each target is an sshd of its own, with its own port and host key. Its
# log lines go to the container's log, each with the name of the target.
# The container ends on its own after $1 seconds (default 900), in case
# the test could not remove it.
#
# The container has only the capabilities that sshd needs, so this script
# writes only files of root: docker cp makes the files in /e2e files of
# root too.
set -eu

for user in deploy ops; do
	install -m 644 /e2e/authorized_keys "/etc/ssh/authorized_keys/$user"
done

while read -r name port; do
	install -m 600 "/e2e/$name.key" "/etc/ssh/e2e_$name.key"
	(/usr/sbin/sshd -D -e -f /etc/ssh/sshd_config.e2e -p "$port" -h "/etc/ssh/e2e_$name.key" 2>&1 |
		sed -u "s/^/$name: /") &
done </e2e/targets

exec sleep "${1:-900}"
