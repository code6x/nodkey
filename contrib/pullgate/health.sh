#!/bin/sh
# The health check of the pullgate recipe of nodkey. pullgate runs it as
# root after apply.sh. It waits until the broker itself says that it runs
# the config in $NKP_ETC/broker.toml, or until the time is up. A failure
# starts the rollback.
#
# The answer is the broker's status file, reload-status.json next to the
# audit log (DESIGN.md section 14, "Reload"). The broker writes it when it
# is ready and listens, and after each reload. It must name the process
# that systemd runs now, a result of "started" or "loaded", and the
# SHA-256 of the config file.
set -u
. "${0%/*}/lib.sh"

audit=$(nkp_top_key "$NKP_ETC/broker.toml" audit_log) || {
	echo "nodkey health: cannot read audit_log = \"...\" at the top of $NKP_ETC/broker.toml; write it as one plain line"
	exit 1
}
status=${audit%/*}/reload-status.json

# once checks the broker one time. It prints what it found.
once() {
	if ! systemctl is-active --quiet "$NKP_UNIT"; then
		echo "$NKP_UNIT does not run"
		return 1
	fi
	pid=$(systemctl show -P MainPID "$NKP_UNIT")
	want=$(sha256sum <"$NKP_ETC/broker.toml") || return 1
	want=${want%% *}
	if [ ! -f "$status" ]; then
		echo "$status is missing"
		return 1
	fi
	line=$(head -c 65536 "$status" | sed -n -E \
		's/^\{"pid":([0-9]+),"start":[0-9]+,"reloads":[0-9]+,"result":"(started|loaded)","config_sha256":"([0-9a-f]{64})".*/\1 \3/p')
	if [ -z "$line" ]; then
		echo "$status says no good start or reload"
		return 1
	fi
	got_pid=${line% *}
	got_sha=${line#* }
	if [ "$got_pid" != "$pid" ]; then
		echo "$status is from process $got_pid, but $NKP_UNIT runs process $pid"
		return 1
	fi
	if [ "$got_sha" != "$want" ]; then
		echo "the broker runs another config (sha256 $got_sha), not $NKP_ETC/broker.toml (sha256 $want)"
		return 1
	fi
	echo "the broker (process $pid) runs $NKP_ETC/broker.toml (sha256 $want)"
}

end=$(($(date +%s) + NKP_HEALTH_TIMEOUT))
while :; do
	if why=$(once); then
		echo "nodkey health: $why"
		exit 0
	fi
	if [ "$(date +%s)" -ge "$end" ]; then
		echo "nodkey health: no good answer in ${NKP_HEALTH_TIMEOUT}s: $why; read journalctl -u $NKP_UNIT"
		exit 1
	fi
	sleep 1
done
