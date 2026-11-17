# shellcheck shell=sh
# The shared part of the pullgate recipe of nodkey (docs/setup.md, "Change
# the config from git with pullgate"). The four scripts source it from
# their own directory. It is never run alone.
#
# The scripts are installed on the broker host from a release of nodkey,
# never run from the tree of a config repo. pullgate runs each one with an
# empty environment, so the NKP_ values below are the defaults on a host.
# Tests set them.

NKP_ETC=${NKP_ETC:-/etc/nodkey}
NKP_UNIT=${NKP_UNIT:-nodkey.service}
NKP_CREDENTIALS=${NKP_CREDENTIALS:-/etc/nodkey/credentials}
NKP_HEALTH_TIMEOUT=${NKP_HEALTH_TIMEOUT:-60}

# The two files of the config, in the repo and in NKP_ETC.
NKP_FILES="broker.toml known_hosts"

# nkp_files_ok DIR: both files are in DIR, as plain files. A symlink is
# refused, even one to a plain file.
nkp_files_ok() {
	for f in $NKP_FILES; do
		if [ -L "$1/$f" ] || [ ! -f "$1/$f" ]; then
			echo "$1/$f is missing, or is not a plain file (a symlink is refused)"
			return 1
		fi
	done
}

# nkp_action OLD NEW prints "reload" when the broker can take every change
# from the config in the directory OLD to the one in NEW with a reload,
# and "restart" when it cannot. This is the one place that decides it.
#
# It reads the full list of nodkey broker config-diff. A reload can change
# the clients, the secrets, the projects, the SSH keys and the host keys
# in known_hosts (DESIGN.md section 14, "Reload"). So each line must name
# one of them; any other line, or a failed compare, means a restart. A new
# SSH key, or a key with another file, also needs a restart: systemd
# loads the credentials only at the start.
nkp_action() {
	nkp_diff=$(nodkey broker config-diff "$1" "$2" 2>/dev/null)
	case $? in
	0)
		# The same meaning. But the reload compares [logins.*] by its exact
		# form, so a new order of a list there needs a restart.
		if ! cmp -s "$1/broker.toml" "$2/broker.toml" && LC_ALL=C grep -q '^[[:space:]]*\[[[:space:]]*logins\.' "$2/broker.toml"; then
			echo restart
		else
			echo reload
		fi
		return 0
		;;
	1) ;;
	*)
		echo restart
		return 0
		;;
	esac
	if printf '%s\n' "$nkp_diff" | LC_ALL=C grep -Eq '^(⚠ |  )SSH key ".*": (new key|file changed)'; then
		echo restart
	elif printf '%s\n' "$nkp_diff" |
		LC_ALL=C grep -Evq '^(⚠ |  )((client|secret|project|SSH key) "|known_hosts: (new host|host) ")'; then
		echo restart
	else
		echo reload
	fi
}

# nkp_host_parts LIVE NEW prints the changes from the live config in the
# directory LIVE to the one in NEW that only a person on the host may make,
# and fails when there is one, or when the compare fails. These parts are
# the gate itself: the approval channel and its token, the TLS key, the
# listen address, the paths of known_hosts and the audit log, and the
# stores with their programs and credentials. A commit that changes them
# could send a credential to another server, or approve its own requests.
nkp_host_parts() {
	nkp_diff=$(nodkey broker config-diff "$1" "$2" 2>&1)
	case $? in
	0) return 0 ;;
	1) ;;
	*)
		printf '%s
' "$nkp_diff"
		return 1
		;;
	esac
	! printf '%s
' "$nkp_diff" | LC_ALL=C grep -E \
		'^⚠ ((listen|tls_key|audit_log|known_hosts): changed|\[(telegram|ntfy)\]|the approval channel|store ")'
}

# nkp_top_key FILE KEY prints the string value of the top-level KEY of the
# TOML file FILE, such as audit_log. It reads only a plain line,
# KEY = "VALUE" or KEY = 'VALUE' with an optional comment, before the
# first section. Anything else, or the key twice, is a failure.
nkp_top_key() {
	awk -v key="$2" '
		/^[ \t]*\[/ { exit }
		{
			line = $0
			sub(/^[ \t]+/, "", line)
			if (index(line, key) != 1) next
			rest = substr(line, length(key) + 1)
			if (rest !~ /^[ \t]*=/) next
			sub(/^[ \t]*=[ \t]*/, "", rest)
			if (match(rest, /^"[^"\\]*"/) || match(rest, /^\047[^\047]*\047/)) {
				val = substr(rest, 2, RLENGTH - 2)
				if (substr(rest, RLENGTH + 1) ~ /^[ \t]*(#.*)?$/) { n++; next }
			}
			bad = 1
		}
		END { if (bad || n != 1) exit 1; print val }
	' "$1"
}

# nkp_run ACTION reloads or restarts the broker.
nkp_run() {
	case $1 in
	reload) nodkey broker reload --config "$NKP_ETC/broker.toml" ;;
	restart) systemctl restart "$NKP_UNIT" ;;
	*) return 1 ;;
	esac
}
