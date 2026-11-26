# shellcheck shell=sh
# The shared part of the host instance of the pullgate recipe of nodkey
# (docs/setup.md, "The host instance"). host-check.sh, host-summary.sh,
# host-apply.sh, host-get-recipe.sh and setup.sh source it from their own
# directory. It is never run alone.
#
# The data repo of the host instance holds only data: host.yml. All code
# that reads it comes from a checked nodkey release: this recipe, and the
# Ansible recipe in /opt. pullgate runs each script with a fixed
# environment (PATH and the PULLGATE_ values only), so the NKH_ values
# below are the paths on a host. Only the tests set them.

NKH_NODKEY=${NKH_NODKEY:-/usr/local/bin/nodkey}
NKH_PULLGATE=${NKH_PULLGATE:-/usr/local/bin/pullgate}
NKH_OPT=${NKH_OPT:-/opt}
NKH_PGETC=${NKH_PGETC:-/etc/pullgate}
NKH_WORK=${NKH_WORK:-/var/lib/nodkey-host}
NKH_PYTHON=${NKH_PYTHON:-/usr/bin/python3}
NKH_ANSIBLE_PLAYBOOK=${NKH_ANSIBLE_PLAYBOOK:-ansible-playbook}
NKH_UNIT_FILE=${NKH_UNIT_FILE:-/etc/systemd/system/nodkey.service}
# Every file of the code must be owned by root. Only the tests, which do
# not run as root, set NKH_ROOT_UID: then their own user counts as root.
NKH_ROOT_UID=${NKH_ROOT_UID:-0}
# The releases of nodkey. The tests set a local server.
NKH_RELEASES=${NKH_RELEASES:-https://github.com/code6x/nodkey/releases/download}
NKH_VERSION_RE='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'

# The only broker config of the host. The role checks it with nodkey
# broker check of the new binary before a restart.
NKH_BROKER_CONFIG=/etc/nodkey/broker.toml

# The only files that the data repo may hold (docs/setup.md, "The data
# repo of the host instance"). Any other path fails the check: so a commit
# cannot push the summary out of the question with many files (pullgate
# cuts a long question).
NKH_ALLOWED_FILES='host.yml
README.md
schema/host.schema.json
.github/workflows/check.yml
.github/pull_request_template.md'

# nkh_root_only PATH...: each path is there, owned by root, no link, and
# nobody but root can write it.
nkh_root_only() {
	for p in "$@"; do
		if [ -L "$p" ] || [ ! -e "$p" ]; then
			echo "$p is missing, or is a link"
			return 1
		fi
		o=$(stat -c %u "$p")
		[ "$o" = 0 ] || [ "$o" = "$NKH_ROOT_UID" ] || {
			echo "$p is not owned by root"
			return 1
		}
		# The bits 020 and 002: a group or others may write.
		[ $((0$(stat -c %a "$p") & 022)) -eq 0 ] || {
			echo "$p can be written by a group or others"
			return 1
		}
	done
}

# nkh_dirs_of PATH prints PATH and each directory above it, up to /.
nkh_dirs_of() {
	p=$1
	while :; do
		printf '%s\n' "$p"
		[ "$p" != / ] || break
		p=${p%/*}
		[ -n "$p" ] || p=/
	done
}

# nkh_installed prints the version of the installed nodkey, X.Y.Z. It runs
# the binary only when only root can change it and each directory above it.
nkh_installed() {
	# shellcheck disable=SC2046 # the paths have no spaces: they are ours
	nkh_root_only $(nkh_dirs_of "$NKH_NODKEY") || return 1
	[ -f "$NKH_NODKEY" ] || {
		echo "$NKH_NODKEY is not a plain file"
		return 1
	}
	v=$("$NKH_NODKEY" version --offline 2>/dev/null | head -n 1) || v=
	v=${v#nodkey }
	if ! printf '%s\n' "$v" | grep -Eq "$NKH_VERSION_RE"; then
		echo "$NKH_NODKEY version does not name a release; install a release as root (docs/setup.md section 2)"
		return 1
	fi
	printf '%s\n' "$v"
}

# nkh_recipe VERSION prints the directory of the checked Ansible recipe of
# a release, made by host-get-recipe.sh. Only root may be able to change
# it, any file in it, and the directories above it.
nkh_recipe() {
	d=$NKH_OPT/nodkey-ansible-$1
	# shellcheck disable=SC2046
	nkh_root_only $(nkh_dirs_of "$d") >/dev/null || {
		echo "the Ansible recipe of nodkey $1 is not in $d (or not safe); as root, run: ${0%/*}/host-get-recipe.sh $1"
		return 1
	}
	bad=$(find "$d" \( -type l -o \( ! -user 0 ! -user "$NKH_ROOT_UID" \) -o -perm /022 \) -print 2>/dev/null | head -n 1)
	if [ -n "$bad" ]; then
		echo "$bad in the Ansible recipe can be changed by someone other than root, or is a link; as root, remove $d and run ${0%/*}/host-get-recipe.sh $1"
		return 1
	fi
	printf '%s\n' "$d"
}

# nkh_plain FILE: a plain file, no link.
nkh_plain() {
	if [ -L "$1" ] || [ ! -f "$1" ]; then
		echo "$1 is missing, or is not a plain file (a link is refused)"
		return 1
	fi
}

# nkh_check_data RECIPE INSTALLED FILE runs check-data of a recipe.
nkh_check_data() {
	"$NKH_PYTHON" -I "$1/check-data" --side broker --installed "$2" "$3"
}

# nkh_value FILE KEY prints the value of KEY of a data file that passed
# check-data: true or false for a bool, the text for a text, and an empty
# line when the key is not there.
nkh_value() {
	"$NKH_PYTHON" -I -c '
import sys, yaml
with open(sys.argv[1], encoding="utf-8") as f:
    d = yaml.safe_load(f)
v = d.get(sys.argv[2], "")
print(("true" if v else "false") if isinstance(v, bool) else v)
' "$1" "$2"
}

# nkh_version FILE prints nodkey_version of a data file that passed
# check-data, and fails when it is not X.Y.Z.
nkh_version() {
	v=$(nkh_value "$1" nodkey_version) || return 1
	printf '%s\n' "$v" | grep -Eq "$NKH_VERSION_RE" || {
		echo "nodkey_version is not X.Y.Z"
		return 1
	}
	printf '%s\n' "$v"
}

# nkh_only_allowed TREE: every file of TREE is in NKH_ALLOWED_FILES. It
# prints the first other path. A path with a newline is never allowed.
nkh_only_allowed() {
	nl='
'
	all=$(cd "$1" && find . -mindepth 1 ! -type d -print) || {
		echo "cannot list the files of $1"
		return 1
	}
	nlp=$(cd "$1" && find . -mindepth 1 -name "*$nl*" -print) || {
		echo "cannot list the files of $1"
		return 1
	}
	[ -z "$nlp" ] || {
		echo "a path in the repo has a newline in its name"
		return 1
	}
	links=$(cd "$1" && find . -mindepth 1 -type l -print) || {
		echo "cannot list the files of $1"
		return 1
	}
	[ -z "$links" ] || {
		echo "the repo holds a link; only plain files are allowed"
		return 1
	}
	bad=$(printf '%s\n' "$all" | sed 's|^\./||' | grep -Fvx "$NKH_ALLOWED_FILES" | head -n 1) || bad=
	if [ -n "$bad" ]; then
		# Only printable characters, and not too long: the owner reads it.
		bad=$(printf '%s' "$bad" | tr -cd '[:print:]' | cut -c1-80)
		printf '%s is not an allowed file of the data repo\n' "$bad"
		return 1
	fi
}

# nkh_changed_allowed FILE FIRST: every name in FILE, the changed paths
# that pullgate gives in PULLGATE_CHANGED_FILES, is in NKH_ALLOWED_FILES.
# pullgate writes the file read-only, each path ended by a NUL byte: all
# paths on the first apply, the changed ones after. It lists submodules
# too, which the tree of PULLGATE_TREE leaves out: so nkh_only_allowed
# alone cannot see them. The file is split on NUL only, so a name with a
# newline stays one name, and is refused.
# An empty list is real after the first apply: a commit with the same
# tree as the applied one changes no path. On the first apply it lists
# all paths, host.yml at least, so an empty list fails when FIRST is 1. A
# missing or unreadable file fails.
nkh_changed_allowed() {
	"$NKH_PYTHON" -I -c '
import sys
path, first, allowed = sys.argv[1], sys.argv[2], sys.argv[3].split("\n")
try:
    with open(path, "rb") as f:
        data = f.read()
except OSError as e:
    print("cannot read the list of changed files %s: %s" % (path, e.strerror))
    sys.exit(1)
if data and not data.endswith(b"\0"):
    print("the list of changed files does not end with a NUL byte")
    sys.exit(1)
names = data.split(b"\0")[:-1] if data else []
if not names and first == "1":
    print("the list of changed files is empty on the first apply")
    sys.exit(1)
for n in names:
    if n.decode("utf-8", "replace") not in allowed:
        # A character that cannot be printed shows as "?", and not too
        # long: the owner reads it.
        shown = "".join(c if c.isprintable() else "?" for c in n.decode("utf-8", "replace"))[:80]
        print("%s is not an allowed file of the data repo (a submodule counts too)" % shown)
        sys.exit(1)
' "$1" "$2" "$NKH_ALLOWED_FILES"
}

# nkh_statement_names JSON NAME FILE: the output of gh attestation verify
# --format json names NAME with the SHA-256 of FILE in a signed statement.
nkh_statement_names() {
	sum=$(sha256sum "$3") || return 1
	"$NKH_PYTHON" -I -c '
import json, sys
path, name, sha = sys.argv[1:4]
try:
    with open(path, encoding="utf-8") as f:
        results = json.load(f)
    ok = any(
        s.get("name") == name and s.get("digest", {}).get("sha256") == sha
        for r in results
        for s in r["verificationResult"]["statement"]["subject"]
    )
except Exception:
    ok = False
sys.exit(0 if ok else 1)
' "$1" "$2" "${sum%% *}"
}

# nkh_rules NEW [INSTALLED OLD]: the rules of the host on a data file that
# passed check-data. nodkey_broker_config must be NKH_BROKER_CONFIG. And
# when NEW names another version than the INSTALLED one, no other key may
# differ from OLD (the last applied file). Against the installed version,
# so a fix after a failed update (installed already) may change other keys.
nkh_rules() {
	"$NKH_PYTHON" -I -c '
import sys, yaml
def load(p):
    with open(p, encoding="utf-8") as f:
        return yaml.safe_load(f)
new = load(sys.argv[2])
if new.get("nodkey_broker_config") != sys.argv[1]:
    print("nodkey_broker_config must be %s on the broker host, so the new nodkey checks the config before a restart" % sys.argv[1])
    sys.exit(1)
if len(sys.argv) > 3 and new.get("nodkey_version") != sys.argv[3]:
    try:
        old = load(sys.argv[4])
    except Exception:
        print("the last applied host.yml cannot be read, so a new nodkey_version cannot be checked against it")
        sys.exit(1)
    if isinstance(old, dict):
        other = sorted(k for k in set(old) | set(new) if k != "nodkey_version" and old.get(k) != new.get(k))
        if other:
            print("nodkey_version changes, and so does %s: change nodkey_version alone, the other keys in a later commit" % ", ".join(other))
            sys.exit(1)
' "$NKH_BROKER_CONFIG" "$@"
}

# nkh_our_instances prints "NAME VERSION" for each pullgate instance whose
# record (NKH_PGETC/NAME.recipe, written by pullgate bootstrap --recipe and
# pullgate recipe use) says that it runs this recipe: code6x/nodkey,
# nodkey_X.Y.Z_pullgate.tar.gz. A record that cannot be read is an error.
nkh_our_instances() {
	"$NKH_PYTHON" -I -c '
import glob, os, re, sys, tomllib
for p in sorted(glob.glob(os.path.join(sys.argv[1], "*.recipe"))):
    name = os.path.basename(p)[: -len(".recipe")]
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", name):
        continue
    try:
        with open(p, "rb") as f:
            r = tomllib.load(f)
    except (OSError, ValueError) as e:
        print("cannot read the pullgate record %s: %s; run pullgate status %s" % (p, e, name))
        sys.exit(1)
    if r.get("repo") == "code6x/nodkey" and re.fullmatch(r"nodkey_[0-9]+\.[0-9]+\.[0-9]+_pullgate\.tar\.gz", str(r.get("file", ""))):
        v = str(r.get("version", ""))
        if not re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", v):
            print("the pullgate record %s has no version X.Y.Z; run pullgate status %s" % (p, name))
            sys.exit(1)
        print(name, v)
' "$NKH_PGETC"
}
