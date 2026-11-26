#!/bin/sh
# The summary of the host instance of the pullgate recipe of nodkey
# (docs/setup.md, "The host instance"). pullgate runs it as the check
# user, after the check passed, and puts its output into the question.
# The lines with ⚠ come first: read them before you tap. pullgate puts the
# commits and the files before this output, and cuts a long question:
# never tap a question that says that lines are left out.
set -u
. "${0%/*}/host-lib.sh"

new=${PULLGATE_TREE:?PULLGATE_TREE is not set; pullgate sets it}
old=${PULLGATE_OLD_TREE:-}
data=$new/host.yml
oldfile=
if [ -n "$old" ] && [ -f "$old/host.yml" ] && [ ! -L "$old/host.yml" ]; then
	oldfile=$old/host.yml
fi

inst=$(nkh_installed) || {
	echo "$inst"
	exit 1
}
want=$(nkh_version "$data") || {
	echo "$want"
	exit 1
}
restart=$(nkh_value "$data" nodkey_restart) || exit 1
# The version of the last applied commit. It differs from the installed
# one when an apply with a new version failed after nodkey update: then
# the role still has a restart due.
prev=$inst
if [ -n "$oldfile" ]; then
	prev=$(nkh_version "$oldfile" 2>/dev/null) || prev=$inst
fi
# The unit of the Ansible recipe of this version; a different one on the
# host is replaced, and that restarts the broker too. Only known when the
# recipe is here already.
unit=same
rec=$(nkh_recipe "$want" 2>/dev/null) &&
	! cmp -s "$rec/roles/nodkey/files/nodkey.service" "$NKH_UNIT_FILE" && unit=new

# The SSH keys of the broker: a change of nodkey_ssh_keys or
# nodkey_ssh_key_with_key rewrites the drop-in of the unit, so the role
# restarts the broker; a new name also makes a new key on the broker.
# On the first apply, a list that is not empty counts as a change. The
# names are safe to show: check-data allows only [a-z0-9-].
# It prints "same" or "changed", then the new names, if any.
keys=$("$NKH_PYTHON" -I -c '
import sys, yaml
def load(p):
    with open(p, encoding="utf-8") as f:
        d = yaml.safe_load(f)
    return d if isinstance(d, dict) else {}
new = load(sys.argv[1])
old = load(sys.argv[2]) if sys.argv[2] else None
nk = new.get("nodkey_ssh_keys") or []
if old is None:
    print("changed" if nk else "same")
    ok = set()
else:
    ok = {k.get("name") for k in (old.get("nodkey_ssh_keys") or [])}
    same = (old.get("nodkey_ssh_keys") or []) == nk and old.get("nodkey_ssh_key_with_key") == new.get("nodkey_ssh_key_with_key")
    print("same" if same else "changed")
print(" ".join(k.get("name", "") for k in nk if k.get("name") not in ok))
' "$data" "$oldfile") || exit 1
keys_changed=${keys%%
*}
keys_new=$(printf '%s\n' "$keys" | sed -n 2p)

# A held commit: its apply stopped part way. The role may have a restart
# due, and the next apply does it. So this line comes first, on every
# commit while a commit is held.
if [ -n "${PULLGATE_FAILED_SHA:-}" ]; then
	echo "⚠ the last apply failed part way: a broker restart may be due"
fi
if [ "$want" != "$inst" ] || [ "$prev" != "$inst" ] || [ "$unit" = new ] || [ "$keys_changed" = changed ]; then
	if [ "$restart" = false ]; then
		echo "⚠ a broker restart is due, but nodkey_restart is false: the broker runs as before until you restart it by hand (all grants end then)"
	else
		echo "⚠ broker restart: all grants end"
	fi
fi
if [ -n "$keys_new" ]; then
	echo "⚠ new SSH keys made on the broker: $keys_new"
fi
if [ "$unit" = new ] && [ "$want" = "$inst" ]; then
	echo "$NKH_UNIT_FILE is not the unit of nodkey $want: Apply installs it."
fi
if [ "$prev" != "$inst" ]; then
	echo "The last apply did not finish after nodkey $inst was installed: a broker restart may be due."
fi
if [ "$want" != "$inst" ]; then
	echo "nodkey $inst → $want: Apply gets the recipes of $want and checks them (SHA-256, build attestation),"
	echo "then its playbook runs nodkey update --version $want with the installed nodkey,"
	echo "and only then both pullgate instances move to the recipe of $want."
fi

# The changed keys and values. check-data allows only the characters of a
# version, a path or a bool, so a value is safe to show.
"$NKH_PYTHON" -I -c '
import sys, yaml
with open(sys.argv[1], encoding="utf-8") as f:
    new = yaml.safe_load(f)
old = None
if sys.argv[2]:
    with open(sys.argv[2], encoding="utf-8") as f:
        old = yaml.safe_load(f)
def show(v):
    if v is None:
        return "(not set)"
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v) if v != "" else "\"\""
if old is None or not isinstance(old, dict):
    print("First apply: the values in host.yml.")
    for k in sorted(new):
        print("  %s: %s" % (k, show(new[k])))
    sys.exit(0)
changed = [k for k in sorted(set(old) | set(new)) if old.get(k) != new.get(k)]
if not changed:
    print("host.yml: no key changed.")
for k in changed:
    print("  %s: %s → %s" % (k, show(old.get(k)), show(new.get(k))))
' "$data" "$oldfile" || exit 1

echo "Apply runs broker-host.yml of the nodkey $want Ansible recipe as root, with --connection local."
