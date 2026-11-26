#!/bin/sh
# recipe.sh checks the pullgate recipe of a release, the file
# nodkey_VERSION_pullgate.tar.gz, as pullgate will read it (pullgate's
# README, "Recipes"), so a broken recipe never goes out:
#
#   sh scripts/release-check/recipe.sh TARBALL VERSION
#
#   - only plain files, at the root, with clean names; no link, no
#     folder, no setuid, setgid or sticky bit;
#   - the manifest pullgate-recipe.toml: format 1, the version VERSION,
#     and the two instances nodkey-broker and nodkey-host, each with its
#     template and its setup in the tarball;
#   - each template: only the placeholders of pullgate, none of the keys
#     that pullgate sets itself, and each program of the recipe that it
#     names (@RECIPE_DIR@/NAME) is in the tarball, with an execute bit.
#
# The Release check workflow and scripts/verify-release.sh run it. It
# needs python3 (3.11 or newer). It prints "ok: ..." or "FAILED: ...",
# and exits with 1 when the recipe is not good, or 2 on a usage error.
set -eu

[ "$#" -eq 2 ] || {
	echo "recipe.sh: give TARBALL VERSION, such as: sh scripts/release-check/recipe.sh dist/nodkey_1.2.3_pullgate.tar.gz 1.2.3 (exit 2)" >&2
	exit 2
}
[ -f "$1" ] || {
	echo "recipe.sh: $1 is not a file; give the pullgate tarball of the release (exit 2)" >&2
	exit 2
}
printf '%s\n' "$2" | grep -Eqx '(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)' || {
	echo "recipe.sh: the version '$2' is not X.Y.Z (exit 2)" >&2
	exit 2
}

python3 -I - "$1" "$2" <<'PY'
import re, sys, tarfile, tomllib

path, version = sys.argv[1], sys.argv[2]
problems = []
NAME = re.compile(r"[A-Za-z0-9_.+-]+")
PLACEHOLDERS = {"@NAME@", "@HOST@", "@REPO_URL@", "@BRANCH@", "@RECIPE_DIR@"}
INSTANCES = {"nodkey-broker", "nodkey-host"}

try:
    tf = tarfile.open(path, "r:gz")
    members = tf.getmembers()
except (OSError, tarfile.TarError) as e:
    print("FAILED: recipe: cannot read %s: %s" % (path, e))
    sys.exit(1)

files = {}
for m in members:
    if not m.isfile():
        problems.append("%s is not a plain file" % m.name)
        continue
    if not NAME.fullmatch(m.name) or m.name.startswith("."):
        problems.append("%r is not a clean name at the root of the tarball" % m.name)
        continue
    if m.mode & 0o7000:
        problems.append("%s has a setuid, setgid or sticky bit" % m.name)
    files[m.name] = m

def text(name):
    return tf.extractfile(files[name]).read().decode("utf-8")

manifest = {}
if "pullgate-recipe.toml" not in files:
    problems.append("there is no pullgate-recipe.toml")
else:
    try:
        manifest = tomllib.loads(text("pullgate-recipe.toml"))
    except (ValueError, UnicodeDecodeError) as e:
        problems.append("pullgate-recipe.toml is not TOML: %s" % e)
if manifest:
    unknown = set(manifest) - {"format", "version", "instance"}
    if unknown:
        problems.append("pullgate-recipe.toml has unknown keys: %s" % ", ".join(sorted(unknown)))
    if manifest.get("format") != 1:
        problems.append("pullgate-recipe.toml: format is not 1")
    if manifest.get("version") != version:
        problems.append("pullgate-recipe.toml: version is %r, not %r" % (manifest.get("version"), version))
    insts = manifest.get("instance", [])
    names = [i.get("name") for i in insts]
    if sorted(names) != sorted(INSTANCES):
        problems.append("pullgate-recipe.toml: the instances are %s, not nodkey-broker and nodkey-host" % names)
    for inst in insts:
        unknown = set(inst) - {"name", "config", "requires", "setup"}
        if unknown:
            problems.append("instance %s: unknown keys: %s" % (inst.get("name"), ", ".join(sorted(unknown))))
        cfg = inst.get("config", "")
        if cfg not in files:
            problems.append("instance %s: the template %r is not in the tarball" % (inst.get("name"), cfg))
            continue
        setup = inst.get("setup", [])
        if not setup or setup[0] not in files or not files[setup[0]].mode & 0o100:
            problems.append("instance %s: the setup %r is not a program of the tarball" % (inst.get("name"), setup))
        tmpl = text(cfg)
        for p in set(re.findall(r"@[A-Z_]+@", tmpl)) - PLACEHOLDERS:
            problems.append("%s: the placeholder %s is not one of pullgate" % (cfg, p))
        try:
            filled = tomllib.loads(tmpl.replace("@", "x"))
        except ValueError as e:
            problems.append("%s is not TOML: %s" % (cfg, e))
            continue
        for key in ("mode", "listener"):
            if key in filled:
                problems.append("%s sets %s, which pullgate sets itself" % (cfg, key))
        for key in ("deploy_key", "known_hosts"):
            if key in filled.get("repo", {}):
                problems.append("%s sets [repo] %s, which pullgate sets itself" % (cfg, key))
        if "check_user" in filled.get("commands", {}):
            problems.append("%s sets [commands] check_user, which pullgate sets itself" % cfg)
        for prog in re.findall(r"@RECIPE_DIR@/([A-Za-z0-9_.+-]+)", tmpl):
            if prog not in files or not files[prog].mode & 0o100:
                problems.append("%s names @RECIPE_DIR@/%s, which is not a program of the tarball" % (cfg, prog))

if problems:
    for p in problems:
        print("FAILED: recipe: %s" % p)
    sys.exit(1)
print("ok: recipe: %s is a pullgate recipe of version %s with the instances nodkey-broker and nodkey-host" % (path.rsplit("/", 1)[-1], version))
PY
