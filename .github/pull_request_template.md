## What and why

<!-- What this pull request changes, and why. Name the issue: "Fixes #N". -->

## Behavior for callers

<!--
Answer with one word: yes or no. The check fails until you do.

"Behavior" means: defaults, the content of stdout and stderr, exit codes,
signals, which process runs the command, the meaning of the config, and
time limits. A change to an existing test under test/contract/ is
always "yes" (a new test is not).

For "yes":
- put "!" after the type or the scope of the title, such as
  "feat(run)!: ...";
- add a section "## Updating from X" to docs/updating.md: who is
  affected, what to do, and a command that shows the new way.

See docs/releasing.md, "Changes in behavior for callers".
-->

Changes behavior for existing callers: yes or no

## Tests

<!-- How you tested it, also the deny paths. -->

## Checklist

- [ ] The title follows [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:` ...).
- [ ] Tests cover the deny paths, not only the happy path.
- [ ] The docs are updated: DESIGN.md and THREAT-MODEL.md if a message, a check or the path of a value changes; `docs/` if a command or the config changes.
- [ ] The security review is done ([AGENTS.md](https://github.com/code6x/nodkey/blob/main/AGENTS.md#rules)).
- [ ] No private data: no real host name, address, token, key or private name.
