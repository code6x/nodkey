# Security policy

nodkey is a security tool. Security reports are important to us.

## Report a problem

Please do **not** open a public issue for a security problem.

Report it privately on GitHub: open the
[Security tab](https://github.com/code6x/nodkey/security) and choose
**Report a vulnerability**. Tell us what you found, how to repeat it, and
what an attacker could do with it.

We will answer within 7 days.

## What counts

Anything that breaks a promise in
[THREAT-MODEL.md section 4](THREAT-MODEL.md#4-what-nodkey-promises), or a
protection described in
[section 6](THREAT-MODEL.md#6-threats-and-answers), for example:

- the agent gets a secret or an SSH signature without an approval;
- a secret value shows up in a log, an error, the audit log or a Telegram
  message;
- a tap approves a different request than the one shown;
- the broker signs data that is not an SSH login for the shown host.

The limits in
[THREAT-MODEL.md section 5](THREAT-MODEL.md#5-what-nodkey-does-not-promise)
are known and are not bugs, but ideas to make them smaller are welcome as
normal issues.

## Supported versions

Until 1.0, only the
[latest release](https://github.com/code6x/nodkey/releases/latest) gets
fixes. To get a fix, upgrade to the newest release
([docs/setup.md section 13](docs/setup.md#a-new-version-of-nodkey)).
