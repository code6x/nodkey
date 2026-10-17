# Changelog

## [0.2.0](https://github.com/code6x/nodkey/compare/v0.1.0...v0.2.0) (2026-10-17)


### Features

* install script and nodkey update ([#95](https://github.com/code6x/nodkey/issues/95)) ([cee02b8](https://github.com/code6x/nodkey/commit/cee02b80c3b5bf4a5b8c602bd9ec07ddc3cf4bd2))
* say when a newer release is out ([#96](https://github.com/code6x/nodkey/issues/96)) ([1ceee4d](https://github.com/code6x/nodkey/commit/1ceee4da456b56d41634cd6450d7a69622104e02))
* warn when the client and the broker run different versions ([#93](https://github.com/code6x/nodkey/issues/93)) ([a79bf9a](https://github.com/code6x/nodkey/commit/a79bf9a78dbe10179e46cc3839b0099989d6448e))


### Documentation

* install from the 0.1.0 release, and fetch the unit from its tag ([#85](https://github.com/code6x/nodkey/issues/85)) ([bbbdf59](https://github.com/code6x/nodkey/commit/bbbdf5981211cee09cfca6d50602d45642871ba8))
* keep the Bitwarden account that can read the secrets off agent machines ([#86](https://github.com/code6x/nodkey/issues/86)) ([24297af](https://github.com/code6x/nodkey/commit/24297afa65048dd2b8c02b047dfb7c3c8081dbf6))
* name Telegram Web as the client of the real test ([#75](https://github.com/code6x/nodkey/issues/75)) ([a9de078](https://github.com/code6x/nodkey/commit/a9de078fc50287880ac29bea16f062a15c91748a))

## 0.1.0 (2026-10-15)


### Features

* **approval:** approval core with rules, grants and limits ([#45](https://github.com/code6x/nodkey/issues/45)) ([fce7477](https://github.com/code6x/nodkey/commit/fce7477e5e0d2f6e421ad8c34e5ac38cb7237a47))
* **audit:** hash-chained audit log and audit verify ([#42](https://github.com/code6x/nodkey/issues/42)) ([7b2a09d](https://github.com/code6x/nodkey/commit/7b2a09ddc4f13bef6cb3e726b3d9c753a7ce58ea))
* **broker:** broker service and client API ([#56](https://github.com/code6x/nodkey/issues/56)) ([2674b08](https://github.com/code6x/nodkey/commit/2674b088043676cfc46183f2a07da8bb5a71dfcd))
* **broker:** nodkey broker command, start and stop order, systemd unit ([#60](https://github.com/code6x/nodkey/issues/60)) ([0129939](https://github.com/code6x/nodkey/commit/0129939b703fd8de4865f5cf1a65c7eb59d8a35b))
* **broker:** refuse variable names that make programs print or run the value ([#66](https://github.com/code6x/nodkey/issues/66)) ([db47e6e](https://github.com/code6x/nodkey/commit/db47e6e63ca51c3788de6aa5f988aa8edd493210))
* **claim:** make claimed text safe to show and mask secrets in it ([#41](https://github.com/code6x/nodkey/issues/41)) ([536ee24](https://github.com/code6x/nodkey/commit/536ee24fb8b8719e8473abc510d72deb77e48ff9))
* **config:** broker and client config, rules and strict known_hosts ([#38](https://github.com/code6x/nodkey/issues/38)) ([ec60c16](https://github.com/code6x/nodkey/commit/ec60c16db6740063eb5a716705992ef0075b0f71))
* **run:** nodkey run passes approved secrets to one command ([#58](https://github.com/code6x/nodkey/issues/58)) ([d2ba8f7](https://github.com/code6x/nodkey/commit/d2ba8f7d92094047bf5cb50b7105639dfde1e1bb))
* **ssh-agent:** nodkey ssh-agent forwards SSH logins to the broker ([#62](https://github.com/code6x/nodkey/issues/62)) ([e1c3f31](https://github.com/code6x/nodkey/commit/e1c3f3181f83bfd95e82011450a423592683c8a2))
* **ssh-grant:** one tap for SSH logins to a list of hosts ([#64](https://github.com/code6x/nodkey/issues/64)) ([ce433f3](https://github.com/code6x/nodkey/commit/ce433f314afb0dd656bc63eebc02bcaa7acd1fb7))
* **sshauth:** check session-bind and SSH login data, then sign ([#46](https://github.com/code6x/nodkey/issues/46)) ([613c813](https://github.com/code6x/nodkey/commit/613c813d3302e96652cee5d9425ea69747f5db3e))
* **store:** fetch secrets with bws and bw ([#50](https://github.com/code6x/nodkey/issues/50)) ([03bb431](https://github.com/code6x/nodkey/commit/03bb4313962fe16a50018545acb7b9ac8fe47666))
* **telegram:** Telegram approver with strict tap checks ([#49](https://github.com/code6x/nodkey/issues/49)) ([fdcaab0](https://github.com/code6x/nodkey/commit/fdcaab0584ec465294a5dc6fc45bd40b4b1e8092))
* **transport:** keygen and mutual TLS with pinned keys ([#44](https://github.com/code6x/nodkey/issues/44)) ([fca1caf](https://github.com/code6x/nodkey/commit/fca1caf2bf194ccbbc049a94759b143beb35fa6d))


### Bug Fixes

* **approval:** a refused notice is a limit, and does not use up max_per_day ([#52](https://github.com/code6x/nodkey/issues/52)) ([4f74782](https://github.com/code6x/nodkey/commit/4f74782a1bc6bea9fdc538bb34a886b1dfad8c3a))
* **broker:** send start alerts at the same time, so a stop stays clean ([#70](https://github.com/code6x/nodkey/issues/70)) ([131611b](https://github.com/code6x/nodkey/commit/131611b30c5129fb1c5ad7568e997023d18a5eef))
* **client:** a cancel always wins over a late answer; fix flaky tests ([#68](https://github.com/code6x/nodkey/issues/68)) ([9ff4a0e](https://github.com/code6x/nodkey/commit/9ff4a0e2253075e0d67da1ed35ac049fd460a2e3))
* **telegram:** keep edited-message reports and count a Deny on an edited message ([#54](https://github.com/code6x/nodkey/issues/54)) ([ed3a810](https://github.com/code6x/nodkey/commit/ed3a8102aaf1557c3c3d6a4396e3220a920e3648))


### Documentation

* design, threat model and repo rules ([#36](https://github.com/code6x/nodkey/issues/36)) ([8297fe8](https://github.com/code6x/nodkey/commit/8297fe82f74ed72bc3b40250aef89889e7d8938e)), closes [#1](https://github.com/code6x/nodkey/issues/1)
* record what the real Telegram test showed ([#74](https://github.com/code6x/nodkey/issues/74)) ([4d4a5e8](https://github.com/code6x/nodkey/commit/4d4a5e85126653776eb30092c4d89ba3b6f777b4))
* release App setup for a shared App, and its risk ([#43](https://github.com/code6x/nodkey/issues/43)) ([3be3fb7](https://github.com/code6x/nodkey/commit/3be3fb72214b590739c188ffa104a8cade5a1835))
* setup guide, quick start and manual Telegram test ([#71](https://github.com/code6x/nodkey/issues/71)) ([7899ee0](https://github.com/code6x/nodkey/commit/7899ee06a82b0c6eb2c9b5d77bad9e4fd6a2c4a5))
