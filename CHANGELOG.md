# Changelog

## [0.4.0](https://github.com/code6x/nodkey/compare/v0.3.0...v0.4.0) (2026-10-31)


### Features

* --from is optional for a scheduled grant (default: now) ([#140](https://github.com/code6x/nodkey/issues/140)) ([1c6291e](https://github.com/code6x/nodkey/commit/1c6291e15e0f2fd46d6ce0dd564a466a09bed6ba))
* 1Password as a store (a read-only service account) ([#145](https://github.com/code6x/nodkey/issues/145)) ([ec4b728](https://github.com/code6x/nodkey/commit/ec4b728dc4c97a54ba0b9d71d2b32790cb1b20ac))
* approval through ntfy ([#147](https://github.com/code6x/nodkey/issues/147)) ([de53e2d](https://github.com/code6x/nodkey/commit/de53e2df995d86f219e30054407c3c83d36cde86))
* every error says what is wrong, where, and how to fix it ([#133](https://github.com/code6x/nodkey/issues/133)) ([22e083c](https://github.com/code6x/nodkey/commit/22e083cb8a55114c66e94f00566b88f160050463))
* Infisical as a store (a read-only machine identity) ([#148](https://github.com/code6x/nodkey/issues/148)) ([5c230fd](https://github.com/code6x/nodkey/commit/5c230fd9f4747876b220a4c5768018285badec97))
* nodkey doctor, a read-only check of the setup ([#136](https://github.com/code6x/nodkey/issues/136)) ([d256524](https://github.com/code6x/nodkey/commit/d256524a1b7cfc7739f2c9cbef535f6bdd375e03))
* nodkey try, a trial on one machine (stage 1 of [#125](https://github.com/code6x/nodkey/issues/125)) ([#143](https://github.com/code6x/nodkey/issues/143)) ([371cd6d](https://github.com/code6x/nodkey/commit/371cd6d6b66e67a93e63924583826ebd86e4ebf0))


### Bug Fixes

* after a standing grant, nodkey preapprove names the window and the uses in each window ([#141](https://github.com/code6x/nodkey/issues/141)) ([9b79688](https://github.com/code6x/nodkey/commit/9b796883f4ab3ee723a8b770f84e83a02c57e5d4))
* nodkey changes says when there is no security fix ([#142](https://github.com/code6x/nodkey/issues/142)) ([d25e11c](https://github.com/code6x/nodkey/commit/d25e11c6d62d613f8b3f001d83d2e00cc4ac9555))

## [0.3.0](https://github.com/code6x/nodkey/compare/v0.2.0...v0.3.0) (2026-10-30)


### Features

* flag security releases in nodkey version, the broker's notices and the answers to clients ([#122](https://github.com/code6x/nodkey/issues/122)) ([1c3cdca](https://github.com/code6x/nodkey/commit/1c3cdcab6610af9050ef7fd0471dcdccc107b75a))
* nodkey changes and nodkey update --notes; a host on nodkey 0.2.0 has no --notes, so update it once first ([#122](https://github.com/code6x/nodkey/issues/122)) ([1c3cdca](https://github.com/code6x/nodkey/commit/1c3cdcab6610af9050ef7fd0471dcdccc107b75a))
* revoke button and notices for scheduled grants (part 2 of [#108](https://github.com/code6x/nodkey/issues/108)) ([#114](https://github.com/code6x/nodkey/issues/114)) ([89d07e9](https://github.com/code6x/nodkey/commit/89d07e9ca58a262d4cd27022d564c2085c0b6ca4))
* scheduled grants with nodkey preapprove (part 1 of [#108](https://github.com/code6x/nodkey/issues/108)) ([#112](https://github.com/code6x/nodkey/issues/112)) ([102d0bf](https://github.com/code6x/nodkey/commit/102d0bf9e495f1973b9af4ba318abd977759873c))
* standing grants (part 1 of [#110](https://github.com/code6x/nodkey/issues/110)) ([#115](https://github.com/code6x/nodkey/issues/115)) ([bfd9036](https://github.com/code6x/nodkey/commit/bfd9036e4a36ffa4e5bed812410c3820dc7db084))
* standing grants (part 2 of [#110](https://github.com/code6x/nodkey/issues/110)) ([#116](https://github.com/code6x/nodkey/issues/116)) ([3442a2a](https://github.com/code6x/nodkey/commit/3442a2a14f2e8df3a0250cc1421a74fe3d691130))


### Bug Fixes

* nodkey --version and nodkey help COMMAND ([#129](https://github.com/code6x/nodkey/issues/129)) ([d3e033f](https://github.com/code6x/nodkey/commit/d3e033f7923f1373b35d631f0a79fe6048101431))


### Documentation

* mark what is new in 0.3.0, and stop naming 0.1.0 as the latest release ([#130](https://github.com/code6x/nodkey/issues/130)) ([3b9e4c6](https://github.com/code6x/nodkey/commit/3b9e4c6ced3643d8aec1672785d83769a5bf8e7a))

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
