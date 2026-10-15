// Package e2e is the end-to-end test of nodkey (DESIGN.md section 17,
// issue #15). It builds the nodkey binary, starts sshd in a Docker
// container, runs the real nodkey broker with a fake Telegram server, and
// logs in with the real ssh and git through nodkey ssh-agent. It needs
// Docker, so its test files have the build tag e2e, and a plain
// "go test ./..." does not run them:
//
//	go test -race -tags e2e ./test/e2e/...
package e2e
