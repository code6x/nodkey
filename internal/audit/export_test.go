package audit

// OpenWithoutDirCheck opens a log like Open, but without the check of the
// directories on the way. Tests in package audit_test use it: their files
// are below the system temporary directory, which everyone can write to,
// so the check would refuse them. TestOpenUsesTheRealDirCheck shows that
// Open itself makes the check.
func OpenWithoutDirCheck(path string, opts Options) (*Logger, error) {
	h := realHooks()
	h.checkDirs = func(string) error { return nil }
	return open(path, opts, h)
}
