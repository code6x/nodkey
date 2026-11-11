package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// noFollow makes an open fail on a symbolic link.
const noFollow = syscall.O_NOFOLLOW

// procStart returns the start time of the process pid, field 22 of
// /proc/PID/stat, in clock ticks after the boot.
func procStart(pid int) (uint64, error) {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, err
	}
	// The second field, the name, is in parentheses and may hold spaces;
	// the fields after the last ")" have none.
	s := string(data)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return 0, errors.New("the stat file of the process has no name field")
	}
	f := strings.Fields(s[i+1:])
	// f[0] is field 3; field 22 is f[19].
	if len(f) < 20 {
		return 0, errors.New("the stat file of the process is too short")
	}
	return strconv.ParseUint(f[19], 10, 64)
}

// readReloadStatus reads the status file at path. It must be a regular
// file, not a symbolic link, and not owned by root: the broker never runs
// as root. It returns the owner too.
func readReloadStatus(path string) (reloadStatus, uint32, error) {
	var st reloadStatus
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) //nolint:gosec // G304: the status file next to the audit log of the config.
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return st, 0, fmt.Errorf("%s is missing: the broker does not run, or it is older than the reload "+
				"command; start the broker (systemctl start nodkey), as root", path)
		}
		return st, 0, fmt.Errorf("cannot read %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return st, 0, fmt.Errorf("cannot read %s: %w", path, err)
	}
	sys, ok := fi.Sys().(*syscall.Stat_t)
	if !fi.Mode().IsRegular() || !ok || sys.Uid == 0 {
		return st, 0, fmt.Errorf("%s is not a regular file of the broker's user; remove it, then restart the "+
			"broker (systemctl restart nodkey), as root", path)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxReloadStatus+1))
	if err == nil && len(data) > maxReloadStatus {
		err = errors.New("the file is too large")
	}
	if err == nil {
		err = json.Unmarshal(data, &st)
	}
	if err != nil || st.PID <= 1 || st.Start == 0 {
		return reloadStatus{}, 0, fmt.Errorf("%s does not hold a status of the broker; restart the broker "+
			"(systemctl restart nodkey), as root", path)
	}
	return st, sys.Uid, nil
}

// signalBroker sends SIGHUP to the broker of st, after it checked that the
// process is the one that wrote the status file: it runs as uid, the owner
// of the file, and it has the same start time. So a stale file never makes
// the signal go to another process.
func signalBroker(st reloadStatus, uid uint32) error {
	fi, err := os.Stat("/proc/" + strconv.Itoa(st.PID))
	start, serr := procStart(st.PID)
	sys, ok := statOwner(fi)
	if err != nil || serr != nil || !ok || sys != uid || start != st.Start {
		return errors.New("the broker that wrote the status file does not run any more; start it " +
			"(systemctl start nodkey), as root")
	}
	if err := syscall.Kill(st.PID, syscall.SIGHUP); err != nil {
		return fmt.Errorf("cannot send SIGHUP to the broker: %w; run nodkey broker reload as root, or as the "+
			"broker's user", err)
	}
	return nil
}

// statOwner returns the owner of fi.
func statOwner(fi os.FileInfo) (uint32, bool) {
	if fi == nil {
		return 0, false
	}
	sys, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return sys.Uid, true
}

// ownStart returns the start time of this process, for the status file.
func ownStart() uint64 {
	start, err := procStart(os.Getpid())
	if err != nil {
		return 0
	}
	return start
}
