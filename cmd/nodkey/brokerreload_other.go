//go:build !linux

package main

import "errors"

// noFollow is 0 here: the broker runs only on Linux.
const noFollow = 0

var errReloadLinux = errors.New("nodkey broker reload works only on Linux, where the broker runs")

func readReloadStatus(string) (reloadStatus, uint32, error) {
	return reloadStatus{}, 0, errReloadLinux
}

func signalBroker(reloadStatus, uint32) error { return errReloadLinux }

func ownStart() uint64 { return 0 }
