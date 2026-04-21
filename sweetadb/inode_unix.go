//go:build linux || darwin || freebsd
// +build linux darwin freebsd

// Real inode via the underlying syscall.Stat_t. Real inodes let us
// detect log rotation cleanly — a new inode at the same path means
// sweetADB (or a third-party logrotate) cut a new file, and we
// should seek back to offset 0.

package main

import (
	"io/fs"
	"syscall"
)

func fileInode(info fs.FileInfo) uint64 {
	if info == nil {
		return 0
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && st != nil {
		return st.Ino
	}
	return 0
}
