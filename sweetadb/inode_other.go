//go:build !linux && !darwin && !freebsd

// Fallback stub for non-unix hosts (Windows, plan9). No real inode
// available, so rotation detection falls back to the size-truncation
// path in the tailer — good enough in practice since sweetADB
// targets Linux anyway. This file exists solely so the package
// builds on the author's Windows dev machine.

package main

import "io/fs"

func fileInode(_ fs.FileInfo) uint64 { return 0 }
