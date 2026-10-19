//go:build linux || openbsd || freebsd

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"fmt"
	"math"
	"runtime"

	"golang.org/x/sys/unix"
)

var fwmarkIoctl int

func init() {
	switch runtime.GOOS {
	case "linux", "android":
		fwmarkIoctl = 36 /* unix.SO_MARK */
	case "freebsd":
		fwmarkIoctl = 0x1015 /* unix.SO_USER_COOKIE */
	case "openbsd":
		fwmarkIoctl = 0x1021 /* unix.SO_RTABLE */
	}
}

func (s *StdNetBind) SetMark(mark uint32) error {
	var operr error
	if fwmarkIoctl == 0 {
		return nil
	}
	// int(mark) below must not wrap on 32-bit platforms: SO_MARK and friends
	// only ever carry values well below 2^31.
	if mark > math.MaxInt32 {
		return fmt.Errorf("fwmark %d exceeds the maximum supported value", mark)
	}
	if s.ipv4 != nil {
		fd, err := s.ipv4.SyscallConn()
		if err != nil {
			return err
		}
		err = fd.Control(func(fd uintptr) {
			operr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, fwmarkIoctl, int(mark))
		})
		if err == nil {
			err = operr
		}
		if err != nil {
			return err
		}
	}
	if s.ipv6 != nil {
		fd, err := s.ipv6.SyscallConn()
		if err != nil {
			return err
		}
		err = fd.Control(func(fd uintptr) {
			operr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, fwmarkIoctl, int(mark))
		})
		if err == nil {
			err = operr
		}
		if err != nil {
			return err
		}
	}
	return nil
}
