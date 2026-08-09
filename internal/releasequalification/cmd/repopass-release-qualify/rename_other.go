//go:build !linux && !windows

package main

import "errors"

func atomicPublishDirectoryNoReplace(string, string) error {
	return errors.New("atomic no-replace release publication is unsupported")
}
