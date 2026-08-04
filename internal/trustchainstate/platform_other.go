//go:build !unix && !windows

package trustchainstate

import "os"

func safeNativePath(string) bool                                      { return false }
func safeNativeInput(string) bool                                     { return false }
func isReparsePoint(string) bool                                      { return true }
func createPrivateDirectory(string) (bool, error)                     { return false, ErrUnavailable }
func createPrivateLock(string) (*os.File, bool, error)                { return nil, false, ErrUnavailable }
func openExistingPrivateLock(string) (*os.File, error)                { return nil, ErrUnavailable }
func createPrivateTemporaryFile(string, string) (*os.File, error)     { return nil, ErrUnavailable }
func validateDirectoryPlatform(string, os.FileInfo) error             { return ErrUnavailable }
func validatePrivateStateDirectoryPlatform(string, os.FileInfo) error { return ErrUnavailable }
func validateOpenedRegularFile(*os.File, string, bool) error          { return ErrUnavailable }
func atomicReplace(string, string) error                              { return ErrUnavailable }
func syncDirectory(string) error                                      { return ErrUnavailable }
func samePathPlatform(string, string) bool                            { return false }
