//go:build !linux && !windows

package main

import (
	"errors"
	"os"
)

func openAcceptanceInput(string) (*os.File, error) {
	return nil, errors.New("acceptance input metadata enforcement is unavailable")
}

func validateAcceptanceInputMetadata(*os.File, os.FileInfo) error {
	return errors.New("acceptance input metadata enforcement is unavailable")
}

func secureAcceptanceOutput(string, *os.File) error {
	return errors.New("acceptance output metadata enforcement is unavailable")
}

func validateAcceptanceOutputSecurity(*os.File, os.FileInfo) error {
	return errors.New("acceptance output metadata enforcement is unavailable")
}
