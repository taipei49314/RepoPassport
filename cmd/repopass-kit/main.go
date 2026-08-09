package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/taipei49314/RepoPassport/internal/releasekit"
)

func main() {
	flags := flag.NewFlagSet("repopass-kit", flag.ExitOnError)
	targetOS := flags.String("os", "", "target operating system")
	targetArch := flags.String("arch", "", "target architecture")
	version := flags.String("version", "", "product version")
	binaryPath := flags.String("binary", "", "verifier-only binary")
	outputPath := flags.String("output", "", "output USTAR kit")
	flags.Parse(os.Args[1:])
	if *targetOS == "" || *targetArch == "" || *version == "" || *binaryPath == "" || *outputPath == "" || flags.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: repopass-kit -os linux|windows -arch amd64 -version VERSION -binary FILE -output FILE")
		os.Exit(2)
	}
	binary, err := readRegularBinary(*binaryPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read binary:", err)
		os.Exit(1)
	}
	kit, err := releasekit.Build(releasekit.Target{OS: *targetOS, Arch: *targetArch}, *version, binary)
	if err != nil {
		fmt.Fprintln(os.Stderr, "build kit:", err)
		os.Exit(1)
	}
	err = writeNewFileAtomically(*outputPath, kit)
	if err != nil {
		fmt.Fprintln(os.Stderr, "write kit:", err)
		os.Exit(1)
	}
}

func readRegularBinary(path string) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > releasekit.MaxBinaryBytes {
		return nil, fmt.Errorf("binary must be a regular file between 1 and %d bytes", releasekit.MaxBinaryBytes)
	}
	input, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer input.Close()
	opened, err := input.Stat()
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() || !sameInput(before, opened) || !os.SameFile(before, opened) {
		return nil, fmt.Errorf("binary changed while opening")
	}
	data := make([]byte, before.Size())
	if _, err := io.ReadFull(input, data); err != nil {
		return nil, err
	}
	after, err := input.Stat()
	if err != nil {
		return nil, err
	}
	pathAfter, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !sameInput(before, after) || !sameInput(before, pathAfter) ||
		!os.SameFile(before, opened) || !os.SameFile(opened, after) ||
		!os.SameFile(before, pathAfter) {
		return nil, fmt.Errorf("binary changed while reading")
	}
	return data, nil
}

func sameInput(left, right os.FileInfo) bool {
	return left.Size() == right.Size() && left.ModTime().Equal(right.ModTime())
}

// writeNewFileAtomically never exposes a partly-written output and refuses to
// replace an existing output. Link is used as the final same-directory,
// no-replace publication step.
func writeNewFileAtomically(outputPath string, data []byte) (err error) {
	dir := filepath.Dir(outputPath)
	temp, err := os.CreateTemp(dir, "."+filepath.Base(outputPath)+".tmp-*")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer func() {
		_ = temp.Close()
		_ = os.Remove(tempName)
	}()
	if err := temp.Chmod(0o644); err != nil {
		return err
	}
	if _, err := temp.Write(data); err != nil {
		return err
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Link(tempName, outputPath); err != nil {
		return err
	}
	return nil
}
