package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"

	"github.com/taipei49314/RepoPassport/internal/buildidentity"
	"github.com/taipei49314/RepoPassport/internal/releasequalification"
)

const (
	phasePreHelper  = "pre-helper"
	phasePrePublish = "pre-publish"
)

var phaseIDs = map[string][]string{
	phasePreHelper: {
		"full-linux-amd64",
		"full-windows-amd64",
		"verifier-linux-amd64",
		"verifier-windows-amd64",
		"kit-helper-host",
	},
	phasePrePublish: {
		"full-linux-amd64",
		"full-windows-amd64",
		"verifier-linux-amd64",
		"verifier-windows-amd64",
		"kit-linux-amd64",
		"kit-windows-amd64",
	},
}

type outputRecord struct {
	ID           string `json:"id"`
	SHA256       string `json:"sha256"`
	Revision     string `json:"revision"`
	Tree         string `json:"tree"`
	Status       string `json:"status"`
	Code         string `json:"code"`
	FirstFailure bool   `json:"firstFailure"`
}

func main() {
	defer func() {
		if recover() != nil {
			_ = json.NewEncoder(os.Stdout).Encode(outputRecord{
				ID:     "qualification",
				Status: string(buildidentity.StatusNotRun),
				Code:   string(buildidentity.CodeRequiredCheckNotRun),
			})
			os.Exit(1)
		}
	}()
	os.Exit(run(os.Args[1:], os.Stdout))
}

func run(args []string, output io.Writer) int {
	flags := flag.NewFlagSet("repopass-release-qualify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	phase := flags.String("phase", "", "qualification phase")
	root := flags.String("root", "", "private artifact root")
	publishTo := flags.String("publish-to", "", "same-parent atomic publication destination")
	revision := flags.String("tested-revision", "", "tested source revision")
	tree := flags.String("tree", "", "tested source tree")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return writeInputFailure(output, safePhase(*phase), safeObjectID(*revision), safeObjectID(*tree))
	}

	expectedIDs, knownPhase := phaseIDs[*phase]
	publicationInputValid := (*phase == phasePreHelper && *publishTo == "") ||
		(*phase == phasePrePublish && *publishTo != "")
	if !knownPhase || !publicationInputValid || *root == "" || !validObjectID(*revision) || !validObjectID(*tree) {
		return writeInputFailure(output, safePhase(*phase), safeObjectID(*revision), safeObjectID(*tree))
	}

	var (
		report          releasequalification.QualificationReport
		publicationRoot string
		err             error
	)
	switch *phase {
	case phasePreHelper:
		report, err = releasequalification.QualifyPreHelper(*root, *revision, *tree)
	case phasePrePublish:
		report, publicationRoot, err = releasequalification.PreparePrePublish(
			*root, *publishTo, *revision, *tree,
		)
	}

	failingIDs := make(map[string]struct{}, len(report.Results))
	resultsFailed := false
	allowedIDs := make(map[string]struct{}, len(expectedIDs))
	for _, id := range expectedIDs {
		allowedIDs[id] = struct{}{}
	}
	for _, result := range report.Results {
		if result.Status == buildidentity.StatusPass {
			continue
		}
		resultsFailed = true
		if _, allowed := allowedIDs[result.Subject]; allowed {
			failingIDs[result.Subject] = struct{}{}
		}
	}
	logInvalid := len(report.Log) > len(expectedIDs)
	logByID := make(map[string]releasequalification.LogRecord, len(report.Log))
	priorIndex := -1
	for _, record := range report.Log {
		index := stringIndex(expectedIDs, record.ID)
		if index <= priorIndex ||
			record.Revision != *revision || record.Tree != *tree || !validSHA256(record.SHA256) {
			logInvalid = true
			continue
		}
		priorIndex = index
		logByID[record.ID] = record
	}
	for _, id := range expectedIDs {
		if _, failed := failingIDs[id]; failed {
			continue
		}
		if _, logged := logByID[id]; !logged {
			logInvalid = true
		}
	}

	records := make([]outputRecord, 0, len(report.Results)+len(expectedIDs)+1)
	firstMarked := false
	for _, result := range report.Results {
		if result.Status == buildidentity.StatusPass {
			continue
		}
		if _, allowed := allowedIDs[result.Subject]; !allowed {
			logInvalid = true
			continue
		}
		log := logByID[result.Subject]
		isFirst := !firstMarked && sameResult(report.FirstFailure, result)
		if isFirst {
			firstMarked = true
		}
		records = append(records, outputRecord{
			ID:           result.Subject,
			SHA256:       log.SHA256,
			Revision:     *revision,
			Tree:         *tree,
			Status:       string(result.Status),
			Code:         string(result.Code),
			FirstFailure: isFirst,
		})
	}
	structuralFailure := report.StructuralFailure || logInvalid || (err != nil && !resultsFailed)
	if structuralFailure {
		records = append(records, outputRecord{
			ID:       *phase,
			Revision: *revision,
			Tree:     *tree,
			Status:   string(buildidentity.StatusNotRun),
			Code:     string(buildidentity.CodeRequiredCheckNotRun),
		})
	}
	for _, id := range expectedIDs {
		if _, failed := failingIDs[id]; failed {
			continue
		}
		log, ok := logByID[id]
		if !ok {
			continue
		}
		records = append(records, outputRecord{
			ID:       id,
			SHA256:   log.SHA256,
			Revision: *revision,
			Tree:     *tree,
			Status:   string(buildidentity.StatusPass),
		})
	}
	failed := err != nil || resultsFailed || logInvalid
	var encoded bytes.Buffer
	if !writeRecords(&encoded, records) {
		return 1
	}
	if failed {
		removeUnpublishedSnapshot(publicationRoot)
		_, _ = output.Write(encoded.Bytes())
		return 1
	}
	if *phase == phasePrePublish {
		if err := removeConstructionDirectory(*root, publicationRoot, *publishTo); err != nil {
			removeUnpublishedSnapshot(publicationRoot)
			return 1
		}
		if err := writeQualificationThenValidateAndPublish(
			output,
			encoded.Bytes(),
			publicationRoot,
			*publishTo,
			func(path string) error {
				finalReport, finalErr := releasequalification.QualifyPrePublish(path, *revision, *tree)
				if finalErr != nil || !reflect.DeepEqual(report, finalReport) {
					return errors.New("sealed publication snapshot changed")
				}
				return nil
			},
		); err != nil {
			removeUnpublishedSnapshot(publicationRoot)
			return 1
		}
		return 0
	}
	if written, err := output.Write(encoded.Bytes()); err != nil || written != encoded.Len() {
		return 1
	}
	return 0
}

func writeInputFailure(output io.Writer, phase, revision, tree string) int {
	if phase == "" {
		phase = "qualification"
	}
	_ = writeRecords(output, []outputRecord{{
		ID:       phase,
		Revision: revision,
		Tree:     tree,
		Status:   string(buildidentity.StatusNotRun),
		Code:     string(buildidentity.CodeRequiredCheckNotRun),
	}})
	return 1
}

func writeRecords(output io.Writer, records []outputRecord) bool {
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(true)
	for _, record := range records {
		if err := encoder.Encode(record); err != nil {
			return false
		}
	}
	return true
}

func sameResult(first *buildidentity.Result, candidate buildidentity.Result) bool {
	return first != nil && *first == candidate
}

func stringIndex(values []string, target string) int {
	for index, value := range values {
		if value == target {
			return index
		}
	}
	return -1
}

func publishQualifiedDirectory(source, destination string) error {
	sourceAbsolute, sourceErr := filepath.Abs(source)
	destinationAbsolute, destinationErr := filepath.Abs(destination)
	if sourceErr != nil || destinationErr != nil ||
		!strings.HasPrefix(filepath.Base(sourceAbsolute), ".release-sealed-") ||
		filepath.Base(destinationAbsolute) != "dist" ||
		!sameDirectoryName(filepath.Dir(sourceAbsolute), filepath.Dir(destinationAbsolute)) ||
		!releasequalification.PublicationPathSafe(sourceAbsolute) ||
		!releasequalification.PublicationPathSafe(filepath.Dir(destinationAbsolute)) {
		return errors.New("publication path is outside the fixed scope")
	}
	sourceInfo, err := os.Lstat(sourceAbsolute)
	if err != nil || !sourceInfo.IsDir() || sourceInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("publication source is not a regular directory")
	}
	if _, err := os.Lstat(destinationAbsolute); !os.IsNotExist(err) {
		return errors.New("publication destination already exists or is unreadable")
	}
	if err := atomicPublishDirectoryNoReplace(sourceAbsolute, destinationAbsolute); err != nil {
		return errors.New("atomic publication failed")
	}
	return nil
}

func removeConstructionDirectory(source, sealed, destination string) error {
	sourceAbsolute, sourceErr := filepath.Abs(source)
	sealedAbsolute, sealedErr := filepath.Abs(sealed)
	destinationAbsolute, destinationErr := filepath.Abs(destination)
	if sourceErr != nil || sealedErr != nil || destinationErr != nil ||
		!strings.HasPrefix(filepath.Base(sourceAbsolute), ".release-publish-") ||
		!strings.HasPrefix(filepath.Base(sealedAbsolute), ".release-sealed-") ||
		filepath.Base(destinationAbsolute) != "dist" ||
		!sameDirectoryName(filepath.Dir(sourceAbsolute), filepath.Dir(sealedAbsolute)) ||
		!sameDirectoryName(filepath.Dir(sourceAbsolute), filepath.Dir(destinationAbsolute)) ||
		sameDirectoryName(sourceAbsolute, sealedAbsolute) ||
		!releasequalification.PublicationPathSafe(sourceAbsolute) ||
		!releasequalification.PublicationPathSafe(sealedAbsolute) ||
		!releasequalification.PublicationPathSafe(filepath.Dir(destinationAbsolute)) {
		return errors.New("publication construction cleanup is outside the fixed scope")
	}
	info, err := os.Lstat(sourceAbsolute)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("publication construction directory is unsafe")
	}
	if err := os.RemoveAll(sourceAbsolute); err != nil {
		return errors.New("publication construction cleanup failed")
	}
	if _, err := os.Lstat(sourceAbsolute); !os.IsNotExist(err) {
		return errors.New("publication construction cleanup was incomplete")
	}
	return nil
}

func removeUnpublishedSnapshot(path string) {
	absolute, err := filepath.Abs(path)
	if err != nil || !strings.HasPrefix(filepath.Base(absolute), ".release-sealed-") {
		return
	}
	_ = os.RemoveAll(absolute)
}

func writeQualificationThenPublish(output io.Writer, encoded []byte, source, destination string) error {
	return writeQualificationThenValidateAndPublish(output, encoded, source, destination, func(string) error { return nil })
}

func writeQualificationThenValidateAndPublish(
	output io.Writer,
	encoded []byte,
	source, destination string,
	validate func(string) error,
) error {
	written, err := output.Write(encoded)
	if err != nil || written != len(encoded) {
		return errors.New("qualification output was not accepted")
	}
	if validate == nil || validate(source) != nil {
		return errors.New("sealed publication snapshot validation failed")
	}
	// The same-parent rename is deliberately the last operation. Once dist is
	// visible, this process performs no further I/O that could turn a successful
	// publication into a failed command while leaving release bytes behind.
	return publishQualifiedDirectory(source, destination)
}

func sameDirectoryName(left, right string) bool {
	left = filepath.Clean(left)
	right = filepath.Clean(right)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(left, right)
	}
	return left == right
}

func safePhase(value string) string {
	if _, ok := phaseIDs[value]; ok {
		return value
	}
	return ""
}

func safeObjectID(value string) string {
	if validObjectID(value) {
		return value
	}
	return ""
}

func validObjectID(value string) bool {
	if len(value) != 40 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func validSHA256(value string) bool {
	const prefix = "sha256:"
	if len(value) != len(prefix)+64 || value[:len(prefix)] != prefix {
		return false
	}
	for _, character := range value[len(prefix):] {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}
