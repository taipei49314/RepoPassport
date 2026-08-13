package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/taipei49314/RepoPassport/internal/acceptanceregistry"
	"github.com/taipei49314/RepoPassport/internal/canonicaljson"
)

const notApplicable = "NOT_APPLICABLE"

type commandRecord struct {
	Code          string `json:"code"`
	OverallStatus string `json:"overallStatus"`
	SHA256        string `json:"sha256"`
	Status        string `json:"status"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, io.Discard))
}

func run(args []string, stdout, _ io.Writer) int {
	record, exitCode := dispatch(args)
	raw, err := canonicaljson.Marshal(record)
	if err != nil {
		return 1
	}
	raw = append(raw, '\n')
	if stdout == nil {
		return 1
	}
	written, writeErr := stdout.Write(raw)
	if writeErr != nil || written != len(raw) {
		return 1
	}
	return exitCode
}

func dispatch(args []string) (commandRecord, int) {
	if len(args) == 0 {
		return failureRecord("ACCEPTANCE_INVALID_INPUT", "FAIL"), 2
	}
	switch args[0] {
	case "validate":
		values, ok := parseExactFlags(args[1:], []string{"--registry"})
		if !ok {
			return failureRecord("ACCEPTANCE_INVALID_INPUT", "FAIL"), 2
		}
		raw, err := readBounded(values["--registry"], acceptanceregistry.MaxRegistryBytes)
		if err != nil {
			return failureRecord("ACCEPTANCE_REGISTRY_INVALID", "FAIL"), 1
		}
		digest, err := acceptanceregistry.RegistryDigest(raw)
		if err != nil {
			return failureRecord(acceptanceregistry.ErrorCode(err), "FAIL"), 1
		}
		return commandRecord{Code: "ACCEPTANCE_REGISTRY_VALID", OverallStatus: "INCOMPLETE", SHA256: digest, Status: "PASS"}, 0
	case "evaluate":
		required := []string{
			"--container-result", "--event", "--go-result", "--output", "--ref",
			"--registry", "--repository", "--revision", "--schema-json-result",
			"--tree-sha", "--windows-go-result", "--workflow-run-attempt", "--workflow-run-id",
		}
		values, ok := parseExactFlags(args[1:], required)
		if !ok {
			return failureRecord("ACCEPTANCE_INVALID_INPUT", "FAIL"), 2
		}
		registryRaw, err := readBounded(values["--registry"], acceptanceregistry.MaxRegistryBytes)
		if err != nil {
			return failureRecord("ACCEPTANCE_REGISTRY_INVALID", "FAIL"), 1
		}
		runID, okID := parsePositiveInteger(values["--workflow-run-id"], 9_007_199_254_740_991)
		attempt, okAttempt := parsePositiveInteger(values["--workflow-run-attempt"], 2_147_483_647)
		if !okID || !okAttempt {
			return failureRecord("ACCEPTANCE_SUBJECT_INVALID", "FAIL"), 1
		}
		evaluationRaw, err := acceptanceregistry.Evaluate(registryRaw, acceptanceregistry.EvaluationRequest{
			Subject: acceptanceregistry.Subject{
				Repository: values["--repository"], Revision: values["--revision"], TreeSHA: values["--tree-sha"],
			},
			Run: acceptanceregistry.Run{
				Attempt: attempt, Event: values["--event"], ID: runID,
				Ref: values["--ref"], WorkflowPath: ".github/workflows/ci.yml",
			},
			Checks: acceptanceregistry.CheckResults{
				Container: values["--container-result"], Go: values["--go-result"],
				SchemaJSON: values["--schema-json-result"], WindowsGo: values["--windows-go-result"],
			},
		})
		if err != nil {
			return failureRecord(acceptanceregistry.ErrorCode(err), "FAIL"), 1
		}
		evaluation, err := acceptanceregistry.ParseEvaluation(registryRaw, evaluationRaw)
		if err != nil {
			return failureRecord("ACCEPTANCE_EVALUATION_INVALID", "FAIL"), 1
		}
		if err := publishNoReplace(values["--output"], evaluationRaw); err != nil {
			return failureRecord("ACCEPTANCE_OUTPUT_UNAVAILABLE", string(evaluation.OverallStatus)), 1
		}
		return commandRecord{Code: "ACCEPTANCE_EVALUATION_WRITTEN", OverallStatus: string(evaluation.OverallStatus), SHA256: evaluation.EvaluationDigest, Status: "PASS"}, 0
	case "require-complete":
		values, ok := parseExactFlags(args[1:], []string{"--evaluation"})
		if !ok {
			return failureRecord("ACCEPTANCE_INVALID_INPUT", "FAIL"), 2
		}
		raw, err := readBounded(values["--evaluation"], acceptanceregistry.MaxEvaluationBytes)
		if err != nil {
			return failureRecord("ACCEPTANCE_EVALUATION_INVALID", "FAIL"), 1
		}
		if err := acceptanceregistry.RequireCompleteEvaluation(raw); err != nil {
			code := acceptanceregistry.ErrorCode(err)
			if code == "ACCEPTANCE_INCOMPLETE" {
				return failureRecord(code, "INCOMPLETE"), 1
			}
			return failureRecord(code, "FAIL"), 1
		}
		var minimal struct {
			EvaluationDigest string `json:"evaluationDigest"`
		}
		if err := json.Unmarshal(raw, &minimal); err != nil {
			return failureRecord("ACCEPTANCE_EVALUATION_INVALID", "FAIL"), 1
		}
		return commandRecord{Code: "ACCEPTANCE_COMPLETE", OverallStatus: "PASS", SHA256: minimal.EvaluationDigest, Status: "PASS"}, 0
	default:
		return failureRecord("ACCEPTANCE_INVALID_INPUT", "FAIL"), 2
	}
}

func parseExactFlags(args, required []string) (map[string]string, bool) {
	if len(args) != len(required)*2 {
		return nil, false
	}
	allowed := make(map[string]struct{}, len(required))
	for _, name := range required {
		allowed[name] = struct{}{}
	}
	values := make(map[string]string, len(required))
	for index := 0; index < len(args); index += 2 {
		name, value := args[index], args[index+1]
		if _, ok := allowed[name]; !ok || strings.Contains(name, "=") || value == "" || strings.HasPrefix(value, "--") {
			return nil, false
		}
		if _, duplicate := values[name]; duplicate {
			return nil, false
		}
		values[name] = value
	}
	return values, len(values) == len(required)
}

func parsePositiveInteger(value string, maximum int64) (int64, bool) {
	if value == "" || (len(value) > 1 && value[0] == '0') {
		return 0, false
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	return parsed, err == nil && parsed >= 1 && parsed <= maximum
}

func readBounded(path string, maximum int) ([]byte, error) {
	absolute, err := canonicalAcceptanceInputPath(path)
	if err != nil {
		return nil, errors.New("input unavailable")
	}
	file, err := openAcceptanceInput(absolute)
	if err != nil {
		return nil, errors.New("input unavailable")
	}
	defer file.Close()
	infoBefore, err := file.Stat()
	if err != nil || validateAcceptanceInputMetadata(file, infoBefore) != nil ||
		infoBefore.Size() < 1 || infoBefore.Size() > int64(maximum) {
		return nil, errors.New("input invalid")
	}
	raw, err := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	if err != nil || len(raw) > maximum {
		return nil, errors.New("input invalid")
	}
	infoAfter, err := file.Stat()
	if err != nil || validateAcceptanceInputMetadata(file, infoAfter) != nil ||
		!os.SameFile(infoBefore, infoAfter) || infoAfter.Size() != int64(len(raw)) {
		return nil, errors.New("input changed")
	}
	return raw, nil
}

func canonicalAcceptanceInputPath(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	absolute = filepath.Clean(absolute)
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", err
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil || !sameAcceptancePath(absolute, filepath.Clean(resolved)) {
		return "", errors.New("input path is redirected")
	}
	info, err := os.Lstat(absolute)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", errors.New("input path is invalid")
	}
	return absolute, nil
}

func sameAcceptancePath(left, right string) bool {
	left, right = filepath.Clean(left), filepath.Clean(right)
	if os.PathSeparator == '\\' {
		return strings.EqualFold(left, right)
	}
	return left == right
}

func publishNoReplace(path string, raw []byte) error {
	absolute, err := filepath.Abs(path)
	if err != nil || filepath.Clean(absolute) != absolute {
		return errors.New("output invalid")
	}
	directory := filepath.Dir(absolute)
	if info, err := os.Stat(directory); err != nil || !info.IsDir() {
		return errors.New("output directory unavailable")
	}
	resolvedDirectory, err := filepath.EvalSymlinks(directory)
	if err != nil {
		return errors.New("output directory unavailable")
	}
	resolvedDirectory, err = filepath.Abs(resolvedDirectory)
	if err != nil || !sameAcceptancePath(directory, resolvedDirectory) {
		return errors.New("output directory is redirected")
	}
	temp, err := os.CreateTemp(directory, ".repopass-acceptance-*")
	if err != nil {
		return errors.New("output unavailable")
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := secureAcceptanceOutput(tempPath, temp); err != nil {
		temp.Close()
		return errors.New("output unavailable")
	}
	if _, err := io.Copy(temp, bytes.NewReader(raw)); err != nil {
		temp.Close()
		return errors.New("output unavailable")
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return errors.New("output unavailable")
	}
	if err := temp.Close(); err != nil {
		return errors.New("output unavailable")
	}
	if err := os.Link(tempPath, absolute); err != nil {
		return errors.New("output unavailable")
	}
	published := true
	defer func() {
		if published {
			_ = os.Remove(absolute)
		}
	}()
	if err := os.Remove(tempPath); err != nil {
		return errors.New("output unavailable")
	}
	publishedFile, err := openAcceptanceInput(absolute)
	if err != nil {
		return errors.New("output unavailable")
	}
	info, statErr := publishedFile.Stat()
	securityErr := statErr
	if statErr == nil {
		securityErr = validateAcceptanceOutputSecurity(publishedFile, info)
	}
	publishedFile.Close()
	if statErr != nil || securityErr != nil {
		return errors.New("output unavailable")
	}
	publishedRaw, err := readBounded(absolute, len(raw))
	if err != nil || !bytes.Equal(publishedRaw, raw) {
		return errors.New("output unavailable")
	}
	published = false
	return nil
}

func failureRecord(code, overall string) commandRecord {
	return commandRecord{Code: code, OverallStatus: overall, SHA256: notApplicable, Status: "FAIL"}
}
