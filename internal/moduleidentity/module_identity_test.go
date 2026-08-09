package moduleidentity

import (
	"context"
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	canonicalModule = "github.com/taipei49314/RepoPassport"
	legacyModule    = "github.com/repopass/repopass"
)

func TestCanonicalModuleIdentitySourceContract(t *testing.T) {
	root := repositoryRoot(t)
	tests := []struct {
		name string
		run  func(*testing.T, string)
	}{
		{"root_module_is_exact", testRootModule},
		{"local_package_paths_use_canonical_prefix", testLocalPackagePaths},
		{"all_go_imports_reject_legacy_and_case_variants", testGoImports},
		{"module_and_workspace_files_have_no_identity_replacements", testIdentityReplacements},
		{"release_builder_uses_canonical_identity", testReleaseBuilder},
		{"readme_describes_the_canonical_repository", testREADME},
		{"active_workflows_and_docs_reject_legacy_identity", testActiveIdentitySurfaces},
		{"external_schemas_consumer_works_offline", testExternalSchemasConsumer},
	}

	// Keep the gate fail-first: a later observation must not obscure the first
	// source-contract failure. Individual subtests remain directly selectable.
	for _, test := range tests {
		test := test
		if !t.Run(test.name, func(t *testing.T) { test.run(t, root) }) {
			t.FailNow()
		}
	}
}

func testRootModule(t *testing.T, root string) {
	out := runGo(t, root, map[string]string{"GOWORK": "off"}, "MODULE_PATH_MISMATCH", "list", "-m", "-f", "{{.Path}}")
	requireExactLine(t, out, canonicalModule)
}

func testLocalPackagePaths(t *testing.T, root string) {
	out := runGo(t, root, map[string]string{"GOWORK": "off"}, "PACKAGE_PATH_MISMATCH", "list", "-f", "{{.ImportPath}}", "./...")
	paths := commandLines(t, out)
	if len(paths) == 0 {
		t.Fatal("go list returned no repository packages")
	}
	for _, path := range paths {
		if path != canonicalModule && !strings.HasPrefix(path, canonicalModule+"/") {
			t.Fatalf("repository package path is outside the exact canonical prefix: %q", path)
		}
	}
}

func testGoImports(t *testing.T, root string) {
	fset := token.NewFileSet()
	var violations []string
	total := 0
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if entry.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(entry.Name(), ".go") {
			return nil
		}

		file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly|parser.AllErrors)
		if err != nil {
			return fmt.Errorf("parse %s without applying build tags: %w", relativePath(root, path), err)
		}
		for _, spec := range file.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				return fmt.Errorf("decode import in %s: %w", relativePath(root, path), err)
			}
			reason := importIdentityViolation(importPath)
			if reason == "" {
				continue
			}
			total++
			if len(violations) < 20 {
				position := fset.Position(spec.Path.Pos())
				violations = append(violations, fmt.Sprintf("%s:%d: %q (%s)", relativePath(root, path), position.Line, importPath, reason))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if total != 0 {
		suffix := ""
		if total > len(violations) {
			suffix = fmt.Sprintf("\n... and %d more", total-len(violations))
		}
		t.Fatalf("found %d non-canonical Go imports (all .go files are parsed regardless of build tags):\n%s%s", total, strings.Join(violations, "\n"), suffix)
	}
}

func testIdentityReplacements(t *testing.T, root string) {
	var moduleFiles []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if entry.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Name() == "go.mod" || entry.Name() == "go.work" {
			moduleFiles = append(moduleFiles, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(moduleFiles)
	if len(moduleFiles) == 0 {
		t.Fatal("repository contains no go.mod or go.work file")
	}

	for _, path := range moduleFiles {
		content := readFile(t, path)
		clauses, err := replacementClauses(string(content))
		if err != nil {
			t.Fatalf("parse replacement directives in %s: %v", relativePath(root, path), err)
		}
		for _, clause := range clauses {
			for _, field := range strings.FieldsFunc(clause.text, func(r rune) bool {
				return r == ' ' || r == '\t' || r == '=' || r == '>' || r == '(' || r == ')' || r == '"' || r == '\''
			}) {
				if hasFoldedSegmentPrefix(field, canonicalModule) || hasFoldedSegmentPrefix(field, legacyModule) {
					t.Fatalf("%s:%d has a replace directive involving a canonical or legacy RepoPassport namespace: %q", relativePath(root, path), clause.line, clause.text)
				}
			}
		}
	}
}

func testReleaseBuilder(t *testing.T, root string) {
	path := filepath.Join(root, "scripts", "build-release.ps1")
	script := string(readFile(t, path))
	requireSource := func(label, fragment string) int {
		t.Helper()
		index := strings.Index(script, fragment)
		if index < 0 {
			t.Fatalf("%s is missing %s contract fragment %q", relativePath(root, path), label, fragment)
		}
		return index
	}
	if !regexp.MustCompile(`(?s)\[Parameter\(Mandatory\s*=\s*\$true\)\]\s*\[ValidatePattern\(['\"]\^\[0-9a-f\]\{40\}\$['\"]\)\]\s*\[string\]\$TestedRevision`).MatchString(script) {
		t.Fatalf("%s must require TestedRevision as an exact lowercase 40-hex SHA", relativePath(root, path))
	}
	exactSymbol := regexp.MustCompile(`(?m)^\s*\$versionSymbol\s*=\s*"` + regexp.QuoteMeta(canonicalModule+"/internal/cli.Version=$Version") + `"\s*$`)
	if !exactSymbol.MatchString(script) {
		t.Fatalf("%s must assign the exact canonical linker target %q", relativePath(root, path), canonicalModule+"/internal/cli.Version=$Version")
	}
	if strings.Contains(asciiLower(script), asciiLower(legacyModule)) {
		t.Fatalf("%s still contains the legacy module prefix", relativePath(root, path))
	}

	goBuild := regexp.MustCompile(`(?i)(?:^|\s)&\s*(?:go(?:\.exe)?|\$goCommand)\s+build(?:\s|$)`)
	goWorkAssignment := regexp.MustCompile(`(?i)^\s*\$env:GOWORK\s*=\s*(.*?)\s*$`)
	goWorkOff := false
	buildCount := 0
	for _, statement := range powershellStatements(script) {
		if match := goWorkAssignment.FindStringSubmatch(statement.text); match != nil {
			value := strings.TrimSpace(match[1])
			goWorkOff = value == `"off"` || value == `'off'`
		}
		if !goBuild.MatchString(statement.text) {
			continue
		}
		buildCount++
		if !goWorkOff {
			t.Fatalf("%s:%d invokes go build without a preceding exact $env:GOWORK = \"off\" assignment", relativePath(root, path), statement.line)
		}
		if !strings.Contains(statement.text, "-buildvcs=true") {
			t.Fatalf("%s:%d invokes go build without the exact -buildvcs=true flag", relativePath(root, path), statement.line)
		}
		if !strings.Contains(statement.text, "-mod=readonly") {
			t.Fatalf("%s:%d invokes go build without the exact -mod=readonly flag", relativePath(root, path), statement.line)
		}
	}
	if buildCount != 3 {
		t.Fatalf("%s contains %d source-level go build invocations; want exactly 3 qualified builds", relativePath(root, path), buildCount)
	}

	if regexp.MustCompile(`(?m)^\s*\$stagingRoot\s*=\s*Join-Path\s+\$repoRoot\b`).MatchString(script) {
		t.Fatalf("%s places pre-qualified build artifacts inside the worktree", relativePath(root, path))
	}
	if !regexp.MustCompile(`(?m)^\s*\$previousGOWORK\s*=\s*\$env:GOWORK\s*$`).MatchString(script) ||
		!regexp.MustCompile(`(?m)^\s*\$env:GOWORK\s*=\s*\$previousGOWORK\s*$`).MatchString(script) {
		t.Fatalf("%s must preserve and restore the caller GOWORK value", relativePath(root, path))
	}
	for _, environmentContract := range []string{
		`$env:GOENV = "off"`,
		`$env:GOFLAGS = ""`,
		`$env:GOTOOLCHAIN = "local"`,
		`$env:GOAMD64 = "v1"`,
		`$env:GOEXPERIMENT = ""`,
		`$env:GOPROXY = "off"`,
		`$env:GIT_DIR = $null`,
		`$env:GIT_WORK_TREE = $null`,
		`Get-Command go -CommandType Application`,
		`Get-Command git -CommandType Application`,
		`$env:GOCACHE = Join-Path $stagingRoot "gocache"`,
		`$env:GOMODCACHE = Join-Path $stagingRoot "gomodcache"`,
		`$env:GOTMPDIR = Join-Path $stagingRoot "gotmp"`,
	} {
		if !strings.Contains(script, environmentContract) {
			t.Fatalf("%s is missing ambient build isolation contract %q", relativePath(root, path), environmentContract)
		}
	}

	firstBuild := requireSource("first build", "& $goCommand build")
	hostEnvironmentReset := requireSource("host build environment reset", "$env:GOOS = $null")
	if hostEnvironmentReset > firstBuild {
		t.Fatalf("%s must clear caller cross-build environment before building the host qualifier", relativePath(root, path))
	}
	qualifierBuild := requireSource("private qualifier", "./internal/releasequalification/cmd/repopass-release-qualify")
	lastBuild := strings.LastIndex(script, "& $goCommand build")
	preHelper := requireSource("pre-helper qualification", "-phase pre-helper")
	helperExecution := requireSource("kit helper execution", "& $kitTool -os")
	publishCreation := requireSource("late publish directory creation", "New-Item -ItemType Directory -Path $publishRoot")
	checksumCreation := requireSource("checksum construction", "$checksumLines =")
	prePublish := requireSource("pre-publish qualification", "-phase pre-publish")
	atomicPublish := requireSource("controller-owned atomic publication", "-publish-to $distRoot")
	if !(qualifierBuild < lastBuild && lastBuild < preHelper && preHelper < helperExecution &&
		helperExecution < publishCreation && publishCreation < checksumCreation &&
		checksumCreation < prePublish && prePublish < atomicPublish) {
		t.Fatalf("%s does not enforce build, qualify, helper, checksum, final qualification, atomic-publish ordering", relativePath(root, path))
	}
	if strings.Contains(script, "[IO.Directory]::Move($publishRoot, $distRoot)") {
		t.Fatalf("%s publishes outside the final fixed-snapshot controller", relativePath(root, path))
	}
	if tail := script[atomicPublish+len("-publish-to $distRoot"):]; strings.Contains(strings.SplitN(tail, "finally", 2)[0], "Assert-") {
		t.Fatalf("%s performs a fallible assertion after atomic publication", relativePath(root, path))
	}
	for _, phase := range []string{"pre-helper", "pre-publish"} {
		pattern := regexp.MustCompile(`(?s)-phase\s+` + regexp.QuoteMeta(phase) + `\b.*?-tested-revision\s+\$TestedRevision\s+-tree\s+\$testedTree`)
		if !pattern.MatchString(script) {
			t.Fatalf("%s %s qualifier invocation must bind TestedRevision and testedTree", relativePath(root, path), phase)
		}
	}
	if !strings.Contains(script, "Remove-ScopedDirectory -Parent $temporaryBase -Path $stagingRoot") ||
		!strings.Contains(script, "Remove-ScopedDirectory -Parent $repoRoot -Path $publishRoot") {
		t.Fatalf("%s must scope cleanup of external staging and unpublished worktree directories", relativePath(root, path))
	}
	for _, inventoryCheck := range []string{
		"Assert-ExactRegularFiles -Path $artifactRoot -ExpectedNames $preHelperInventory",
		"Assert-ExactRegularFiles -Path $artifactRoot -ExpectedNames $postHelperInventory",
	} {
		if !strings.Contains(script, inventoryCheck) {
			t.Fatalf("%s is missing frozen staging inventory check %q", relativePath(root, path), inventoryCheck)
		}
	}
	for _, digestCheck := range []string{
		"Assert-FileSHA256 -Path $qualifier -ExpectedSHA256 $qualifierSHA256",
		"Assert-FileSHA256 -Path $kitTool -ExpectedSHA256 $kitToolSHA256",
	} {
		if strings.Count(script, digestCheck) < 2 {
			t.Fatalf("%s must bind each executed private tool before and after use with %q", relativePath(root, path), digestCheck)
		}
	}
}

func testREADME(t *testing.T, root string) {
	path := filepath.Join(root, "README.md")
	readme := string(readFile(t, path))
	if regexp.MustCompile(`(?i)\bmirror(?:ed|ing|s)?\b`).MatchString(readme) {
		t.Fatalf("%s still describes the active public repository as a mirror", relativePath(root, path))
	}
	if strings.Contains(asciiLower(readme), asciiLower(legacyModule)) {
		t.Fatalf("%s still names the legacy Go module; historical mentions belong only in RFC or changelog history", relativePath(root, path))
	}
	if !strings.Contains(readme, canonicalModule) {
		t.Fatalf("%s must name the exact case-sensitive canonical module %q", relativePath(root, path), canonicalModule)
	}
	for offset := 0; ; {
		index := strings.Index(asciiLower(readme[offset:]), asciiLower(canonicalModule))
		if index < 0 {
			break
		}
		index += offset
		if readme[index:index+len(canonicalModule)] != canonicalModule {
			t.Fatalf("%s contains a non-byte-exact case variant of the canonical module", relativePath(root, path))
		}
		offset = index + len(canonicalModule)
	}
}

func testActiveIdentitySurfaces(t *testing.T, root string) {
	paths := []string{
		filepath.Join(root, "README.md"),
		filepath.Join(root, "IMPLEMENTATION_STATUS.md"),
		filepath.Join(root, "docs", "release.md"),
		filepath.Join(root, "spec", "versioning.md"),
	}
	workflowRoot := filepath.Join(root, ".github", "workflows")
	if err := filepath.WalkDir(workflowRoot, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && (strings.HasSuffix(entry.Name(), ".yml") || strings.HasSuffix(entry.Name(), ".yaml")) {
			paths = append(paths, path)
		}
		return nil
	}); err != nil {
		t.Fatalf("active identity surface scan failed")
	}
	for _, path := range paths {
		content := string(readFile(t, path))
		if strings.Contains(asciiLower(content), asciiLower(legacyModule)) {
			t.Fatalf("%s contains LEGACY_MODULE_REFERENCE", relativePath(root, path))
		}
		for offset := 0; ; {
			index := strings.Index(asciiLower(content[offset:]), asciiLower(canonicalModule))
			if index < 0 {
				break
			}
			index += offset
			if content[index:index+len(canonicalModule)] != canonicalModule {
				t.Fatalf("%s contains PACKAGE_PATH_MISMATCH", relativePath(root, path))
			}
			offset = index + len(canonicalModule)
		}
	}
}

func testExternalSchemasConsumer(t *testing.T, root string) {
	goVersion := rootGoVersion(t, filepath.Join(root, "go.mod"))
	temp := t.TempDir()
	localReplacement := strconv.Quote(filepath.ToSlash(root))
	goMod := fmt.Sprintf(`module example.invalid/repopass-schema-consumer

go %s

require %s v0.0.0

replace %s => %s
`, goVersion, canonicalModule, canonicalModule, localReplacement)
	writeFile(t, filepath.Join(temp, "go.mod"), []byte(goMod))
	consumerTest := fmt.Sprintf(`package consumer

import (
	"testing"

	"%s/schemas"
)

func TestValidateManifest(t *testing.T) {
	if err := schemas.ValidateManifest(nil); err == nil {
		t.Fatal("ValidateManifest accepted a nil manifest")
	}
}
`, canonicalModule)
	writeFile(t, filepath.Join(temp, "consumer_test.go"), []byte(consumerTest))

	// Network-backed dependency setup is deliberately separate from the
	// conformance commands. A cache miss after this point must fail closed.
	runGo(t, temp, map[string]string{"GOWORK": "off"}, "EXTERNAL_IMPORT_FAILED", "mod", "tidy")
	runGo(t, temp, map[string]string{"GOWORK": "off"}, "EXTERNAL_IMPORT_FAILED", "mod", "verify")
	offline := map[string]string{"GOPROXY": "off", "GOWORK": "off"}
	runGo(t, temp, offline, "EXTERNAL_IMPORT_FAILED", "test", "-count=1", "./...")

	out := runGo(t, temp, offline, "EXTERNAL_IMPORT_FAILED", "list", "-m", "-f", "{{.Path}}", canonicalModule)
	requireExactLine(t, out, canonicalModule)

	out = runGo(t, temp, offline, "EXTERNAL_IMPORT_FAILED", "list", "-m", "all")
	canonicalCount := 0
	for _, line := range commandLines(t, out) {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			t.Fatalf("go list -m all emitted an empty module line")
		}
		path := fields[0]
		if hasFoldedSegmentPrefix(path, legacyModule) {
			t.Fatalf("external consumer resolved a legacy RepoPassport module: %q", path)
		}
		if hasFoldedSegmentPrefix(path, canonicalModule) {
			if path != canonicalModule {
				t.Fatalf("external consumer resolved a non-exact or nested RepoPassport module: %q", path)
			}
			canonicalCount++
		}
	}
	if canonicalCount != 1 {
		t.Fatalf("go list -m all contained %d exact canonical RepoPassport modules; want exactly 1", canonicalCount)
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if info, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil && !info.IsDir() {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("could not find repository go.mod above %s", dir)
		}
		dir = parent
	}
}

func runGo(t *testing.T, dir string, overrides map[string]string, failureCode string, args ...string) []byte {
	t.Helper()
	const commandTimeout = 90 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, goTool(t), args...)
	command.WaitDelay = 5 * time.Second
	command.Dir = dir
	command.Env = environment(overrides)
	out, err := command.Output()
	if ctx.Err() != nil {
		t.Fatalf("%s: required Go command timed out after %s", failureCode, commandTimeout)
	}
	if err == nil {
		return out
	}
	t.Fatalf("%s: required Go command failed", failureCode)
	return nil
}

func goTool(t *testing.T) string {
	t.Helper()
	if path, err := exec.LookPath("go"); err == nil {
		return path
	}
	name := "go"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	path := filepath.Join(runtime.GOROOT(), "bin", name)
	if info, err := os.Stat(path); err == nil && !info.IsDir() {
		return path
	}
	t.Fatalf("could not locate the Go tool in PATH or runtime.GOROOT()=%q", runtime.GOROOT())
	return ""
}

func environment(overrides map[string]string) []string {
	normalized := make(map[string]string, len(overrides))
	for key, value := range overrides {
		normalized[strings.ToUpper(key)] = key + "=" + value
	}
	env := make([]string, 0, len(os.Environ())+len(overrides))
	for _, entry := range os.Environ() {
		key, _, ok := strings.Cut(entry, "=")
		if ok {
			if _, replaced := normalized[strings.ToUpper(key)]; replaced {
				continue
			}
		}
		env = append(env, entry)
	}
	keys := make([]string, 0, len(normalized))
	for key := range normalized {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		env = append(env, normalized[key])
	}
	return env
}

func requireExactLine(t *testing.T, output []byte, want string) {
	t.Helper()
	lines := commandLines(t, output)
	if len(lines) != 1 || lines[0] != want {
		t.Fatalf("command output was %q; want exactly one line %q", string(output), want)
	}
}

func commandLines(t *testing.T, output []byte) []string {
	t.Helper()
	text := strings.ReplaceAll(string(output), "\r\n", "\n")
	if strings.ContainsRune(text, '\r') {
		t.Fatalf("command output contains a bare carriage return: %q", string(output))
	}
	if !strings.HasSuffix(text, "\n") {
		t.Fatalf("command output is not newline terminated: %q", string(output))
	}
	text = strings.TrimSuffix(text, "\n")
	lines := strings.Split(text, "\n")
	for _, line := range lines {
		if line == "" || strings.TrimSpace(line) != line {
			t.Fatalf("command output contains an empty or whitespace-padded line: %q", string(output))
		}
	}
	return lines
}

func importIdentityViolation(path string) string {
	if hasFoldedSegmentPrefix(path, legacyModule) {
		return "legacy module segment-prefix"
	}
	if hasFoldedSegmentPrefix(path, canonicalModule) && path != canonicalModule && !strings.HasPrefix(path, canonicalModule+"/") {
		return "canonical module prefix has non-exact ASCII case"
	}
	return ""
}

func hasFoldedSegmentPrefix(value, prefix string) bool {
	value = asciiLower(value)
	prefix = asciiLower(prefix)
	return value == prefix || strings.HasPrefix(value, prefix+"/")
}

func asciiLower(value string) string {
	buffer := []byte(value)
	for index, char := range buffer {
		if char >= 'A' && char <= 'Z' {
			buffer[index] = char + ('a' - 'A')
		}
	}
	return string(buffer)
}

type replacementClause struct {
	line int
	text string
}

func replacementClauses(content string) ([]replacementClause, error) {
	var clauses []replacementClause
	inBlock := false
	blockStart := 0
	for index, rawLine := range strings.Split(content, "\n") {
		lineNumber := index + 1
		line := strings.TrimSpace(stripLineComment(rawLine))
		if line == "" {
			continue
		}
		if inBlock {
			if closeIndex := strings.IndexByte(line, ')'); closeIndex >= 0 {
				before := strings.TrimSpace(line[:closeIndex])
				if before != "" {
					clauses = append(clauses, replacementClause{line: lineNumber, text: before})
				}
				if strings.TrimSpace(line[closeIndex+1:]) != "" {
					return nil, fmt.Errorf("unexpected content after replace block at line %d", lineNumber)
				}
				inBlock = false
				continue
			}
			clauses = append(clauses, replacementClause{line: lineNumber, text: line})
			continue
		}

		if !strings.HasPrefix(line, "replace") {
			continue
		}
		if len(line) > len("replace") && line[len("replace")] != ' ' && line[len("replace")] != '\t' && line[len("replace")] != '(' {
			continue
		}
		rest := strings.TrimSpace(line[len("replace"):])
		if strings.HasPrefix(rest, "(") {
			blockStart = lineNumber
			inBlock = true
			rest = strings.TrimSpace(rest[1:])
			if rest == "" {
				continue
			}
			if closeIndex := strings.IndexByte(rest, ')'); closeIndex >= 0 {
				before := strings.TrimSpace(rest[:closeIndex])
				if before != "" {
					clauses = append(clauses, replacementClause{line: lineNumber, text: before})
				}
				if strings.TrimSpace(rest[closeIndex+1:]) != "" {
					return nil, fmt.Errorf("unexpected content after replace block at line %d", lineNumber)
				}
				inBlock = false
			}
			continue
		}
		if rest != "" {
			clauses = append(clauses, replacementClause{line: lineNumber, text: rest})
		}
	}
	if inBlock {
		return nil, fmt.Errorf("unterminated replace block starting at line %d", blockStart)
	}
	return clauses, nil
}

func stripLineComment(line string) string {
	inQuote := byte(0)
	escaped := false
	for index := 0; index+1 < len(line); index++ {
		char := line[index]
		if inQuote != 0 {
			if escaped {
				escaped = false
				continue
			}
			if char == '\\' && inQuote == '"' {
				escaped = true
				continue
			}
			if char == inQuote {
				inQuote = 0
			}
			continue
		}
		if char == '"' || char == '\'' {
			inQuote = char
			continue
		}
		if char == '/' && line[index+1] == '/' {
			return line[:index]
		}
	}
	return line
}

type powershellStatement struct {
	line int
	text string
}

func powershellStatements(script string) []powershellStatement {
	var statements []powershellStatement
	current := ""
	start := 0
	for index, rawLine := range strings.Split(strings.ReplaceAll(script, "\r\n", "\n"), "\n") {
		lineNumber := index + 1
		line := strings.TrimSpace(rawLine)
		if current == "" {
			start = lineNumber
		}
		continued := strings.HasSuffix(line, "`")
		line = strings.TrimSpace(strings.TrimSuffix(line, "`"))
		if current == "" {
			current = line
		} else {
			current += " " + line
		}
		if continued {
			continue
		}
		statements = append(statements, powershellStatement{line: start, text: current})
		current = ""
	}
	if current != "" {
		statements = append(statements, powershellStatement{line: start, text: current})
	}
	return statements
}

func rootGoVersion(t *testing.T, path string) string {
	t.Helper()
	match := regexp.MustCompile(`(?m)^go[ \t]+([0-9]+\.[0-9]+(?:\.[0-9]+)?)[ \t]*\r?$`).FindSubmatch(readFile(t, path))
	if match == nil {
		t.Fatalf("%s has no simple go version directive", path)
	}
	return string(match[1])
}

func relativePath(root, path string) string {
	relative, err := filepath.Rel(root, path)
	if err != nil {
		return filepath.ToSlash(path)
	}
	return filepath.ToSlash(relative)
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func writeFile(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
}
