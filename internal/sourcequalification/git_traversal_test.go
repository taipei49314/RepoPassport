package sourcequalification

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestGitTraversalUsesOnlyBoundedDirectoryReads(t *testing.T) {
	t.Parallel()
	if gitTraversalBatchSize != 128 || maximumGitMetadataEntries != 1_000_000 ||
		maximumGitWorktreeEntries != 1_000_000 || maximumGitTraversalDepth != 64 {
		t.Fatalf(
			"Git traversal bounds changed: batch=%d metadata=%d worktree=%d depth=%d",
			gitTraversalBatchSize,
			maximumGitMetadataEntries,
			maximumGitWorktreeEntries,
			maximumGitTraversalDepth,
		)
	}

	_, testPath, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate Git traversal contract test")
	}
	productionPath := filepath.Join(filepath.Dir(testPath), "git.go")
	file, err := parser.ParseFile(token.NewFileSet(), productionPath, nil, 0)
	if err != nil {
		t.Fatalf("parse git.go: %v", err)
	}

	readDirCalls := 0
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		packageName, packageCall := selector.X.(*ast.Ident)
		if selector.Sel.Name == "Walk" || selector.Sel.Name == "WalkDir" {
			t.Errorf("git.go uses allocation-unbounded filepath.%s", selector.Sel.Name)
		}
		if selector.Sel.Name != "ReadDir" {
			return true
		}
		readDirCalls++
		if packageCall && packageName.Name == "os" {
			t.Error("git.go uses allocation-unbounded os.ReadDir")
			return true
		}
		if len(call.Args) != 1 || !boundedGitReadDirArgument(call.Args[0]) {
			t.Error("git.go contains a ReadDir call not statically bounded to 128 entries")
		}
		return true
	})
	if readDirCalls == 0 {
		t.Fatal("git.go has no bounded ReadDir traversal")
	}
}

func TestGitTraversalConsumesBatchBeforeSortPathAllocationAndCallback(t *testing.T) {
	t.Parallel()

	_, testPath, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate Git traversal ordering contract test")
	}
	productionPath := filepath.Join(filepath.Dir(testPath), "git.go")
	file, err := parser.ParseFile(token.NewFileSet(), productionPath, nil, 0)
	if err != nil {
		t.Fatalf("parse git.go: %v", err)
	}

	var traversal *ast.FuncDecl
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok && function.Name.Name == "walkOpenedGitDirectory" {
			traversal = function
			break
		}
	}
	if traversal == nil {
		t.Fatal("walkOpenedGitDirectory is missing")
	}

	positions := map[string]token.Pos{}
	ast.Inspect(traversal.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch function := call.Fun.(type) {
		case *ast.Ident:
			if function.Name == "visit" && positions["visit"] == token.NoPos {
				positions["visit"] = call.Pos()
			}
		case *ast.SelectorExpr:
			receiver, _ := function.X.(*ast.Ident)
			switch {
			case function.Sel.Name == "ReadDir" && positions["read"] == token.NoPos:
				positions["read"] = call.Pos()
			case function.Sel.Name == "consume" && receiver != nil &&
				receiver.Name == "budget" && positions["consume"] == token.NoPos:
				positions["consume"] = call.Pos()
			case function.Sel.Name == "Slice" && receiver != nil &&
				receiver.Name == "sort" && positions["sort"] == token.NoPos:
				positions["sort"] = call.Pos()
			case function.Sel.Name == "Join" && receiver != nil &&
				receiver.Name == "filepath" && positions["path"] == token.NoPos:
				positions["path"] = call.Pos()
			}
		}
		return true
	})
	ordered := []string{"read", "consume", "sort", "path", "visit"}
	for index, name := range ordered {
		if positions[name] == token.NoPos {
			t.Fatalf("walkOpenedGitDirectory has no %s operation", name)
		}
		if index > 0 && positions[ordered[index-1]] >= positions[name] {
			t.Fatalf("Git traversal operation order is %v, want %v", positions, ordered)
		}
	}
}

func TestVerifyWorktreeUsesConstantTimeFixedHandleIdentitySet(t *testing.T) {
	t.Parallel()
	_, testPath, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate Git traversal identity contract test")
	}
	productionPath := filepath.Join(filepath.Dir(testPath), "git.go")
	file, err := parser.ParseFile(token.NewFileSet(), productionPath, nil, 0)
	if err != nil {
		t.Fatalf("parse git.go: %v", err)
	}

	var target *ast.FuncDecl
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok && function.Name.Name == "verifyWorktreeWithTraversalLimits" {
			target = function
			break
		}
	}
	if target == nil {
		t.Fatal("verifyWorktreeWithTraversalLimits is missing")
	}

	hasIdentityMap := false
	hasLinearHistory := false
	ast.Inspect(target.Body, func(node ast.Node) bool {
		switch current := node.(type) {
		case *ast.MapType:
			identifier, ok := current.Key.(*ast.Ident)
			if ok && identifier.Name == "packageFileIdentity" {
				hasIdentityMap = true
			}
		case *ast.Ident:
			if current.Name == "priorFileInfo" {
				hasLinearHistory = true
			}
		}
		return true
	})
	if !hasIdentityMap || hasLinearHistory {
		t.Fatalf("worktree hard-link detection must use a packageFileIdentity map, identityMap=%t linearHistory=%t", hasIdentityMap, hasLinearHistory)
	}
}

func boundedGitReadDirArgument(expression ast.Expr) bool {
	switch argument := expression.(type) {
	case *ast.Ident:
		return argument.Name == "gitTraversalBatchSize"
	case *ast.BasicLit:
		if argument.Kind != token.INT {
			return false
		}
		value, err := strconv.ParseInt(argument.Value, 0, 64)
		return err == nil && value > 0 && value <= 128
	default:
		return false
	}
}

func TestWalkGitTreeBoundedStopsBeforeCapPlusOneCallback(t *testing.T) {
	root := t.TempDir()
	for index := 0; index < 4; index++ {
		name := filepath.Join(root, "entry-"+strconv.Itoa(index))
		if err := os.WriteFile(name, []byte("bounded\n"), 0o600); err != nil {
			t.Fatalf("create traversal fixture: %v", err)
		}
	}

	budget := &gitTraversalBudget{maximumEntries: 4, maximumDepth: 8}
	visited := make([]string, 0, 4)
	err := walkGitTreeBounded(root, budget, func(path string, _ os.FileInfo, _ int) error {
		visited = append(visited, path)
		return nil
	})
	if !errors.Is(err, errGitTraversalEntryLimit) {
		t.Fatalf("walk error = %v, want entry-limit error", err)
	}
	if budget.entries != budget.maximumEntries {
		t.Fatalf("consumed entries = %d, want exact cap %d", budget.entries, budget.maximumEntries)
	}
	if len(visited) > budget.maximumEntries {
		t.Fatalf("callbacks = %d, exceeded total cap %d", len(visited), budget.maximumEntries)
	}
	for _, path := range visited {
		if filepath.Base(path) == "entry-3" {
			t.Fatal("cap+1 entry reached the callback")
		}
	}
}

func TestWalkGitTreeBoundedAcceptsExactCap(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"one", "two", "three"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(name), 0o600); err != nil {
			t.Fatalf("create traversal fixture: %v", err)
		}
	}

	budget := &gitTraversalBudget{maximumEntries: 4, maximumDepth: 8}
	callbacks := 0
	err := walkGitTreeBounded(root, budget, func(_ string, _ os.FileInfo, _ int) error {
		callbacks++
		return nil
	})
	if err != nil {
		t.Fatalf("exact-cap walk failed: %v", err)
	}
	if callbacks != budget.maximumEntries || budget.entries != budget.maximumEntries {
		t.Fatalf(
			"callbacks=%d consumed=%d, want exact cap %d",
			callbacks,
			budget.entries,
			budget.maximumEntries,
		)
	}
}

func TestWalkGitTreeBoundedRejectsDepthBeforeCallback(t *testing.T) {
	root := t.TempDir()
	deep := filepath.Join(root, "one", "two", "three")
	if err := os.MkdirAll(deep, 0o700); err != nil {
		t.Fatalf("create depth fixture: %v", err)
	}

	budget := &gitTraversalBudget{maximumEntries: 16, maximumDepth: 2}
	deepestCallback := -1
	err := walkGitTreeBounded(root, budget, func(_ string, _ os.FileInfo, depth int) error {
		if depth > deepestCallback {
			deepestCallback = depth
		}
		return nil
	})
	if !errors.Is(err, errGitTraversalDepthLimit) {
		t.Fatalf("walk error = %v, want depth-limit error", err)
	}
	if deepestCallback != budget.maximumDepth {
		t.Fatalf("deepest callback = %d, want %d", deepestCallback, budget.maximumDepth)
	}
}

func TestWalkGitTreeBoundedRejectsRedirectBeforeCallback(t *testing.T) {
	root := t.TempDir()
	target := t.TempDir()
	redirect := filepath.Join(root, "redirect")
	if !createDirectoryRedirectForTest(t, redirect, target) {
		t.Skip("directory redirects are unavailable without elevated host support")
	}

	budget := &gitTraversalBudget{maximumEntries: 8, maximumDepth: 8}
	redirectVisited := false
	err := walkGitTreeBounded(root, budget, func(path string, _ os.FileInfo, _ int) error {
		if sameCanonicalPath(path, redirect) {
			redirectVisited = true
		}
		return nil
	})
	if err == nil {
		t.Fatal("redirected directory was accepted")
	}
	if redirectVisited {
		t.Fatal("redirected directory reached the callback")
	}
}

func TestValidateObjectStoreLayoutCountsEveryEntry(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"aa", "bb", "cc"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(name), 0o600); err != nil {
			t.Fatalf("create object-store fixture: %v", err)
		}
	}

	err := validateObjectStoreLayoutWithLimits(root, 3, 8)
	if err == nil || !strings.Contains(err.Error(), "metadata entry bound") {
		t.Fatalf("object-store error = %v, want metadata entry bound", err)
	}
}

func TestVerifyWorktreeCountsGitDirectoryDescendants(t *testing.T) {
	root := t.TempDir()
	objectDirectory := filepath.Join(root, ".git", "objects", "aa")
	if err := os.MkdirAll(objectDirectory, 0o700); err != nil {
		t.Fatalf("create Git metadata fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(objectDirectory, "object"), []byte("object\n"), 0o600); err != nil {
		t.Fatalf("create Git object fixture: %v", err)
	}

	inspector := &repositoryInspector{root: root}
	err := inspector.verifyWorktreeWithTraversalLimits(nil, 3, 8)
	if err == nil || !strings.Contains(err.Error(), "inventory entry bound") {
		t.Fatalf("worktree error = %v, want inventory entry bound", err)
	}
}

func TestVerifyWorktreeTraversesExactTrackedFiles(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".git", "objects"), 0o700); err != nil {
		t.Fatalf("create Git metadata fixture: %v", err)
	}
	data := []byte("tracked\n")
	path := filepath.Join(root, "nested", "tracked.txt")
	if err := os.Mkdir(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("create tracked directory fixture: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("create tracked file fixture: %v", err)
	}

	inspector := &repositoryInspector{root: root}
	err := inspector.verifyWorktreeWithTraversalLimits([]RepositoryFile{{
		Path:    "nested/tracked.txt",
		GitMode: "100644",
		Size:    int64(len(data)),
		Data:    data,
	}}, 16, 8)
	if err != nil {
		t.Fatalf("exact tracked worktree failed verification: %v", err)
	}
}

func TestVerifyWorktreeConsumesUntrackedBatchBeforeValidation(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a-untracked"), []byte("untracked\n"), 0o600); err != nil {
		t.Fatalf("create untracked file fixture: %v", err)
	}
	if err := os.Mkdir(filepath.Join(root, "z-untracked-directory"), 0o700); err != nil {
		t.Fatalf("create untracked directory fixture: %v", err)
	}

	inspector := &repositoryInspector{root: root}
	err := inspector.verifyWorktreeWithTraversalLimits(nil, 2, 8)
	if err == nil || !strings.Contains(err.Error(), "inventory entry bound") {
		t.Fatalf("worktree error = %v, want pre-validation inventory entry bound", err)
	}
}
