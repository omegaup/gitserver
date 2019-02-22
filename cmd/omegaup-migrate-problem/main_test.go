package main

import (
	git "github.com/lhchavez/git2go"
	base "github.com/omegaup/go-base"
	"github.com/omegaup/quark/common"
	"io/ioutil"
	"os"
	"path"
	"testing"
	"time"
)

var (
	defaultSettings = common.ProblemSettings{
		Limits: common.LimitsSettings{
			MemoryLimit:          base.Byte(64) * base.Mebibyte,
			OutputLimit:          base.Byte(16) * base.Kibibyte,
			OverallWallTimeLimit: base.Duration(time.Duration(1) * time.Minute),
			TimeLimit:            base.Duration(time.Duration(3) * time.Second),
		},
		Slow: false,
		Validator: common.ValidatorSettings{
			Name: "token",
		},
	}
)

func testBranchContents(t *testing.T, repo *git.Repository, branchName string, fileList []string) {
	reference, err := repo.LookupBranch(branchName, git.BranchLocal)
	if err != nil {
		t.Fatalf("failed to lookup branch %s: %v", branchName, err)
	}
	defer reference.Free()

	commit, err := repo.LookupCommit(reference.Target())
	if err != nil {
		t.Fatalf("failed to get the commit for branch %s: %v", branchName, err)
	}
	defer commit.Free()

	tree, err := commit.Tree()
	if err != nil {
		t.Fatalf("failed to get the tree for branch %s: %v", branchName, err)
	}
	defer tree.Free()

	foundFiles := make(map[string]struct{})
	if err := tree.Walk(func(relativePath string, entry *git.TreeEntry) int {
		if entry.Type == git.ObjectBlob {
			foundFiles[path.Join(relativePath, entry.Name)] = struct{}{}
		}
		return 0
	}); err != nil {
		t.Fatalf("failed to walk the repository's HEAD tree: %v", err)
	}

	for _, filename := range fileList {
		if _, ok := foundFiles[filename]; !ok {
			t.Errorf("missing file in branch %s: %s", branchName, filename)
		}
		delete(foundFiles, filename)
	}
	if len(foundFiles) != 0 {
		t.Errorf("extra files found in branch %s: %v", branchName, foundFiles)
	}
}

func TestProblemMigrateNormal(t *testing.T) {
	tmpdir, err := ioutil.TempDir("", "omegaup-migrate-problem")
	if err != nil {
		t.Fatalf("failed to create tempdir: %v", err)
	}
	if os.Getenv("PRESERVE") == "" {
		defer os.RemoveAll(tmpdir)
	}

	log := base.StderrLog()

	settings := defaultSettings

	if err := migrateProblem(
		"testdata/sumas",
		tmpdir,
		&settings,
		true,
		log,
	); err != nil {
		t.Fatalf("failed to migrate problem: %v", err)
	}

	repo, err := git.OpenRepository(tmpdir)
	if err != nil {
		t.Fatalf("failed to open original repository: %v", err)
	}
	defer repo.Free()

	for branchName, fileList := range map[string][]string{
		"master": {
			".gitattributes",
			".gitignore",
			"cases/0.in",
			"cases/0.out",
			"cases/1.in",
			"cases/1.out",
			"settings.distrib.json",
			"settings.json",
			"statements/es.markdown",
		},
		"public": {
			".gitattributes",
			".gitignore",
			"settings.distrib.json",
			"statements/es.markdown",
		},
		"protected": {},
		"private": {
			"cases/0.in",
			"cases/0.out",
			"cases/1.in",
			"cases/1.out",
			"settings.json",
		},
	} {
		testBranchContents(t, repo, branchName, fileList)
	}
}

func TestProblemMigrateInteractive(t *testing.T) {
	if _, err := os.Stat("/usr/share/java/libinteractive.jar"); os.IsNotExist(err) {
		t.Skip("libinteractive not supported")
	}

	tmpdir, err := ioutil.TempDir("", "omegaup-migrate-problem")
	if err != nil {
		t.Fatalf("failed to create tempdir: %v", err)
	}
	if os.Getenv("PRESERVE") == "" {
		defer os.RemoveAll(tmpdir)
	}

	log := base.StderrLog()

	settings := defaultSettings

	if err := migrateProblem(
		"testdata/interactive",
		tmpdir,
		&settings,
		true,
		log,
	); err != nil {
		t.Fatalf("failed to migrate problem: %v", err)
	}

	repo, err := git.OpenRepository(tmpdir)
	if err != nil {
		t.Fatalf("failed to open original repository: %v", err)
	}
	defer repo.Free()

	for branchName, fileList := range map[string][]string{
		"master": {
			".gitattributes",
			".gitignore",
			"cases/0.in",
			"cases/0.out",
			"cases/sample.in",
			"cases/sample.out",
			"examples/sample.in",
			"examples/sample.out",
			"interactive/Main.cpp11",
			"interactive/Main.distrib.cpp11",
			"interactive/sumas.idl",
			"settings.distrib.json",
			"settings.json",
			"statements/es.markdown",
		},
		"public": {
			".gitattributes",
			".gitignore",
			"examples/sample.in",
			"examples/sample.out",
			"interactive/Main.distrib.cpp11",
			"settings.distrib.json",
			"statements/es.markdown",
		},
		"protected": {},
		"private": {
			"cases/0.in",
			"cases/0.out",
			"cases/sample.in",
			"cases/sample.out",
			"interactive/Main.cpp11",
			"interactive/sumas.idl",
			"settings.json",
		},
	} {
		testBranchContents(t, repo, branchName, fileList)
	}
}
