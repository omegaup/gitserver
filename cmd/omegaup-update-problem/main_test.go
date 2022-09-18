package main

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"io/ioutil"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/omegaup/githttp/v2"
	"github.com/omegaup/gitserver"
	"github.com/omegaup/gitserver/gitservertest"
	"github.com/omegaup/go-base/logging/log15/v3"
	"github.com/omegaup/go-base/v3/logging"
	"github.com/omegaup/quark/common"

	git "github.com/libgit2/git2go/v33"
)

func getTreeOid(t *testing.T, extraFileContents map[string]io.Reader, log logging.Logger) *git.Oid {
	t.Helper()
	ctx := context.Background()
	tmpdir, err := ioutil.TempDir("", "gitrepo")
	if err != nil {
		t.Fatalf("Failed to create tempdir: %v", err)
	}
	if os.Getenv("PRESERVE") == "" {
		defer os.RemoveAll(tmpdir)
	}
	m := githttp.NewLockfileManager()
	defer m.Clear()

	fileContents := map[string]io.Reader{
		"cases/0.in":             strings.NewReader("1 2"),
		"cases/0.out":            strings.NewReader("3"),
		"statements/es.markdown": strings.NewReader("Sumas"),
	}
	for name, contents := range extraFileContents {
		fileContents[name] = contents
	}
	zipContents, err := gitservertest.CreateZip(fileContents)
	if err != nil {
		t.Fatalf("Failed to create zip: %v", err)
	}
	zipReader, err := zip.NewReader(bytes.NewReader(zipContents), int64(len(zipContents)))
	if err != nil {
		t.Fatalf("Failed to write zip: %v", err)
	}

	repo, err := gitserver.InitRepository(ctx, tmpdir)
	if err != nil {
		t.Fatalf("Failed to initialize bare repository: %v", err)
	}

	lockfile := m.NewLockfile(repo.Path())
	if err := lockfile.RLock(); err != nil {
		t.Fatalf("Failed to acquire the lockfile: %v", err)
	}
	defer lockfile.Unlock()

	if _, err := commitZipFile(
		m,
		common.NewProblemFilesFromZip(zipReader, ":memory:"),
		repo,
		lockfile,
		"test",
		"initial commit",
		nil,
		gitserver.ZipMergeStrategyTheirs,
		true,
		true,
		log,
	); err != nil {
		t.Fatalf("Failed to commit zip: %v", err)
	}

	reference, err := repo.Head()
	if err != nil {
		t.Fatalf("Failed to get head reference: %v", err)
	}
	defer reference.Free()

	commit, err := repo.LookupCommit(reference.Target())
	if err != nil {
		t.Fatalf("Failed to get headi commit: %v", err)
	}
	defer commit.Free()

	log.Info(
		"Commit",
		map[string]any{
			"parents": commit.ParentCount(),
		},
	)

	return commit.TreeId()
}

func TestIdenticalTrees(t *testing.T) {
	log, err := log15.New("info", false)
	if err != nil {
		t.Fatalf("Failed to create log: %v", err)
	}

	defaultSettingsTree := getTreeOid(t, map[string]io.Reader{}, log)

	explicitSettingsTree := getTreeOid(t, map[string]io.Reader{
		"settings.json": strings.NewReader(gitservertest.DefaultSettingsJSON),
	}, log)
	if !defaultSettingsTree.Equal(explicitSettingsTree) {
		t.Errorf(
			"explicit settings.json tree. Expected %q, got %q",
			defaultSettingsTree.String(),
			explicitSettingsTree.String(),
		)
	}
	testplanTree := getTreeOid(t, map[string]io.Reader{
		"testplan": strings.NewReader("0 1"),
	}, log)
	if !defaultSettingsTree.Equal(testplanTree) {
		t.Errorf(
			"testplan tree. Expected %q, got %q",
			defaultSettingsTree.String(),
			testplanTree.String(),
		)
	}
}

func discoverReferences(t *testing.T, repo *git.Repository) map[string]*git.Oid {
	it, err := repo.NewReferenceIterator()
	if err != nil {
		t.Fatalf("Failed to create ReferenceIterator: %v", err)
	}
	defer it.Free()

	references := make(map[string]*git.Oid)
	for {
		ref, err := it.Next()
		if err != nil {
			if git.IsErrorCode(err, git.ErrorCodeIterOver) {
				break
			}
			t.Fatalf("Failed to iterate references: %v", err)
		}
		references[ref.Name()] = ref.Target()
	}
	return references
}

func validateReferences(
	t *testing.T,
	repo *git.Repository,
	oldReferences, newReferences map[string]*git.Oid,
) {
	// old master should have three parents.
	oldMasterCommit, err := repo.LookupCommit(oldReferences["refs/heads/master"])
	if err != nil {
		t.Fatalf("Failed to find old master commit: %v", err)
	}
	if oldMasterCommit.ParentCount() != 3 {
		t.Errorf("Expected 3 parents, got %d", oldMasterCommit.ParentCount())
	}

	// private and protected should be unmodified refs.
	if !oldReferences["refs/heads/private"].Equal(newReferences["refs/heads/private"]) {
		t.Errorf(
			"Unexpected change to refs/heads/private. Expected %s, got %s",
			oldReferences["refs/heads/private"].String(),
			newReferences["refs/heads/private"].String(),
		)
	}
	if !oldReferences["refs/heads/protected"].Equal(newReferences["refs/heads/protected"]) {
		t.Errorf(
			"Unexpected change to refs/heads/protected. Expected %s, got %s",
			oldReferences["refs/heads/protected"].String(),
			newReferences["refs/heads/protected"].String(),
		)
	}

	// public and master should be modified.
	if oldReferences["refs/heads/public"].Equal(newReferences["refs/heads/public"]) {
		t.Errorf(
			"Unexpected non-change to refs/heads/public. Expected not %s, got %s",
			oldReferences["refs/heads/public"].String(),
			newReferences["refs/heads/public"].String(),
		)
	}
	if oldReferences["refs/heads/master"].Equal(newReferences["refs/heads/master"]) {
		t.Errorf(
			"Unexpected non-change to refs/heads/master. Expected not %s, got %s",
			oldReferences["refs/heads/master"].String(),
			newReferences["refs/heads/master"].String(),
		)
	}

	// new master should have four parents.
	newMasterCommit, err := repo.LookupCommit(newReferences["refs/heads/master"])
	if err != nil {
		t.Fatalf("Failed to find old master commit: %v", err)
	}
	if newMasterCommit.ParentCount() != 4 {
		t.Errorf("Expected 4 parents, got %d", newMasterCommit.ParentCount())
	}
}

func TestProblemUpdateZip(t *testing.T) {
	log, err := log15.New("info", false)
	if err != nil {
		t.Fatalf("Failed to create log: %v", err)
	}

	tmpdir, err := ioutil.TempDir("", "gitrepo")
	if err != nil {
		t.Fatalf("Failed to create tempdir: %v", err)
	}
	if os.Getenv("PRESERVE") == "" {
		defer os.RemoveAll(tmpdir)
	}
	m := githttp.NewLockfileManager()
	defer m.Clear()
	ctx := context.Background()

	repo, err := gitserver.InitRepository(ctx, tmpdir)
	if err != nil {
		t.Fatalf("Failed to initialize bare repository: %v", err)
	}

	lockfile := m.NewLockfile(repo.Path())
	if err := lockfile.RLock(); err != nil {
		t.Fatalf("Failed to acquire the lockfile: %v", err)
	}
	defer lockfile.Unlock()

	var oldReferences, newReferences map[string]*git.Oid
	{
		// One of the statements has a typo.
		zipContents, err := gitservertest.CreateZip(map[string]io.Reader{
			"cases/0.in":             strings.NewReader("1 2"),
			"cases/0.out":            strings.NewReader("3"),
			"statements/es.markdown": strings.NewReader("Sumaz"),
		})
		if err != nil {
			t.Fatalf("Failed to create zip: %v", err)
		}
		zipReader, err := zip.NewReader(bytes.NewReader(zipContents), int64(len(zipContents)))
		if err != nil {
			t.Fatalf("Failed to write zip: %v", err)
		}

		updateResult, err := commitZipFile(
			m,
			common.NewProblemFilesFromZip(zipReader, ":memory:"),
			repo,
			lockfile,
			"test",
			"initial commit",
			nil,
			gitserver.ZipMergeStrategyTheirs,
			true,
			true,
			log,
		)
		if err != nil {
			t.Fatalf("Failed to commit zip: %v", err)
		}
		if err := lockfile.Unlock(); err != nil {
			t.Fatalf("Failed to release the lockfile: %v", err)
		}
		if err := lockfile.RLock(); err != nil {
			t.Fatalf("Failed to acquire the lockfile: %v", err)
		}

		expectedUpdatedFiles := []gitserver.UpdatedFile{
			{Path: ".gitattributes", Type: "added"},
			{Path: ".gitignore", Type: "added"},
			{Path: "cases/0.in", Type: "added"},
			{Path: "cases/0.out", Type: "added"},
			{Path: "settings.distrib.json", Type: "added"},
			{Path: "settings.json", Type: "added"},
			{Path: "statements/es.markdown", Type: "added"},
		}
		if !reflect.DeepEqual(expectedUpdatedFiles, updateResult.UpdatedFiles) {
			t.Errorf(
				"updated files. expected %v, got %v",
				expectedUpdatedFiles,
				updateResult.UpdatedFiles,
			)
		}

		oldReferences = discoverReferences(t, repo)
	}
	{
		// Typo has been corrected.
		zipContents, err := gitservertest.CreateZip(map[string]io.Reader{
			"cases/0.in":             strings.NewReader("1 2"),
			"cases/0.out":            strings.NewReader("3"),
			"statements/es.markdown": strings.NewReader("Sumas"),
		})
		if err != nil {
			t.Fatalf("Failed to create zip: %v", err)
		}
		zipReader, err := zip.NewReader(bytes.NewReader(zipContents), int64(len(zipContents)))
		if err != nil {
			t.Fatalf("Failed to write zip: %v", err)
		}

		updateResult, err := commitZipFile(
			m,
			common.NewProblemFilesFromZip(zipReader, ":memory:"),
			repo,
			lockfile,
			"test",
			"fix a typo",
			nil,
			gitserver.ZipMergeStrategyTheirs,
			true,
			true,
			log,
		)
		if err != nil {
			t.Fatalf("Failed to commit zip: %v", err)
		}
		if err := lockfile.Unlock(); err != nil {
			t.Fatalf("Failed to release the lockfile: %v", err)
		}
		if err := lockfile.RLock(); err != nil {
			t.Fatalf("Failed to acquire the lockfile: %v", err)
		}

		expectedUpdatedFiles := []gitserver.UpdatedFile{
			{Path: "statements/es.markdown", Type: "modified"},
		}
		if !reflect.DeepEqual(expectedUpdatedFiles, updateResult.UpdatedFiles) {
			t.Errorf(
				"updated files. expected %v, got %v",
				expectedUpdatedFiles,
				updateResult.UpdatedFiles,
			)
		}

		newReferences = discoverReferences(t, repo)
	}

	validateReferences(t, repo, oldReferences, newReferences)
}

func TestProblemUpdateBlobs(t *testing.T) {
	log, err := log15.New("info", false)
	if err != nil {
		t.Fatalf("Failed to create log: %v", err)
	}

	tmpdir, err := ioutil.TempDir("", "gitrepo")
	if err != nil {
		t.Fatalf("Failed to create tempdir: %v", err)
	}
	if os.Getenv("PRESERVE") == "" {
		defer os.RemoveAll(tmpdir)
	}
	m := githttp.NewLockfileManager()
	defer m.Clear()
	ctx := context.Background()

	repo, err := gitserver.InitRepository(ctx, tmpdir)
	if err != nil {
		t.Fatalf("Failed to initialize bare repository: %v", err)
	}

	lockfile := m.NewLockfile(repo.Path())
	if err := lockfile.RLock(); err != nil {
		t.Fatalf("Failed to acquire the lockfile: %v", err)
	}
	defer lockfile.Unlock()

	var oldReferences, newReferences map[string]*git.Oid
	{
		// One of the statements has a typo.
		zipContents, err := gitservertest.CreateZip(map[string]io.Reader{
			"cases/0.in":             strings.NewReader("1 2"),
			"cases/0.out":            strings.NewReader("3"),
			"statements/es.markdown": strings.NewReader("Sumaz"),
		})
		if err != nil {
			t.Fatalf("Failed to create zip: %v", err)
		}
		zipReader, err := zip.NewReader(bytes.NewReader(zipContents), int64(len(zipContents)))
		if err != nil {
			t.Fatalf("Failed to write zip: %v", err)
		}

		updateResult, err := commitZipFile(
			m,
			common.NewProblemFilesFromZip(zipReader, ":memory:"),
			repo,
			lockfile,
			"test",
			"initial commit",
			nil,
			gitserver.ZipMergeStrategyTheirs,
			true,
			true,
			log,
		)
		if err != nil {
			t.Fatalf("Failed to commit zip: %v", err)
		}
		if err := lockfile.Unlock(); err != nil {
			t.Fatalf("Failed to release the lockfile: %v", err)
		}
		if err := lockfile.RLock(); err != nil {
			t.Fatalf("Failed to acquire the lockfile: %v", err)
		}

		expectedUpdatedFiles := []gitserver.UpdatedFile{
			{Path: ".gitattributes", Type: "added"},
			{Path: ".gitignore", Type: "added"},
			{Path: "cases/0.in", Type: "added"},
			{Path: "cases/0.out", Type: "added"},
			{Path: "settings.distrib.json", Type: "added"},
			{Path: "settings.json", Type: "added"},
			{Path: "statements/es.markdown", Type: "added"},
		}
		if !reflect.DeepEqual(expectedUpdatedFiles, updateResult.UpdatedFiles) {
			t.Errorf(
				"updated files. expected %v, got %v",
				expectedUpdatedFiles,
				updateResult.UpdatedFiles,
			)
		}

		oldReferences = discoverReferences(t, repo)
	}
	{
		// Typo has been corrected.
		if _, err = commitBlobs(
			m,
			repo,
			lockfile,
			"test",
			"fix a typo",
			map[string]io.Reader{
				"statements/es.markdown": strings.NewReader("Sumas"),
			},
			log,
		); err != nil {
			t.Fatalf("Failed to commit blobs: %v", err)
		}
		if err := lockfile.Unlock(); err != nil {
			t.Fatalf("Failed to release the lockfile: %v", err)
		}
		if err := lockfile.RLock(); err != nil {
			t.Fatalf("Failed to acquire the lockfile: %v", err)
		}

		newReferences = discoverReferences(t, repo)
	}

	validateReferences(t, repo, oldReferences, newReferences)
}
