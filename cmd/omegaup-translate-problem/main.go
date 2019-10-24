package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/inconshreveable/log15"
	git "github.com/lhchavez/git2go"
	"github.com/omegaup/githttp"
	"github.com/omegaup/gitserver"
	"github.com/omegaup/gitserver/request"
	base "github.com/omegaup/go-base"
	"github.com/pkg/errors"
	"io/ioutil"
	"os"
	"path"
	"strings"
)

var (
	reportPath = flag.String(
		"report-path",
		"",
		"path of a json file with the translation report",
	)
)

type unmergeResult struct {
	OriginalCommitID      string `json:"original_commit_id,omitempty"`
	NewCommitID           string `json:"new_commit_id,omitempty"`
	OriginalPrivateTreeID string `json:"original_private_tree_id,omitempty"`
	NewPrivateTreeID      string `json:"new_private_tree_id,omitempty"`
	Published             bool   `json:"published,omitempty"`
}

func createPackfileFromSplitCommit(
	sourceRepo, destRepo *git.Repository,
	commit *git.Commit,
	publishedID *git.Oid,
	log log15.Logger,
) error {
	// Create the new commit object and add it to a packfile builder.
	head, err := destRepo.Head()
	if err != nil && !git.IsErrorCode(err, git.ErrUnbornBranch) {
		return errors.Wrap(err, "failed to get HEAD for new repository")
	}
	if head != nil {
		defer head.Free()
	}

	privateCommit := commit.Parent(commit.ParentCount() - 1)
	defer privateCommit.Free()

	privateTree, err := privateCommit.Tree()
	if err != nil {
		return errors.Wrapf(
			err,
			"failed to get tree for commit %s in private branch",
			privateCommit.Id(),
		)
	}
	defer privateTree.Free()

	var parents []*git.Oid
	if head != nil {
		parents = append(parents, head.Target())
	}
	problemTag, err := json.Marshal(unmergeResult{
		OriginalCommitID:      commit.Id().String(),
		OriginalPrivateTreeID: privateTree.Id().String(),
		Published:             commit.Id().Equal(publishedID),
	})
	if err != nil {
		return errors.Wrap(err, "failed to marshal the problem tag")
	}
	newCommitID, err := sourceRepo.CreateCommitFromIds(
		"",
		commit.Author(),
		commit.Committer(),
		fmt.Sprintf(
			"%s\n\nOmegaup-Translate-Problem-Tag: %s",
			commit.Message(),
			string(problemTag),
		),
		commit.TreeId(),
		parents...,
	)
	if err != nil {
		return errors.Wrap(err, "failed to create new commit")
	}

	packbuilder, err := sourceRepo.NewPackbuilder()
	if err != nil {
		return errors.Wrap(err, "failed to create packbuilder")
	}
	defer packbuilder.Free()

	if err := packbuilder.InsertCommit(newCommitID); err != nil {
		return errors.Wrap(
			err,
			"failed to create insert new commit into the packbuilder",
		)
	}

	var buf bytes.Buffer
	if err := packbuilder.Write(&buf); err != nil {
		return errors.Wrapf(err, "failed to write packfile into the packbuilder")
	}

	lockfile := githttp.NewLockfile(destRepo.Path())
	defer lockfile.Unlock()

	protocol := githttp.NewGitProtocol(
		nil,
		nil,
		nil,
		nil,
		true,
		log,
	)

	var oldCommitID *git.Oid
	if head != nil {
		oldCommitID = head.Target()
	}

	_, err, unpackErr := protocol.PushPackfile(
		context.Background(),
		destRepo,
		lockfile,
		githttp.AuthorizationAllowed,
		[]*githttp.GitCommand{
			{
				Old:           oldCommitID,
				New:           newCommitID,
				ReferenceName: "refs/heads/master",
				Reference:     nil,
			},
		},
		&buf,
	)
	if unpackErr != nil {
		return errors.Wrapf(err, "failed to unpack packfile")
	}
	if err != nil {
		return errors.Wrapf(err, "failed to push packfile")
	}

	return nil
}

func mergeRepository(sourceRepositoryPath, destRepositoryPath string, log log15.Logger) error {
	sourceRepo, err := git.OpenRepository(sourceRepositoryPath)
	if err != nil {
		return errors.Wrapf(
			err,
			"failed to open source repository at %s",
			sourceRepositoryPath,
		)
	}
	defer sourceRepo.Free()

	destRepo, err := git.InitRepository(destRepositoryPath, true)
	if err != nil {
		return errors.Wrapf(
			err,
			"failed to open destination repository at %s",
			destRepositoryPath,
		)
	}
	defer destRepo.Free()

	// Setup a temporary ODB in the source repository to create the new commit
	// object.
	odb, err := sourceRepo.Odb()
	if err != nil {
		return errors.Wrapf(
			err,
			"failed to create a new object database for source repository at %s",
			sourceRepositoryPath,
		)
	}
	defer odb.Free()

	looseObjectsDir, err := ioutil.TempDir("", fmt.Sprintf("loose_objects_%s", path.Base(sourceRepo.Path())))
	if err != nil {
		return errors.Wrap(
			err,
			"failed to create temporary directory for loose objects",
		)
	}
	defer os.RemoveAll(looseObjectsDir)

	looseObjectsBackend, err := git.NewOdbBackendLoose(looseObjectsDir, -1, false, 0, 0)
	if err != nil {
		return errors.Wrap(
			err,
			"failed to create a new loose object backend",
		)
	}
	if err := odb.AddBackend(looseObjectsBackend, 999); err != nil {
		looseObjectsBackend.Free()
		return errors.Wrap(
			err,
			"failed to register loose object backend",
		)
	}

	masterBranch, err := sourceRepo.LookupBranch("master", git.BranchLocal)
	if err != nil {
		return errors.Wrap(err, "failed to lookup master branch")
	}
	defer masterBranch.Free()

	masterObject, err := masterBranch.Peel(git.ObjectCommit)
	if err != nil {
		return errors.Wrap(err, "failed to peel master branch")
	}
	defer masterObject.Free()

	master, err := masterObject.AsCommit()
	if err != nil {
		return errors.Wrap(err, "failed to get master commit")
	}
	defer master.Free()

	var commits []*git.Commit
	{
		commit := master
		for {
			if commit.ParentCount() < 3 || commit.ParentCount() > 4 {
				return errors.Errorf(
					"commit %s has %d parents, expected 3 or 4",
					commit.Id(),
					commit.ParentCount(),
				)
			}
			commits = append(commits, commit)

			commit = commit.Parent(0)
			defer commit.Free()

			if commit.ParentCount() == 0 {
				// First commit in the public branch.
				break
			}
		}
	}

	// Reverse the commit array
	for i, j := 0, len(commits)-1; i < j; i, j = i+1, j-1 {
		commits[i], commits[j] = commits[j], commits[i]
	}

	publishedBranch, err := sourceRepo.LookupBranch("published", git.BranchLocal)
	if err != nil {
		return errors.Wrap(err, "failed to lookup master branch")
	}
	defer publishedBranch.Free()

	for _, commit := range commits {
		if err := createPackfileFromSplitCommit(
			sourceRepo,
			destRepo,
			commit,
			publishedBranch.Target(),
			log,
		); err != nil {
			return errors.Wrapf(
				err,
				"failed to merge commit %s",
				commit.Id(),
			)
		}
	}

	return nil
}

func createPackfileFromMergedCommit(
	sourceRepo, destRepo *git.Repository,
	commit *git.Commit,
	log log15.Logger,
) (*unmergeResult, error) {
	// Create the new commit object and add it to a packfile builder.
	head, err := destRepo.Head()
	if err != nil && !git.IsErrorCode(err, git.ErrUnbornBranch) {
		return nil, errors.Wrap(err, "failed to get HEAD for new repository")
	}
	if head != nil {
		defer head.Free()
	}

	trailersIndex := strings.LastIndex(commit.Message(), "\n\n")
	if trailersIndex == -1 {
		return nil, errors.Errorf("trailer block not found in %q", commit.Message())
	}

	var parents []*git.Oid
	if commit.ParentCount() > 0 {
		parents = append(parents, commit.ParentId(0))
	}
	newCommitID, err := sourceRepo.CreateCommitFromIds(
		"",
		commit.Author(),
		commit.Committer(),
		commit.Message()[:trailersIndex],
		commit.TreeId(),
		parents...,
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create new commit")
	}

	var parentCommit *git.Commit
	if commit.ParentCount() > 0 {
		parentCommit = commit.Parent(0)
		defer parentCommit.Free()
	}

	packbuilder, err := sourceRepo.NewPackbuilder()
	if err != nil {
		return nil, errors.Wrap(err, "failed to create packbuilder")
	}
	defer packbuilder.Free()

	if err := packbuilder.InsertCommit(newCommitID); err != nil {
		return nil, errors.Wrap(
			err,
			"failed to create insert new commit into the packbuilder",
		)
	}

	var buf bytes.Buffer
	if err := packbuilder.Write(&buf); err != nil {
		return nil, errors.Wrapf(err, "failed to write packfile into the packbuilder")
	}

	lockfile := githttp.NewLockfile(destRepo.Path())
	defer lockfile.Unlock()

	protocol := gitserver.NewGitProtocol(
		nil,
		nil,
		true,
		gitserver.OverallWallTimeHardLimit,
		&gitserver.LibinteractiveCompiler{
			LibinteractiveJarPath: "/usr/share/java/libinteractive.jar",
			Log:                   log,
		},
		log,
	)

	var oldCommitID *git.Oid
	if head != nil {
		oldCommitID = head.Target()
	}

	ctx := request.NewContext(context.Background(), nil)
	requestCtx := request.FromContext(ctx)
	requestCtx.Create = false
	requestCtx.IsAdmin = true
	requestCtx.CanView = true
	requestCtx.CanEdit = true

	updatedRefs, err, unpackErr := protocol.PushPackfile(
		ctx,
		destRepo,
		lockfile,
		githttp.AuthorizationAllowed,
		[]*githttp.GitCommand{
			{
				Old:           oldCommitID,
				New:           newCommitID,
				ReferenceName: "refs/heads/master",
				Reference:     nil,
			},
		},
		&buf,
	)
	if unpackErr != nil {
		return nil, errors.Wrap(err, "failed to unpack packfile")
	}
	if err != nil {
		return nil, errors.Wrap(err, "failed to push packfile")
	}

	problemTagString := strings.TrimPrefix(
		commit.Message()[trailersIndex+2:],
		"Omegaup-Translate-Problem-Tag: ",
	)
	var result unmergeResult

	if err := json.Unmarshal([]byte(problemTagString), &result); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal the problem tag")
	}

	for _, updatedRef := range updatedRefs {
		if updatedRef.Name == "refs/heads/private" {
			result.NewPrivateTreeID = updatedRef.ToTree
		}
		if updatedRef.Name == "refs/heads/master" {
			result.NewCommitID = updatedRef.To
		}
	}

	if result.Published {
		publishedID, err := git.NewOid(result.NewCommitID)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to parse commit ID %q", result.NewCommitID)
		}
		publishedReference, err := destRepo.References.Create("refs/heads/published", publishedID, true, "")
		if err != nil {
			return nil, errors.Wrapf(err, "failed to update published branch for commit %q", result.NewCommitID)
		}
		publishedReference.Free()
	}

	return &result, nil
}

func unmergeRepository(sourceRepositoryPath, destRepositoryPath string, log log15.Logger) ([]unmergeResult, error) {
	sourceRepo, err := git.OpenRepository(sourceRepositoryPath)
	if err != nil {
		return nil, errors.Wrapf(
			err,
			"failed to open source repository at %s",
			sourceRepositoryPath,
		)
	}
	defer sourceRepo.Free()

	destRepo, err := git.InitRepository(destRepositoryPath, true)
	if err != nil {
		return nil, errors.Wrapf(
			err,
			"failed to open destination repository at %s",
			destRepositoryPath,
		)
	}
	defer destRepo.Free()

	// Setup a temporary ODB in the source repository to create the new commit
	// object.
	odb, err := sourceRepo.Odb()
	if err != nil {
		return nil, errors.Wrapf(
			err,
			"failed to create a new object database for source repository at %s",
			sourceRepositoryPath,
		)
	}
	defer odb.Free()

	looseObjectsDir, err := ioutil.TempDir("", fmt.Sprintf("loose_objects_%s", path.Base(sourceRepo.Path())))
	if err != nil {
		return nil, errors.Wrap(
			err,
			"failed to create temporary directory for loose objects",
		)
	}
	defer os.RemoveAll(looseObjectsDir)

	looseObjectsBackend, err := git.NewOdbBackendLoose(looseObjectsDir, -1, false, 0, 0)
	if err != nil {
		return nil, errors.Wrap(
			err,
			"failed to create a new loose object backend",
		)
	}
	if err := odb.AddBackend(looseObjectsBackend, 999); err != nil {
		looseObjectsBackend.Free()
		return nil, errors.Wrap(
			err,
			"failed to register loose object backend",
		)
	}

	masterBranch, err := sourceRepo.LookupBranch("master", git.BranchLocal)
	if err != nil {
		return nil, errors.Wrap(err, "failed to lookup master branch")
	}
	defer masterBranch.Free()

	masterObject, err := masterBranch.Peel(git.ObjectCommit)
	if err != nil {
		return nil, errors.Wrap(err, "failed to peel master branch")
	}
	defer masterObject.Free()

	master, err := masterObject.AsCommit()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get master commit")
	}
	defer master.Free()

	var commits []*git.Commit
	{
		commit := master
		for {
			if commit.ParentCount() > 1 {
				return nil, errors.Errorf(
					"commit %s has %d parents, expected 0 or 1",
					commit.Id(),
					commit.ParentCount(),
				)
			}

			commits = append(commits, commit)

			if commit.ParentCount() == 0 {
				// First commit in the branch.
				break
			}

			commit = commit.Parent(0)
			defer commit.Free()
		}
	}

	// Reverse the commit array
	for i, j := 0, len(commits)-1; i < j; i, j = i+1, j-1 {
		commits[i], commits[j] = commits[j], commits[i]
	}

	var results []unmergeResult
	for _, commit := range commits {
		result, err := createPackfileFromMergedCommit(sourceRepo, destRepo, commit, log)
		if err != nil {
			return nil, errors.Wrapf(
				err,
				"failed to merge commit %s",
				commit.Id(),
			)
		}
		results = append(results, *result)
	}

	return results, nil
}

func main() {
	defer git.Shutdown()

	flag.Parse()
	log := base.StderrLog()

	args := flag.Args()
	if len(args) != 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <merge|unmerge> <src> <dest>\n", os.Args[0])
		os.Exit(1)
	}

	operation := args[0]
	sourceRepositoryPath := args[1]
	destRepositoryPath := args[2]

	if operation == "merge" {
		if err := mergeRepository(sourceRepositoryPath, destRepositoryPath, log); err != nil {
			log.Crit(
				"failed to merge repository",
				"err", err,
			)
			os.Exit(1)
		}
	} else if operation == "unmerge" {
		if *reportPath == "" {
			fmt.Fprintf(os.Stderr, "Usage: %s unmerge <src> <dest> -report-path=somefile.json\n", os.Args[0])
			os.Exit(1)
		}

		f, err := os.Create(*reportPath)
		if err != nil {
			log.Crit(
				"failed to create report JSON file",
				"path", *reportPath,
				"err", err,
			)
			os.Exit(1)
		}
		defer f.Close()

		report, err := unmergeRepository(sourceRepositoryPath, destRepositoryPath, log)
		if err != nil {
			log.Crit(
				"failed to unmerge repository",
				"err", err,
			)
			os.Exit(1)
		}

		encoder := json.NewEncoder(f)
		encoder.SetIndent("  ", "  ")
		if err := encoder.Encode(report); err != nil {
			log.Crit(
				"failed to marshal report",
				"path", *reportPath,
				"err", err,
			)
			os.Exit(1)
		}
	} else {
		log.Crit(
			"unrecognized operation",
			"operation", operation,
		)
		os.Exit(1)
	}
}