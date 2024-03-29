package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strings"
	"time"

	"github.com/omegaup/githttp/v2"
	"github.com/omegaup/gitserver"
	"github.com/omegaup/gitserver/request"
	"github.com/omegaup/go-base/logging/log15/v3"
	base "github.com/omegaup/go-base/v3"
	"github.com/omegaup/go-base/v3/logging"

	git "github.com/libgit2/git2go/v33"
	"github.com/pkg/errors"
)

var (
	reportPath = flag.String(
		"report-path",
		"",
		"path of a json file with the translation report",
	)
	ignoreCommitter = flag.Bool(
		"ignore-committer",
		false,
		"ignore the committer and use the author instead",
	)
	ignoreTimeLimit = flag.Bool(
		"ignore-time-limit",
		false,
		"ignore the hard wall time limit",
	)
)

type unmergeResult struct {
	OriginalCommitID      string `json:"original_commit_id,omitempty"`
	NewCommitID           string `json:"new_commit_id,omitempty"`
	OriginalPrivateTreeID string `json:"original_private_tree_id,omitempty"`
	NewPrivateTreeID      string `json:"new_private_tree_id,omitempty"`
	Published             bool   `json:"published,omitempty"`
}

type originalCommit struct {
	CommitID      string `json:"commit_id"`
	PrivateTreeID string `json:"private_tree_id"`
}

var _ fmt.Stringer = (*originalCommit)(nil)

func (c *originalCommit) String() string {
	return fmt.Sprintf("{CommitID: %q, PrivateTreeID: %q}", c.CommitID, c.PrivateTreeID)
}

type unmergeReport struct {
	CommitMapping        map[string]string `json:"commit_mapping,omitempty"`
	PrivateTreeIDMapping map[string]string `json:"private_tree_id_mapping,omitempty"`
	OriginalCommits      []*originalCommit `json:"original_commits,omitempty"`
}

func createPackfileFromSplitCommit(
	sourceRepo, destRepo *git.Repository,
	commit *git.Commit,
	publishedID *git.Oid,
	log logging.Logger,
) error {
	// Create the new commit object and add it to a packfile builder.
	head, err := destRepo.Head()
	if err != nil && !git.IsErrorCode(err, git.ErrorCodeUnbornBranch) {
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

	lockfileManager := githttp.NewLockfileManager()
	defer lockfileManager.Clear()

	lockfile := lockfileManager.NewLockfile(destRepo.Path())
	defer lockfile.Unlock()

	protocol := githttp.NewGitProtocol(githttp.GitProtocolOpts{
		AllowNonFastForward: true,
		Log:                 log,
	})

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

func mergeRepository(sourceRepositoryPath, destRepositoryPath string, log logging.Logger) error {
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

			log.Info(
				"commit",
				map[string]any{
					"id":      commit.Id().String(),
					"parents": commit.ParentCount(),
				},
			)
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
	ignoreCommitter bool,
	log logging.Logger,
) ([]*unmergeResult, error) {
	// Create the new commit object and add it to a packfile builder.
	head, err := destRepo.Head()
	if err != nil && !git.IsErrorCode(err, git.ErrorCodeUnbornBranch) {
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
	committer := commit.Committer()
	if ignoreCommitter {
		// Send the author as committer in case there was some surgery done to the commit.
		committer = commit.Author()
	}
	newCommitID, err := sourceRepo.CreateCommitFromIds(
		"",
		commit.Author(),
		committer,
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

	lockfileManager := githttp.NewLockfileManager()
	defer lockfileManager.Clear()

	lockfile := lockfileManager.NewLockfile(destRepo.Path())
	defer lockfile.Unlock()

	overallWallTimeHardLimit := gitserver.OverallWallTimeHardLimit
	if *ignoreTimeLimit {
		overallWallTimeHardLimit = base.Duration(time.Duration(int64(^uint64(0) >> 1)))
	}

	protocol := gitserver.NewGitProtocol(gitserver.GitProtocolOpts{
		GitProtocolOpts: githttp.GitProtocolOpts{
			Log: log,
		},
		LockfileManager:          lockfileManager,
		AllowDirectPushToMaster:  true,
		HardOverallWallTimeLimit: overallWallTimeHardLimit,
		InteractiveSettingsCompiler: &gitserver.LibinteractiveCompiler{
			LibinteractiveJarPath: "/usr/share/java/libinteractive.jar",
			Log:                   log,
		},
	})

	var oldCommitID *git.Oid
	if head != nil {
		oldCommitID = head.Target()
	}

	ctx := request.NewContext(context.Background(), nil)
	requestCtx := request.FromContext(ctx)
	requestCtx.Request.Create = false
	requestCtx.Request.IsAdmin = true
	requestCtx.Request.CanView = true
	requestCtx.Request.CanEdit = true

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

	var results []*unmergeResult
	trailers := strings.Split(
		strings.TrimSpace(commit.Message()[trailersIndex+2:]),
		"\n",
	)
	for _, trailer := range trailers {
		problemTagString := strings.TrimPrefix(trailer, "Omegaup-Translate-Problem-Tag: ")
		var singleResult unmergeResult

		if err := json.Unmarshal([]byte(problemTagString), &singleResult); err != nil {
			return nil, errors.Wrapf(err, "failed to unmarshal the problem tag for %q", problemTagString)
		}

		for _, updatedRef := range updatedRefs {
			if updatedRef.Name == "refs/heads/private" {
				singleResult.NewPrivateTreeID = updatedRef.ToTree
			}
			if updatedRef.Name == "refs/heads/master" {
				singleResult.NewCommitID = updatedRef.To
			}
		}

		if singleResult.Published {
			publishedID, err := git.NewOid(singleResult.NewCommitID)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to parse commit ID %q", singleResult.NewCommitID)
			}
			publishedReference, err := destRepo.References.Create("refs/heads/published", publishedID, true, "")
			if err != nil {
				return nil, errors.Wrapf(err, "failed to update published branch for commit %q", singleResult.NewCommitID)
			}
			publishedReference.Free()
		}
		results = append(results, &singleResult)
	}

	return results, nil
}

func unmergeRepository(
	ctx context.Context,
	sourceRepositoryPath,
	destRepositoryPath string,
	ignoreCommitter bool,
	log logging.Logger,
) (*unmergeReport, error) {
	sourceRepo, err := git.OpenRepository(sourceRepositoryPath)
	if err != nil {
		return nil, errors.Wrapf(
			err,
			"failed to open source repository at %s",
			sourceRepositoryPath,
		)
	}
	defer sourceRepo.Free()

	destRepo, err := gitserver.InitRepository(ctx, destRepositoryPath)
	if err != nil {
		return nil, errors.Wrapf(
			err,
			"failed to create destination repository at %s",
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

	report := &unmergeReport{
		CommitMapping:        make(map[string]string),
		PrivateTreeIDMapping: make(map[string]string),
	}
	lastPrivateTreeID := ""
	for _, commit := range commits {
		results, err := createPackfileFromMergedCommit(sourceRepo, destRepo, commit, ignoreCommitter, log)
		if err != nil {
			return nil, errors.Wrapf(
				err,
				"failed to merge commit %s",
				commit.Id(),
			)
		}
		for _, result := range results {
			report.CommitMapping[result.OriginalCommitID] = result.NewCommitID
			if result.NewPrivateTreeID != "" {
				lastPrivateTreeID = result.NewPrivateTreeID
			}
			report.PrivateTreeIDMapping[result.OriginalPrivateTreeID] = lastPrivateTreeID
			report.OriginalCommits = append(
				report.OriginalCommits,
				&originalCommit{
					CommitID:      result.OriginalCommitID,
					PrivateTreeID: result.OriginalPrivateTreeID,
				},
			)
		}
	}

	return report, nil
}

func main() {
	defer git.Shutdown()

	flag.Parse()
	log, err := log15.New("info", false)
	if err != nil {
		panic(err)
	}

	args := flag.Args()
	if len(args) != 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <merge|unmerge> <src> <dest>\n", os.Args[0])
		os.Exit(1)
	}

	ctx := context.Background()
	operation := args[0]
	sourceRepositoryPath := args[1]
	destRepositoryPath := args[2]

	if operation == "merge" {
		if err := mergeRepository(sourceRepositoryPath, destRepositoryPath, log); err != nil {
			log.Error(
				"failed to merge repository",
				map[string]any{
					"err": err,
				},
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
			log.Error(
				"failed to create report JSON file",
				map[string]any{
					"path": *reportPath,
					"err":  err,
				},
			)
			os.Exit(1)
		}
		defer f.Close()

		report, err := unmergeRepository(ctx, sourceRepositoryPath, destRepositoryPath, *ignoreCommitter, log)
		if err != nil {
			log.Error(
				"failed to unmerge repository",
				map[string]any{
					"err": err,
				},
			)
			os.Exit(1)
		}

		encoder := json.NewEncoder(f)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(report); err != nil {
			log.Error(
				"failed to marshal report",
				map[string]any{
					"path": *reportPath,
					"err":  err,
				},
			)
			os.Exit(1)
		}
	} else {
		log.Error(
			"unrecognized operation",
			map[string]any{
				"operation": operation,
			},
		)
		os.Exit(1)
	}
}
