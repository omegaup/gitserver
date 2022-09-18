package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/omegaup/githttp/v2"
	"github.com/omegaup/gitserver"
	"github.com/omegaup/gitserver/request"
	"github.com/omegaup/go-base/logging/log15/v3"
	base "github.com/omegaup/go-base/v3"
	"github.com/omegaup/go-base/v3/logging"
	"github.com/omegaup/quark/common"

	git "github.com/libgit2/git2go/v33"
	"github.com/pkg/errors"
)

var (
	author              = flag.String("author", "", "Author of the commit")
	commitMessage       = flag.String("commit-message", "", "Commit message")
	repositoryPath      = flag.String("repository-path", "", "Path of the git repository")
	problemSettingsJSON = flag.String("problem-settings", "", "(Optional) JSON-encoded ProblemSettings")

	// Flags that are used when updating a repository with a .zip.
	zipPath            = flag.String("zip-path", "", "Path of the .zip file")
	mergeStrategyName  = flag.String("merge-strategy", "theirs", "Merge strategy to use. Valid values are 'ours', 'theirs', 'statement-ours', and 'recursive-theirs'")
	acceptsSubmissions = flag.Bool("accepts-submissions", true, "Problem accepts submissions")
	updatePublished    = flag.Bool("update-published", false, "Update the published branch")
	libinteractivePath = flag.String("libinteractive-path", "/usr/share/java/libinteractive.jar", "Path of libinteractive.jar")

	// Flags that are used when updating a repository with a []BlobUpdate.
	blobUpdateJSON = flag.String("blob-update", "", "Update a subset of the blobs")

	// An empty .zip file.
	emptyZipFile = []byte{
		0x50, 0x4b, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
)

// BlobUpdate represents updating a single blob in the repository.
type BlobUpdate struct {
	Path         string `json:"path"`
	ContentsPath string `json:"contents_path"`
}

func commitZipFile(
	lockfileManager *githttp.LockfileManager,
	problemFiles common.ProblemFiles,
	repo *git.Repository,
	lockfile *githttp.Lockfile,
	authorUsername string,
	commitMessage string,
	problemSettings *common.ProblemSettings,
	zipMergeStrategy gitserver.ZipMergeStrategy,
	acceptsSubmissions bool,
	updatePublished bool,
	log logging.Logger,
) (*gitserver.UpdateResult, error) {
	ctx := request.NewContext(context.Background(), &base.NoOpMetrics{})
	requestContext := request.FromContext(ctx)
	requestContext.Request.Username = authorUsername
	requestContext.Request.ProblemName = path.Base(repo.Path())
	requestContext.Request.IsAdmin = true
	requestContext.Request.CanView = true
	requestContext.Request.CanEdit = true

	protocol := gitserver.NewGitProtocol(gitserver.GitProtocolOpts{
		GitProtocolOpts: githttp.GitProtocolOpts{
			Log: log,
		},
		LockfileManager:          lockfileManager,
		AllowDirectPushToMaster:  true,
		HardOverallWallTimeLimit: gitserver.OverallWallTimeHardLimit,
		InteractiveSettingsCompiler: &gitserver.LibinteractiveCompiler{
			LibinteractiveJarPath: *libinteractivePath,
			Log:                   log,
		},
	})

	return gitserver.PushZip(
		ctx,
		problemFiles,
		githttp.AuthorizationAllowed,
		repo,
		lockfile,
		authorUsername,
		commitMessage,
		problemSettings,
		zipMergeStrategy,
		acceptsSubmissions,
		updatePublished,
		protocol,
		log,
	)
}

func convertBlobsToPackfile(
	contents map[string]io.Reader,
	repo *git.Repository,
	parent *git.Oid,
	author, committer *git.Signature,
	commitMessage string,
	w io.Writer,
	log logging.Logger,
) (*git.Oid, error) {
	headCommit, err := repo.LookupCommit(parent)
	if err != nil {
		return nil, errors.Wrap(
			err,
			"failed to get the repository's HEAD's commit",
		)
	}
	defer headCommit.Free()

	headTree, err := headCommit.Tree()
	if err != nil {
		return nil, errors.Wrap(
			err,
			"failed to get the repository's HEAD's commit's tree",
		)
	}
	defer headTree.Free()

	odb, err := repo.Odb()
	if err != nil {
		return nil, errors.Wrap(
			err,
			"failed to open odb",
		)
	}
	defer odb.Free()

	looseObjectsDir, err := ioutil.TempDir("", fmt.Sprintf("loose_objects_%s", path.Base(repo.Path())))
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
			"failed to create new loose object backend",
		)
	}
	if err := odb.AddBackend(looseObjectsBackend, 999); err != nil {
		looseObjectsBackend.Free()
		return nil, errors.Wrap(
			err,
			"failed to register loose object backend",
		)
	}

	tree, err := githttp.BuildTree(
		repo,
		contents,
		log,
	)
	if err != nil {
		return nil, errors.Wrap(
			err,
			"failed to create new tree",
		)
	}
	defer tree.Free()

	mergedTree, err := githttp.MergeTrees(
		repo,
		tree,
		headTree,
	)
	if err != nil {
		return nil, errors.Wrap(
			err,
			"failed to merge tree",
		)
	}
	defer mergedTree.Free()

	newCommitID, err := repo.CreateCommit(
		"",
		author,
		committer,
		commitMessage,
		mergedTree,
		headCommit,
	)
	if err != nil {
		return nil, errors.Wrap(
			err,
			"failed to create commit",
		)
	}

	walk, err := repo.Walk()
	if err != nil {
		return nil, errors.Wrap(
			err,
			"failed to create revwalk",
		)
	}
	defer walk.Free()

	if err := walk.Hide(headCommit.Id()); err != nil {
		return nil, errors.Wrapf(
			err,
			"failed to hide commit %s", headCommit.Id().String(),
		)
	}
	if err := walk.Push(newCommitID); err != nil {
		return nil, errors.Wrapf(
			err,
			"failed to add commit %s", newCommitID.String(),
		)
	}

	pb, err := repo.NewPackbuilder()
	if err != nil {
		return nil, errors.Wrap(
			err,
			"failed to create packbuilder",
		)
	}
	defer pb.Free()

	if err := pb.InsertWalk(walk); err != nil {
		return nil, errors.Wrap(
			err,
			"failed to insert walk into packbuilder",
		)
	}

	if err := pb.Write(w); err != nil {
		return nil, errors.Wrap(
			err,
			"failed to write packfile",
		)
	}

	return newCommitID, nil
}

func commitBlobs(
	lockfileManager *githttp.LockfileManager,
	repo *git.Repository,
	lockfile *githttp.Lockfile,
	authorUsername string,
	commitMessage string,
	contents map[string]io.Reader,
	log logging.Logger,
) (*gitserver.UpdateResult, error) {
	reference, err := repo.Head()
	if err != nil {
		log.Error(
			"Failed to get the repository's HEAD",
			map[string]any{
				"err": err,
			},
		)
		return nil, err
	}
	defer reference.Free()
	oldOid := reference.Target()

	signature := git.Signature{
		Name:  authorUsername,
		Email: fmt.Sprintf("%s@omegaup", authorUsername),
		When:  time.Now(),
	}

	var pack bytes.Buffer
	newOid, err := convertBlobsToPackfile(
		contents,
		repo,
		oldOid,
		&signature,
		&signature,
		commitMessage,
		&pack,
		log,
	)
	if err != nil {
		return nil, err
	}

	ctx := request.NewContext(context.Background(), &base.NoOpMetrics{})
	requestContext := request.FromContext(ctx)
	requestContext.Request.Username = authorUsername
	requestContext.Request.ProblemName = path.Base(repo.Path())
	requestContext.Request.IsAdmin = true
	requestContext.Request.CanView = true
	requestContext.Request.CanEdit = true

	protocol := gitserver.NewGitProtocol(gitserver.GitProtocolOpts{
		GitProtocolOpts: githttp.GitProtocolOpts{
			Log: log,
		},
		LockfileManager:          lockfileManager,
		AllowDirectPushToMaster:  true,
		HardOverallWallTimeLimit: gitserver.OverallWallTimeHardLimit,
		InteractiveSettingsCompiler: &gitserver.LibinteractiveCompiler{
			LibinteractiveJarPath: *libinteractivePath,
		},
	})
	updatedRefs, err, unpackErr := protocol.PushPackfile(
		ctx,
		repo,
		lockfile,
		githttp.AuthorizationAllowed,
		[]*githttp.GitCommand{
			{
				Old:           oldOid,
				New:           newOid,
				ReferenceName: "refs/heads/master",
				Reference:     reference,
			},
		},
		&pack,
	)
	if err != nil {
		log.Error(
			"Failed to push blobs",
			map[string]any{
				"err": err,
			},
		)
		return nil, err
	}
	if unpackErr != nil {
		log.Error(
			"Failed to unpack packfile",
			map[string]any{
				"err": unpackErr,
			},
		)
		return nil, err
	}

	updatedFiles, err := gitserver.GetUpdatedFiles(ctx, repo, updatedRefs)
	if err != nil {
		log.Error(
			"failed to get updated files",
			map[string]any{
				"err": err,
			},
		)
	}
	return &gitserver.UpdateResult{
		Status:       "ok",
		UpdatedRefs:  updatedRefs,
		UpdatedFiles: updatedFiles,
	}, nil
}

func main() {
	flag.Parse()
	log, err := log15.New("info", false)
	if err != nil {
		panic(err)
	}

	if *author == "" {
		log.Error("author cannot be empty. Please specify one with -author", nil)
		os.Exit(1)
	}
	if *commitMessage == "" {
		log.Error("commit message cannot be empty. Please specify one with -commit-message", nil)
		os.Exit(1)
	}
	if *repositoryPath == "" {
		log.Error("repository path cannot be empty. Please specify one with -repository-path", nil)
		os.Exit(1)
	}

	ctx := context.Background()
	var repo *git.Repository
	commitCallback := func() error { return nil }
	if _, err := os.Stat(*repositoryPath); os.IsNotExist(err) {
		dir, err := ioutil.TempDir(filepath.Dir(*repositoryPath), "repository")
		if err != nil {
			log.Error(
				"Failed to create temporary directory",
				map[string]any{
					"err": err,
				},
			)
			os.Exit(1)
		}
		defer os.RemoveAll(dir)

		if err := os.Chmod(dir, 0755); err != nil {
			log.Error(
				"Failed to chmod temporary directory",
				map[string]any{
					"err": err,
				},
			)
			os.Exit(1)
		}

		repo, err = gitserver.InitRepository(ctx, dir)
		if err != nil {
			log.Error(
				"Failed to init bare repository",
				map[string]any{
					"err": err,
				},
			)
			os.Exit(1)
		}
		commitCallback = func() error {
			return os.Rename(dir, *repositoryPath)
		}
	} else {
		if _, err := os.Stat(path.Join(*repositoryPath, "omegaup/version")); os.IsNotExist(err) {
			encoder := json.NewEncoder(os.Stdout)
			encoder.SetIndent("", "\t")
			encoder.Encode(&gitserver.UpdateResult{
				Status: "error",
				Error:  "omegaup-update-problem-old-version",
			})

			os.Exit(1)
		}
		repo, err = git.OpenRepository(*repositoryPath)
		if err != nil {
			log.Error(
				"failed to open existing repository",
				map[string]any{
					"err": err,
				},
			)
			os.Exit(1)
		}
	}
	defer repo.Free()

	lockfileManager := githttp.NewLockfileManager()
	defer lockfileManager.Clear()

	lockfile := lockfileManager.NewLockfile(repo.Path())
	if ok, err := lockfile.TryLock(); !ok {
		log.Info(
			"Waiting for the lockfile",
			map[string]any{
				"err": err,
			},
		)
		if err := lockfile.Lock(); err != nil {
			log.Error(
				"Failed to acquire the lockfile",
				map[string]any{
					"err": err,
				},
			)
			os.Exit(1)
		}
	}
	defer lockfile.Unlock()

	var problemSettings *common.ProblemSettings
	if *problemSettingsJSON != "" {
		problemSettings = &common.ProblemSettings{}
		if err := json.Unmarshal([]byte(*problemSettingsJSON), problemSettings); err != nil {
			log.Error(
				"Failed to parse -problem-settings",
				map[string]any{
					"err": err,
				},
			)
			os.Exit(1)
		}
	}

	var updateResult *gitserver.UpdateResult
	if *zipPath != "" {
		zipMergeStrategy, err := gitserver.ParseZipMergeStrategy(*mergeStrategyName)
		if err != nil {
			log.Error(
				"Invalid value for -merge-strategy",
				map[string]any{
					"strategy": *mergeStrategyName,
				},
			)
			os.Exit(1)
		}

		zipReader, err := zip.OpenReader(*zipPath)
		if err != nil {
			log.Error(
				"Failed to open the zip file",
				map[string]any{
					"err": err,
				},
			)
			os.Exit(1)
		}
		defer zipReader.Close()

		updateResult, err = commitZipFile(
			lockfileManager,
			common.NewProblemFilesFromZip(&zipReader.Reader, *zipPath),
			repo,
			lockfile,
			*author,
			*commitMessage,
			problemSettings,
			zipMergeStrategy,
			*acceptsSubmissions,
			*updatePublished,
			log,
		)
		if err != nil {
			log.Error(
				"Failed update the repository",
				map[string]any{
					"path": *repositoryPath,
					"err":  err,
				},
			)
			updateResult = &gitserver.UpdateResult{
				Status: "error",
				Error:  err.Error(),
			}
		} else if err := commitCallback(); err != nil {
			log.Error(
				"Failed to commit the write to the repository",
				map[string]any{
					"err": err,
				},
			)
			updateResult = &gitserver.UpdateResult{
				Status: "error",
				Error:  err.Error(),
			}
		}
	} else if *blobUpdateJSON != "" {
		var blobUpdates []BlobUpdate
		if err := json.Unmarshal([]byte(*blobUpdateJSON), &blobUpdates); err != nil {
			log.Error(
				"Failed to parse -blob-update",
				map[string]any{
					"err": err,
				},
			)
			os.Exit(1)
		}

		contents := make(map[string]io.Reader)
		for _, blobUpdate := range blobUpdates {
			f, err := os.Open(blobUpdate.ContentsPath)
			if err != nil {
				log.Error(
					"failed to open blob contents",
					map[string]any{
						"contents path": blobUpdate.ContentsPath,
						"path":          blobUpdate.Path,
					},
				)
				os.Exit(1)
			}
			defer f.Close()
			contents[blobUpdate.Path] = f
		}

		var err error
		updateResult, err = commitBlobs(
			lockfileManager,
			repo,
			lockfile,
			*author,
			*commitMessage,
			contents,
			log,
		)
		if err != nil {
			log.Error(
				"Failed update the repository",
				map[string]any{
					"path": *repositoryPath,
					"err":  err,
				},
			)
			updateResult = &gitserver.UpdateResult{
				Status: "error",
				Error:  err.Error(),
			}
		}
	} else if *problemSettingsJSON != "" {
		var err error
		zipReader, err := zip.NewReader(bytes.NewReader(emptyZipFile), int64(len(emptyZipFile)))
		if err != nil {
			log.Error(
				"Failed to open the empty zip file",
				map[string]any{
					"err": err,
				},
			)
			os.Exit(1)
		}

		updateResult, err = commitZipFile(
			lockfileManager,
			common.NewProblemFilesFromZip(zipReader, ":memory:"),
			repo,
			lockfile,
			*author,
			*commitMessage,
			problemSettings,
			gitserver.ZipMergeStrategyOurs,
			*acceptsSubmissions,
			*updatePublished,
			log,
		)
		if err != nil {
			log.Error(
				"Failed update the repository",
				map[string]any{
					"path": *repositoryPath,
					"err":  err,
				},
			)
			updateResult = &gitserver.UpdateResult{
				Status: "error",
				Error:  err.Error(),
			}
		}
	} else {
		log.Error("-zip-path, -blob-update, and -problem-settings cannot be simultaneously empty.", nil)
		os.Exit(1)
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "\t")
	encoder.Encode(&updateResult)

	if updateResult.Status != "ok" {
		os.Exit(1)
	}
}
