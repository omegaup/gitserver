package main

import (
	"bytes"
	"context"
	"database/sql"
	"flag"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"github.com/inconshreveable/log15"
	git "github.com/lhchavez/git2go"
	_ "github.com/mattn/go-sqlite3"
	"github.com/omegaup/githttp"
	"github.com/omegaup/gitserver"
	"github.com/omegaup/gitserver/request"
	base "github.com/omegaup/go-base"
	"github.com/omegaup/quark/common"
	"github.com/pkg/errors"
	"io"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

var (
	repositoryPath     = flag.String("repository-path", "", "Path of the git repository")
	libinteractivePath = flag.String(
		"libinteractive-path",
		"/usr/share/java/libinteractive.jar",
		"Path of libinteractive.jar",
	)
	configPath = flag.String(
		"config",
		"/etc/omegaup/grader/config.json",
		"Grader configuration file",
	)
)

func getBaseProblemSettings(problemAlias string) (*common.ProblemSettings, bool, error) {
	f, err := os.Open(*configPath)
	if err != nil {
		return nil, false, errors.Wrapf(err, "failed to open config file %s", *configPath)
	}
	defer f.Close()

	config, err := common.NewConfig(f)
	if err != nil {
		return nil, false, errors.Wrapf(err, "failed to read config file %s", *configPath)
	}

	db, err := sql.Open(
		config.Db.Driver,
		config.Db.DataSourceName,
	)
	if err != nil {
		return nil, false, errors.Wrap(err, "failed to open database")
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		return nil, false, errors.Wrap(err, "failed to ping database")
	}

	var settings common.ProblemSettings
	validatorLimits := common.DefaultValidatorLimits
	var acceptsSubmissions bool

	if err := db.QueryRow(
		`SELECT
			p.extra_wall_time, p.memory_limit, p.output_limit,
			p.overall_wall_time_limit, p.time_limit, p.validator_time_limit, p.slow,
			p.validator, p.languages != ''
		FROM
			Problems p
		WHERE
			p.alias = ?;`, problemAlias).Scan(
		&settings.Limits.ExtraWallTime,
		&settings.Limits.MemoryLimit,
		&settings.Limits.OutputLimit,
		&settings.Limits.OverallWallTimeLimit,
		&settings.Limits.TimeLimit,
		&validatorLimits.TimeLimit,
		&settings.Slow,
		&settings.Validator.Name,
		&acceptsSubmissions,
	); err != nil {
		return nil, false, errors.Wrap(err, "failed to query database")
	}

	settings.Limits.MemoryLimit *= common.Kibibyte
	settings.Limits.ExtraWallTime *= common.Duration(time.Millisecond)
	settings.Limits.OverallWallTimeLimit *= common.Duration(time.Millisecond)
	settings.Limits.TimeLimit *= common.Duration(time.Millisecond)
	validatorLimits.TimeLimit *= common.Duration(time.Millisecond)

	if settings.Validator.Name == "custom" {
		if validatorLimits.ExtraWallTime < settings.Limits.ExtraWallTime {
			validatorLimits.ExtraWallTime = settings.Limits.ExtraWallTime
		}
		if validatorLimits.MemoryLimit < settings.Limits.MemoryLimit {
			validatorLimits.MemoryLimit = settings.Limits.MemoryLimit
		}
		if validatorLimits.OutputLimit < settings.Limits.OutputLimit {
			validatorLimits.OutputLimit = settings.Limits.OutputLimit
		}
		if validatorLimits.OverallWallTimeLimit < settings.Limits.OverallWallTimeLimit {
			validatorLimits.OverallWallTimeLimit = settings.Limits.OverallWallTimeLimit
		}
		settings.Validator.Limits = &validatorLimits
	}

	return &settings, acceptsSubmissions, nil
}

func getCommitLog(repo *git.Repository) ([]git.Oid, error) {
	head, err := repo.Head()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get the problem's HEAD")
	}
	defer head.Free()

	headObject, err := head.Peel(git.ObjectCommit)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get HEAD commit")
	}
	defer headObject.Free()

	walk, err := repo.Walk()
	if err != nil {
		return nil, errors.Wrap(err, "failed to create a revwalk")
	}
	defer walk.Free()

	walk.SimplifyFirstParent()
	if err := walk.Push(headObject.Id()); err != nil {
		return nil, errors.Wrap(err, "failed to push HEAD into revwalk")
	}

	var commitLog []git.Oid
	if err := walk.Iterate(func(commit *git.Commit) bool {
		defer commit.Free()
		commitLog = append(commitLog, *commit.Id())
		return true
	}); err != nil {
		return nil, errors.Wrap(err, "failed to get repository log")
	}

	for left, right := 0, len(commitLog)-1; left < right; left, right = left+1, right-1 {
		commitLog[left], commitLog[right] = commitLog[right], commitLog[left]
	}
	return commitLog, nil
}

func convertCommitToPackfile(
	settings *common.ProblemSettings,
	acceptsSubmissions bool,
	originalRepo *git.Repository,
	commitID *git.Oid,
	newRepo *git.Repository,
	parentID *git.Oid,
	w io.Writer,
	log log15.Logger,
) (*git.Oid, error) {
	originalCommit, err := originalRepo.LookupCommit(commitID)
	if err != nil {
		return nil, errors.Wrap(
			err,
			"failed to lookup commit",
		)
	}
	defer originalCommit.Free()

	originalTree, err := originalCommit.Tree()
	if err != nil {
		return nil, errors.Wrap(
			err,
			"failed to lookup tree",
		)
	}
	defer originalTree.Free()

	fileMapping := make(map[string]string)
	looseObjectsDir, err := ioutil.TempDir(
		"",
		fmt.Sprintf("@%s@loose_objects@%s", path.Base(originalRepo.Path()), commitID.String()),
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create temporary directory")
	}
	defer os.RemoveAll(looseObjectsDir)

	var walkErr error
	if err := originalTree.Walk(func(relativePath string, entry *git.TreeEntry) int {
		originalFilePath := path.Join(relativePath, entry.Name)

		if entry.Type != git.ObjectBlob {
			return 0
		}

		if relativePath == "cases/in/" || relativePath == "cases/out/" {
			relativePath = "cases/"
		}

		objectPath := path.Join(relativePath, entry.Name)

		isValidFile := false
		for _, description := range gitserver.DefaultCommitDescriptions {
			if description.ContainsPath(objectPath) {
				isValidFile = true
				break
			}
		}

		// testplan is not going to be part of the final tree, but we still add it
		// because it will be integrated into the settings.json file.
		if objectPath == "testplan" {
			isValidFile = true
		}

		if !isValidFile {
			return 0
		}
		log.Info("Visiting entry", "path", originalFilePath)

		if strings.HasPrefix(objectPath, "validator.") &&
			settings.Validator.Name == "custom" &&
			entry.Type == git.ObjectBlob {
			lang := strings.Trim(filepath.Ext(objectPath), ".")
			settings.Validator.Lang = &lang
		}

		originalBlob, err := originalRepo.LookupBlob(entry.Id)
		if err != nil {
			walkErr = errors.Wrapf(
				err,
				"failed to lookup blob %s: %s",
				objectPath,
				entry.Id,
			)
			return -1
		}
		defer originalBlob.Free()

		fileMapping[objectPath] = path.Join(looseObjectsDir, entry.Id.String())
		f, err := os.OpenFile(
			fileMapping[objectPath],
			os.O_WRONLY|os.O_CREATE|os.O_EXCL,
			0644,
		)
		if err != nil {
			if os.IsExist(err) {
				// This is okay.
				return 0
			}
			walkErr = errors.Wrapf(err, "failed to create file for %s", objectPath)
			return -1
		}
		defer f.Close()

		if _, err := f.Write(originalBlob.Contents()); err != nil {
			walkErr = errors.Wrapf(err, "failed to write entry %s", objectPath)
			return -1
		}
		return 0
	}); err != nil {
		return nil, errors.Wrap(err, "failed to walk the original tree")
	}
	if walkErr != nil {
		return nil, errors.Wrap(walkErr, "failed to walk the original tree")
	}

	contents := make(map[string]io.Reader)
	for objectPath, contentsPath := range fileMapping {
		f, err := os.Open(contentsPath)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to open contents for %s", objectPath)
		}
		defer f.Close()

		if strings.HasPrefix(objectPath, "examples/") && strings.HasSuffix(objectPath, ".in") {
			exampleContents, err := ioutil.ReadAll(f)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to read %s", objectPath)
			}
			if _, err := f.Seek(0, 0); err != nil {
				return nil, errors.Wrapf(err, "failed to rewind stream for %s", objectPath)
			}

			outFilename := strings.TrimSuffix(objectPath, ".in") + ".out"
			if _, ok := contents[outFilename]; !ok && bytes.Contains(exampleContents, []byte("<ejecucion>")) {
				log.Info("generated an artificial .out for the example", "filename", objectPath)
				contents[outFilename] = bytes.NewReader([]byte{})
			}
		}

		contents[objectPath] = f
	}

	// Handle mismatched examples.
	for filename := range contents {
		if !strings.HasPrefix(filename, "examples/") || !strings.HasSuffix(filename, ".in") {
			continue
		}
		outFilename := strings.TrimSuffix(filename, ".in") + ".out"
		if _, ok := contents[outFilename]; !ok {
			log.Info("dropping example due to it being mismatched", "filename", filename)
			delete(contents, filename)
		}
	}

	// Drop some problematic files.
	for filename := range contents {
		for _, extension := range []string{
			".DS_Store",
			".bz2",
			".hi",
			".html",
			".js",
			".o",
			".swp",
			".zip",
			"~",
		} {
			if strings.HasSuffix(filename, extension) {
				log.Info("dropping problematic file", "filename", filename)
				delete(contents, filename)
				break
			}
		}
	}

	// Handle mismatch between problems having validators and claiming to need
	// validators.
	hasValidator := false
	for filename := range contents {
		if strings.HasPrefix(filename, "validator.") {
			hasValidator = true
			if settings.Validator.Name != "custom" {
				log.Info("deleting unused validator", "filename", filename, "commit", commitID.String())
				delete(contents, filename)
			}
		}
	}
	if settings.Validator.Name == "custom" && !hasValidator {
		log.Info("settings validator to 'token-caseless' for a single commit", "commit", commitID.String())
		settings.Validator.Name = "token-caseless"
	}

	return gitserver.CreatePackfile(
		contents,
		settings,
		gitserver.ConvertZipUpdateAll,
		newRepo,
		parentID,
		originalCommit.Author(),
		originalCommit.Committer(),
		originalCommit.Message(),
		w,
		log,
	)
}

func renameExchange(oldPath, newPath string) error {
	oldAbsPath, err := filepath.Abs(oldPath)
	if err != nil {
		return errors.Wrapf(err, "failed to get the absolute path for old path %s", oldPath)
	}
	oldAbsPathPtr, err := syscall.BytePtrFromString(oldAbsPath)
	if err != nil {
		return err
	}

	newAbsPath, err := filepath.Abs(newPath)
	if err != nil {
		return errors.Wrapf(err, "failed to get the absolute path for new path %s", newPath)
	}
	newAbsPathPtr, err := syscall.BytePtrFromString(newAbsPath)
	if err != nil {
		return err
	}

	SysRenameat2 := uintptr(316)
	AtFDCWD := -100
	RenameExchange := 1 << 1
	if _, _, errno := syscall.Syscall6(
		SysRenameat2,
		uintptr(AtFDCWD),
		uintptr(unsafe.Pointer(oldAbsPathPtr)),
		uintptr(AtFDCWD),
		uintptr(unsafe.Pointer(newAbsPathPtr)),
		uintptr(RenameExchange),
		0,
	); errno != 0 {
		return errors.Errorf(
			"failed to exchange %s and %s: errno %d",
			oldAbsPath,
			newAbsPath,
			errno,
		)
	}
	return nil
}

func migrateProblem(
	repositoryPath string,
	newRepositoryPath string,
	baseProblemSettings *common.ProblemSettings,
	acceptsSubmissions bool,
	log log15.Logger,
) error {
	originalRepo, err := git.OpenRepository(repositoryPath)
	if err != nil {
		return errors.Wrap(err, "failed to open original repository")
	}
	defer originalRepo.Free()

	{
		newRepo, err := gitserver.InitRepository(newRepositoryPath)
		if err != nil {
			return errors.Wrap(err, "failed to init bare repository")
		}
		newRepo.Free()
	}

	lockfile := githttp.NewLockfile(newRepositoryPath)
	if ok, err := lockfile.TryLock(); !ok {
		log.Info("Waiting for the lockfile", "err", err)
		if err := lockfile.Lock(); err != nil {
			return errors.Wrap(err, "failed to acquire the lockfile")
		}
	}
	defer lockfile.Unlock()

	tmpPackfile, err := ioutil.TempFile("", fmt.Sprintf("@%s@migration@*.pack", path.Base(repositoryPath)))
	if err != nil {
		return errors.Wrap(err, "failed to create temporary packfile")
	}
	defer os.Remove(tmpPackfile.Name())

	commitLog, err := getCommitLog(originalRepo)
	if err != nil {
		return errors.Wrap(err, "failed to get commit log")
	}
	log.Info("commit log", "log", commitLog)

	ctx := request.NewContext(context.Background())
	requestContext := request.FromContext(ctx)
	requestContext.IsAdmin = true
	requestContext.CanView = true
	requestContext.CanEdit = true
	protocol := gitserver.NewGitProtocol(
		nil,
		nil,
		true,
		// Legacy problems have high limits.
		common.Duration(time.Duration(5)*time.Minute),
		&gitserver.LibinteractiveCompiler{
			LibinteractiveJarPath: *libinteractivePath,
			Log:                   log,
		},
		log,
	)

	parentID := &git.Oid{}

	for _, originalCommitID := range commitLog {
		if err := (func() error {
			newRepo, err := git.OpenRepository(newRepositoryPath)
			if err != nil {
				return errors.Wrap(err, "failed to init bare repository")
			}
			defer newRepo.Free()

			tmpPackfile.Seek(0, 0)
			tmpPackfile.Truncate(0)
			newID, err := convertCommitToPackfile(
				baseProblemSettings,
				acceptsSubmissions,
				originalRepo,
				&originalCommitID,
				newRepo,
				parentID,
				tmpPackfile,
				log,
			)
			if err != nil {
				return errors.Wrapf(err, "failed to convert commit %s to packfile", originalCommitID.String())
			}
			var reference *git.Reference
			if ok, _ := newRepo.IsHeadUnborn(); !ok {
				reference, err = newRepo.Head()
				if err != nil {
					return errors.Wrap(err, "failed to get the repository's HEAD")
				}
				defer reference.Free()
			}

			tmpPackfile.Seek(0, 0)
			updatedRefs, err, unpackErr := protocol.PushPackfile(
				ctx,
				newRepo,
				lockfile,
				githttp.AuthorizationAllowed,
				[]*githttp.GitCommand{
					{
						Old:           parentID,
						New:           newID,
						ReferenceName: "refs/heads/master",
						Reference:     reference,
					},
				},
				tmpPackfile,
			)
			if err != nil {
				return errors.Wrapf(err, "failed to push packfile for commit %s", originalCommitID.String())
			}
			if unpackErr != nil {
				return errors.Wrapf(unpackErr, "failed to unpack packfile for commit %s", originalCommitID.String())
			}
			for _, updatedRef := range updatedRefs {
				if updatedRef.Name != "refs/heads/master" {
					continue
				}
				if parentID, err = git.NewOid(updatedRef.To); err != nil {
					return errors.Wrapf(unpackErr, "failed to parse updated ID %s", updatedRef)
				}
				break
			}

			return nil
		})(); err != nil {
			return err
		}
	}

	return nil
}

func main() {
	flag.Parse()
	log := base.StderrLog()

	if *repositoryPath == "" {
		log.Crit("repository path cannot be empty. Please specify one with -repository-path")
		os.Exit(1)
	}

	if _, err := os.Stat(path.Join(*repositoryPath, "omegaup/version")); !os.IsNotExist(err) {
		log.Info("problem has already been migrated")
		return
	}

	baseProblemSettings, acceptsSubmissions, err := getBaseProblemSettings(
		strings.TrimSuffix(path.Base(*repositoryPath), ".git"),
	)
	if err != nil {
		log.Crit("failed to get problem settings", "err", err)
		os.Exit(1)
	}
	log.Info("problem settings", "settings", baseProblemSettings)

	if err := (func() error {
		originalStat, err := os.Stat(*repositoryPath)
		if err != nil {
			return errors.Wrap(err, "failed to read original problem")
		}

		repositoryParent := path.Dir(strings.TrimSuffix(*repositoryPath, "/"))
		newRepositoryPath, err := ioutil.TempDir(
			repositoryParent,
			fmt.Sprintf("@%s@migration", path.Base(*repositoryPath)),
		)
		if err != nil {
			return errors.Wrap(err, "failed to create temporary directory")
		}
		defer os.RemoveAll(newRepositoryPath)

		if err := migrateProblem(
			*repositoryPath,
			newRepositoryPath,
			baseProblemSettings,
			acceptsSubmissions,
			log,
		); err != nil {
			return err
		}

		if err := filepath.Walk(
			newRepositoryPath,
			func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return errors.Wrapf(err, "failed to access %s", path)
				}
				if info.IsDir() {
					if err := os.Chmod(path, originalStat.Mode()); err != nil {
						return errors.Wrapf(
							err,
							"failed to chmod directory in temporary directory %s",
							path,
						)
					}
				} else {
					if err := os.Chmod(path, 0644); err != nil {
						return errors.Wrapf(
							err,
							"failed to chmod file in temporary directory %s",
							path,
						)
					}
				}
				if err := os.Chown(
					path,
					int(originalStat.Sys().(*syscall.Stat_t).Uid),
					int(originalStat.Sys().(*syscall.Stat_t).Gid),
				); err != nil {
					return errors.Wrapf(err, "failed to chown temporary directory %s", path)
				}
				return nil
			},
		); err != nil {
			return errors.Wrap(err, "failed to walk the new directory")
		}

		if err := renameExchange(*repositoryPath, newRepositoryPath); err != nil {
			return errors.Wrap(err, "failed to exchange the new problem contents")
		}

		return nil
	})(); err != nil {
		log.Crit("failed to migrate repository", "err", err)
		os.Exit(1)
	}
}
