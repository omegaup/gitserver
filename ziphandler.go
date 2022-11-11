package gitserver

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"mime/multipart"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/omegaup/githttp/v2"
	"github.com/omegaup/gitserver/request"
	base "github.com/omegaup/go-base/v3"
	"github.com/omegaup/go-base/v3/logging"
	"github.com/omegaup/go-base/v3/tracing"
	"github.com/omegaup/quark/common"

	git "github.com/libgit2/git2go/v33"
	"github.com/pkg/errors"
)

const (
	maxAllowedZipSize          = 200 * base.Mebibyte
	slowQueueThresholdDuration = base.Duration(time.Duration(30) * time.Second)

	// OverallWallTimeHardLimit is the absolute maximum wall time that problems
	// are allowed to have.
	OverallWallTimeHardLimit = base.Duration(time.Duration(60) * time.Second)
)

// A ZipMergeStrategy represents the strategy to use when merging the trees of
// a .zip upload and its parent.
type ZipMergeStrategy int

const (
	// ZipMergeStrategyOurs will use the parent commit's tree as-is without even
	// looking at the contents of the .zip or doing any kind of merge.  This is
	// exactly what what git-merge does with '-s ours'.
	ZipMergeStrategyOurs ZipMergeStrategy = iota
	// ZipMergeStrategyTheirs will use the tree that was contained in the .zip
	// as-is without even looking at the parent tree or doing any kind of merge.
	// This the opposite of ZipMergeStrategyOurs, and has no equivalent in
	// git-merge.
	ZipMergeStrategyTheirs
	// ZipMergeStrategyStatementsOurs will keep the statements/ subtree from the
	// parent commit as-is, and replace the rest of the tree with the contents of
	// the .zip file.
	ZipMergeStrategyStatementsOurs
	// ZipMergeStrategyRecursiveTheirs will merge the contents of the .zip file
	// with the parent commit's tree, preferring whatever is present in the .zip
	// file. This is similar to what git-merge does with `-srecursive -Xtheirs`.
	ZipMergeStrategyRecursiveTheirs
)

var (
	defaultGitfiles = map[string]string{
		".gitignore": `# OS-specific resources
.DS_Store
Thumbs.db

# Backup files
*~
*.bak
*.swp
*.orig

# Packaged files
*.zip
*.bz2

# Karel
*.kx

# Python
*.pyc

# IDE files
*.cbp
*.depend
*.layout

# Compiled Object files
*.slo
*.lo
*.o
*.obj
*.hi

# Precompiled Headers
*.gch
*.pch

# Compiled Dynamic libraries
*.so
*.dylib
*.dll

# Fortran module files
*.mod

# Compiled Static libraries
*.lai
*.la
*.a
*.lib

# Executables
*.exe
*.app

# libinteractive files
Makefile
libinteractive/
libinteractive.jar
`,
		".gitattributes": GitAttributesContents,
	}

	casesRegexp = regexp.MustCompile("^cases/([^/]+)\\.in$")
)

func (z ZipMergeStrategy) String() string {
	switch z {
	case ZipMergeStrategyOurs:
		return "ours"
	case ZipMergeStrategyTheirs:
		return "theirs"
	case ZipMergeStrategyStatementsOurs:
		return "statement-ours"
	case ZipMergeStrategyRecursiveTheirs:
		return "recursive-theirs"
	}
	return ""
}

// ParseZipMergeStrategy returns the corresponding ZipMergeStrategy for the provided name.
func ParseZipMergeStrategy(name string) (ZipMergeStrategy, error) {
	switch name {
	case "ours":
		return ZipMergeStrategyOurs, nil
	case "theirs":
		return ZipMergeStrategyTheirs, nil
	case "statement-ours":
		return ZipMergeStrategyStatementsOurs, nil
	case "recursive-theirs":
		return ZipMergeStrategyRecursiveTheirs, nil
	}

	return ZipMergeStrategyOurs, errors.Errorf("invalid value for ZipMergeStrategy: %q", name)
}

// UpdatedFile represents an updated file. Type is either "added", "deleted",
// or "modified".
type UpdatedFile struct {
	Path string `json:"path"`
	Type string `json:"type"`
}

type byPath []UpdatedFile

func (p byPath) Len() int           { return len(p) }
func (p byPath) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
func (p byPath) Less(i, j int) bool { return p[i].Path < p[j].Path }

// UpdateResult represents the result of running this command.
type UpdateResult struct {
	Status       string               `json:"status"`
	Error        string               `json:"error,omitempty"`
	UpdatedRefs  []githttp.UpdatedRef `json:"updated_refs,omitempty"`
	UpdatedFiles []UpdatedFile        `json:"updated_files"`
}

func getAllFilesForCommit(
	ctx context.Context,
	repo *git.Repository,
	commitID *git.Oid,
) (map[string]*git.Oid, error) {
	defer tracing.FromContext(ctx).StartSegment("getAllFilesForCommit").End()
	if commitID.IsZero() {
		return map[string]*git.Oid{}, nil
	}

	commit, err := repo.LookupCommit(commitID)
	if err != nil {
		return nil, base.ErrorWithCategory(
			ErrInternalGit,
			errors.Wrapf(
				err,
				"failed to lookup commit %s",
				commitID.String(),
			),
		)
	}
	defer commit.Free()

	tree, err := commit.Tree()
	if err != nil {
		return nil, base.ErrorWithCategory(
			ErrInternalGit,
			errors.Wrapf(
				err,
				"failed to lookup commit %s",
				commitID.String(),
			),
		)
	}
	defer tree.Free()

	commitFiles := make(map[string]*git.Oid)
	err = tree.Walk(func(name string, entry *git.TreeEntry) error {
		if entry.Type != git.ObjectBlob {
			return nil
		}
		filename := path.Join(name, entry.Name)
		commitFiles[filename] = entry.Id
		return nil
	})
	if err != nil {
		return nil, base.ErrorWithCategory(
			ErrInternalGit,
			errors.Wrapf(
				err,
				"failed to traverse tree for commit %s",
				commitID.String(),
			),
		)
	}

	return commitFiles, nil
}

// GetUpdatedFiles returns the files that were updated in the master branch.
func GetUpdatedFiles(
	ctx context.Context,
	repo *git.Repository,
	updatedRefs []githttp.UpdatedRef,
) ([]UpdatedFile, error) {
	defer tracing.FromContext(ctx).StartSegment("GetUpdatedFiles").End()
	var masterUpdatedRef *githttp.UpdatedRef
	for _, updatedRef := range updatedRefs {
		if updatedRef.Name != "refs/heads/master" {
			continue
		}
		masterUpdatedRef = &updatedRef
		break
	}

	if masterUpdatedRef == nil {
		return nil, base.ErrorWithCategory(
			ErrInternalGit,
			errors.New("failed to find the updated master ref"),
		)
	}

	fromCommitID, err := git.NewOid(masterUpdatedRef.From)
	if err != nil {
		return nil, base.ErrorWithCategory(
			ErrInternalGit,
			errors.Wrapf(
				err,
				"failed to parse the old OID '%s'",
				masterUpdatedRef.From,
			),
		)
	}

	toCommitID, err := git.NewOid(masterUpdatedRef.To)
	if err != nil {
		return nil, base.ErrorWithCategory(
			ErrInternalGit,
			errors.Wrapf(
				err,
				"failed to parse the new OID '%s'",
				masterUpdatedRef.To,
			),
		)
	}

	fromIDs, err := getAllFilesForCommit(ctx, repo, fromCommitID)
	if err != nil {
		return nil, base.ErrorWithCategory(
			ErrInternalGit,
			errors.Wrapf(
				err,
				"failed to get the old files for commit %s",
				fromCommitID.String(),
			),
		)
	}
	toIDs, err := getAllFilesForCommit(ctx, repo, toCommitID)
	if err != nil {
		return nil, base.ErrorWithCategory(
			ErrInternalGit,
			errors.Wrapf(
				err,
				"failed to get the new files for commit %s",
				toCommitID.String(),
			),
		)
	}

	var updatedFiles []UpdatedFile
	// Deleted files.
	for filename := range fromIDs {
		if _, ok := toIDs[filename]; !ok {
			updatedFiles = append(updatedFiles, UpdatedFile{
				Path: filename,
				Type: "deleted",
			})
		}
	}

	// Added / modified files.
	for filename, toID := range toIDs {
		if fromID, ok := fromIDs[filename]; ok {
			if !fromID.Equal(toID) {
				updatedFiles = append(updatedFiles, UpdatedFile{
					Path: filename,
					Type: "modified",
				})
			}
		} else {
			updatedFiles = append(updatedFiles, UpdatedFile{
				Path: filename,
				Type: "added",
			})
		}
	}

	sort.Sort(byPath(updatedFiles))
	return updatedFiles, nil
}

// isValidProblemFile returns whether a file is considered to be part of a
// problem layout.
func isValidProblemFile(filename string) bool {
	for _, commitDescription := range DefaultCommitDescriptions {
		for _, pathRegexp := range commitDescription.PathRegexps {
			if pathRegexp.MatchString(filename) {
				return true
			}
		}
	}
	return false
}

// CreatePackfile creates a packfile that contains a commit that contains the
// specified contents plus a subset of the parent commit's tree, depending of
// the value of zipMergeStrategy.
func CreatePackfile(
	ctx context.Context,
	contents map[string]io.Reader,
	settings *common.ProblemSettings,
	zipMergeStrategy ZipMergeStrategy,
	repo *git.Repository,
	parent *git.Oid,
	author, committer *git.Signature,
	commitMessage string,
	w io.Writer,
	log logging.Logger,
) (*git.Oid, error) {
	defer tracing.FromContext(ctx).StartSegment("CreatePackfile").End()
	odb, err := repo.Odb()
	if err != nil {
		return nil, base.ErrorWithCategory(
			ErrInternalGit,
			errors.Wrap(
				err,
				"failed to create a new object database",
			),
		)
	}
	defer odb.Free()

	looseObjectsDir, err := os.MkdirTemp("", fmt.Sprintf("loose_objects_%s", path.Base(repo.Path())))
	if err != nil {
		return nil, errors.Wrap(
			err,
			"failed to create temporary directory for loose objects",
		)
	}
	defer os.RemoveAll(looseObjectsDir)

	looseObjectsBackend, err := git.NewOdbBackendLoose(looseObjectsDir, -1, false, 0, 0)
	if err != nil {
		return nil, base.ErrorWithCategory(
			ErrInternalGit,
			errors.Wrap(
				err,
				"failed to create a new loose object backend",
			),
		)
	}
	if err := odb.AddBackend(looseObjectsBackend, 999); err != nil {
		looseObjectsBackend.Free()
		return nil, base.ErrorWithCategory(
			ErrInternalGit,
			errors.Wrap(
				err,
				"failed to register loose object backend",
			),
		)
	}

	// trees will contain a map of top-level entries (strings) to a map of full
	// pathnames to io.Readers. This will be used to create individual trees that
	// will then be spliced using a git.TreeBuilder.
	trees := make(map[string]map[string]io.Reader)
	topLevelEntries := make(map[string]*git.Oid)

	// .gitattributes is always overwritten.
	delete(contents, ".gitattributes")

	if zipMergeStrategy != ZipMergeStrategyOurs &&
		zipMergeStrategy != ZipMergeStrategyRecursiveTheirs {
		if settings != nil {
			// If we were given an explicit settings object, that takes
			// precedence over whatever was bundled in the .zip.
		} else if r, ok := contents["settings.json"]; ok {
			settings = &common.ProblemSettings{}
			if err := json.NewDecoder(r).Decode(settings); err != nil {
				return nil, base.ErrorWithCategory(
					ErrJSONParseError,
					errors.Wrap(
						err,
						"failed to parse settings.json",
					),
				)
			}
		} else {
			settings = &common.ProblemSettings{
				Limits: common.DefaultLimits,
				Slow:   false,
				Validator: common.ValidatorSettings{
					Name: common.ValidatorNameTokenCaseless,
				},
			}
		}
		delete(contents, "settings.json")

		// Information needed to build ProblemSettings.Cases.
		caseWeightMapping := common.NewCaseWeightMapping()
		for filename := range contents {
			casesMatches := casesRegexp.FindStringSubmatch(filename)
			if casesMatches == nil {
				continue
			}
			caseName := casesMatches[1]

			caseWeightMapping.AddCaseName(caseName, big.NewRat(1, 1), false)
		}
		if r, ok := contents["testplan"]; ok {
			zipGroupSettings := caseWeightMapping
			caseWeightMapping, err = common.NewCaseWeightMappingFromTestplan(r)
			if err != nil {
				return nil, base.ErrorWithCategory(
					ErrInvalidTestplan,
					err,
				)
			}

			// Validate that the files in the testplan are all present in the .zip file.
			if err := zipGroupSettings.SymmetricDiff(caseWeightMapping, ".zip"); err != nil {
				return nil, base.ErrorWithCategory(
					ErrInvalidTestplan,
					err,
				)
			}
			// ... and viceversa.
			if err := caseWeightMapping.SymmetricDiff(zipGroupSettings, "testplan"); err != nil {
				return nil, base.ErrorWithCategory(
					ErrInvalidTestplan,
					err,
				)
			}
		}
		// Remove this file since it's redundant with settings.json.
		delete(contents, "testplan")

		// Update the problem settings.
		settings.Cases = caseWeightMapping.ToGroupSettings()
	}

	// libinteractive samples don't require an .out file. Generate one just for
	// validation's sake.
	for filename := range contents {
		if !strings.HasPrefix(filename, "interactive/examples/") || !strings.HasSuffix(filename, ".in") {
			continue
		}
		filename = strings.TrimSuffix(filename, ".in") + ".out"
		if _, ok := contents[filename]; !ok {
			contents[filename] = bytes.NewReader([]byte{})
		}
	}

	for filename, r := range contents {
		if !isValidProblemFile(filename) {
			continue
		}

		if strings.HasPrefix(filename, "interactive/examples/") {
			// we move the libinteractive examples to the examples/ directory.
			filename = strings.TrimPrefix(filename, "interactive/")
		}
		if strings.HasPrefix(filename, "examples/") || strings.HasPrefix(filename, "cases/") {
			normalizedReader, err := NormalizeCase(r)
			if err != nil {
				// removeBOM already wrapped the error correctly.
				return nil, err
			}
			r = normalizedReader
		} else if (strings.HasPrefix(filename, "statements/") || strings.HasPrefix(filename, "solutions/")) &&
			(strings.HasSuffix(filename, ".markdown") || strings.HasSuffix(filename, ".md")) {
			utfReader, err := ConvertMarkdownToUTF8(r)
			if err != nil {
				return nil, base.ErrorWithCategory(
					ErrInvalidMarkup,
					errors.Wrapf(
						err,
						"failed to convert %s to UTF-8",
						filename,
					),
				)
			}
			r = utfReader
		}

		if !strings.Contains(filename, "/") {
			blobContents, err := io.ReadAll(r)
			if err != nil {
				return nil, base.ErrorWithCategory(
					ErrInternalGit,
					errors.Wrapf(
						err,
						"failed to read file %s",
						filename,
					),
				)
			}
			oid, err := repo.CreateBlobFromBuffer(blobContents)
			if err != nil {
				return nil, base.ErrorWithCategory(
					ErrInternalGit,
					errors.Wrapf(
						err,
						"failed to create blob for %s",
						filename,
					),
				)
			}
			topLevelEntries[filename] = oid
		} else {
			components := strings.SplitN(filename, "/", 2)
			topLevelComponent := components[0]
			componentSubpath := components[1]
			if _, ok := trees[topLevelComponent]; !ok {
				trees[topLevelComponent] = make(map[string]io.Reader)
			}
			trees[topLevelComponent][componentSubpath] = r
		}
	}

	if settings != nil {
		var buf bytes.Buffer
		encoder := json.NewEncoder(&buf)
		encoder.SetIndent("", "\t")
		if err := encoder.Encode(settings); err != nil {
			return nil, base.ErrorWithCategory(
				ErrInternal,
				errors.Wrap(
					err,
					"failed to marshal settings.json",
				),
			)
		}
		oid, err := repo.CreateBlobFromBuffer(buf.Bytes())
		if err != nil {
			return nil, base.ErrorWithCategory(
				ErrInternalGit,
				errors.Wrap(
					err,
					"failed to create blob for settings.json",
				),
			)
		}
		topLevelEntries["settings.json"] = oid
	}

	// Some default, useful files to have.
	for filename, contents := range defaultGitfiles {
		if _, ok := topLevelEntries[filename]; ok {
			continue
		}
		oid, err := repo.CreateBlobFromBuffer([]byte(contents))
		if err != nil {
			return nil, base.ErrorWithCategory(
				ErrInternalGit,
				errors.Wrapf(
					err,
					"failed to create blob for %s",
					filename,
				),
			)
		}
		topLevelEntries[filename] = oid
	}

	treebuilder, err := repo.TreeBuilder()
	if err != nil {
		return nil, base.ErrorWithCategory(
			ErrInternalGit,
			errors.Wrap(
				err,
				"failed to create treebuilder",
			),
		)
	}
	defer treebuilder.Free()

	for topLevelComponent, files := range trees {
		log.Debug(
			"Building top-level tree",
			map[string]any{
				"name":  topLevelComponent,
				"files": files,
			},
		)
		tree, err := githttp.BuildTree(repo, files, log)
		if err != nil {
			return nil, base.ErrorWithCategory(
				ErrInternalGit,
				errors.Wrapf(
					err,
					"failed to build tree for %s",
					topLevelComponent,
				),
			)
		}
		treeID := tree.Id()
		tree.Free()

		if err = treebuilder.Insert(topLevelComponent, treeID, 040000); err != nil {
			return nil, base.ErrorWithCategory(
				ErrInternalGit,
				errors.Wrapf(
					err,
					"failed to insert tree %s into treebuilder",
					topLevelComponent,
				),
			)
		}
	}

	for topLevelComponent, oid := range topLevelEntries {
		log.Debug(
			"Adding top-level file",
			map[string]any{
				"name": topLevelComponent,
				"id":   oid.String(),
			},
		)
		if err = treebuilder.Insert(topLevelComponent, oid, 0100644); err != nil {
			return nil, base.ErrorWithCategory(
				ErrInternalGit,
				errors.Wrapf(
					err,
					"failed to insert file %s into treebuilder",
					topLevelComponent,
				),
			)
		}
	}

	var parentCommits []*git.Commit
	var parentTree *git.Tree
	if !parent.IsZero() {
		parentCommit, err := repo.LookupCommit(parent)
		if err != nil {
			return nil, base.ErrorWithCategory(
				ErrInternalGit,
				errors.Wrapf(
					err,
					"failed to find parent commit %s",
					parent,
				),
			)
		}
		defer parentCommit.Free()
		parentCommits = append(parentCommits, parentCommit)

		parentTree, err = parentCommit.Tree()
		if err != nil {
			return nil, base.ErrorWithCategory(
				ErrInternalGit,
				errors.Wrapf(
					err,
					"failed to find tree for parent commit %s",
					parent,
				),
			)
		}
		defer parentTree.Free()

		if zipMergeStrategy == ZipMergeStrategyStatementsOurs {
			// This merge strategy takes the whole statements subtree as-is, so we
			// avoid performing an actual tree merge.
			for i := uint64(0); i < parentTree.EntryCount(); i++ {
				entry := parentTree.EntryByIndex(i)

				if entry.Name != "statements" {
					continue
				}

				if err = treebuilder.Insert(entry.Name, entry.Id, entry.Filemode); err != nil {
					return nil, base.ErrorWithCategory(
						ErrInternalGit,
						errors.Wrapf(
							err,
							"failed to insert file %s into treebuilder",
							entry.Name,
						),
					)
				}
			}
		}
	}

	treeID, err := treebuilder.Write()
	if err != nil {
		return nil, base.ErrorWithCategory(
			ErrInternalGit,
			errors.Wrap(
				err,
				"failed to create merged tree",
			),
		)
	}

	if parentTree != nil && (zipMergeStrategy == ZipMergeStrategyOurs ||
		zipMergeStrategy == ZipMergeStrategyRecursiveTheirs) {
		// If we could not do the easy merge strategies (theirs and
		// statement-ours), we need to perform an actual merge of the trees.
		// Regardless of which of the two merge strategies was chosen, we will be
		// choosing the files in the recently created tree because we have already
		// filtered out all of the files that should not have been in the tree.
		tree, err := repo.LookupTree(treeID)
		if err != nil {
			return nil, base.ErrorWithCategory(
				ErrInternalGit,
				errors.Wrap(
					err,
					"failed to lookup recently-created tree",
				),
			)
		}
		defer tree.Free()

		mergedTree, err := githttp.MergeTrees(
			repo,
			tree,
			parentTree,
		)
		if err != nil {
			return nil, base.ErrorWithCategory(
				ErrInternalGit,
				errors.Wrap(
					err,
					"failed to merge tree",
				),
			)
		}
		defer mergedTree.Free()
		treeID = mergedTree.Id()
	}

	log.Debug(
		"Final tree created",
		map[string]any{
			"id": treeID.String(),
		},
	)
	tree, err := repo.LookupTree(treeID)
	if err != nil {
		return nil, base.ErrorWithCategory(
			ErrInternalGit,
			errors.Wrap(
				err,
				"failed to find newly merged tree",
			),
		)
	}
	defer tree.Free()

	newCommitID, err := repo.CreateCommit(
		"",
		author,
		committer,
		commitMessage,
		tree,
		parentCommits...,
	)
	if err != nil {
		return nil, base.ErrorWithCategory(
			ErrInternalGit,
			errors.Wrap(
				err,
				"failed to create merged commit",
			),
		)
	}

	walk, err := repo.Walk()
	if err != nil {
		return nil, base.ErrorWithCategory(
			ErrInternalGit,
			errors.Wrap(
				err,
				"failed to create revwalk",
			),
		)
	}
	defer walk.Free()

	for _, parentCommit := range parentCommits {
		if err := walk.Hide(parentCommit.Id()); err != nil {
			return nil, base.ErrorWithCategory(
				ErrInternalGit,
				errors.Wrapf(
					err,
					"failed to hide commit %s", parentCommit.Id().String(),
				),
			)
		}
	}
	if err := walk.Push(newCommitID); err != nil {
		return nil, base.ErrorWithCategory(
			ErrInternalGit,
			errors.Wrapf(
				err,
				"failed to add commit %s", newCommitID.String(),
			),
		)
	}

	pb, err := repo.NewPackbuilder()
	if err != nil {
		return nil, base.ErrorWithCategory(
			ErrInternalGit,
			errors.Wrap(
				err,
				"failed to create packbuilder",
			),
		)
	}
	defer pb.Free()

	if err := pb.InsertWalk(walk); err != nil {
		return nil, base.ErrorWithCategory(
			ErrInternalGit,
			errors.Wrap(
				err,
				"failed to insert walk into packbuilder",
			),
		)
	}

	if err := pb.Write(w); err != nil {
		return nil, base.ErrorWithCategory(
			ErrInternalGit,
			errors.Wrap(
				err,
				"failed to write packfile",
			),
		)
	}

	return newCommitID, nil
}

func getUpdatedProblemSettings(
	ctx context.Context,
	problemSettings *common.ProblemSettings,
	repo *git.Repository,
	parent *git.Oid,
) (*common.ProblemSettings, error) {
	defer tracing.FromContext(ctx).StartSegment("getUpdatedProblemSettings").End()
	parentCommit, err := repo.LookupCommit(parent)
	if err != nil {
		return nil, base.ErrorWithCategory(
			ErrInternalGit,
			errors.Wrapf(
				err,
				"failed to find parent commit %s",
				parent.String(),
			),
		)
	}
	defer parentCommit.Free()

	parentTree, err := parentCommit.Tree()
	if err != nil {
		return nil, base.ErrorWithCategory(
			ErrInternalGit,
			errors.Wrapf(
				err,
				"failed to find tree for parent commit %s",
				parentCommit.Id(),
			),
		)
	}
	defer parentTree.Free()

	var updatedProblemSettings common.ProblemSettings
	entry := parentTree.EntryByName("settings.json")
	if entry == nil {
		return nil, base.ErrorWithCategory(
			ErrInternalGit,
			errors.New("failed to find settings.json"),
		)
	}
	blob, err := repo.LookupBlob(entry.Id)
	if err != nil {
		return nil, base.ErrorWithCategory(
			ErrInternalGit,
			errors.Wrap(
				err,
				"failed to lookup settings.json",
			),
		)
	}
	defer blob.Free()

	if err := json.Unmarshal(blob.Contents(), &updatedProblemSettings); err != nil {
		return nil, base.ErrorWithCategory(
			ErrJSONParseError,
			errors.Wrap(
				err,
				"settings.json",
			),
		)
	}

	updatedProblemSettings.Limits = problemSettings.Limits
	updatedProblemSettings.Validator.Name = problemSettings.Validator.Name
	updatedProblemSettings.Validator.GroupScorePolicy = problemSettings.Validator.GroupScorePolicy
	updatedProblemSettings.Validator.Tolerance = problemSettings.Validator.Tolerance
	updatedProblemSettings.Validator.Limits = problemSettings.Validator.Limits

	return &updatedProblemSettings, nil
}

// ConvertZipToPackfile receives a .zip file from the caller and converts it
// into a git packfile that can be used to update the repository.
func ConvertZipToPackfile(
	ctx context.Context,
	problemFiles common.ProblemFiles,
	settings *common.ProblemSettings,
	zipMergeStrategy ZipMergeStrategy,
	repo *git.Repository,
	parent *git.Oid,
	author, committer *git.Signature,
	commitMessage string,
	acceptsSubmissions bool,
	w io.Writer,
	log logging.Logger,
) (*git.Oid, error) {
	defer tracing.FromContext(ctx).StartSegment("ConvertZipToPackfile").End()
	contents := make(map[string]io.Reader)

	inCases := make(map[string]struct{})
	outCases := make(map[string]struct{})

	hasStatements := false
	hasEsStatement := false
	if zipMergeStrategy != ZipMergeStrategyOurs {
		for _, zipfilePath := range problemFiles.Files() {
			components := strings.Split(zipfilePath, "/")

			topLevelComponent := components[0]
			if zipMergeStrategy == ZipMergeStrategyStatementsOurs &&
				topLevelComponent == "statements" {
				continue
			}

			isValidFile := false
			for _, description := range DefaultCommitDescriptions {
				if description.ContainsPath(zipfilePath) {
					isValidFile = true
					break
				}
			}

			// testplan is not going to be part of the final tree, but we still add it
			// because it will be integrated into the settings.json file.
			if zipfilePath == "testplan" {
				isValidFile = true
			}

			if !isValidFile {
				log.Info(
					"Skipping file",
					map[string]any{
						"path": zipfilePath,
					},
				)
			}

			zipFile, err := problemFiles.Open(zipfilePath)
			if err != nil {
				return nil, base.ErrorWithCategory(
					ErrInvalidZipFilename,
					errors.Wrapf(
						err,
						"failed to open file %s",
						zipfilePath,
					),
				)
			}
			defer zipFile.Close()
			var r io.Reader = zipFile

			componentSubpath := strings.Join(components[1:], "/")

			if topLevelComponent == "statements" {
				if strings.HasSuffix(componentSubpath, ".markdown") || strings.HasSuffix(componentSubpath, ".md") {
					hasStatements = true
					if componentSubpath == "es.markdown" {
						hasEsStatement = true
					}
				}
			} else if topLevelComponent == "cases" {
				caseName := strings.TrimSuffix(componentSubpath, filepath.Ext(componentSubpath))
				if strings.HasSuffix(componentSubpath, ".in") {
					inCases[caseName] = struct{}{}
				} else if strings.HasSuffix(componentSubpath, ".out") && acceptsSubmissions {
					outCases[caseName] = struct{}{}
				}
			}

			contents[zipfilePath] = r
		}
	}

	if zipMergeStrategy == ZipMergeStrategyOurs ||
		zipMergeStrategy == ZipMergeStrategyRecursiveTheirs {
		if settings != nil {
			var err error
			if settings, err = getUpdatedProblemSettings(
				ctx,
				settings,
				repo,
				parent,
			); err != nil {
				return nil, err
			}
		}

		return CreatePackfile(
			ctx,
			contents,
			settings,
			zipMergeStrategy,
			repo,
			parent,
			author,
			committer,
			commitMessage,
			w,
			log,
		)
	}

	// Perform a few validations.
	if zipMergeStrategy == ZipMergeStrategyTheirs && !hasStatements {
		return nil, ErrNoStatements
	}
	if zipMergeStrategy == ZipMergeStrategyTheirs && !hasEsStatement {
		return nil, ErrNoEsStatement
	}
	if acceptsSubmissions {
		if len(inCases) == 0 && len(outCases) == 0 {
			return nil, base.ErrorWithCategory(
				ErrProblemBadLayout,
				errors.New("cases/ directory missing or empty"),
			)
		}
		for inName := range inCases {
			if _, ok := outCases[inName]; !ok {
				return nil, base.ErrorWithCategory(
					ErrMismatchedInputFile,
					errors.Errorf(
						"failed to find the output file for cases/%s",
						inName,
					),
				)
			}
		}
		for outName := range outCases {
			if _, ok := inCases[outName]; !ok {
				return nil, base.ErrorWithCategory(
					ErrMismatchedInputFile,
					errors.Errorf(
						"failed to find the input file for cases/%s",
						outName,
					),
				)
			}
		}
	}

	log.Info(
		"Zip is valid",
		map[string]any{
			"Files": problemFiles.Files(),
		},
	)

	return CreatePackfile(
		ctx,
		contents,
		settings,
		zipMergeStrategy,
		repo,
		parent,
		author,
		committer,
		commitMessage,
		w,
		log,
	)
}

// PushZip reads the contents of the .zip file pointed at to by problemFiles,
// creates a packfile out of it, and pushes it to the master branch of the
// repository.
func PushZip(
	ctx context.Context,
	problemFiles common.ProblemFiles,
	authorizationLevel githttp.AuthorizationLevel,
	repo *git.Repository,
	lockfile *githttp.Lockfile,
	authorUsername string,
	commitMessage string,
	problemSettings *common.ProblemSettings,
	zipMergeStrategy ZipMergeStrategy,
	acceptsSubmissions bool,
	updatePublished bool,
	protocol *githttp.GitProtocol,
	log logging.Logger,
) (*UpdateResult, error) {
	defer tracing.FromContext(ctx).StartSegment("PushZip").End()
	oldOid := &git.Oid{}
	var reference *git.Reference
	if ok, _ := repo.IsHeadUnborn(); !ok {
		var err error
		reference, err = repo.Head()
		if err != nil {
			return nil, base.ErrorWithCategory(
				ErrInternalGit,
				errors.Wrap(
					err,
					"failed to get the repository's HEAD",
				),
			)
		}
		defer reference.Free()
		oldOid = reference.Target()
	}

	signature := &git.Signature{
		Name:  authorUsername,
		Email: fmt.Sprintf("%s@omegaup", authorUsername),
		When:  time.Now(),
	}

	packfile, err := os.CreateTemp("", "gitserver-packfile")
	if err != nil {
		return nil, err
	}
	defer os.Remove(packfile.Name())

	newOid, err := ConvertZipToPackfile(
		ctx,
		problemFiles,
		problemSettings,
		zipMergeStrategy,
		repo,
		oldOid,
		signature,
		signature,
		commitMessage,
		acceptsSubmissions,
		packfile,
		log,
	)
	if err != nil {
		return nil, base.ErrorWithCategory(
			githttp.ErrBadRequest,
			err,
		)
	}

	packfile.Seek(0, 0)
	updatedRefs, err, unpackErr := protocol.PushPackfile(
		ctx,
		repo,
		lockfile,
		authorizationLevel,
		[]*githttp.GitCommand{
			{
				Old:           oldOid,
				New:           newOid,
				ReferenceName: "refs/heads/master",
				Reference:     nil,
			},
		},
		packfile,
	)

	if unpackErr != nil {
		return nil, base.ErrorWithCategory(
			githttp.ErrBadRequest,
			errors.Wrap(
				err,
				"failed to push .zip",
			),
		)
	}
	if err != nil {
		return nil, err
	}

	updatedFiles, err := GetUpdatedFiles(ctx, repo, updatedRefs)
	if err != nil {
		return nil, errors.Wrap(
			err,
			"failed to get list of updated files",
		)
	}

	// Update the published ref.
	if updatePublished {
		publishedUpdatedRef := githttp.UpdatedRef{
			Name: "refs/heads/published",
		}
		masterNewOid := &git.Oid{}
		for _, ref := range updatedRefs {
			if ref.Name == "refs/heads/master" {
				publishedUpdatedRef.To = ref.To
				publishedUpdatedRef.ToTree = ref.ToTree
				masterNewOid, err = git.NewOid(ref.To)
				if err != nil {
					return nil, errors.Wrap(
						err,
						"failed to parse the updated ID",
					)
				}
				break
			}
		}
		if masterNewOid.IsZero() {
			log.Error("could not find the updated reference for master", nil)
		} else {
			if publishedBranch, err := repo.LookupBranch("published", git.BranchLocal); err == nil {
				publishedUpdatedRef.From = publishedBranch.Target().String()
				publishedBranch.Free()
			}
			ref, err := repo.References.Create(
				publishedUpdatedRef.Name,
				masterNewOid,
				true,
				"",
			)
			if err != nil {
				return nil, errors.Wrap(
					err,
					"failed to update the published ref",
				)
			}
			ref.Free()
			updatedRefs = append(updatedRefs, publishedUpdatedRef)
		}
	}

	return &UpdateResult{
		Status:       "ok",
		UpdatedRefs:  updatedRefs,
		UpdatedFiles: updatedFiles,
	}, nil
}

type zipUploadHandler struct {
	rootPath        string
	protocol        *githttp.GitProtocol
	metrics         base.Metrics
	log             logging.Logger
	lockfileManager *githttp.LockfileManager
	tracing         tracing.Provider
}

func (h *zipUploadHandler) handleGitUploadZip(
	w http.ResponseWriter,
	r *http.Request,
	repositoryName string,
	log logging.Logger,
) {
	txn := tracing.FromContext(r.Context())
	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var requestZip io.ReadCloser
	var paramValue func(string) string
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		if err := r.ParseMultipartForm((32 * base.Mebibyte).Bytes()); err != nil {
			log.Error(
				"Unable to parse multipart form",
				map[string]any{
					"err": err,
				},
			)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		paramValue = func(name string) string {
			return r.PostFormValue(name)
		}
		var requestZipHeader *multipart.FileHeader
		var err error
		requestZip, requestZipHeader, err = r.FormFile("contents")
		if err != nil {
			log.Error(
				"Invalid contents",
				map[string]any{
					"err": err,
				},
			)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		defer requestZip.Close()
		if requestZipHeader.Size >= maxAllowedZipSize.Bytes() {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
	} else if r.Header.Get("Content-Type") == "application/zip" {
		paramValue = func(name string) string {
			return r.URL.Query().Get(name)
		}
		requestZip = r.Body
	} else {
		log.Error(
			"Bad content type",
			map[string]any{
				"Content-Type": r.Header.Get("Content-Type"),
			},
		)
		w.WriteHeader(http.StatusUnsupportedMediaType)
		return
	}

	commitMessage := paramValue("message")
	if commitMessage == "" {
		log.Error("Missing 'message' field", nil)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var problemSettings *common.ProblemSettings
	if paramValue("settings") != "" {
		var unmarshaledSettings common.ProblemSettings
		if err := json.Unmarshal([]byte(paramValue("settings")), &unmarshaledSettings); err != nil {
			log.Error(
				"invalid settings",
				map[string]any{
					"err": err,
				},
			)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		problemSettings = &unmarshaledSettings
	}
	acceptsSubmissions := (paramValue("acceptsSubmissions") == "" ||
		paramValue("acceptsSubmissions") == "true")
	updatePublished := (paramValue("updatePublished") == "" ||
		paramValue("updatePublished") == "true")
	zipMergeStrategy, err := ParseZipMergeStrategy(paramValue("mergeStrategy"))
	if err != nil {
		log.Error(
			"invalid merge strategy",
			map[string]any{
				"mergeStrategy": paramValue("mergeStrategy"),
			},
		)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	ctx := request.NewContext(r.Context(), h.metrics)
	requestContext := request.FromContext(ctx)
	requestContext.Request.Create = r.URL.Query().Get("create") != ""

	repositoryPath := path.Join(h.rootPath, repositoryName)
	log.Info(
		"git-upload-zip",
		map[string]any{
			"path":   repositoryPath,
			"create": requestContext.Request.Create,
		},
	)
	if _, err := os.Stat(repositoryPath); os.IsNotExist(err) != requestContext.Request.Create {
		if requestContext.Request.Create {
			log.Error(
				"Creating on top of an existing directory",
				map[string]any{
					"path": repositoryPath,
				},
			)
			w.WriteHeader(http.StatusConflict)
		} else {
			log.Error(
				"Updating a missing directory",
				map[string]any{
					"path": repositoryPath,
				},
			)
			w.WriteHeader(http.StatusNotFound)
		}
		return
	}

	level, username := h.protocol.AuthCallback(ctx, w, r, repositoryName, githttp.OperationPull)
	if level == githttp.AuthorizationDenied {
		return
	}

	tempfile, err := os.CreateTemp("", "gitserver-zip")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer os.Remove(tempfile.Name())

	zipSize, err := io.Copy(tempfile, &io.LimitedReader{R: requestZip, N: maxAllowedZipSize.Bytes()})
	if err != nil {
		log.Error(
			"failed to copy zip",
			map[string]any{
				"err":     err,
				"zipSize": zipSize,
			},
		)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if zipSize >= maxAllowedZipSize.Bytes() {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		return
	}
	zipReader, err := zip.OpenReader(tempfile.Name())
	if err != nil {
		log.Error(
			"failed to read zip",
			map[string]any{
				"err": err,
			},
		)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	defer zipReader.Close()

	var uncompressedZipSize uint64
	for _, file := range zipReader.File {
		uncompressedZipSize += file.UncompressedSize64
	}
	if uncompressedZipSize >= uint64(maxAllowedZipSize.Bytes()) {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		return
	}

	var repo *git.Repository
	openRepoSegment := txn.StartSegment("open repository")
	commitCallback := func() error { return nil }
	if requestContext.Request.Create {
		dir, err := os.MkdirTemp(filepath.Dir(repositoryPath), "temp.repository.")
		if err != nil {
			log.Error(
				"Failed to create temporary directory",
				map[string]any{
					"err": err,
				},
			)
			w.WriteHeader(http.StatusInternalServerError)
			openRepoSegment.End()
			return
		}
		defer os.RemoveAll(dir)

		if err := os.Chmod(dir, 0755); err != nil {
			log.Error(
				"Failed to chmod temporary directory",
				map[string]any{
					"err": err,
				},
			)
			w.WriteHeader(http.StatusInternalServerError)
			openRepoSegment.End()
			return
		}

		repo, err = InitRepository(ctx, dir)
		if err != nil {
			log.Error(
				"failed to init repository",
				map[string]any{
					"err": err,
				},
			)
			w.WriteHeader(http.StatusInternalServerError)
			openRepoSegment.End()
			return
		}
		commitCallback = func() error {
			return os.Rename(dir, repositoryPath)
		}
	} else {
		repo, err = git.OpenRepository(repositoryPath)
		if err != nil {
			log.Error(
				"failed to open repository",
				map[string]any{
					"err": err,
				},
			)
			w.WriteHeader(http.StatusInternalServerError)
			openRepoSegment.End()
			return
		}
	}
	openRepoSegment.End()
	defer repo.Free()

	acquireLockSegment := txn.StartSegment("acquire lock")
	lockfile := h.lockfileManager.NewLockfile(repo.Path())
	if ok, err := lockfile.TryRLock(); !ok {
		log.Info(
			"Waiting for the lockfile",
			map[string]any{
				"err": err,
			},
		)
		err := lockfile.RLock()
		acquireLockSegment.End()
		if err != nil {
			log.Error(
				"Failed to acquire the lockfile",
				map[string]any{
					"err": err,
				},
			)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	} else {
		acquireLockSegment.End()
	}
	defer lockfile.Unlock()

	pushZipSegment := txn.StartSegment("push zip")
	updateResult, err := PushZip(
		ctx,
		common.NewProblemFilesFromZip(
			&zipReader.Reader,
			fmt.Sprintf("%s.zip", path.Base(repositoryPath)),
		),
		level,
		repo,
		lockfile,
		username,
		commitMessage,
		problemSettings,
		zipMergeStrategy,
		acceptsSubmissions,
		updatePublished,
		h.protocol,
		log,
	)
	pushZipSegment.End()
	if err != nil {
		log.Error(
			"push failed",
			map[string]any{
				"path": repositoryPath,
				"err":  err,
			},
		)
		cause := githttp.WriteHeader(w, err, false)

		updateResult = &UpdateResult{
			Status: "error",
			Error:  cause.Error(),
		}
	} else {
		if err := commitCallback(); err != nil {
			log.Info(
				"push successful, but commit failed",
				map[string]any{
					"path":   repositoryPath,
					"result": updateResult,
					"err":    err,
				},
			)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		log.Info(
			"push successful",
			map[string]any{
				"path":   repositoryPath,
				"result": updateResult,
			},
		)
		w.WriteHeader(http.StatusOK)
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "\t")
	encoder.Encode(&updateResult)
}

func (h *zipUploadHandler) handleRenameRepository(
	w http.ResponseWriter,
	r *http.Request,
	repositoryName string,
	targetRepositoryName string,
	log logging.Logger,
) {
	if r.Method != "GET" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	ctx := request.NewContext(r.Context(), h.metrics)

	repositoryPath := path.Join(h.rootPath, repositoryName)
	targetRepositoryPath := path.Join(h.rootPath, targetRepositoryName)
	log.Info(
		"rename-repository",
		map[string]any{
			"path":        repositoryPath,
			"target path": targetRepositoryPath,
		},
	)

	level, _ := h.protocol.AuthCallback(ctx, w, r, repositoryName, githttp.OperationPush)
	requestContext := request.FromContext(ctx)
	if level != githttp.AuthorizationAllowed || !requestContext.Request.IsSystem {
		log.Error(
			"not allowed to rename repository",
			map[string]any{
				"authorization level": level,
				"request context":     requestContext.Request,
			},
		)
		w.WriteHeader(http.StatusForbidden)
		return
	}

	// Nobody is going to update the files pre-rename, so to avoid
	// acquiring a lock, we get the list of files in the problem
	// pre-rename.
	updatedFiles, err := listFilesRecursively(repositoryPath)
	if err != nil {
		log.Error(
			"failed to get list of updated files",
			map[string]any{
				"err":         err,
				"path":        repositoryPath,
				"target path": targetRepositoryPath,
			},
		)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if err := os.Rename(repositoryPath, targetRepositoryPath); err != nil {
		log.Error(
			"failed to rename repository",
			map[string]any{
				"err":         err,
				"path":        repositoryPath,
				"target path": targetRepositoryPath,
			},
		)
		if os.IsNotExist(err) {
		} else if os.IsExist(err) {
			w.WriteHeader(http.StatusNotFound)
		} else if os.IsPermission(err) {
			w.WriteHeader(http.StatusForbidden)
		} else {
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	}

	repo, err := git.OpenRepository(targetRepositoryPath)
	if err != nil {
		log.Error(
			"failed to open repository post-rename",
			map[string]any{
				"path":        repositoryPath,
				"target path": targetRepositoryPath,
			},
		)
	} else {
		defer repo.Free()
		h.protocol.PostUpdateCallback(r.Context(), repo, updatedFiles)
	}

	log.Info(
		"rename successful",
		map[string]any{
			"path":        repositoryPath,
			"target path": targetRepositoryPath,
		},
	)
	w.WriteHeader(http.StatusOK)
}

func (h *zipUploadHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log := h.log.NewContext(r.Context())
	splitPath := strings.Split(r.URL.Path[1:], "/")
	if len(splitPath) < 2 {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	repositoryName := splitPath[0]
	if strings.HasPrefix(repositoryName, ".") {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	if splitPath[1] == "git-upload-zip" {
		if len(splitPath) != 2 {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		h.handleGitUploadZip(w, r, repositoryName, log)
		return
	}
	if splitPath[1] == "rename-repository" {
		if len(splitPath) != 3 {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		h.handleRenameRepository(w, r, repositoryName, splitPath[2], log)
		return
	}
	log.Error(
		"failed to rename repository",
		map[string]any{
			"split path": splitPath,
		},
	)
	w.WriteHeader(http.StatusNotFound)
}

func listFilesRecursively(dir string) ([]string, error) {
	var result []string
	prefix := strings.TrimSuffix(dir, "/") + "/"
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}
		relpath := strings.TrimPrefix(p, prefix)
		result = append(result, relpath)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// ZipHandlerOpts contains all the possible options to initialize the zip handler.
type ZipHandlerOpts struct {
	RootPath        string
	Protocol        *githttp.GitProtocol
	Metrics         base.Metrics
	Log             logging.Logger
	LockfileManager *githttp.LockfileManager
	Tracing         tracing.Provider
}

// NewZipHandler is the HTTP handler that allows uploading .zip files.
func NewZipHandler(opts ZipHandlerOpts) http.Handler {
	if opts.Metrics == nil {
		opts.Metrics = &base.NoOpMetrics{}
	}
	if opts.Tracing == nil {
		opts.Tracing = tracing.NewNoOpProvider()
	}
	return &zipUploadHandler{
		rootPath:        opts.RootPath,
		protocol:        opts.Protocol,
		metrics:         opts.Metrics,
		log:             opts.Log,
		lockfileManager: opts.LockfileManager,
		tracing:         opts.Tracing,
	}
}
