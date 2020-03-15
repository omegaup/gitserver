package gitserver

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
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

	"github.com/inconshreveable/log15"
	git "github.com/lhchavez/git2go/v29"
	"github.com/omegaup/githttp"
	"github.com/omegaup/gitserver/request"
	base "github.com/omegaup/go-base"
	"github.com/omegaup/quark/common"
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
	topLevelEntryNames = []string{
		// public branch:
		"statements",
		"examples",

		// protected branch:
		"solution",
		"tests",

		// private branch:
		"cases",
		"settings.json",
		"testplan",

		// public/private:
		"interactive",
	}

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
	repo *git.Repository,
	commitID *git.Oid,
) (map[string]*git.Oid, error) {
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
	if err := tree.Walk(func(name string, entry *git.TreeEntry) int {
		if entry.Type != git.ObjectBlob {
			return 0
		}
		filename := path.Join(name, entry.Name)
		commitFiles[filename] = entry.Id
		return 0
	}); err != nil {
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
	repo *git.Repository,
	updatedRefs []githttp.UpdatedRef,
) ([]UpdatedFile, error) {
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

	fromIDs, err := getAllFilesForCommit(repo, fromCommitID)
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
	toIDs, err := getAllFilesForCommit(repo, toCommitID)
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

func isTopLevelEntry(component string) bool {
	for _, entry := range topLevelEntryNames {
		if entry == component {
			return true
		}
		if strings.HasPrefix(component, "validator.") {
			return true
		}
	}
	return false
}

func getLongestPathPrefix(zipReader *zip.Reader) []string {
	for _, file := range zipReader.File {
		path := path.Clean(file.Name)
		components := strings.Split(path, "/")
		for idx, component := range components {
			// Whenever we see one of these directories, we know we've reached the
			// root of the problem structure.
			if isTopLevelEntry(component) {
				return components[:idx]
			}
		}
	}
	return []string{}
}

func hasPathPrefix(a, b []string) bool {
	if len(a) > len(b) {
		return false
	}
	for idx, p := range a {
		if b[idx] != p {
			return false
		}
	}
	return true
}

func addCaseName(
	caseName string,
	groupSettings map[string]map[string]*big.Rat,
	weight *big.Rat,
	overwrite bool,
) {
	groupComponents := strings.SplitN(caseName, ".", 2)
	groupName := groupComponents[0]
	if _, ok := groupSettings[groupName]; !ok {
		groupSettings[groupName] = make(map[string]*big.Rat)
	}
	if _, ok := groupSettings[groupName][caseName]; !ok || overwrite {
		// Only add the weight if there is no previous entry or if it should be
		// overwritten.
		groupSettings[groupName][caseName] = weight
	}
}

func symmetricDiffSettings(
	aGroupSettings map[string]map[string]*big.Rat,
	bGroupSettings map[string]map[string]*big.Rat,
	leftName string,
) error {
	for groupName, aGroup := range aGroupSettings {
		bGroup, ok := bGroupSettings[groupName]
		if !ok {
			bGroup = nil
		}

		for caseName := range aGroup {
			if _, ok = bGroup[caseName]; !ok {
				return base.ErrorWithCategory(
					ErrInvalidTestplan,
					errors.Errorf(
						"%s missing case %s",
						leftName,
						caseName,
					),
				)
			}
		}
	}

	return nil
}

func parseTestplan(
	testplan io.Reader,
	groupSettings map[string]map[string]*big.Rat,
	zipGroupSettings map[string]map[string]*big.Rat,
	log log15.Logger,
) error {
	matcher := regexp.MustCompile("^\\s*([^#[:space:]]+)\\s+([0-9.]+)\\s*$")
	s := bufio.NewScanner(testplan)

	for s.Scan() {
		tokens := matcher.FindStringSubmatch(s.Text())
		if len(tokens) != 3 {
			continue
		}

		caseName := tokens[1]
		weight, err := base.ParseRational(tokens[2])
		if err != nil {
			return base.ErrorWithCategory(
				ErrInvalidTestplan,
				errors.Wrapf(
					err,
					"invalid weight '%s'",
					tokens[2],
				),
			)
		}

		addCaseName(caseName, groupSettings, weight, true)
	}
	if err := s.Err(); err != nil {
		return base.ErrorWithCategory(
			ErrInvalidTestplan,
			err,
		)
	}

	// Validate that the files in the testplan are all present in the .zip file.
	if err := symmetricDiffSettings(zipGroupSettings, groupSettings, ".zip"); err != nil {
		return err
	}
	// ... and viceversa.
	if err := symmetricDiffSettings(groupSettings, zipGroupSettings, "testplan"); err != nil {
		return err
	}

	return nil
}

// CreatePackfile creates a packfile that contains a commit that contains the
// specified contents plus a subset of the parent commit's tree, depending of
// the value of zipMergeStrategy.
func CreatePackfile(
	contents map[string]io.Reader,
	settings *common.ProblemSettings,
	zipMergeStrategy ZipMergeStrategy,
	repo *git.Repository,
	parent *git.Oid,
	author, committer *git.Signature,
	commitMessage string,
	w io.Writer,
	log log15.Logger,
) (*git.Oid, error) {
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
					Name: "token-caseless",
				},
			}
		}
		delete(contents, "settings.json")

		// Information needed to build ProblemSettings.Cases.
		groupSettings := make(map[string]map[string]*big.Rat)
		for filename := range contents {
			if !strings.HasPrefix(filename, "cases/") {
				continue
			}
			filename = strings.TrimPrefix(filename, "cases/")
			if !strings.HasSuffix(filename, ".in") {
				continue
			}
			caseName := strings.TrimSuffix(filename, ".in")

			addCaseName(caseName, groupSettings, big.NewRat(1, 1), false)
		}
		if r, ok := contents["testplan"]; ok {
			zipGroupSettings := groupSettings
			groupSettings = make(map[string]map[string]*big.Rat)
			if err := parseTestplan(r, groupSettings, zipGroupSettings, log); err != nil {
				// parseTestplan already wrapped the error correctly.
				return nil, err
			}
		}
		// Remove this file since it's redundant with settings.json.
		delete(contents, "testplan")

		// Update the problem settings.
		settings.Cases = make([]common.GroupSettings, 0)
		for groupName, groupContents := range groupSettings {
			var caseSettings []common.CaseSettings
			for caseName, caseWeight := range groupContents {
				caseSettings = append(caseSettings, common.CaseSettings{
					Name:   caseName,
					Weight: caseWeight,
				})
			}
			sort.Sort(common.ByCaseName(caseSettings))

			settings.Cases = append(settings.Cases, common.GroupSettings{
				Name:  groupName,
				Cases: caseSettings,
			})
		}
		sort.Sort(common.ByGroupName(settings.Cases))
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
			blobContents, err := ioutil.ReadAll(r)
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
		log.Debug("Building top-level tree", "name", topLevelComponent, "files", files)
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
		defer tree.Free()

		if err = treebuilder.Insert(topLevelComponent, tree.Id(), 040000); err != nil {
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
		log.Debug("Adding top-level file", "name", topLevelComponent, "id", oid.String())
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

	log.Debug("Final tree created", "id", treeID.String())
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
	problemSettings *common.ProblemSettings,
	repo *git.Repository,
	parent *git.Oid,
) (*common.ProblemSettings, error) {
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
	updatedProblemSettings.Validator.Tolerance = problemSettings.Validator.Tolerance
	updatedProblemSettings.Validator.Limits = problemSettings.Validator.Limits

	return &updatedProblemSettings, nil
}

// ConvertZipToPackfile receives a .zip file from the caller and converts it
// into a git packfile that can be used to update the repository.
func ConvertZipToPackfile(
	zipReader *zip.Reader,
	settings *common.ProblemSettings,
	zipMergeStrategy ZipMergeStrategy,
	repo *git.Repository,
	parent *git.Oid,
	author, committer *git.Signature,
	commitMessage string,
	acceptsSubmissions bool,
	w io.Writer,
	log log15.Logger,
) (*git.Oid, error) {
	contents := make(map[string]io.Reader)
	longestPrefix := getLongestPathPrefix(zipReader)

	inCases := make(map[string]struct{})
	outCases := make(map[string]struct{})

	hasStatements := false
	if zipMergeStrategy != ZipMergeStrategyOurs {
		for _, file := range zipReader.File {
			zipfilePath := path.Clean(file.Name)
			components := strings.Split(zipfilePath, "/")
			if len(longestPrefix) >= len(components) || !hasPathPrefix(longestPrefix, components) {
				continue
			}
			// BuildTree only cares about files.
			if file.FileInfo().IsDir() {
				continue
			}

			topLevelComponent := components[len(longestPrefix)]
			if zipMergeStrategy == ZipMergeStrategyStatementsOurs &&
				topLevelComponent == "statements" {
				continue
			}

			isValidFile := false
			trimmedZipfilePath := strings.Join(components[len(longestPrefix):], "/")
			for _, description := range DefaultCommitDescriptions {
				if description.ContainsPath(trimmedZipfilePath) {
					isValidFile = true
					break
				}
			}

			// testplan is not going to be part of the final tree, but we still add it
			// because it will be integrated into the settings.json file.
			if trimmedZipfilePath == "testplan" {
				isValidFile = true
			}

			if !isValidFile {
				log.Info("Skipping file", "path", zipfilePath)
			}

			zipFile, err := file.Open()
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

			componentSubpath := strings.Join(components[len(longestPrefix)+1:], "/")

			if topLevelComponent == "statements" {
				if strings.HasSuffix(componentSubpath, ".markdown") || strings.HasSuffix(componentSubpath, ".md") {
					hasStatements = true
				}
			} else if topLevelComponent == "cases" {
				caseName := strings.TrimSuffix(componentSubpath, filepath.Ext(componentSubpath))
				if strings.HasSuffix(componentSubpath, ".in") {
					inCases[caseName] = struct{}{}
				} else if strings.HasSuffix(componentSubpath, ".out") && acceptsSubmissions {
					outCases[caseName] = struct{}{}
				}
			}

			contents[trimmedZipfilePath] = r
		}
	}

	if zipMergeStrategy == ZipMergeStrategyOurs ||
		zipMergeStrategy == ZipMergeStrategyRecursiveTheirs {
		if settings != nil {
			var err error
			if settings, err = getUpdatedProblemSettings(
				settings,
				repo,
				parent,
			); err != nil {
				return nil, err
			}
		}

		return CreatePackfile(
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
	if acceptsSubmissions {
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
		"Files", zipReader.File,
	)

	return CreatePackfile(
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

// PushZip reads the contents of the .zip file pointed at to by zipReader,
// creates a packfile out of it, and pushes it to the master branch of the
// repository.
func PushZip(
	ctx context.Context,
	zipReader *zip.Reader,
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
	log log15.Logger,
) (*UpdateResult, error) {
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

	packfile, err := ioutil.TempFile("", "gitserver-packfile")
	if err != nil {
		return nil, err
	}
	defer os.Remove(packfile.Name())

	newOid, err := ConvertZipToPackfile(
		zipReader,
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

	updatedFiles, err := GetUpdatedFiles(repo, updatedRefs)
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
			log.Error("could not find the updated reference for master")
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
	rootPath string
	protocol *githttp.GitProtocol
	metrics  base.Metrics
	log      log15.Logger
}

func (h *zipUploadHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	splitPath := strings.SplitN(r.URL.Path[1:], "/", 2)
	if len(splitPath) != 2 {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	repositoryName := splitPath[0]
	if strings.HasPrefix(repositoryName, ".") {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if splitPath[1] != "git-upload-zip" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var requestZip io.ReadCloser
	var paramValue func(string) string
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		if err := r.ParseMultipartForm((32 * base.Mebibyte).Bytes()); err != nil {
			h.log.Error("Unable to parse multipart form", "err", err)
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
			h.log.Error("Invalid contents", "err", err)
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
		h.log.Error("Bad content type", "Content-Type", r.Header.Get("Content-Type"))
		w.WriteHeader(http.StatusUnsupportedMediaType)
		return
	}

	commitMessage := paramValue("message")
	if commitMessage == "" {
		h.log.Error("Missing 'message' field")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var problemSettings *common.ProblemSettings
	if paramValue("settings") != "" {
		var unmarshaledSettings common.ProblemSettings
		if err := json.Unmarshal([]byte(paramValue("settings")), &unmarshaledSettings); err != nil {
			h.log.Error("invalid settings", "err", err)
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
		h.log.Error("invalid merge strategy", "mergeStrategy", paramValue("mergeStrategy"))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	ctx := request.NewContext(r.Context(), h.metrics)
	requestContext := request.FromContext(ctx)
	requestContext.Request.Create = r.URL.Query().Get("create") != ""

	repositoryPath := path.Join(h.rootPath, repositoryName)
	h.log.Info(
		"Request",
		"Method", r.Method,
		"path", repositoryPath,
		"create", requestContext.Request.Create,
	)
	if _, err := os.Stat(repositoryPath); os.IsNotExist(err) != requestContext.Request.Create {
		if requestContext.Request.Create {
			h.log.Error("Creating on top of an existing directory", "path", repositoryPath)
			w.WriteHeader(http.StatusConflict)
		} else {
			h.log.Error("Updating a missing directory", "path", repositoryPath)
			w.WriteHeader(http.StatusNotFound)
		}
		return
	}

	level, username := h.protocol.AuthCallback(ctx, w, r, repositoryName, githttp.OperationPull)
	if level == githttp.AuthorizationDenied {
		return
	}

	tempfile, err := ioutil.TempFile("", "gitserver-zip")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer os.Remove(tempfile.Name())

	zipSize, err := io.Copy(tempfile, &io.LimitedReader{R: requestZip, N: maxAllowedZipSize.Bytes()})
	if err != nil {
		h.log.Error("failed to copy zip", "err", err, "zipSize", zipSize)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if zipSize >= maxAllowedZipSize.Bytes() {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		return
	}
	zipReader, err := zip.OpenReader(tempfile.Name())
	if err != nil {
		h.log.Error("failed to read zip", "err", err)
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
	commitCallback := func() error { return nil }
	if requestContext.Request.Create {
		dir, err := ioutil.TempDir(filepath.Dir(repositoryPath), "repository")
		if err != nil {
			h.log.Error("Failed to create temporary directory", "err", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer os.RemoveAll(dir)

		if err := os.Chmod(dir, 0755); err != nil {
			h.log.Error("Failed to chmod temporary directory", "err", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		repo, err = InitRepository(dir)
		if err != nil {
			h.log.Error("failed to init repository", "err", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		commitCallback = func() error {
			return os.Rename(dir, repositoryPath)
		}
	} else {
		repo, err = git.OpenRepository(repositoryPath)
		if err != nil {
			h.log.Error("failed to open repository", "err", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}
	defer repo.Free()

	lockfile := githttp.NewLockfile(repo.Path())
	if ok, err := lockfile.TryRLock(); !ok {
		h.log.Info("Waiting for the lockfile", "err", err)
		if err := lockfile.RLock(); err != nil {
			h.log.Crit("Failed to acquire the lockfile", "err", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}
	defer lockfile.Unlock()

	updateResult, err := PushZip(
		ctx,
		&zipReader.Reader,
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
		h.log,
	)
	if err != nil {
		h.log.Error("push failed", "path", repositoryPath, "err", err)
		cause := githttp.WriteHeader(w, err, false)

		updateResult = &UpdateResult{
			Status: "error",
			Error:  cause.Error(),
		}
	} else {
		if err := commitCallback(); err != nil {
			h.log.Info("push successful, but commit failed", "path", repositoryPath, "result", updateResult, "err", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		h.log.Info("push successful", "path", repositoryPath, "result", updateResult)
		w.WriteHeader(http.StatusOK)
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "\t")
	encoder.Encode(&updateResult)
}

// ZipHandler is the HTTP handler that allows uploading .zip files.
func ZipHandler(
	rootPath string,
	protocol *githttp.GitProtocol,
	metrics base.Metrics,
	log log15.Logger,
) http.Handler {
	return &zipUploadHandler{
		rootPath: rootPath,
		protocol: protocol,
		metrics:  metrics,
		log:      log,
	}
}
