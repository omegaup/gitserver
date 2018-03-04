package gitserver

import (
	"archive/zip"
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/inconshreveable/log15"
	git "github.com/lhchavez/git2go"
	"github.com/omegaup/githttp"
	"github.com/omegaup/gitserver/request"
	base "github.com/omegaup/go-base"
	"github.com/omegaup/quark/common"
	"github.com/pkg/errors"
	"io"
	"io/ioutil"
	"math/big"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	maxAllowedZipSize          = 200 * common.Mebibyte
	slowQueueThresholdDuration = common.Duration(time.Duration(30) * time.Second)

	// OverallWallTimeHardLimit is the absolute maximum wall time that problems
	// are allowed to have.
	OverallWallTimeHardLimit = common.Duration(time.Duration(60) * time.Second)
)

// A ConvertZipUpdateMask represents a bitfield of elements that will be
// extracted from the .zip file and updated in the git branch.
type ConvertZipUpdateMask int

const (
	// ConvertZipUpdateStatements will extract the contents of the statements/
	// directory.
	ConvertZipUpdateStatements ConvertZipUpdateMask = 1 << iota
	// ConvertZipUpdateNonStatements will extract everything that is not in the
	// statements/ directory.
	ConvertZipUpdateNonStatements
	// ConvertZipUpdateAll extracts all entries from the .zip file.
	ConvertZipUpdateAll = ConvertZipUpdateStatements | ConvertZipUpdateNonStatements
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
		".gitattributes": "cases/* -diff -delta -merge -text -crlf\n",
	}
)

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

func parseTestplan(testplan io.Reader, groupSettings map[string]map[string]*big.Rat) error {
	matcher := regexp.MustCompile("^\\s*([^#[:space:]]+)\\s+([0-9.]+)\\s*$")
	s := bufio.NewScanner(testplan)

	for s.Scan() {
		tokens := matcher.FindStringSubmatch(s.Text())
		if len(tokens) != 3 {
			continue
		}

		caseName := tokens[1]
		weight, err := common.ParseRational(tokens[2])
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

	return nil
}

func CreatePackfile(
	contents map[string]io.Reader,
	settings *common.ProblemSettings,
	updateMask ConvertZipUpdateMask,
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
	if r, ok := contents["testplan"]; ok {
		if err := parseTestplan(r, groupSettings); err != nil {
			// parseTestplan already wrapped the error correctly.
			return nil, err
		}
	} else {
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

	{
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

		parentTree, err := parentCommit.Tree()
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

		for i := uint64(0); i < parentTree.EntryCount(); i++ {
			entry := parentTree.EntryByIndex(i)

			if updateMask&ConvertZipUpdateStatements != 0 &&
				entry.Name == "statements" {
				continue
			}
			if updateMask&ConvertZipUpdateNonStatements != 0 &&
				entry.Name != "statements" {
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

// ConvertZipToPackfile receives a .zip file from the caller and converts it
// into a git packfile that can be used to update the repository.
func ConvertZipToPackfile(
	zipReader *zip.Reader,
	settings *common.ProblemSettings,
	updateMask ConvertZipUpdateMask,
	repo *git.Repository,
	parent *git.Oid,
	author, committer *git.Signature,
	commitMessage string,
	acceptsSubmissions bool,
	w io.Writer,
	log log15.Logger,
) (*git.Oid, error) {
	if updateMask == 0 {
		if _, err := w.Write(githttp.EmptyPackfile); err != nil {
			return nil, base.ErrorWithCategory(
				ErrInternal,
				errors.Wrap(
					err,
					"failed to write the packfile",
				),
			)
		}
		return parent, nil
	}

	longestPrefix := getLongestPathPrefix(zipReader)
	contents := make(map[string]io.Reader)

	inCases := make(map[string]struct{})
	outCases := make(map[string]struct{})

	hasStatements := false
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
		if (updateMask&ConvertZipUpdateStatements == 0 ||
			topLevelComponent != "statements") &&
			(updateMask&ConvertZipUpdateNonStatements == 0 ||
				topLevelComponent == "statements" ||
				!isTopLevelEntry(topLevelComponent)) {
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

	// Perform a few validations.
	if !hasStatements {
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
		updateMask,
		repo,
		parent,
		author,
		committer,
		commitMessage,
		w,
		log,
	)
}

type zipUploadHandler struct {
	rootPath string
	protocol *githttp.GitProtocol
	log      log15.Logger
}

func (h *zipUploadHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	splitPath := strings.Split(strings.TrimSuffix(r.URL.Path[1:], "/"), "/")
	if len(splitPath) != 2 {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	repositoryName := splitPath[0]
	if strings.HasPrefix(repositoryName, ".") {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if splitPath[1] != "create" && splitPath[1] != "update" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseMultipartForm((32 * common.Mebibyte).Bytes()); err != nil {
		h.log.Error("Unable to parse multipart form", "err", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if r.PostFormValue("message") == "" {
		h.log.Error("Missing 'message' field")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	requestZip, requestZipHeader, err := r.FormFile("contents")
	if err != nil {
		h.log.Error("Invalid contents", "err", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	defer requestZip.Close()
	if requestZipHeader.Size == maxAllowedZipSize.Bytes() {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		return
	}
	ctx := request.NewContext(r.Context())

	create := splitPath[1] == "create"

	repositoryPath := path.Join(h.rootPath, fmt.Sprintf("%s.git", repositoryName))
	h.log.Info(
		"Request",
		"Method", r.Method,
		"path", repositoryPath,
		"create", create,
	)
	if _, err := os.Stat(repositoryPath); os.IsNotExist(err) != create {
		if create {
			w.WriteHeader(http.StatusConflict)
		} else {
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
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if zipSize == maxAllowedZipSize.Bytes() {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		return
	}
	zipReader, err := zip.OpenReader(tempfile.Name())
	if err != nil {
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
	if create {
		repo, err = InitRepository(repositoryPath)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	} else {
		repo, err = git.OpenRepository(repositoryPath)
		if err != nil {
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

	oldOid := &git.Oid{}
	signature := &git.Signature{
		Name:  username,
		Email: fmt.Sprintf("%s@omegaup", username),
		When:  time.Now(),
	}
	var packfile bytes.Buffer
	newOid, err := ConvertZipToPackfile(
		&zipReader.Reader,
		nil,
		ConvertZipUpdateAll,
		repo,
		oldOid,
		signature,
		signature,
		r.PostFormValue("message"),
		true,
		&packfile,
		h.log,
	)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	_, err, unpackErr := h.protocol.PushPackfile(
		ctx,
		repo,
		lockfile,
		level,
		[]*githttp.GitCommand{
			{
				Old:           oldOid,
				New:           newOid,
				ReferenceName: "refs/changes/foo",
				Reference:     nil,
			},
		},
		&packfile,
	)

	if err != nil {
		h.log.Error("Failed to push .zip", "err", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if unpackErr != nil {
		h.log.Error("Failed to push .zip", "err", unpackErr)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// ZipHandler is the HTTP handler that allows uploading .zip files.
func ZipHandler(
	rootPath string,
	protocol *githttp.GitProtocol,
	log log15.Logger,
) http.Handler {
	return &zipUploadHandler{
		rootPath: rootPath,
		protocol: protocol,
		log:      log,
	}
}
