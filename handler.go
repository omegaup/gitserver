package gitserver

import (
	"bytes"
	"context"
	"encoding/json"
	stderrors "errors"
	"fmt"
	"github.com/inconshreveable/log15"
	git "github.com/lhchavez/git2go"
	"github.com/omegaup/githttp"
	"github.com/omegaup/gitserver/request"
	base "github.com/omegaup/go-base"
	"github.com/omegaup/quark/common"
	"github.com/pkg/errors"
	"math"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	iterationLabel = "Iteration: "
	objectLimit    = 10000

	// GitAttributesContents is what the .gitattributes and info/attributes files
	// contain.
	GitAttributesContents = "cases/* -diff -delta -merge -text -crlf\n"
)

var (
	// ErrNotAReview is returned if a merge to master is attempted and does not
	// come from a review commit.
	ErrNotAReview = stderrors.New("not-a-review")

	// ErrJSONParseError is returned if one of the JSON files fails to be parsed.
	ErrJSONParseError = stderrors.New("json-parse-error")

	// ErrChangeMissingSettingsJSON is returned if the settings.json file is missing.
	ErrChangeMissingSettingsJSON = stderrors.New("change-missing-settings-json")

	// ErrPublishedNotFromMaster is returned if an update to the published branch
	// is attempted and the new reference does not point to a commit in the
	// master branch.
	ErrPublishedNotFromMaster = stderrors.New("published-must-point-to-commit-in-master")

	// ErrConfigSubdirectoryMissingTarget is returned if a 'subdirectory'
	// publishing config is missing a 'target' entry.
	ErrConfigSubdirectoryMissingTarget = stderrors.New("config-subdirectory-missing-target")

	// ErrConfigInvalidPublishingMode is returned if a publishing config is not
	// 'subdirectory' or 'mirror'.
	ErrConfigInvalidPublishingMode = stderrors.New("config-invalid-publishing-mode")

	// ErrConfigRepositoryNotAbsoluteURL is returned if a publishing config does
	// not have a valid, absolute URL for 'repository'.
	ErrConfigRepositoryNotAbsoluteURL = stderrors.New("config-repository-not-absolute-url")

	// ErrConfigBadLayout is returned if the refs/meta/config structure does not
	// contain the correct layout.
	ErrConfigBadLayout = stderrors.New("config-bad-layout")

	// ErrTestsBadLayout is returned if the tests/ directory does not contain the
	// correct layout.
	ErrTestsBadLayout = stderrors.New("tests-bad-layout")

	// ErrInteractiveBadLayout is returned if the interactive/ directory does not
	// contain the correct layout.
	ErrInteractiveBadLayout = stderrors.New("interactive-bad-layout")

	// ErrProblemBadLayout is returned if the problem structure does not contain the
	// correct layout.
	ErrProblemBadLayout = stderrors.New("problem-bad-layout")

	// ErrReviewBadLayout is returned if the review structure does not contain
	// the correct layout.
	ErrReviewBadLayout = stderrors.New("review-bad-layout")

	// ErrMismatchedInputFile is returned if there is an .in without an .out.
	ErrMismatchedInputFile = stderrors.New("mismatched-input-file")

	// ErrInternalGit is returned if there is a problem with the git structure.
	ErrInternalGit = stderrors.New("internal-git-error")

	// ErrInternal is returned if there is an internal error.
	ErrInternal = stderrors.New("internal-error")

	// ErrTooManyObjects is returned if the packfile has too many objects.
	ErrTooManyObjects = stderrors.New("too-many-objects-in-packfile")

	// ErrInvalidZipFilename is returned if a path in the .zip is invalid.
	ErrInvalidZipFilename = stderrors.New("invalid-zip-filename")

	// ErrNoStatements is returned if the problem does not have any statements.
	ErrNoStatements = stderrors.New("no-statements")

	// ErrSlowRejected is returned if the maximum runtime would exceed the hard
	// limit.
	ErrSlowRejected = stderrors.New("slow-rejected")

	// ErrInvalidTestplan is returned if the testplan file is not valid.
	ErrInvalidTestplan = stderrors.New("invalid-testplan")

	// ErrInvalidMarkup is returned if the markup file is not valid.
	ErrInvalidMarkup = stderrors.New("invalid-markup")

	// DefaultCommitDescriptions describes which files go to which branches.
	DefaultCommitDescriptions = []githttp.SplitCommitDescription{
		{
			ReferenceName: "refs/heads/public",
			PathRegexps: []*regexp.Regexp{
				regexp.MustCompile("^.gitattributes$"),
				regexp.MustCompile("^.gitignore$"),
				regexp.MustCompile("^statements(/[^/]+\\.(markdown|gif|jpe?g|png))?$"),
				regexp.MustCompile("^examples(/[^/]+\\.(in|out))?$"),
				regexp.MustCompile("^interactive/Main\\.distrib\\.[a-z0-9]+$"),
				regexp.MustCompile("^interactive/examples(/[^/]+\\.(in|out))?$"),
				regexp.MustCompile("^validator\\.distrib\\.[a-z]+$"),
				regexp.MustCompile("^settings\\.distrib\\.json$"),
			},
		},
		{
			ReferenceName: "refs/heads/protected",
			PathRegexps: []*regexp.Regexp{
				regexp.MustCompile("^solutions(/[^/]+\\.(markdown|gif|jpe?g|png|py|cpp|c|java|kp|kj))?$"),
				regexp.MustCompile("^tests(/.*)?$"),
			},
		},
		{
			ReferenceName: "refs/heads/private",
			PathRegexps: []*regexp.Regexp{
				regexp.MustCompile("^cases(/[^/]+\\.(in|out))?$"),
				regexp.MustCompile("^interactive/Main\\.[a-z0-9]+$"),
				regexp.MustCompile("^interactive/[^/]+\\.idl$"),
				regexp.MustCompile("^validator\\.[a-z0-9]+$"),
				regexp.MustCompile("^settings\\.json$"),
			},
		},
	}

	// statementExampleBoundaryRegexp is the regular expression that finds all
	// example boundary tokens.
	statementExampleBoundaryRegexp = regexp.MustCompile(
		`(?:\n|^)\s*\|\|(input|output|description|end)\s*(?:\n|$)`,
	)
)

// LedgerIteration is an entry in the iteration ledger.
type LedgerIteration struct {
	Author  string `json:"author"`
	Date    int64  `json:"date"`
	Summary string `json:"summary"`
	UUID    string `json:"uuid"`
	Vote    string `json:"vote"`
}

// Range is a range in the source code that is associated with a Comment.
type Range struct {
	LineStart int `json:"lineStart"`
	LineEnd   int `json:"lineEnd"`
	ColStart  int `json:"colStart"`
	ColEnd    int `json:"colEnd"`
}

// Comment is a comment in the code review.
type Comment struct {
	Author                string  `json:"author"`
	Date                  int64   `json:"date"`
	Done                  bool    `json:"done"`
	Filename              string  `json:"filename"`
	IterationUUID         string  `json:"iterationUuid"`
	Message               string  `json:"message"`
	ParentUUID            *string `json:"parentUuid"`
	Range                 *Range  `json:"range"`
	ReplacementSuggestion bool    `json:"replacementSuggestion"`
	UUID                  string  `json:"uuid"`
}

// PublishingConfig represents the publishing section of config.json in
// refs/meta/config.
type PublishingConfig struct {
	Mode       string `json:"mode"`
	Repository string `json:"repository"`
	Target     string `json:"target,omitempty"`
	Branch     string `json:"branch,omitempty"`
}

// MetaConfig represents the contents of config.json in refs/meta/config.
type MetaConfig struct {
	Publishing PublishingConfig `json:"publishing"`
}

type gitProtocol struct {
	allowDirectPushToMaster     bool
	hardOverallWallTimeLimit    base.Duration
	interactiveSettingsCompiler InteractiveSettingsCompiler
	log                         log15.Logger
}

// NewGitProtocol creates a new GitProtocol with the provided authorization
// callback.
func NewGitProtocol(
	authCallback githttp.AuthorizationCallback,
	referenceDiscoveryCallback githttp.ReferenceDiscoveryCallback,
	allowDirectPushToMaster bool,
	hardOverallWallTimeLimit base.Duration,
	interactiveSettingsCompiler InteractiveSettingsCompiler,
	log log15.Logger,
) *githttp.GitProtocol {
	protocol := &gitProtocol{
		allowDirectPushToMaster:     allowDirectPushToMaster,
		hardOverallWallTimeLimit:    hardOverallWallTimeLimit,
		interactiveSettingsCompiler: interactiveSettingsCompiler,
		log:                         log,
	}
	return githttp.NewGitProtocol(
		authCallback,
		referenceDiscoveryCallback,
		protocol.validateUpdate,
		protocol.preprocess,
		true,
		log,
	)
}

func getProblemSettings(repo *git.Repository, tree *git.Tree) (*common.ProblemSettings, error) {
	settingsJSONEntry, err := tree.EntryByPath("settings.json")
	if err != nil {
		return nil, base.ErrorWithCategory(
			ErrChangeMissingSettingsJSON,
			err,
		)
	}
	settingsJSONBlob, err := repo.LookupBlob(settingsJSONEntry.Id)
	if err != nil {
		return nil, base.ErrorWithCategory(
			ErrInternalGit,
			errors.Wrap(
				err,
				"failed to lookup blob for settings.json",
			),
		)
	}
	defer settingsJSONBlob.Free()

	var settings common.ProblemSettings
	if err := json.Unmarshal(settingsJSONBlob.Contents(), &settings); err != nil {
		return nil, base.ErrorWithCategory(
			ErrJSONParseError,
			errors.Wrap(
				err,
				settingsJSONEntry.Name,
			),
		)
	}
	return &settings, nil
}

func isSlow(
	settings *common.ProblemSettings,
	hardOverallWallTimeLimit base.Duration,
) (bool, error) {
	if settings.Limits.OverallWallTimeLimit <= slowQueueThresholdDuration {
		return false, nil
	}

	inputCount := 0
	for _, group := range settings.Cases {
		inputCount += len(group.Cases)
	}

	maxRunDuration := settings.Limits.TimeLimit + settings.Limits.ExtraWallTime
	if settings.Validator.Limits != nil && settings.Validator.Name == "custom" {
		maxRunDuration += settings.Validator.Limits.TimeLimit + settings.Validator.Limits.ExtraWallTime
	}

	maxRuntime := base.Duration(
		time.Duration(math.Ceil(maxRunDuration.Seconds())*float64(inputCount)) * time.Second,
	)
	if settings.Limits.OverallWallTimeLimit > hardOverallWallTimeLimit &&
		maxRuntime > hardOverallWallTimeLimit {
		return false, base.ErrorWithCategory(
			ErrSlowRejected,
			errors.Errorf(
				"rejecting problem: overall wall time limit %s, max runtime %s",
				settings.Limits.OverallWallTimeLimit,
				maxRuntime,
			),
		)
	}

	return maxRuntime >= slowQueueThresholdDuration, nil
}

func extractExampleCasesFromStatement(
	statementContents string,
) map[string]*common.LiteralCaseSettings {
	examples := make(map[string]*common.LiteralCaseSettings)
	lastLabel := ""
	lastIndex := 0

	var labelMapping []struct {
		label, chunk string
	}
	for _, boundaryIndices := range statementExampleBoundaryRegexp.FindAllStringSubmatchIndex(
		statementContents,
		-1,
	) {
		currentLabel := statementContents[boundaryIndices[2]:boundaryIndices[3]]
		lastChunk := statementContents[lastIndex:boundaryIndices[0]]

		if lastLabel != "" {
			labelMapping = append(
				labelMapping,
				struct {
					label, chunk string
				}{
					label: lastLabel,
					chunk: lastChunk,
				},
			)
		}

		lastLabel = currentLabel
		lastIndex = boundaryIndices[1]
	}

	for i := 0; i < len(labelMapping)-1; i++ {
		if labelMapping[i].label != "input" || labelMapping[i+1].label != "output" {
			continue
		}
		examples[fmt.Sprintf("statement_%03d", len(examples)+1)] = &common.LiteralCaseSettings{
			Input:          labelMapping[i].chunk,
			ExpectedOutput: labelMapping[i+1].chunk,
			Weight:         big.NewRat(1, 1),
		}
	}

	return examples
}

func extractExampleCases(
	repository *git.Repository,
	tree *git.Tree,
) (map[string]*common.LiteralCaseSettings, error) {
	exampleCases := make(map[string]*common.LiteralCaseSettings)

	for _, examplesDirectory := range []string{"examples", "interactive/examples"} {
		entry, err := tree.EntryByPath(examplesDirectory)
		if err != nil {
			if git.IsErrorCode(err, git.ErrNotFound) {
				continue
			}
			return nil, base.ErrorWithCategory(
				ErrInternalGit,
				errors.Wrapf(
					err,
					"failed to find the %s directory",
					examplesDirectory,
				),
			)
		}

		examplesTree, err := repository.LookupTree(entry.Id)
		if err != nil {
			return nil, base.ErrorWithCategory(
				ErrInternalGit,
				errors.Wrapf(
					err,
					"failed to lookup the %s directory",
					examplesDirectory,
				),
			)
		}
		defer examplesTree.Free()

		for i := uint64(0); i < examplesTree.EntryCount(); i++ {
			inputEntry := examplesTree.EntryByIndex(i)
			if !strings.HasSuffix(inputEntry.Name, ".in") {
				continue
			}
			inputName := inputEntry.Name[:len(inputEntry.Name)-3]
			outputEntry := examplesTree.EntryByName(
				fmt.Sprintf("%s.out", inputName),
			)
			if outputEntry == nil {
				return nil, base.ErrorWithCategory(
					ErrMismatchedInputFile,
					errors.Errorf(
						"failed to find the output file for %s/%s",
						examplesDirectory,
						inputEntry.Name,
					),
				)
			}

			inputBlob, err := repository.LookupBlob(inputEntry.Id)
			if err != nil {
				return nil, base.ErrorWithCategory(
					ErrInternalGit,
					errors.Wrapf(
						err,
						"failed to lookup input file %s/%s",
						examplesDirectory,
						inputEntry.Name,
					),
				)
			}
			defer inputBlob.Free()

			outputBlob, err := repository.LookupBlob(outputEntry.Id)
			if err != nil {
				return nil, base.ErrorWithCategory(
					ErrInternalGit,
					errors.Wrapf(
						err,
						"failed to lookup output file %s/%s",
						examplesDirectory,
						inputEntry.Name,
					),
				)
			}
			defer outputBlob.Free()

			exampleCases[inputName] = &common.LiteralCaseSettings{
				Input:          string(inputBlob.Contents()),
				ExpectedOutput: string(outputBlob.Contents()),
				Weight:         big.NewRat(1, 1),
			}
		}
	}

	if len(exampleCases) == 0 {
		// If the problem author did not explicitly specify some sample cases,
		// let's try to extract them from the statements.
		entry, err := tree.EntryByPath("statements")
		if err != nil {
			return nil, base.ErrorWithCategory(
				ErrInternalGit,
				errors.Wrap(
					err,
					"failed to find the statements directory",
				),
			)
		}

		statementsTree, err := repository.LookupTree(entry.Id)
		if err != nil {
			return nil, base.ErrorWithCategory(
				ErrInternalGit,
				errors.Wrap(
					err,
					"failed to lookup the statements directory",
				),
			)
		}
		defer statementsTree.Free()

		for _, statementLanguage := range []string{"es", "en", "pt"} {
			statementEntry := statementsTree.EntryByName(
				fmt.Sprintf("%s.markdown", statementLanguage),
			)
			if statementEntry == nil {
				continue
			}

			statementBlob, err := repository.LookupBlob(statementEntry.Id)
			if err != nil {
				if git.IsErrorCode(err, git.ErrNotFound) {
					continue
				}
				return nil, base.ErrorWithCategory(
					ErrInternalGit,
					errors.Wrapf(
						err,
						"failed to lookup statements/%s.markdown",
						statementLanguage,
					),
				)
			}
			defer statementBlob.Free()

			exampleCases = extractExampleCasesFromStatement(string(statementBlob.Contents()))
			if len(exampleCases) > 0 {
				break
			}
		}
	}

	return exampleCases, nil
}

func validateUpdateMaster(
	ctx context.Context,
	repository *git.Repository,
	newCommit *git.Commit,
	allowDirectPush bool,
	hardOverallWallTimeLimit base.Duration,
	interactiveSettingsCompiler InteractiveSettingsCompiler,
	log log15.Logger,
) error {
	it, err := repository.NewReferenceIteratorGlob("refs/changes/*")
	if err != nil {
		return base.ErrorWithCategory(
			ErrInternalGit,
			errors.Wrap(
				err,
				"failed to iterate over refs/changes/* references",
			),
		)
	}
	defer it.Free()

	var sourceReview string
	for {
		ref, err := it.Next()
		if err != nil {
			if git.IsErrorCode(err, git.ErrIterOver) {
				break
			}
			return base.ErrorWithCategory(
				ErrInternalGit,
				errors.Wrapf(
					err,
					"failed to iterate over refs/changes/* references",
				),
			)
		}
		defer ref.Free()

		if newCommit.Id().Equal(ref.Target()) {
			sourceReview = ref.Name()
		}
	}

	if sourceReview == "" && !allowDirectPush {
		return ErrNotAReview
	}

	requestContext := request.FromContext(ctx)
	requestContext.ReviewRef = sourceReview

	tree, err := newCommit.Tree()
	if err != nil {
		return base.ErrorWithCategory(
			ErrInternalGit,
			errors.Wrapf(
				err,
				"failed to get tree for new commit %s",
				newCommit.Id(),
			),
		)
	}
	defer tree.Free()

	// Validate and re-generate the problem settings.
	problemSettings, err := getProblemSettings(repository, tree)
	if err != nil {
		// getProblemSettings already wrapped the error correctly.
		return err
	}

	// Tests.
	testsTreeEntry := tree.EntryByName("tests")
	if testsTreeEntry != nil {
		if testsTreeEntry.Type != git.ObjectTree {
			return base.ErrorWithCategory(
				ErrTestsBadLayout,
				errors.New("tests/ directory is not a tree"),
			)
		}
		testsTree, err := repository.LookupTree(testsTreeEntry.Id)
		if err != nil {
			return base.ErrorWithCategory(
				ErrInternalGit,
				errors.Wrap(
					err,
					"failed to lookup the tests/ tree",
				),
			)
		}
		defer testsTree.Free()

		testSettingsJSONEntry := testsTree.EntryByName("tests.json")
		if testSettingsJSONEntry == nil {
			return base.ErrorWithCategory(
				ErrTestsBadLayout,
				errors.New("tests/tests.json is missing"),
			)
		}
		testSettingsJSONBlob, err := repository.LookupBlob(testSettingsJSONEntry.Id)
		if err != nil {
			return base.ErrorWithCategory(
				ErrInternalGit,
				errors.Wrap(
					err,
					"failed to lookup tests/tests.json",
				),
			)
		}
		defer testSettingsJSONBlob.Free()

		var testsSettings common.TestsSettings
		{
			decoder := json.NewDecoder(bytes.NewReader(testSettingsJSONBlob.Contents()))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&testsSettings); err != nil {
				return base.ErrorWithCategory(
					ErrJSONParseError,
					errors.Wrap(
						err,
						"tests/tests.json",
					),
				)
			}
		}

		for _, solutionSettings := range testsSettings.Solutions {
			if _, err := testsTree.EntryByPath(solutionSettings.Filename); err != nil {
				return base.ErrorWithCategory(
					ErrTestsBadLayout,
					errors.Wrapf(
						err,
						"tests/%s is missing",
						solutionSettings.Filename,
					),
				)
			}

			if solutionSettings.ScoreRange == nil && solutionSettings.Verdict == "" {
				return base.ErrorWithCategory(
					ErrTestsBadLayout,
					errors.Errorf(
						"score_range or validator for %s in tests/tests.json should be set",
						solutionSettings.Filename,
					),
				)
			}

			if solutionSettings.Verdict != "" {
				foundVerdict := false
				for _, verdict := range common.VerdictList {
					if verdict == solutionSettings.Verdict {
						foundVerdict = true
						break
					}
				}
				if !foundVerdict {
					return base.ErrorWithCategory(
						ErrTestsBadLayout,
						errors.Errorf(
							"verdict for %s in tests/tests.json is not valid",
							solutionSettings.Filename,
						),
					)
				}
			}
		}

		if testsSettings.InputsValidator != nil {
			if _, err := testsTree.EntryByPath(testsSettings.InputsValidator.Filename); err != nil {
				return base.ErrorWithCategory(
					ErrTestsBadLayout,
					errors.Wrapf(
						err,
						"tests/%s is missing",
						testsSettings.InputsValidator.Filename,
					),
				)
			}
		}
	}

	// Interactive settings.
	interactiveTreeEntry := tree.EntryByName("interactive")
	var mainDistribSourceContents, idlFileContents []byte
	if interactiveTreeEntry == nil {
		problemSettings.Interactive = nil
	} else {
		if interactiveTreeEntry.Type != git.ObjectTree {
			return base.ErrorWithCategory(
				ErrInteractiveBadLayout,
				errors.New("interactive/ directory is not a tree"),
			)
		}
		interactiveTree, err := repository.LookupTree(interactiveTreeEntry.Id)
		if err != nil {
			return base.ErrorWithCategory(
				ErrInternalGit,
				errors.Wrap(
					err,
					"failed to lookup the interactive/ tree",
				),
			)
		}
		defer interactiveTree.Free()
		var moduleName, parentLang, distribLang string
		var idlFileOid, mainDistribSourceOid, mainSourceOid *git.Oid
		for i := uint64(0); i < interactiveTree.EntryCount(); i++ {
			entry := interactiveTree.EntryByIndex(i)
			if strings.HasPrefix(entry.Name, "Main.distrib.") {
				if distribLang != "" {
					return base.ErrorWithCategory(
						ErrInteractiveBadLayout,
						errors.Errorf(
							"multiple Main.distrib sources: Main.distrib.%s and %s",
							distribLang,
							entry.Name,
						),
					)
				}
				distribLang = path.Ext(entry.Name)[1:]
				mainDistribSourceOid = entry.Id
			} else if strings.HasPrefix(entry.Name, "Main.") {
				if parentLang != "" {
					return base.ErrorWithCategory(
						ErrInteractiveBadLayout,
						errors.Errorf(
							"multiple Main sources: Main.distrib.%s and %s",
							parentLang,
							entry.Name,
						),
					)
				}
				parentLang = path.Ext(entry.Name)[1:]
				mainSourceOid = entry.Id
			} else if strings.HasSuffix(entry.Name, ".idl") {
				if moduleName != "" {
					return base.ErrorWithCategory(
						ErrInteractiveBadLayout,
						errors.Errorf(
							"multiple .idl files: %s.idl and %s",
							moduleName,
							entry.Name,
						),
					)
				}
				moduleName = entry.Name[:len(entry.Name)-4]
				idlFileOid = entry.Id
			}
		}
		if moduleName == "" {
			return base.ErrorWithCategory(
				ErrInteractiveBadLayout,
				errors.New("missing .idl file"),
			)
		}
		if parentLang == "" {
			return base.ErrorWithCategory(
				ErrInteractiveBadLayout,
				errors.New("missing Main source file"),
			)
		}
		if distribLang == "" {
			mainSourceBlob, err := repository.LookupBlob(mainSourceOid)
			if err != nil {
				return base.ErrorWithCategory(
					ErrInteractiveBadLayout,
					errors.Wrapf(
						err,
						"failed to lookup blob for the main source file: interactive/Main.%s",
						parentLang,
					),
				)
			}
			defer mainSourceBlob.Free()

			mainDistribSourceContents = mainSourceBlob.Contents()
			distribPath := fmt.Sprintf("interactive/Main.distrib.%s", parentLang)
			requestContext.UpdatedFiles[distribPath] = bytes.NewReader(
				mainDistribSourceContents,
			)
		} else if parentLang != distribLang {
			return base.ErrorWithCategory(
				ErrInteractiveBadLayout,
				errors.Errorf(
					"mismatched parent language: Main.%s and Main.distrib.%s",
					parentLang,
					distribLang,
				),
			)
		} else {
			mainDistribSourceBlob, err := repository.LookupBlob(mainDistribSourceOid)
			if err != nil {
				return base.ErrorWithCategory(
					ErrInternalGit,
					errors.Wrapf(
						err,
						"failed to lookup blob for the main distrib source file interactive/Main.distrib.%s",
						parentLang,
					),
				)
			}
			defer mainDistribSourceBlob.Free()

			mainDistribSourceContents = mainDistribSourceBlob.Contents()
		}

		idlFileBlob, err := repository.LookupBlob(idlFileOid)
		if err != nil {
			return base.ErrorWithCategory(
				ErrInternalGit,
				errors.Wrapf(
					err,
					"failed to lookup blob for the idl file interactive/%s.idl",
					moduleName,
				),
			)
		}
		defer idlFileBlob.Free()

		idlFileContents = idlFileBlob.Contents()
		problemSettings.Interactive, err = interactiveSettingsCompiler.GetInteractiveSettings(
			bytes.NewReader(idlFileContents),
			moduleName,
			parentLang,
		)
		if err != nil {
			return base.ErrorWithCategory(
				ErrInteractiveBadLayout,
				errors.Wrap(
					err,
					"failed to get the interactive settings",
				),
			)
		}
	}

	// Validator settings.
	var validatorLang string
	for i := uint64(0); i < tree.EntryCount(); i++ {
		entry := tree.EntryByIndex(i)
		if entry.Type != git.ObjectBlob {
			continue
		}
		if !strings.HasPrefix(entry.Name, "validator.") {
			continue
		}
		if validatorLang != "" {
			return base.ErrorWithCategory(
				ErrProblemBadLayout,
				errors.Errorf(
					"multiple validator sources: validator.%s and %s",
					validatorLang,
					entry.Name,
				),
			)
		}
		validatorLang = filepath.Ext(entry.Name)[1:]
	}
	if problemSettings.Validator.Name == "custom" {
		if validatorLang == "" {
			return base.ErrorWithCategory(
				ErrProblemBadLayout,
				errors.Errorf(
					"problem with custom validator missing a validator",
				),
			)
		}
		problemSettings.Validator.Lang = &validatorLang
		problemSettings.Validator.Name = "custom"
	} else if validatorLang != "" {
		return base.ErrorWithCategory(
			ErrProblemBadLayout,
			errors.Errorf(
				"problem requested using validator %s, but has an unused validator.%s file",
				problemSettings.Validator.Name,
				validatorLang,
			),
		)
	}

	// Slowness.
	if problemSettings.Slow, err = isSlow(problemSettings, hardOverallWallTimeLimit); err != nil {
		// isSlow already wrapped the error correctly.
		return err
	}

	problemSettingsBytes, err := json.MarshalIndent(problemSettings, "", "  ")
	if err != nil {
		return base.ErrorWithCategory(
			ErrInteractiveBadLayout,
			errors.Wrap(
				err,
				"failed to marshal the new interactive settings",
			),
		)
	}
	requestContext.UpdatedFiles["settings.json"] = bytes.NewReader(problemSettingsBytes)

	// Generate the distributable problem settings (that can be used by the
	// ephemeral grader).
	problemDistribSettings := common.LiteralInput{
		Cases:  make(map[string]*common.LiteralCaseSettings),
		Limits: &problemSettings.Limits,
		Validator: &common.LiteralValidatorSettings{
			Name:      problemSettings.Validator.Name,
			Tolerance: problemSettings.Validator.Tolerance,
		},
	}
	if problemDistribSettings.Cases, err = extractExampleCases(repository, tree); err != nil {
		// extractExampleCases already wrapped the error correctly.
		return err
	}
	if problemSettings.Validator.Name == "custom" {
		problemDistribSettings.Validator.CustomValidator = &common.LiteralCustomValidatorSettings{
			Source:   "",
			Language: *problemSettings.Validator.Lang,
			Limits:   problemSettings.Validator.Limits,
		}
		validatorDistribTreeEntry := tree.EntryByName(
			fmt.Sprintf("validator.distrib.%s", *problemSettings.Validator.Lang),
		)
		if validatorDistribTreeEntry != nil {
			validatorDistribBlob, err := repository.LookupBlob(validatorDistribTreeEntry.Id)
			if err != nil {
				return base.ErrorWithCategory(
					ErrInternalGit,
					errors.Wrap(
						err,
						"failed to lookup the distributable validator",
					),
				)
			}
			defer validatorDistribBlob.Free()

			problemDistribSettings.Validator.CustomValidator.Source = string(validatorDistribBlob.Contents())
		}
	}
	if problemSettings.Interactive != nil {
		problemDistribSettings.Interactive = &common.LiteralInteractiveSettings{
			IDLSource:  string(idlFileContents),
			Templates:  problemSettings.Interactive.Templates,
			ModuleName: problemSettings.Interactive.ModuleName,
			ParentLang: problemSettings.Interactive.ParentLang,
			MainSource: string(mainDistribSourceContents),
		}
	}
	problemDistribSettingsBytes, err := json.MarshalIndent(problemDistribSettings, "", "  ")
	if err != nil {
		return base.ErrorWithCategory(
			ErrInternal,
			errors.Wrap(
				err,
				"failed to marshal the new interactive settings",
			),
		)
	}

	requestContext.UpdatedFiles["settings.distrib.json"] = bytes.NewReader(problemDistribSettingsBytes)

	return nil
}

func validateUpdatePublished(repository *git.Repository, newCommit *git.Commit) error {
	head, err := repository.Head()
	if err != nil {
		// The master branch has not been yet created.
		return ErrPublishedNotFromMaster
	}
	defer head.Free()
	descendant, err := repository.DescendantOf(head.Target(), newCommit.Id())
	if err != nil {
		return base.ErrorWithCategory(
			ErrInternalGit,
			errors.Wrapf(
				err,
				"failed to determine whether %s is a descendant of %s",
				head.Target(),
				newCommit.Id(),
			),
		)
	}
	if !head.Target().Equal(newCommit.Id()) && !descendant {
		return ErrPublishedNotFromMaster
	}

	return nil
}

func (p *gitProtocol) validateUpdateConfig(repository *git.Repository, oldCommit, newCommit *git.Commit) error {
	newTree, err := newCommit.Tree()
	if err != nil {
		return base.ErrorWithCategory(
			ErrInternalGit,
			errors.Wrapf(
				err,
				"failed to get tree for new commit %s",
				newCommit.Id(),
			),
		)
	}
	defer newTree.Free()

	// Sanity checks.
	if newTree.EntryCount() == 0 {
		// Empty tree is valid.
		return nil
	} else if newTree.EntryCount() != 1 {
		return base.ErrorWithCategory(
			ErrConfigBadLayout,
			errors.New("refs/meta/config can only contain a single config.json file"),
		)
	}
	treeEntry := newTree.EntryByIndex(0)
	if treeEntry.Type != git.ObjectBlob || treeEntry.Name != "config.json" {
		return base.ErrorWithCategory(
			ErrConfigBadLayout,
			errors.New("refs/meta/config can only contain a single config.json file"),
		)
	}
	configBlob, err := repository.LookupBlob(treeEntry.Id)
	if err != nil {
		return base.ErrorWithCategory(
			ErrInternalGit,
			errors.Wrapf(
				err,
				"failed to lookup blob for %s",
				treeEntry.Name,
			),
		)
	}
	contents := configBlob.Contents()
	configBlob.Free()

	var metaConfig MetaConfig
	if err := json.Unmarshal([]byte(contents), &metaConfig); err != nil {
		return base.ErrorWithCategory(
			ErrJSONParseError,
			errors.Wrap(
				err,
				treeEntry.Name,
			),
		)
	}
	if metaConfig.Publishing.Mode == "mirror" {
		// No additional checks needed.
	} else if metaConfig.Publishing.Mode == "subdirectory" {
		if metaConfig.Publishing.Target == "" {
			return ErrConfigSubdirectoryMissingTarget
		}
	} else {
		return ErrConfigInvalidPublishingMode
	}
	if parsed, err := url.Parse(metaConfig.Publishing.Repository); err != nil || !parsed.IsAbs() {
		return ErrConfigRepositoryNotAbsoluteURL
	}
	return nil
}

func validateUpdateReview(repository *git.Repository, oldCommit, newCommit *git.Commit) error {
	iterationUUID := ""

	for _, line := range strings.Split(newCommit.Message(), "\n") {
		if strings.HasPrefix(line, iterationLabel) {
			iterationUUID = strings.TrimSpace(line[len(iterationLabel):])
			break
		}
	}

	if len(iterationUUID) != 36 {
		return base.ErrorWithCategory(
			ErrReviewBadLayout,
			errors.New("iteration uuid in commit message missing or malformed"),
		)
	}

	var oldTree *git.Tree
	if oldCommit != nil {
		var err error
		oldTree, err = oldCommit.Tree()
		if err != nil {
			return base.ErrorWithCategory(
				ErrInternalGit,
				errors.Wrapf(
					err,
					"failed to get tree for old commit %s",
					oldCommit.Id(),
				),
			)
		}
		defer oldTree.Free()
	}
	newTree, err := newCommit.Tree()
	if err != nil {
		return base.ErrorWithCategory(
			ErrInternalGit,
			errors.Wrapf(
				err,
				"failed to get tree for new commit %s",
				newCommit.Id(),
			),
		)
	}
	defer newTree.Free()

	type reviewEntry struct {
		reviewContents   string
		previousContents string
		appendedContents string
		masterTree       *git.Tree
	}
	var ledgerEntry *reviewEntry

	// Sanity checks.
	newEntries := make(map[string]*reviewEntry)
	for i := uint64(0); i < newTree.EntryCount(); i++ {
		treeEntry := newTree.EntryByIndex(i)
		if treeEntry.Type != git.ObjectBlob {
			return base.ErrorWithCategory(
				ErrReviewBadLayout,
				errors.New("refs/meta/review must have a flat tree"),
			)
		}

		reviewBlob, err := repository.LookupBlob(treeEntry.Id)
		if err != nil {
			return base.ErrorWithCategory(
				ErrInternalGit,
				errors.Wrapf(
					err,
					"failed to lookup the blob for %s",
					treeEntry.Name,
				),
			)
		}
		contents := string(reviewBlob.Contents())
		reviewBlob.Free()

		if !utf8.ValidString(contents) {
			return base.ErrorWithCategory(
				ErrReviewBadLayout,
				fmt.Errorf("%s is not valid utf-8 encoded", treeEntry.Name),
			)
		}
		if !strings.HasSuffix(contents, "\n") {
			return base.ErrorWithCategory(
				ErrReviewBadLayout,
				fmt.Errorf("%s does not end in newline", treeEntry.Name),
			)
		}

		if treeEntry.Name == "ledger" {
			ledgerEntry = &reviewEntry{
				reviewContents:   contents,
				previousContents: "",
				appendedContents: contents,
			}
			continue
		}

		masterCommitOid, err := git.NewOid(treeEntry.Name)
		if err != nil {
			return base.ErrorWithCategory(
				ErrReviewBadLayout,
				errors.Wrapf(
					err,
					"invalid filename %s, should be a git commit id",
					treeEntry.Name,
				),
			)
		}
		masterCommit, err := repository.LookupCommit(masterCommitOid)
		if err != nil {
			return base.ErrorWithCategory(
				ErrReviewBadLayout,
				errors.Wrapf(
					err,
					"invalid filename %s, should point to a valid git commit id",
					treeEntry.Name,
				),
			)
		}
		defer masterCommit.Free()
		masterTree, err := masterCommit.Tree()
		if err != nil {
			return base.ErrorWithCategory(
				ErrInternalGit,
				errors.Wrapf(
					err,
					"failed to get tree for old commit %s",
					masterCommit.Id(),
				),
			)
		}
		defer masterTree.Free()
		newEntries[treeEntry.Name] = &reviewEntry{
			reviewContents:   contents,
			previousContents: "",
			appendedContents: contents,
			masterTree:       masterTree,
		}
	}

	if ledgerEntry == nil {
		return base.ErrorWithCategory(
			ErrReviewBadLayout,
			errors.New("missing ledger file"),
		)
	}

	// Perform append-only validations.
	if oldTree != nil {
		for i := uint64(0); i < oldTree.EntryCount(); i++ {
			treeEntry := oldTree.EntryByIndex(i)

			newEntry, ok := newEntries[treeEntry.Name]
			if !ok && treeEntry.Name != "ledger" {
				return base.ErrorWithCategory(
					ErrReviewBadLayout,
					fmt.Errorf("failed to find %s in review iteration", treeEntry.Name),
				)
			}
			if treeEntry.Name == "ledger" {
				newEntry = ledgerEntry
			}

			reviewBlob, err := repository.LookupBlob(treeEntry.Id)
			if err != nil {
				return base.ErrorWithCategory(
					ErrInternalGit,
					errors.Wrapf(
						err,
						"failed to lookup file %s",
						treeEntry.Name,
					),
				)
			}
			contents := string(reviewBlob.Contents())
			reviewBlob.Free()

			if !strings.HasPrefix(newEntry.reviewContents, contents) {
				return base.ErrorWithCategory(
					ErrReviewBadLayout,
					fmt.Errorf("unexpected non-append to %s", treeEntry.Name),
				)
			}
			newEntry.previousContents = newEntry.reviewContents[:len(contents)]
			newEntry.appendedContents = newEntry.reviewContents[len(contents):]
		}
	}

	var ledgerIteration LedgerIteration
	if err := json.Unmarshal([]byte(ledgerEntry.appendedContents), &ledgerIteration); err != nil {
		return base.ErrorWithCategory(
			ErrJSONParseError,
			errors.Wrap(
				err,
				"appended ledger contents",
			),
		)
	}
	if ledgerIteration.UUID != iterationUUID {
		return base.ErrorWithCategory(
			ErrReviewBadLayout,
			errors.New("invalid iteration uuid in ledger entry"),
		)
	}
	// TODO(lhchavez): Validate author.

	for commentHash, entry := range newEntries {
		previousUUIDs := make(map[string]struct{})
		var comment Comment
		for _, line := range strings.Split(entry.previousContents, "\n") {
			if line == "" {
				continue
			}
			if err := json.Unmarshal([]byte(line), &comment); err != nil {
				return base.ErrorWithCategory(
					ErrReviewBadLayout,
					errors.Wrapf(
						err,
						"malformed appended comment in %s",
						commentHash,
					),
				)
			}
			previousUUIDs[comment.UUID] = struct{}{}
		}
		for _, line := range strings.Split(entry.appendedContents, "\n") {
			if line == "" {
				continue
			}
			if err := json.Unmarshal([]byte(line), &comment); err != nil {
				return base.ErrorWithCategory(
					ErrReviewBadLayout,
					errors.Wrapf(
						err,
						"malformed appended comment in %s",
						commentHash,
					),
				)
			}
			if comment.Author != ledgerIteration.Author {
				return base.ErrorWithCategory(
					ErrReviewBadLayout,
					fmt.Errorf("invalid author in %s", commentHash),
				)
			}
			if comment.IterationUUID != iterationUUID {
				return base.ErrorWithCategory(
					ErrReviewBadLayout,
					fmt.Errorf("invalid iteration uuid in %s", commentHash),
				)
			}
			if len(comment.UUID) != 36 {
				return base.ErrorWithCategory(
					ErrReviewBadLayout,
					fmt.Errorf("missing or malformed comment uuid in %s", commentHash),
				)
			}
			if _, ok := previousUUIDs[comment.UUID]; ok {
				return base.ErrorWithCategory(
					ErrReviewBadLayout,
					fmt.Errorf("duplicate comment uuid in %s", commentHash),
				)
			}
			if comment.ParentUUID != nil {
				if _, ok := previousUUIDs[*comment.ParentUUID]; !ok {
					return base.ErrorWithCategory(
						ErrReviewBadLayout,
						fmt.Errorf("parent uuid missing in %s", commentHash),
					)
				}
				if comment.Range != nil {
					return base.ErrorWithCategory(
						ErrReviewBadLayout,
						fmt.Errorf("cannot specify both parentUuid and range in %s", commentHash),
					)
				}
			}
			if _, err := entry.masterTree.EntryByPath(comment.Filename); err != nil {
				return base.ErrorWithCategory(
					ErrReviewBadLayout,
					errors.Wrapf(
						err,
						"file '%s' not found in %s",
						comment.Filename,
						commentHash,
					),
				)
			}
			if comment.Message == "" && !comment.Done {
				return base.ErrorWithCategory(
					ErrReviewBadLayout,
					fmt.Errorf("empty comment message in %s", commentHash),
				)
			}
			previousUUIDs[comment.UUID] = struct{}{}
		}
	}

	return nil
}

func (p *gitProtocol) validateChange(
	repository *git.Repository,
	oldCommit, newCommit *git.Commit,
) error {
	newTree, err := newCommit.Tree()
	if err != nil {
		return base.ErrorWithCategory(
			ErrInternalGit,
			errors.Wrapf(
				err,
				"failed to get tree for new commit %s",
				newCommit.Id(),
			),
		)
	}
	defer newTree.Free()

	var walkErr error
	objectCount := 0
	newTree.Walk(func(name string, entry *git.TreeEntry) int {
		objectCount++
		if objectCount > objectLimit {
			p.log.Error(
				"Tree exceeded object limit",
			)
			walkErr = ErrTooManyObjects
			return -1
		}
		return 0
	})
	if walkErr != nil {
		return walkErr
	}

	// settings.json
	treeEntry := newTree.EntryByName("settings.json")
	if treeEntry == nil || treeEntry.Type != git.ObjectBlob {
		return ErrChangeMissingSettingsJSON
	}
	settingsBlob, err := repository.LookupBlob(treeEntry.Id)
	if err != nil {
		return base.ErrorWithCategory(
			ErrInternalGit,
			errors.Wrapf(
				err,
				"failed to lookup file %s",
				treeEntry.Name,
			),
		)
	}
	contents := settingsBlob.Contents()
	settingsBlob.Free()

	var settings common.ProblemSettings
	if err := json.Unmarshal([]byte(contents), &settings); err != nil {
		return base.ErrorWithCategory(
			ErrJSONParseError,
			errors.Wrap(
				err,
				treeEntry.Name,
			),
		)
	}

	// TODO(lhchavez): Really validate the change.
	return nil
}

func (p *gitProtocol) validateUpdate(
	ctx context.Context,
	repository *git.Repository,
	level githttp.AuthorizationLevel,
	command *githttp.GitCommand,
	oldCommit, newCommit *git.Commit,
) error {
	p.log.Info(
		"Update",
		"command", command,
	)
	if command.IsDelete() {
		return githttp.ErrDeleteDisallowed
	}

	// Since we allow non-fast-forward refs globally, we need to check if the
	// published branch is the one being updated.
	if command.ReferenceName != "refs/heads/published" &&
		!githttp.ValidateFastForward(repository, newCommit, command.Reference) {
		return githttp.ErrNonFastForward
	}

	// These are the only references that can be changed.
	if command.ReferenceName != "refs/heads/master" &&
		command.ReferenceName != "refs/heads/public" &&
		command.ReferenceName != "refs/heads/protected" &&
		command.ReferenceName != "refs/heads/private" &&
		command.ReferenceName != "refs/heads/published" &&
		command.ReferenceName != "refs/meta/config" &&
		command.ReferenceName != "refs/meta/review" &&
		!strings.HasPrefix(command.ReferenceName, "refs/changes/") {
		return githttp.ErrInvalidRef
	}

	// These references cannot be changed directly. Only implicitly when merging
	// reviews.
	if command.ReferenceName == "refs/heads/public" ||
		command.ReferenceName == "refs/heads/protected" ||
		command.ReferenceName == "refs/heads/private" {
		return githttp.ErrReadOnlyRef
	}

	requestContext := request.FromContext(ctx)
	if command.ReferenceName == "refs/heads/master" {
		if !requestContext.IsAdmin {
			return githttp.ErrForbidden
		}
		return validateUpdateMaster(
			ctx,
			repository,
			newCommit,
			p.allowDirectPushToMaster,
			p.hardOverallWallTimeLimit,
			p.interactiveSettingsCompiler,
			p.log,
		)
	} else if command.ReferenceName == "refs/heads/published" {
		if !requestContext.IsAdmin {
			return githttp.ErrForbidden
		}
		return validateUpdatePublished(repository, newCommit)
	} else if command.ReferenceName == "refs/meta/config" {
		if !requestContext.IsAdmin {
			return githttp.ErrForbidden
		}
		return p.validateUpdateConfig(repository, oldCommit, newCommit)
	} else if command.ReferenceName == "refs/meta/review" {
		if !requestContext.CanEdit && !requestContext.HasSolved {
			return githttp.ErrForbidden
		}
		return validateUpdateReview(repository, oldCommit, newCommit)
	}

	if !requestContext.CanEdit && !requestContext.HasSolved {
		return githttp.ErrForbidden
	}
	return p.validateChange(repository, oldCommit, newCommit)
}

func (p *gitProtocol) preprocessMaster(
	ctx context.Context,
	originalRepository *git.Repository,
	tmpDir string,
	originalPackPath string,
	originalCommands []*githttp.GitCommand,
) (string, []*githttp.GitCommand, error) {
	originalCommit, err := originalRepository.LookupCommit(originalCommands[0].New)
	if err != nil {
		return originalPackPath, originalCommands, base.ErrorWithCategory(
			ErrInternalGit,
			errors.Wrapf(
				err,
				"failed to lookup commit %s",
				originalCommands[0].New,
			),
		)
	}
	defer originalCommit.Free()

	var commitDescriptions []githttp.SplitCommitDescription
	for _, originalDescription := range DefaultCommitDescriptions {
		commitDescriptions = append(commitDescriptions, githttp.SplitCommitDescription{
			ReferenceName: originalDescription.ReferenceName,
			PathRegexps:   originalDescription.PathRegexps,
		})
		description := &commitDescriptions[len(commitDescriptions)-1]

		ref, err := originalRepository.References.Lookup(description.ReferenceName)
		if err != nil {
			if git.IsErrorCode(err, git.ErrNotFound) {
				continue
			}
			return originalPackPath, originalCommands, base.ErrorWithCategory(
				ErrInternalGit,
				errors.Wrapf(
					err,
					"failed to lookup reference %s",
					description.ReferenceName,
				),
			)
		}
		defer ref.Free()

		description.Reference = ref
		commit, err := originalRepository.LookupCommit(ref.Target())
		if err != nil {
			return originalPackPath, originalCommands, base.ErrorWithCategory(
				ErrInternalGit,
				errors.Wrapf(
					err,
					"failed to lookup commit %s",
					ref.Target(),
				),
			)
		}
		defer commit.Free()

		description.ParentCommit = commit
	}

	masterRef, err := originalRepository.References.Lookup("refs/heads/master")
	var masterCommit *git.Commit
	if err != nil && !git.IsErrorCode(err, git.ErrNotFound) {
		return originalPackPath, originalCommands, base.ErrorWithCategory(
			ErrInternalGit,
			errors.Wrap(
				err,
				"failed to lookup reference refs/heads/master",
			),
		)
	}
	if masterRef != nil {
		defer masterRef.Free()

		masterCommit, err = originalRepository.LookupCommit(masterRef.Target())
		if err != nil {
			return originalPackPath, originalCommands, base.ErrorWithCategory(
				ErrInternalGit,
				errors.Wrap(
					err,
					"failed to lookup commit for reference refs/heads/master",
				),
			)
		}
		defer masterCommit.Free()
	}
	p.log.Info("Updating ref", "ref", masterRef, "err", err, "masterCommit", masterCommit)

	requestContext := request.FromContext(ctx)
	reviewRef := requestContext.ReviewRef
	commitMessageTag := ""
	if reviewRef != "" {
		commitMessageTag = fmt.Sprintf("Reviewed-In: %s", reviewRef)
	}

	newPackPath := filepath.Join(tmpDir, "new.pack")
	newCommands, err := githttp.SpliceCommit(
		originalRepository,
		originalCommit,
		masterCommit,
		requestContext.UpdatedFiles,
		commitDescriptions,
		originalCommit.Author(),
		originalCommit.Committer(),
		"refs/heads/master",
		masterRef,
		commitMessageTag,
		newPackPath,
		p.log,
	)
	if err != nil {
		return originalPackPath, originalCommands, base.ErrorWithCategory(
			ErrInternalGit,
			errors.Wrap(
				err,
				"failed to splice commit",
			),
		)
	}
	return newPackPath, newCommands, nil
}

func (p *gitProtocol) preprocess(
	ctx context.Context,
	originalRepository *git.Repository,
	tmpDir string,
	originalPackPath string,
	originalCommands []*githttp.GitCommand,
) (string, []*githttp.GitCommand, error) {
	p.log.Info("Updating", "reference", originalCommands)
	if originalCommands[0].ReferenceName == "refs/heads/master" {
		return p.preprocessMaster(ctx, originalRepository, tmpDir, originalPackPath, originalCommands)
	}
	return originalPackPath, originalCommands, nil
}

type gitHandler struct {
	handler http.Handler
	log     log15.Logger
}

func (g *gitHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.handler.ServeHTTP(w, r)
}

// GitHandler is the HTTP handler for the omegaUp git server.
func GitHandler(
	rootPath string,
	protocol *githttp.GitProtocol,
	metrics base.Metrics,
	log log15.Logger,
) http.Handler {
	return &gitHandler{
		handler: githttp.GitServer(
			rootPath,
			"",
			true,
			protocol,
			func(ctx context.Context) context.Context {
				return request.NewContext(ctx, metrics)
			},
			log,
		),
		log: log,
	}
}

// InitRepository is a wrapper around git.CreateRepository() that also adds
// omegaUp-specific files to the repository.
func InitRepository(
	repositoryPath string,
) (*git.Repository, error) {
	repo, err := git.InitRepository(repositoryPath, true)
	if err != nil {
		return nil, base.ErrorWithCategory(
			ErrInternalGit,
			errors.Wrapf(
				err,
				"failed to initialize repository at %s",
				repositoryPath,
			),
		)
	}

	// Disable delta.
	repoConfig, err := repo.Config()
	if err != nil {
		return nil, base.ErrorWithCategory(
			ErrInternalGit,
			errors.Wrapf(
				err,
				"failed to create config for repository at %s",
				repositoryPath,
			),
		)
	}
	defer repoConfig.Free()

	if err := repoConfig.SetInt32("pack.deltaCacheSize", 0); err != nil {
		return nil, base.ErrorWithCategory(
			ErrInternalGit,
			errors.Wrapf(
				err,
				"failed to disable delta compression for repository at %s",
				repositoryPath,
			),
		)
	}

	omegaupPath := path.Join(repositoryPath, "omegaup")
	if err := os.Mkdir(omegaupPath, 0755); err != nil {
		return nil, base.ErrorWithCategory(
			ErrInternalGit,
			errors.Wrapf(
				err,
				"failed to create omegaUp git directory at %s",
				omegaupPath,
			),
		)
	}

	{
		versionPath := path.Join(omegaupPath, "version")
		f, err := os.Create(versionPath)
		if err != nil {
			return nil, base.ErrorWithCategory(
				ErrInternalGit,
				errors.Wrapf(
					err,
					"failed to create omegaUp repository version file at %s",
					versionPath,
				),
			)
		}
		defer f.Close()
		if _, err := f.WriteString("1\n"); err != nil {
			return nil, base.ErrorWithCategory(
				ErrInternalGit,
				errors.Wrapf(
					err,
					"failed to write the omegaUp repository version file at %s",
					versionPath,
				),
			)
		}
	}

	{
		attributesPath := path.Join(repositoryPath, "info/attributes")
		f, err := os.Create(attributesPath)
		if err != nil {
			return nil, base.ErrorWithCategory(
				ErrInternalGit,
				errors.Wrapf(
					err,
					"failed to create git attributes file at %s",
					attributesPath,
				),
			)
		}
		defer f.Close()
		if _, err := f.WriteString(GitAttributesContents); err != nil {
			return nil, base.ErrorWithCategory(
				ErrInternalGit,
				errors.Wrapf(
					err,
					"failed to write git attributes file at %s",
					attributesPath,
				),
			)
		}
	}

	return repo, nil
}
