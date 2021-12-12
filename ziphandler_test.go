package gitserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/omegaup/githttp/v2"
	"github.com/omegaup/gitserver/gitservertest"
	"github.com/omegaup/go-base/logging/log15"
	base "github.com/omegaup/go-base/v3"
	"github.com/omegaup/quark/common"

	git "github.com/libgit2/git2go/v33"
)

func wrapReaders(contents map[string]string) map[string]io.Reader {
	result := make(map[string]io.Reader)
	for filename, s := range contents {
		result[filename] = strings.NewReader(s)
	}
	return result
}

func postZip(
	authorization string,
	problemAlias string,
	problemSettings *common.ProblemSettings,
	zipMergeStrategy ZipMergeStrategy,
	zipContents []byte,
	commitMessage string,
	create bool,
	useMultipartFormData bool,
	acceptsSubmissions bool,
	ts *httptest.Server,
) (*UpdateResult, error) {
	problemSettingsString := ""
	if problemSettings != nil {
		problemSettingsBytes, err := json.Marshal(problemSettings)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal the problem settings: %w", err)
		}
		problemSettingsString = string(problemSettingsBytes)
	}

	pushURL, err := url.Parse(fmt.Sprintf("%s/%s/git-upload-zip?acceptsSubmissions=%v", ts.URL, problemAlias, acceptsSubmissions))
	if err != nil {
		return nil, fmt.Errorf("Failed to parse URL: %w", err)
	}
	var buf bytes.Buffer
	req := &http.Request{
		URL:    pushURL,
		Method: "POST",
		Body:   ioutil.NopCloser(&buf),
		Header: map[string][]string{
			"Authorization": {authorization},
		},
	}
	query := url.Values{}
	if useMultipartFormData {
		var boundary string
		{
			w := multipart.NewWriter(&buf)
			boundary = w.Boundary()
			w.WriteField("message", commitMessage)
			w.WriteField("mergeStrategy", zipMergeStrategy.String())
			if problemSettingsString != "" {
				w.WriteField("settings", problemSettingsString)
			}
			zipWriter, _ := w.CreateFormFile("contents", "file.zip")
			zipWriter.Write(zipContents)
			w.Close()
		}
		req.Header.Add("Content-Type", fmt.Sprintf("multipart/form-data; boundary=%s", boundary))
	} else {
		query.Set("message", commitMessage)
		query.Set("mergeStrategy", zipMergeStrategy.String())
		if problemSettingsString != "" {
			query.Set("settings", problemSettingsString)
		}
		req.Header.Add("Content-Type", "application/zip")
		buf.Write(zipContents)
	}
	if create {
		query.Set("create", "1")
	}
	req.URL.RawQuery = query.Encode()
	res, err := ts.Client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("Failed to upload zip: %w", err)
	}
	defer res.Body.Close()

	var updateResult UpdateResult
	if err := json.NewDecoder(res.Body).Decode(&updateResult); err != nil && res.StatusCode == http.StatusOK {
		return nil, fmt.Errorf("Failed to unmarshal updateResult: %w", err)
	}

	if res.StatusCode != http.StatusOK {
		return &updateResult, fmt.Errorf("Failed to upload zip: Status %v, headers: %v", res.StatusCode, res.Header)
	}

	return &updateResult, nil
}

func mustPostZip(
	t *testing.T,
	authorization string,
	problemAlias string,
	problemSettings *common.ProblemSettings,
	zipMergeStrategy ZipMergeStrategy,
	zipContents []byte,
	commitMessage string,
	create bool,
	useMultipartFormData bool,
	acceptsSubmissions bool,
	ts *httptest.Server,
) *UpdateResult {
	result, err := postZip(
		authorization,
		problemAlias,
		problemSettings,
		zipMergeStrategy,
		zipContents,
		commitMessage,
		create,
		useMultipartFormData,
		acceptsSubmissions,
		ts,
	)
	if err != nil {
		t.Fatalf("%v, result=%v", err, result)
	}
	return result
}

func TestPushZip(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", t.Name())
	if err != nil {
		t.Fatalf("Failed to create directory: %v", err)
	}
	if os.Getenv("PRESERVE") == "" {
		defer os.RemoveAll(tmpDir)
	}

	log, err := log15.New("info", false)
	if err != nil {
		t.Fatalf("Failed to create log: %v", err)
	}
	ts := httptest.NewServer(NewZipHandler(ZipHandlerOpts{
		RootPath: tmpDir,
		Protocol: NewGitProtocol(GitProtocolOpts{
			GitProtocolOpts: githttp.GitProtocolOpts{
				AuthCallback: authorize,
				Log:          log,
			},
			AllowDirectPushToMaster:     true,
			HardOverallWallTimeLimit:    OverallWallTimeHardLimit,
			InteractiveSettingsCompiler: fakeInteractiveSettingsCompiler,
		}),
		Log: log,
	}))
	defer ts.Close()

	problemAlias := "sumas"

	{
		zipContents, err := gitservertest.CreateZip(
			map[string]io.Reader{
				"settings.json":          strings.NewReader(gitservertest.DefaultSettingsJSON),
				"cases/0.in":             strings.NewReader("1 2\n"),
				"cases/0.out":            strings.NewReader("3\n"),
				"statements/es.markdown": strings.NewReader("Sumaz\n"),
			},
		)
		if err != nil {
			t.Fatalf("Failed to create zip: %v", err)
		}
		mustPostZip(
			t,
			adminAuthorization,
			problemAlias,
			nil,
			ZipMergeStrategyTheirs,
			zipContents,
			"initial commit",
			true, // create
			true, // useMultipartFormData
			true, // acceptsSubmissions
			ts,
		)
	}

	{
		zipContents, err := gitservertest.CreateZip(
			map[string]io.Reader{
				"settings.json":          strings.NewReader(gitservertest.DefaultSettingsJSON),
				"cases/0.in":             strings.NewReader("1 2\n"),
				"cases/0.out":            strings.NewReader("3\n"),
				"statements/es.markdown": strings.NewReader("Sumas\n"),
			},
		)
		if err != nil {
			t.Fatalf("Failed to create zip: %v", err)
		}
		mustPostZip(
			t,
			adminAuthorization,
			problemAlias,
			nil,
			ZipMergeStrategyTheirs,
			zipContents,
			"initial commit",
			false, // create
			false, // useMultipartFormData
			true,  // acceptsSubmissions
			ts,
		)
	}
}

func TestConvertZip(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", t.Name())
	if err != nil {
		t.Fatalf("Failed to create directory: %v", err)
	}
	if os.Getenv("PRESERVE") == "" {
		defer os.RemoveAll(tmpDir)
	}
	ctx := context.Background()

	problemAlias := "sumas"

	repo, err := InitRepository(ctx, path.Join(tmpDir, problemAlias))
	if err != nil {
		t.Fatalf("Failed to initialize git repository: %v", err)
	}
	defer repo.Free()

	log, err := log15.New("info", false)
	if err != nil {
		t.Fatalf("Failed to create log: %v", err)
	}

	fileContents := map[string]string{
		".gitignore":             defaultGitfiles[".gitignore"],
		".gitattributes":         defaultGitfiles[".gitattributes"],
		"settings.json":          gitservertest.DefaultSettingsJSON,
		"cases/0.in":             "1 2\n",
		"cases/0.out":            "3\n",
		"statements/es.markdown": "Sumas\n",
	}

	parent := &git.Oid{}
	commitMessage := "Initial commit"

	zipOid, err := ConvertZipToPackfile(
		ctx,
		common.NewProblemFilesFromMap(
			fileContents,
			"problem.zip",
		),
		nil,
		ZipMergeStrategyTheirs,
		repo,
		parent,
		&git.Signature{
			Name:  "author",
			Email: "author@test.test",
			When:  time.Unix(0, 0).In(time.UTC),
		},
		&git.Signature{
			Name:  "committer",
			Email: "committer@test.test",
			When:  time.Unix(0, 0).In(time.UTC),
		},
		commitMessage,
		true,
		ioutil.Discard,
		log,
	)
	if err != nil {
		t.Fatalf("Failed to convert zip: %v", err)
	}

	commitOid, _ := createCommit(
		t,
		tmpDir,
		problemAlias,
		parent,
		wrapReaders(fileContents),
		commitMessage,
		log,
	)

	if !commitOid.Equal(zipOid) {
		t.Fatalf("Failed to create a commit. Expected %q, got %q", commitOid, zipOid)
	}
}

func TestZiphandlerCases(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", strings.ReplaceAll(t.Name(), "/", "_"))
	if err != nil {
		t.Fatalf("Failed to create directory: %v", err)
	}
	if os.Getenv("PRESERVE") == "" {
		defer os.RemoveAll(tmpDir)
	}

	problemAlias := "sumas"

	log, err := log15.New("info", false)
	if err != nil {
		t.Fatalf("Failed to create log: %v", err)
	}

	ts := httptest.NewServer(NewZipHandler(ZipHandlerOpts{
		RootPath: tmpDir,
		Protocol: NewGitProtocol(GitProtocolOpts{
			GitProtocolOpts: githttp.GitProtocolOpts{
				AuthCallback: authorize,
				Log:          log,
			},
			AllowDirectPushToMaster:     true,
			HardOverallWallTimeLimit:    OverallWallTimeHardLimit,
			InteractiveSettingsCompiler: fakeInteractiveSettingsCompiler,
		}),
		Log: log,
	}))
	defer ts.Close()

	for name, tc := range map[string]struct {
		contents      map[string]io.Reader
		expectedError string
	}{
		"missing cases": {
			contents: map[string]io.Reader{
				".gitignore":             strings.NewReader(defaultGitfiles[".gitignore"]),
				".gitattributes":         strings.NewReader(defaultGitfiles[".gitattributes"]),
				"statements/es.markdown": strings.NewReader("Sumas\n"),
			},
			expectedError: "problem-bad-layout: cases/ directory missing or empty",
		},
		"cases with extension": {
			contents: map[string]io.Reader{
				".gitignore":             strings.NewReader(defaultGitfiles[".gitignore"]),
				".gitattributes":         strings.NewReader(defaultGitfiles[".gitattributes"]),
				"cases/case.in.txt":      strings.NewReader("1 2"),
				"cases/case.out.txt":     strings.NewReader("3"),
				"statements/es.markdown": strings.NewReader("Sumas\n"),
			},
			expectedError: "problem-bad-layout: cases/ directory missing or empty",
		},
		"cases with missing .out": {
			contents: map[string]io.Reader{
				".gitignore":             strings.NewReader(defaultGitfiles[".gitignore"]),
				".gitattributes":         strings.NewReader(defaultGitfiles[".gitattributes"]),
				"cases/case.in":          strings.NewReader("1 2"),
				"statements/es.markdown": strings.NewReader("Sumas\n"),
			},
			expectedError: "mismatched-input-file: failed to find the output file for cases/case",
		},
	} {
		tc := tc
		t.Run(name, func(t *testing.T) {
			zipContents, err := gitservertest.CreateZip(tc.contents)
			if err != nil {
				t.Fatalf("Failed to create .zip: %v", err)
			}
			result, err := postZip(
				adminAuthorization,
				problemAlias,
				nil,
				ZipMergeStrategyTheirs,
				zipContents,
				"initial commit",
				true, // create
				true, // useMultipartFormData
				true, // acceptsSubmissions
				ts,
			)
			if result == nil {
				t.Fatalf("Failed to upload .zip: %v", err)
			}
			if tc.expectedError != result.Error {
				t.Fatalf("Unexpected error. Expected %q, got %q", tc.expectedError, result.Error)
			}
		})
	}
}

func TestZiphandlerSolutions(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", strings.ReplaceAll(t.Name(), "/", "_"))
	if err != nil {
		t.Fatalf("Failed to create directory: %v", err)
	}
	if os.Getenv("PRESERVE") == "" {
		defer os.RemoveAll(tmpDir)
	}

	problemAlias := "sumas"

	log, err := log15.New("info", false)
	if err != nil {
		t.Fatalf("Failed to create log: %v", err)
	}

	ts := httptest.NewServer(NewZipHandler(ZipHandlerOpts{
		RootPath: tmpDir,
		Protocol: NewGitProtocol(GitProtocolOpts{
			GitProtocolOpts: githttp.GitProtocolOpts{
				AuthCallback: authorize,
				Log:          log,
			},
			AllowDirectPushToMaster:     true,
			HardOverallWallTimeLimit:    OverallWallTimeHardLimit,
			InteractiveSettingsCompiler: fakeInteractiveSettingsCompiler,
		}),
		Log: log,
	}))
	defer ts.Close()
	zipContents, err := gitservertest.CreateZip(
		map[string]io.Reader{
			".gitignore":                strings.NewReader(defaultGitfiles[".gitignore"]),
			".gitattributes":            strings.NewReader(defaultGitfiles[".gitattributes"]),
			"cases/0.in":                strings.NewReader("1 2\n"),
			"cases/0.out":               strings.NewReader("3\n"),
			"statements/es.markdown":    strings.NewReader("Sumas\n"),
			"solutions/es.markdown":     strings.NewReader("Sumas\n"),
			"solutions/thiswontbeadded": strings.NewReader("Unexpected file\n"),
		},
	)
	if err != nil {
		t.Fatalf("Failed to create .zip: %v", err)
	}

	updateResult := mustPostZip(
		t,
		adminAuthorization,
		problemAlias,
		nil,
		ZipMergeStrategyTheirs,
		zipContents,
		"initial commit",
		true, // create
		true, // useMultipartFormData
		true, // acceptsSubmissions
		ts,
	)

	updatedFiles := make(map[string]string)
	for _, updatedFile := range updateResult.UpdatedFiles {
		updatedFiles[updatedFile.Path] = updatedFile.Type
	}

	expectedUpdatedFiles := map[string]string{
		".gitattributes":         "added",
		".gitignore":             "added",
		"cases/0.in":             "added",
		"cases/0.out":            "added",
		"settings.distrib.json":  "added",
		"settings.json":          "added",
		"statements/es.markdown": "added",
		"solutions/es.markdown":  "added",
	}
	if !reflect.DeepEqual(expectedUpdatedFiles, updatedFiles) {
		t.Errorf("mismatched updated files, expected %v, got %v", expectedUpdatedFiles, updatedFiles)
	}
}

func TestZiphandlerStatements(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", t.Name())
	if err != nil {
		t.Fatalf("Failed to create directory: %v", err)
	}
	if os.Getenv("PRESERVE") == "" {
		defer os.RemoveAll(tmpDir)
	}
	ctx := context.Background()

	problemAlias := "sumas"

	repo, err := InitRepository(ctx, path.Join(tmpDir, problemAlias))
	if err != nil {
		t.Fatalf("Failed to initialize git repository: %v", err)
	}
	defer repo.Free()

	log, err := log15.New("info", false)
	if err != nil {
		t.Fatalf("Failed to create log: %v", err)
	}

	for idx, testcase := range []struct {
		name          string
		fileContents  map[string]string
		expectedError string
	}{
		{
			"missing statements/",
			map[string]string{
				".gitignore":     defaultGitfiles[".gitignore"],
				".gitattributes": defaultGitfiles[".gitattributes"],
				"cases/0.in":     "1 2\n",
				"cases/0.out":    "3\n",
			},
			"no-statements",
		},
		{
			"missing statements/es.markdown",
			map[string]string{
				".gitignore":        defaultGitfiles[".gitignore"],
				".gitattributes":    defaultGitfiles[".gitattributes"],
				"cases/0.in":        "1 2\n",
				"cases/0.out":       "3\n",
				"statements/foo.md": "",
			},
			"no-es-statement",
		},
	} {
		t.Run(fmt.Sprintf("%d %s", idx, testcase.name), func(t *testing.T) {
			parent := &git.Oid{}
			commitMessage := "Initial commit"

			_, err = ConvertZipToPackfile(
				ctx,
				common.NewProblemFilesFromMap(
					testcase.fileContents,
					"problem.zip",
				),
				nil,
				ZipMergeStrategyTheirs,
				repo,
				parent,
				&git.Signature{
					Name:  "author",
					Email: "author@test.test",
					When:  time.Unix(0, 0).In(time.UTC),
				},
				&git.Signature{
					Name:  "committer",
					Email: "committer@test.test",
					When:  time.Unix(0, 0).In(time.UTC),
				},
				commitMessage,
				true,
				ioutil.Discard,
				log,
			)
			if err == nil {
				t.Errorf("Expected to fail converting .zip, but didn't")
			} else if err.Error() != testcase.expectedError {
				t.Errorf("Expected %q, got %q", testcase.expectedError, err.Error())
			}
		})
	}
}

func TestTestplan(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", t.Name())
	if err != nil {
		t.Fatalf("Failed to create directory: %v", err)
	}
	if os.Getenv("PRESERVE") == "" {
		defer os.RemoveAll(tmpDir)
	}
	ctx := context.Background()

	problemAlias := "sumas"

	repo, err := InitRepository(ctx, path.Join(tmpDir, problemAlias))
	if err != nil {
		t.Fatalf("Failed to initialize git repository: %v", err)
	}
	defer repo.Free()

	log, err := log15.New("info", false)
	if err != nil {
		t.Fatalf("Failed to create log: %v", err)
	}

	for testplanContents, expectedError := range map[string]string{
		"0 0.0.0.0":        "invalid-testplan: invalid weight '0.0.0.0': strconv.ParseFloat: parsing \"0.0.0.0\": invalid syntax",
		"0 invalid-weight": "invalid-testplan: .zip missing case \"0\"",
		"1 1":              "invalid-testplan: .zip missing case \"0\"",
		"0 1\n1 1":         "invalid-testplan: testplan missing case \"1\"",
		"0 1\n0.1 1":       "invalid-testplan: testplan missing case \"0.1\"",
	} {
		fileContents := map[string]string{
			".gitignore":             defaultGitfiles[".gitignore"],
			".gitattributes":         defaultGitfiles[".gitattributes"],
			"cases/0.in":             "1 2\n",
			"cases/0.out":            "3\n",
			"statements/es.markdown": "Sumas\n",
			"testplan":               testplanContents,
		}

		parent := &git.Oid{}
		commitMessage := "Initial commit"

		_, err = ConvertZipToPackfile(
			ctx,
			common.NewProblemFilesFromMap(
				fileContents,
				"problem.zip",
			),
			nil,
			ZipMergeStrategyTheirs,
			repo,
			parent,
			&git.Signature{
				Name:  "author",
				Email: "author@test.test",
				When:  time.Unix(0, 0).In(time.UTC),
			},
			&git.Signature{
				Name:  "committer",
				Email: "committer@test.test",
				When:  time.Unix(0, 0).In(time.UTC),
			},
			commitMessage,
			true,
			ioutil.Discard,
			log,
		)
		if err == nil {
			t.Errorf("For testplan %s, expected to fail converting .zip, but didn't", testplanContents)
		} else if err.Error() != expectedError {
			t.Errorf("For testplan %s, expected %q, got %q", testplanContents, expectedError, err.Error())
		}
	}
}

func TestUpdateProblemSettings(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", t.Name())
	if err != nil {
		t.Fatalf("Failed to create directory: %v", err)
	}
	if os.Getenv("PRESERVE") == "" {
		defer os.RemoveAll(tmpDir)
	}

	log, err := log15.New("info", false)
	if err != nil {
		t.Fatalf("Failed to create log: %v", err)
	}
	ts := httptest.NewServer(NewZipHandler(ZipHandlerOpts{
		RootPath: tmpDir,
		Protocol: NewGitProtocol(GitProtocolOpts{
			GitProtocolOpts: githttp.GitProtocolOpts{
				AuthCallback: authorize,
				Log:          log,
			},
			AllowDirectPushToMaster:     true,
			HardOverallWallTimeLimit:    OverallWallTimeHardLimit,
			InteractiveSettingsCompiler: fakeInteractiveSettingsCompiler,
		}),
		Log: log,
	}))
	defer ts.Close()

	problemAlias := "sumas"

	{
		zipContents, err := gitservertest.CreateZip(
			map[string]io.Reader{
				"settings.json":          strings.NewReader(gitservertest.DefaultSettingsJSON),
				"cases/0.in":             strings.NewReader("1 2\n"),
				"cases/0.out":            strings.NewReader("3\n"),
				"statements/es.markdown": strings.NewReader("Sumaz\n"),
			},
		)
		if err != nil {
			t.Fatalf("Failed to create zip: %v", err)
		}
		mustPostZip(
			t,
			adminAuthorization,
			problemAlias,
			nil,
			ZipMergeStrategyTheirs,
			zipContents,
			"initial commit",
			true, // create
			true, // useMultipartFormData
			true, // acceptsSubmissions
			ts,
		)
	}

	{
		zipContents, err := gitservertest.CreateZip(
			map[string]io.Reader{},
		)
		if err != nil {
			t.Fatalf("Failed to create zip: %v", err)
		}
		problemSettings := &common.ProblemSettings{
			Limits: common.LimitsSettings{
				ExtraWallTime:        base.Duration(0),
				MemoryLimit:          33554432,
				OutputLimit:          10240,
				OverallWallTimeLimit: base.Duration(5 * time.Minute),
				TimeLimit:            base.Duration(time.Second),
			},
			Slow: false,
			Validator: common.ValidatorSettings{
				Name: common.ValidatorNameTokenCaseless,
			},
		}
		updateResult := mustPostZip(
			t,
			adminAuthorization,
			problemAlias,
			problemSettings,
			ZipMergeStrategyOurs,
			zipContents,
			"updated settings",
			false, // create
			false, // useMultipartFormData
			true,  // acceptsSubmissions
			ts,
		)

		updatedFiles := make(map[string]struct{})
		for _, updatedFile := range updateResult.UpdatedFiles {
			updatedFiles[updatedFile.Path] = struct{}{}
			if updatedFile.Type != "modified" {
				t.Errorf("unexpected updated file: %v", updatedFile)
			}
		}

		expectedUpdatedFiles := map[string]struct{}{
			"settings.json":         {},
			"settings.distrib.json": {},
		}
		if !reflect.DeepEqual(expectedUpdatedFiles, updatedFiles) {
			t.Errorf("mismatched updated files, expected %v, got %v", expectedUpdatedFiles, updatedFiles)
		}
	}

	{
		zipContents, err := gitservertest.CreateZip(
			map[string]io.Reader{
				"statements/es.markdown": strings.NewReader("Sumas\n"),
			},
		)
		if err != nil {
			t.Fatalf("Failed to create zip: %v", err)
		}
		updateResult := mustPostZip(
			t,
			adminAuthorization,
			problemAlias,
			nil,
			ZipMergeStrategyRecursiveTheirs,
			zipContents,
			"updated statement",
			false, // create
			false, // useMultipartFormData
			true,  // acceptsSubmissions
			ts,
		)

		updatedFiles := make(map[string]struct{})
		for _, updatedFile := range updateResult.UpdatedFiles {
			updatedFiles[updatedFile.Path] = struct{}{}
			if updatedFile.Type != "modified" {
				t.Errorf("unexpected updated file: %v", updatedFile)
			}
		}

		expectedUpdatedFiles := map[string]struct{}{
			"statements/es.markdown": {},
		}
		if !reflect.DeepEqual(expectedUpdatedFiles, updatedFiles) {
			t.Errorf("mismatched updated files, expected %v, got %v", expectedUpdatedFiles, updatedFiles)
		}
	}
}

func TestUpdateProblemSettingsWithCustomValidator(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", t.Name())
	if err != nil {
		t.Fatalf("Failed to create directory: %v", err)
	}
	if os.Getenv("PRESERVE") == "" {
		defer os.RemoveAll(tmpDir)
	}

	log, err := log15.New("info", false)
	if err != nil {
		t.Fatalf("Failed to create log: %v", err)
	}
	ts := httptest.NewServer(NewZipHandler(ZipHandlerOpts{
		RootPath: tmpDir,
		Protocol: NewGitProtocol(GitProtocolOpts{
			GitProtocolOpts: githttp.GitProtocolOpts{
				AuthCallback: authorize,
				Log:          log,
			},
			AllowDirectPushToMaster:     true,
			HardOverallWallTimeLimit:    OverallWallTimeHardLimit,
			InteractiveSettingsCompiler: fakeInteractiveSettingsCompiler,
		}),
		Log: log,
	}))
	defer ts.Close()

	problemAlias := "sumas-validator"

	// Create the problem.
	{
		zipContents, err := gitservertest.CreateZip(
			map[string]io.Reader{
				"settings.json":          strings.NewReader(gitservertest.CustomValidatorSettingsJSON),
				"cases/0.in":             strings.NewReader("1 2\n"),
				"cases/0.out":            strings.NewReader("3\n"),
				"statements/es.markdown": strings.NewReader("Sumaz\n"),
				"validator.py":           strings.NewReader("print 1\n"),
			},
		)
		if err != nil {
			t.Fatalf("Failed to create zip: %v", err)
		}
		mustPostZip(
			t,
			adminAuthorization,
			problemAlias,
			nil,
			ZipMergeStrategyTheirs,
			zipContents,
			"initial commit",
			true, // create
			true, // useMultipartFormData
			true, // acceptsSubmissions
			ts,
		)
	}

	// Update settings.
	{
		zipContents, err := gitservertest.CreateZip(
			map[string]io.Reader{},
		)
		if err != nil {
			t.Fatalf("Failed to create zip: %v", err)
		}
		problemSettings := &common.ProblemSettings{
			Limits: common.LimitsSettings{
				ExtraWallTime:        base.Duration(0),
				MemoryLimit:          33554432,
				OutputLimit:          10240,
				OverallWallTimeLimit: base.Duration(5 * time.Minute),
				TimeLimit:            base.Duration(time.Second),
			},
			Slow: false,
			Validator: common.ValidatorSettings{
				Name: common.ValidatorNameCustom,
			},
		}
		updateResult := mustPostZip(
			t,
			adminAuthorization,
			problemAlias,
			problemSettings,
			ZipMergeStrategyOurs,
			zipContents,
			"updated settings",
			false, // create
			false, // useMultipartFormData
			true,  // acceptsSubmissions
			ts,
		)

		updatedFiles := make(map[string]struct{})
		for _, updatedFile := range updateResult.UpdatedFiles {
			updatedFiles[updatedFile.Path] = struct{}{}
			if updatedFile.Type != "modified" {
				t.Errorf("unexpected updated file: %v", updatedFile)
			}
		}

		expectedUpdatedFiles := map[string]struct{}{
			"settings.json":         {},
			"settings.distrib.json": {},
		}
		if !reflect.DeepEqual(expectedUpdatedFiles, updatedFiles) {
			t.Errorf("mismatched updated files, expected %v, got %v", expectedUpdatedFiles, updatedFiles)
		}
	}

	// Update statements.
	{
		zipContents, err := gitservertest.CreateZip(
			map[string]io.Reader{
				"statements/es.markdown": strings.NewReader("Sumas\n"),
			},
		)
		if err != nil {
			t.Fatalf("Failed to create zip: %v", err)
		}
		updateResult := mustPostZip(
			t,
			adminAuthorization,
			problemAlias,
			nil,
			ZipMergeStrategyRecursiveTheirs,
			zipContents,
			"updated statement",
			false, // create
			false, // useMultipartFormData
			true,  // acceptsSubmissions
			ts,
		)

		updatedFiles := make(map[string]struct{})
		for _, updatedFile := range updateResult.UpdatedFiles {
			updatedFiles[updatedFile.Path] = struct{}{}
			if updatedFile.Type != "modified" {
				t.Errorf("unexpected updated file: %v", updatedFile)
			}
		}

		expectedUpdatedFiles := map[string]struct{}{
			"statements/es.markdown": {},
		}
		if !reflect.DeepEqual(expectedUpdatedFiles, updatedFiles) {
			t.Errorf("mismatched updated files, expected %v, got %v", expectedUpdatedFiles, updatedFiles)
		}
	}

	// Use token validator.
	{
		zipContents, err := gitservertest.CreateZip(
			map[string]io.Reader{
				"cases/0.in":             strings.NewReader("1 2\n"),
				"cases/0.out":            strings.NewReader("3\n"),
				"statements/es.markdown": strings.NewReader("Sumas\n"),
			},
		)
		if err != nil {
			t.Fatalf("Failed to create zip: %v", err)
		}
		problemSettings := &common.ProblemSettings{
			Limits: common.LimitsSettings{
				ExtraWallTime:        base.Duration(0),
				MemoryLimit:          33554432,
				OutputLimit:          10240,
				OverallWallTimeLimit: base.Duration(5 * time.Minute),
				TimeLimit:            base.Duration(time.Second),
			},
			Slow: false,
			Validator: common.ValidatorSettings{
				Name: common.ValidatorNameTokenCaseless,
			},
		}
		updateResult := mustPostZip(
			t,
			adminAuthorization,
			problemAlias,
			problemSettings,
			ZipMergeStrategyTheirs,
			zipContents,
			"updated validator",
			false, // create
			false, // useMultipartFormData
			true,  // acceptsSubmissions
			ts,
		)

		updatedFiles := make(map[string]string)
		for _, updatedFile := range updateResult.UpdatedFiles {
			updatedFiles[updatedFile.Path] = updatedFile.Type
		}

		expectedUpdatedFiles := map[string]string{
			"settings.distrib.json": "modified",
			"settings.json":         "modified",
			"validator.py":          "deleted",
		}
		if !reflect.DeepEqual(expectedUpdatedFiles, updatedFiles) {
			t.Errorf("mismatched updated files, expected %v, got %v", expectedUpdatedFiles, updatedFiles)
		}
	}

	// Restore custom validator.
	{
		zipContents, err := gitservertest.CreateZip(
			map[string]io.Reader{
				"cases/0.in":             strings.NewReader("1 2\n"),
				"cases/0.out":            strings.NewReader("3\n"),
				"statements/es.markdown": strings.NewReader("Sumas\n"),
				"validator.py":           strings.NewReader("print 1\n"),
			},
		)
		if err != nil {
			t.Fatalf("Failed to create zip: %v", err)
		}
		problemSettings := &common.ProblemSettings{
			Limits: common.LimitsSettings{
				ExtraWallTime:        base.Duration(0),
				MemoryLimit:          33554432,
				OutputLimit:          10240,
				OverallWallTimeLimit: base.Duration(5 * time.Minute),
				TimeLimit:            base.Duration(time.Second),
			},
			Slow: false,
			Validator: common.ValidatorSettings{
				Name: common.ValidatorNameCustom,
			},
		}
		updateResult := mustPostZip(
			t,
			adminAuthorization,
			problemAlias,
			problemSettings,
			ZipMergeStrategyTheirs,
			zipContents,
			"updated validator",
			false, // create
			false, // useMultipartFormData
			true,  // acceptsSubmissions
			ts,
		)

		updatedFiles := make(map[string]string)
		for _, updatedFile := range updateResult.UpdatedFiles {
			updatedFiles[updatedFile.Path] = updatedFile.Type
		}

		expectedUpdatedFiles := map[string]string{
			"settings.distrib.json": "modified",
			"settings.json":         "modified",
			"validator.py":          "added",
		}
		if !reflect.DeepEqual(expectedUpdatedFiles, updatedFiles) {
			t.Errorf("mismatched updated files, expected %v, got %v", expectedUpdatedFiles, updatedFiles)
		}
	}
}

func TestRenameProblem(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", t.Name())
	if err != nil {
		t.Fatalf("Failed to create directory: %v", err)
	}
	if os.Getenv("PRESERVE") == "" {
		defer os.RemoveAll(tmpDir)
	}

	log, err := log15.New("info", false)
	if err != nil {
		t.Fatalf("Failed to create log: %v", err)
	}
	ts := httptest.NewServer(NewZipHandler(ZipHandlerOpts{
		RootPath: tmpDir,
		Protocol: NewGitProtocol(GitProtocolOpts{
			GitProtocolOpts: githttp.GitProtocolOpts{
				AuthCallback: authorize,
				Log:          log,
			},
			AllowDirectPushToMaster:     true,
			HardOverallWallTimeLimit:    OverallWallTimeHardLimit,
			InteractiveSettingsCompiler: fakeInteractiveSettingsCompiler,
		}),
		Log: log,
	}))
	defer ts.Close()

	problemAlias := "sumas-validator"

	// Create the problem.
	{
		zipContents, err := gitservertest.CreateZip(
			map[string]io.Reader{
				"settings.json":          strings.NewReader(gitservertest.CustomValidatorSettingsJSON),
				"cases/0.in":             strings.NewReader("1 2\n"),
				"cases/0.out":            strings.NewReader("3\n"),
				"statements/es.markdown": strings.NewReader("Sumaz\n"),
				"validator.py":           strings.NewReader("print 1\n"),
			},
		)
		if err != nil {
			t.Fatalf("Failed to create zip: %v", err)
		}
		mustPostZip(
			t,
			adminAuthorization,
			problemAlias,
			nil,
			ZipMergeStrategyTheirs,
			zipContents,
			"initial commit",
			true, // create
			true, // useMultipartFormData
			true, // acceptsSubmissions
			ts,
		)
		if _, err := os.Stat(path.Join(tmpDir, problemAlias)); err != nil {
			t.Fatalf("Stat on old problem repository failed: %v", err)
		}
	}

	// Rename the problem using an admin user.
	{
		renameURL, err := url.Parse(ts.URL + "/" + problemAlias + "/rename-repository/renamed")
		if err != nil {
			t.Fatalf("Failed to parse URL: %v", err)
		}
		req := &http.Request{
			URL:    renameURL,
			Method: "GET",
			Header: map[string][]string{
				"Authorization": {adminAuthorization},
			},
		}
		res, err := ts.Client().Do(req)
		if err != nil {
			t.Fatalf("Failed to rename problem: %v", err)
		}
		defer res.Body.Close()
		if http.StatusForbidden != res.StatusCode {
			t.Fatalf("Unexpected result: expected %v, got %v", http.StatusForbidden, res.StatusCode)
		}
	}

	// Rename the problem using the system user.
	{
		renameURL, err := url.Parse(ts.URL + "/" + problemAlias + "/rename-repository/renamed")
		if err != nil {
			t.Fatalf("Failed to parse URL: %v", err)
		}
		req := &http.Request{
			URL:    renameURL,
			Method: "GET",
			Header: map[string][]string{
				"Authorization": {systemAuthorization},
			},
		}
		res, err := ts.Client().Do(req)
		if err != nil {
			t.Fatalf("Failed to rename problem: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("Failed to rename problem: Status %v, headers: %v", res.StatusCode, res.Header)
		}

		if _, err := os.Stat(path.Join(tmpDir, problemAlias)); !os.IsNotExist(err) {
			t.Fatalf("Stat on old problem repository failed: %v", err)
		}
		if _, err := os.Stat(path.Join(tmpDir, "renamed")); err != nil {
			t.Fatalf("Stat on new problem repository failed: %v", err)
		}
	}
}
