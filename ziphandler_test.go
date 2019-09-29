package gitserver

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	git "github.com/lhchavez/git2go"
	"github.com/omegaup/gitserver/gitservertest"
	base "github.com/omegaup/go-base"
	"github.com/omegaup/quark/common"
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
)

func wrapReaders(contents map[string]string) map[string]io.Reader {
	result := make(map[string]io.Reader)
	for filename, s := range contents {
		result[filename] = strings.NewReader(s)
	}
	return result
}

func postZip(
	t *testing.T,
	authorization string,
	problemAlias string,
	problemSettings *common.ProblemSettings,
	zipMergeStrategy ZipMergeStrategy,
	zipContents []byte,
	commitMessage string,
	create bool,
	useMultipartFormData bool,
	ts *httptest.Server,
) *UpdateResult {
	problemSettingsString := ""
	if problemSettings != nil {
		problemSettingsBytes, err := json.Marshal(problemSettings)
		if err != nil {
			t.Fatalf("failed to marshal the problem settings: %v", err)
		}
		problemSettingsString = string(problemSettingsBytes)
	}

	pushURL, err := url.Parse(ts.URL + "/" + problemAlias + "/git-upload-zip")
	if err != nil {
		t.Fatalf("Failed to parse URL: %v", err)
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
		t.Fatalf("Failed to upload zip: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("Failed to upload zip: Status %v, headers: %v", res.StatusCode, res.Header)
	}

	var updateResult UpdateResult
	if err := json.NewDecoder(res.Body).Decode(&updateResult); err != nil {
		t.Fatalf("Failed to unmarshal updateResult: %v", err)
	}
	return &updateResult
}

func TestPushZip(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", t.Name())
	if err != nil {
		t.Fatalf("Failed to create directory: %v", err)
	}
	if os.Getenv("PRESERVE") == "" {
		defer os.RemoveAll(tmpDir)
	}

	log := base.StderrLog()
	ts := httptest.NewServer(ZipHandler(
		tmpDir,
		NewGitProtocol(authorize, nil, true, OverallWallTimeHardLimit, fakeInteractiveSettingsCompiler, log),
		&base.NoOpMetrics{},
		log,
	))
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
		postZip(
			t,
			adminAuthorization,
			problemAlias,
			nil,
			ZipMergeStrategyTheirs,
			zipContents,
			"initial commit",
			true, // create
			true, // useMultipartFormData
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
		postZip(
			t,
			adminAuthorization,
			problemAlias,
			nil,
			ZipMergeStrategyTheirs,
			zipContents,
			"initial commit",
			false, // create
			false, // useMultipartFormData
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

	problemAlias := "sumas"

	repo, err := InitRepository(path.Join(tmpDir, problemAlias))
	if err != nil {
		t.Fatalf("Failed to initialize git repository: %v", err)
	}
	defer repo.Free()

	log := base.StderrLog()

	fileContents := map[string]string{
		".gitignore":             defaultGitfiles[".gitignore"],
		".gitattributes":         defaultGitfiles[".gitattributes"],
		"settings.json":          gitservertest.DefaultSettingsJSON,
		"cases/0.in":             "1 2\n",
		"cases/0.out":            "3\n",
		"statements/es.markdown": "Sumas\n",
	}

	zipContents, err := gitservertest.CreateZip(wrapReaders(fileContents))
	if err != nil {
		t.Fatalf("Failed to create zip: %v", err)
	}
	zipReader, err := zip.NewReader(bytes.NewReader(zipContents), int64(len(zipContents)))
	if err != nil {
		t.Fatalf("Failed to create directory: %v", err)
	}

	parent := &git.Oid{}
	commitMessage := "Initial commit"

	zipOid, err := ConvertZipToPackfile(
		zipReader,
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

func TestTestplan(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", t.Name())
	if err != nil {
		t.Fatalf("Failed to create directory: %v", err)
	}
	if os.Getenv("PRESERVE") == "" {
		defer os.RemoveAll(tmpDir)
	}

	problemAlias := "sumas"

	repo, err := InitRepository(path.Join(tmpDir, problemAlias))
	if err != nil {
		t.Fatalf("Failed to initialize git repository: %v", err)
	}
	defer repo.Free()

	log := base.StderrLog()

	for testplanContents, expectedError := range map[string]string{
		"0 0.0.0.0":        "invalid-testplan: invalid weight '0.0.0.0': strconv.ParseFloat: parsing \"0.0.0.0\": invalid syntax",
		"0 invalid-weight": "invalid-testplan: .zip missing case 0",
		"1 1":              "invalid-testplan: .zip missing case 0",
		"0 1\n1 1":         "invalid-testplan: testplan missing case 1",
		"0 1\n0.1 1":       "invalid-testplan: testplan missing case 0.1",
	} {
		fileContents := map[string]string{
			".gitignore":             defaultGitfiles[".gitignore"],
			".gitattributes":         defaultGitfiles[".gitattributes"],
			"cases/0.in":             "1 2\n",
			"cases/0.out":            "3\n",
			"statements/es.markdown": "Sumas\n",
			"testplan":               testplanContents,
		}

		zipContents, err := gitservertest.CreateZip(wrapReaders(fileContents))
		if err != nil {
			t.Fatalf("Failed to create zip: %v", err)
		}
		zipReader, err := zip.NewReader(bytes.NewReader(zipContents), int64(len(zipContents)))
		if err != nil {
			t.Fatalf("Failed to create directory: %v", err)
		}

		parent := &git.Oid{}
		commitMessage := "Initial commit"

		_, err = ConvertZipToPackfile(
			zipReader,
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

	log := base.StderrLog()
	ts := httptest.NewServer(ZipHandler(
		tmpDir,
		NewGitProtocol(authorize, nil, true, OverallWallTimeHardLimit, fakeInteractiveSettingsCompiler, log),
		&base.NoOpMetrics{},
		log,
	))
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
		postZip(
			t,
			adminAuthorization,
			problemAlias,
			nil,
			ZipMergeStrategyTheirs,
			zipContents,
			"initial commit",
			true, // create
			true, // useMultipartFormData
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
				Name: "token-caseless",
			},
		}
		updateResult := postZip(
			t,
			adminAuthorization,
			problemAlias,
			problemSettings,
			ZipMergeStrategyOurs,
			zipContents,
			"updated settings",
			false, // create
			false, // useMultipartFormData
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
		updateResult := postZip(
			t,
			adminAuthorization,
			problemAlias,
			nil,
			ZipMergeStrategyRecursiveTheirs,
			zipContents,
			"updated statement",
			false, // create
			false, // useMultipartFormData
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

	log := base.StderrLog()
	ts := httptest.NewServer(ZipHandler(
		tmpDir,
		NewGitProtocol(authorize, nil, true, OverallWallTimeHardLimit, fakeInteractiveSettingsCompiler, log),
		&base.NoOpMetrics{},
		log,
	))
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
		postZip(
			t,
			adminAuthorization,
			problemAlias,
			nil,
			ZipMergeStrategyTheirs,
			zipContents,
			"initial commit",
			true, // create
			true, // useMultipartFormData
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
				Name: "custom",
			},
		}
		updateResult := postZip(
			t,
			adminAuthorization,
			problemAlias,
			problemSettings,
			ZipMergeStrategyOurs,
			zipContents,
			"updated settings",
			false, // create
			false, // useMultipartFormData
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
		updateResult := postZip(
			t,
			adminAuthorization,
			problemAlias,
			nil,
			ZipMergeStrategyRecursiveTheirs,
			zipContents,
			"updated statement",
			false, // create
			false, // useMultipartFormData
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
				Name: "token-caseless",
			},
		}
		updateResult := postZip(
			t,
			adminAuthorization,
			problemAlias,
			problemSettings,
			ZipMergeStrategyTheirs,
			zipContents,
			"updated validator",
			false, // create
			false, // useMultipartFormData
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
				Name: "custom",
			},
		}
		updateResult := postZip(
			t,
			adminAuthorization,
			problemAlias,
			problemSettings,
			ZipMergeStrategyTheirs,
			zipContents,
			"updated validator",
			false, // create
			false, // useMultipartFormData
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
