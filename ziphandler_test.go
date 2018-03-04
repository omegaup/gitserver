package gitserver

import (
	"archive/zip"
	"bytes"
	"fmt"
	git "github.com/lhchavez/git2go"
	"github.com/omegaup/gitserver/gitservertest"
	base "github.com/omegaup/go-base"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
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
	zipContents []byte,
	commitMessage string,
	create bool,
	ts *httptest.Server,
) {
	action := "update"
	if create {
		action = "create"
	}
	pushURL, err := url.Parse(ts.URL + "/" + problemAlias + "/" + action)
	if err != nil {
		t.Fatalf("Failed to parse URL: %v", err)
	}
	var buf bytes.Buffer
	var boundary string
	{
		w := multipart.NewWriter(&buf)
		boundary = w.Boundary()
		w.WriteField("message", commitMessage)
		zipWriter, _ := w.CreateFormFile("contents", "file.zip")
		zipWriter.Write(zipContents)
		w.Close()
	}
	req := &http.Request{
		Method: "POST",
		URL:    pushURL,
		Body:   ioutil.NopCloser(&buf),
		Header: map[string][]string{
			"Authorization": {authorization},
			"Content-Type":  {fmt.Sprintf("multipart/form-data; boundary=%s", boundary)},
		},
	}
	res, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("Failed to upload zip: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("Failed to upload zip: Status %v, headers: %v", res.StatusCode, res.Header)
	}
}

func TestPushZip(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "handler_test")
	if err != nil {
		t.Fatalf("Failed to create directory: %v", err)
	}
	if os.Getenv("PRESERVE") == "" {
		defer os.RemoveAll(tmpDir)
	}

	log := base.StderrLog()
	ts := httptest.NewServer(ZipHandler(
		tmpDir,
		NewGitProtocol(authorize, nil, false, OverallWallTimeHardLimit, fakeInteractiveSettingsCompiler, log),
		log,
	))
	defer ts.Close()

	problemAlias := "sumas"

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
		zipContents,
		"initial commit",
		true, // create
		ts,
	)
}

func TestConvertZip(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "handler_test")
	if err != nil {
		t.Fatalf("Failed to create directory: %v", err)
	}
	if os.Getenv("PRESERVE") == "" {
		defer os.RemoveAll(tmpDir)
	}

	problemAlias := "sumas"

	repo, err := InitRepository(path.Join(tmpDir, problemAlias+".git"))
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
		ConvertZipUpdateAll,
		repo,
		parent,
		&git.Signature{
			Name:  "author",
			Email: "author@test.test",
			When:  time.Unix(0, 0),
		},
		&git.Signature{
			Name:  "committer",
			Email: "committer@test.test",
			When:  time.Unix(0, 0),
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
