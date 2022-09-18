package gitserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
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
	"github.com/omegaup/gitserver/request"
	"github.com/omegaup/go-base/logging/log15/v3"
	"github.com/omegaup/go-base/v3/logging"
	"github.com/omegaup/quark/common"

	git "github.com/libgit2/git2go/v33"
)

const (
	userAuthorization     = "Basic dXNlcjp1c2Vy"
	editorAuthorization   = "Basic ZWRpdG9yOmVkaXRvcg=="
	adminAuthorization    = "Basic YWRtaW46YWRtaW4="
	systemAuthorization   = "OmegaUpSharedSecret secret-token omegaup:system"
	readonlyAuthorization = "Basic cmVhZG9ubHk6cmVhZG9ubHk="
)

var (
	fakeInteractiveSettingsCompiler = &FakeInteractiveSettingsCompiler{
		Settings: nil,
		Err:      errors.New("unsupported"),
	}
)

func authorize(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	repositoryName string,
	operation githttp.GitOperation,
) (githttp.AuthorizationLevel, string) {
	if r.Header.Get("Authorization") == systemAuthorization {
		requestContext := request.FromContext(ctx)
		requestContext.Request.Username = "omegaup:system"
		requestContext.Request.ProblemName = repositoryName
		requestContext.Request.IsSystem = true
		requestContext.Request.IsAdmin = true
		requestContext.Request.CanView = true
		requestContext.Request.CanEdit = true
		return githttp.AuthorizationAllowed, "omegaup:system"
	}

	username, _, ok := r.BasicAuth()
	if !ok {
		w.Header().Set("WWW-Authenticate", "Basic realm=\"Git\"")
		w.WriteHeader(http.StatusUnauthorized)
		return githttp.AuthorizationDenied, ""
	}

	requestContext := request.FromContext(ctx)
	requestContext.Request.Username = username
	requestContext.Request.ProblemName = repositoryName
	if username == "admin" {
		requestContext.Request.IsAdmin = true
		requestContext.Request.CanView = true
		requestContext.Request.CanEdit = true
		return githttp.AuthorizationAllowed, username
	}
	if username == "editor" {
		requestContext.Request.CanView = true
		requestContext.Request.CanEdit = true
		return githttp.AuthorizationAllowedRestricted, username
	}
	if username == "user" {
		requestContext.Request.CanView = true
		return githttp.AuthorizationAllowedRestricted, username
	}
	if username == "readonly" {
		requestContext.Request.CanView = true
		return githttp.AuthorizationAllowedReadOnly, username
	}
	w.WriteHeader(http.StatusForbidden)
	return githttp.AuthorizationDenied, username
}

func getReference(
	t *testing.T,
	problemAlias string,
	refName string,
	ts *httptest.Server,
) *git.Oid {
	prePushURL, err := url.Parse(ts.URL + "/" + problemAlias + "/info/refs?service=git-receive-pack")
	if err != nil {
		t.Fatalf("Failed to parse URL: %v", err)
	}
	req := &http.Request{
		Method: "GET",
		URL:    prePushURL,
		Header: map[string][]string{
			"Authorization": {adminAuthorization},
		},
	}
	res, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("Failed to create pre-pull request: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("Failed to request pre-pull: Status %v, headers: %v", res.StatusCode, res.Header)
	}

	pr := githttp.NewPktLineReader(res.Body)

	for {
		line, err := pr.ReadPktLine()
		if err == io.EOF {
			break
		}
		if err == githttp.ErrFlush {
			continue
		}
		tokens := strings.FieldsFunc(
			strings.Trim(string(line), "\n"),
			func(r rune) bool {
				return r == ' ' || r == '\x00'
			},
		)
		if len(tokens) < 2 {
			continue
		}
		if strings.HasPrefix(tokens[0], "#") || tokens[1] != refName {
			continue
		}
		oid, err := git.NewOid(tokens[0])
		if err != nil {
			t.Fatalf("Failed to parse oid %v: %v", tokens[0], err)
		}
		return oid
	}
	return &git.Oid{}
}

func createCommit(
	t *testing.T,
	tmpDir string,
	problemAlias string,
	oldOid *git.Oid,
	contents map[string]io.Reader,
	commitMessage string,
	log logging.Logger,
) (*git.Oid, []byte) {
	repo, err := git.OpenRepository(path.Join(tmpDir, problemAlias))
	if err != nil {
		t.Fatalf("Failed to open repository: %v", err)
	}
	defer repo.Free()

	var parentCommits []*git.Commit
	if !oldOid.IsZero() {
		var err error
		parentCommit, err := repo.LookupCommit(oldOid)
		if err != nil {
			t.Fatalf("Failed to lookup commit %v: %v", oldOid, err)
		}
		parentCommits = append(parentCommits, parentCommit)
	}

	odb, err := repo.Odb()
	if err != nil {
		t.Fatalf("Failed to open odb: %v", err)
	}
	defer odb.Free()

	mempack, err := git.NewMempack(odb)
	if err != nil {
		t.Fatalf("Failed to create mempack: %v", err)
	}

	tree, err := githttp.BuildTree(repo, contents, log)
	if err != nil {
		t.Fatalf("Failed to build tree: %v", err)
	}
	defer tree.Free()

	newCommitID, err := repo.CreateCommit(
		"",
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
		tree,
		parentCommits...,
	)
	if err != nil {
		t.Fatalf("Failed to create commit: %v", err)
	}

	packContents, err := mempack.Dump(repo)
	if err != nil {
		t.Fatalf("Failed to create mempack: %v", err)
	}

	return newCommitID, packContents
}

func push(
	t *testing.T,
	tmpDir string,
	authorization string,
	problemAlias string,
	refName string,
	oldOid, newOid *git.Oid,
	packContents []byte,
	expectedResponse []githttp.PktLineResponse,
	ts *httptest.Server,
) {
	t.Helper()
	var inBuf bytes.Buffer

	{
		// Taken from git 2.14.1
		pw := githttp.NewPktLineWriter(&inBuf)
		pw.WritePktLine([]byte(fmt.Sprintf(
			"%s %s %s\x00report-status\n",
			oldOid.String(),
			newOid.String(),
			refName,
		)))

		if len(packContents) > 0 {
			pw.Flush()
			if _, err := inBuf.Write(packContents); err != nil {
				t.Fatalf("Failed to write packfile: %v", err)
			}
		}
	}

	pushURL, err := url.Parse(ts.URL + "/" + problemAlias + "/git-receive-pack")
	if err != nil {
		t.Fatalf("Failed to parse URL: %v", err)
	}
	req := &http.Request{
		Method: "POST",
		URL:    pushURL,
		Body:   ioutil.NopCloser(&inBuf),
		Header: map[string][]string{
			"Authorization": {authorization},
		},
	}
	res, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("Failed to create pre-push request: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusForbidden {
		t.Fatalf("Failed to request pre-push: Status %v, headers: %v", res.StatusCode, res.Header)
	}

	if actual, ok := githttp.ComparePktLineResponse(res.Body, expectedResponse); !ok {
		t.Errorf("push expected %q, got %q", expectedResponse, actual)
	}
}

func TestInvalidRef(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", t.Name())
	if err != nil {
		t.Fatalf("Failed to create directory: %v", err)
	}
	if os.Getenv("PRESERVE") == "" {
		defer os.RemoveAll(tmpDir)
	}
	ctx := context.Background()

	log, err := log15.New("info", false)
	if err != nil {
		t.Fatalf("Failed to create log: %v", err)
	}
	ts := httptest.NewServer(NewGitHandler(GitHandlerOpts{
		RootPath: tmpDir,
		Protocol: NewGitProtocol(GitProtocolOpts{
			GitProtocolOpts: githttp.GitProtocolOpts{
				AuthCallback: authorize,
				Log:          log,
			},
			HardOverallWallTimeLimit:    OverallWallTimeHardLimit,
			InteractiveSettingsCompiler: fakeInteractiveSettingsCompiler,
		}),
		Log: log,
	}))
	defer ts.Close()

	problemAlias := "sumas"

	{
		repo, err := InitRepository(ctx, path.Join(tmpDir, problemAlias))
		if err != nil {
			t.Fatalf("Failed to initialize git repository: %v", err)
		}
		repo.Free()
	}

	newOid, packContents := createCommit(
		t,
		tmpDir,
		problemAlias,
		&git.Oid{},
		map[string]io.Reader{
			"settings.json":          strings.NewReader(gitservertest.DefaultSettingsJSON),
			"cases/0.in":             strings.NewReader("1 2"),
			"cases/0.out":            strings.NewReader("3"),
			"statements/es.markdown": strings.NewReader("Sumas"),
		},
		"Initial commit",
		log,
	)
	push(
		t,
		tmpDir,
		userAuthorization,
		problemAlias,
		"refs/heads/private",
		&git.Oid{}, newOid,
		packContents,
		[]githttp.PktLineResponse{
			{Line: "unpack ok\n", Err: nil},
			{Line: "ng refs/heads/private read-only\n", Err: nil},
		},
		ts,
	)
	push(
		t,
		tmpDir,
		userAuthorization,
		problemAlias,
		"refs/heads/arbitrarybranchname",
		&git.Oid{}, newOid,
		packContents,
		[]githttp.PktLineResponse{
			{Line: "unpack ok\n", Err: nil},
			{Line: "ng refs/heads/arbitrarybranchname invalid-ref\n", Err: nil},
		},
		ts,
	)
}

func TestDelete(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", t.Name())
	if err != nil {
		t.Fatalf("Failed to create directory: %v", err)
	}
	if os.Getenv("PRESERVE") == "" {
		defer os.RemoveAll(tmpDir)
	}
	ctx := context.Background()

	log, err := log15.New("info", false)
	if err != nil {
		t.Fatalf("Failed to create log: %v", err)
	}
	ts := httptest.NewServer(NewGitHandler(GitHandlerOpts{
		RootPath: tmpDir,
		Protocol: NewGitProtocol(GitProtocolOpts{
			GitProtocolOpts: githttp.GitProtocolOpts{
				AuthCallback: authorize,
				Log:          log,
			},
			HardOverallWallTimeLimit:    OverallWallTimeHardLimit,
			InteractiveSettingsCompiler: fakeInteractiveSettingsCompiler,
		}),
		Log: log,
	}))
	defer ts.Close()

	problemAlias := "sumas"

	{
		repo, err := InitRepository(ctx, path.Join(tmpDir, problemAlias))
		if err != nil {
			t.Fatalf("Failed to initialize git repository: %v", err)
		}
		repo.Free()
	}

	{
		newOid, packContents := createCommit(
			t,
			tmpDir,
			problemAlias,
			&git.Oid{},
			map[string]io.Reader{
				"settings.json":          strings.NewReader(gitservertest.DefaultSettingsJSON),
				"cases/0.in":             strings.NewReader("1 2"),
				"cases/0.out":            strings.NewReader("3"),
				"statements/es.markdown": strings.NewReader("Sumas"),
			},
			"Initial commit",
			log,
		)
		push(
			t,
			tmpDir,
			editorAuthorization,
			problemAlias,
			"refs/changes/initial",
			&git.Oid{}, newOid,
			packContents,
			[]githttp.PktLineResponse{
				{Line: "unpack ok\n", Err: nil},
				{Line: "ok refs/changes/initial\n", Err: nil},
			},
			ts,
		)
	}
	push(
		t,
		tmpDir,
		userAuthorization,
		problemAlias,
		"refs/changes/initial",
		getReference(t, problemAlias, "refs/changes/initial", ts),
		&git.Oid{},
		githttp.EmptyPackfile,
		[]githttp.PktLineResponse{
			{Line: "unpack ok\n", Err: nil},
			{Line: "ng refs/changes/initial delete-unallowed\n", Err: nil},
		},
		ts,
	)
}

func TestServerCreateReview(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", t.Name())
	if err != nil {
		t.Fatalf("Failed to create directory: %v", err)
	}
	if os.Getenv("PRESERVE") == "" {
		defer os.RemoveAll(tmpDir)
	}
	ctx := context.Background()

	log, err := log15.New("info", false)
	if err != nil {
		t.Fatalf("Failed to create log: %v", err)
	}
	ts := httptest.NewServer(NewGitHandler(GitHandlerOpts{
		RootPath: tmpDir,
		Protocol: NewGitProtocol(GitProtocolOpts{
			GitProtocolOpts: githttp.GitProtocolOpts{
				AuthCallback: authorize,
				Log:          log,
			},
			HardOverallWallTimeLimit:    OverallWallTimeHardLimit,
			InteractiveSettingsCompiler: fakeInteractiveSettingsCompiler,
		}),
		Log: log,
	}))
	defer ts.Close()

	problemAlias := "sumas"

	{
		repo, err := InitRepository(ctx, path.Join(tmpDir, problemAlias))
		if err != nil {
			t.Fatalf("Failed to initialize git repository: %v", err)
		}
		repo.Free()
	}

	// Create code review
	{
		newOid, packContents := createCommit(
			t,
			tmpDir,
			problemAlias,
			&git.Oid{},
			map[string]io.Reader{
				"settings.json":          strings.NewReader(gitservertest.DefaultSettingsJSON),
				"cases/0.in":             strings.NewReader("1 2"),
				"cases/0.out":            strings.NewReader("3"),
				"statements/es.markdown": strings.NewReader("Sumas"),
			},
			"Initial commit",
			log,
		)
		push(
			t,
			tmpDir,
			editorAuthorization,
			problemAlias,
			"refs/changes/initial",
			&git.Oid{}, newOid,
			packContents,
			[]githttp.PktLineResponse{
				{Line: "unpack ok\n", Err: nil},
				{Line: "ok refs/changes/initial\n", Err: nil},
			},
			ts,
		)
	}

	// Try a few invalid publish paths
	{
		// User is not an editor, so they cannot change refs/heads/master.
		push(
			t,
			tmpDir,
			userAuthorization,
			problemAlias,
			"refs/heads/master",
			getReference(t, problemAlias, "refs/heads/master", ts),
			getReference(t, problemAlias, "refs/changes/initial", ts),
			githttp.EmptyPackfile,
			[]githttp.PktLineResponse{
				{Line: "unpack ok\n", Err: nil},
				{Line: "ng refs/heads/master forbidden\n", Err: nil},
			},
			ts,
		)
		// User is not an editor, so they cannot change refs/heads/published.
		push(
			t,
			tmpDir,
			userAuthorization,
			problemAlias,
			"refs/heads/published",
			getReference(t, problemAlias, "refs/heads/published", ts),
			getReference(t, problemAlias, "refs/changes/initial", ts),
			githttp.EmptyPackfile,
			[]githttp.PktLineResponse{
				{Line: "unpack ok\n", Err: nil},
				{Line: "ng refs/heads/published forbidden\n", Err: nil},
			},
			ts,
		)
		// User is an administrator, but cannot point refs/heads/published to
		// something that's not a commit in master.
		push(
			t,
			tmpDir,
			adminAuthorization,
			problemAlias,
			"refs/heads/published",
			getReference(t, problemAlias, "refs/heads/published", ts),
			getReference(t, problemAlias, "refs/changes/initial", ts),
			githttp.EmptyPackfile,
			[]githttp.PktLineResponse{
				{Line: "unpack ok\n", Err: nil},
				{Line: "ng refs/heads/published published-must-point-to-commit-in-master\n", Err: nil},
			},
			ts,
		)
	}

	// Publish initial review
	{
		push(
			t,
			tmpDir,
			adminAuthorization,
			problemAlias,
			"refs/heads/master",
			getReference(t, problemAlias, "refs/heads/master", ts),
			getReference(t, problemAlias, "refs/changes/initial", ts),
			githttp.EmptyPackfile,
			[]githttp.PktLineResponse{
				{Line: "unpack ok\n", Err: nil},
				{Line: "ok refs/heads/master\n", Err: nil},
			},
			ts,
		)
		push(
			t,
			tmpDir,
			adminAuthorization,
			problemAlias,
			"refs/heads/published",
			getReference(t, problemAlias, "refs/heads/published", ts),
			getReference(t, problemAlias, "refs/heads/master", ts),
			githttp.EmptyPackfile,
			[]githttp.PktLineResponse{
				{Line: "unpack ok\n", Err: nil},
				{Line: "ok refs/heads/published\n", Err: nil},
			},
			ts,
		)
	}

	// Create new revision
	{
		newOid, packContents := createCommit(
			t,
			tmpDir,
			problemAlias,
			getReference(t, problemAlias, "refs/heads/master", ts),
			map[string]io.Reader{
				"settings.json":          strings.NewReader(gitservertest.DefaultSettingsJSON),
				"cases/0.in":             strings.NewReader("3 2"),
				"cases/0.out":            strings.NewReader("1"),
				"statements/es.markdown": strings.NewReader("Restas"),
			},
			"Initial commit",
			log,
		)
		push(
			t,
			tmpDir,
			editorAuthorization,
			problemAlias,
			"refs/changes/initial2",
			&git.Oid{}, newOid,
			packContents,
			[]githttp.PktLineResponse{
				{Line: "unpack ok\n", Err: nil},
				{Line: "ok refs/changes/initial2\n", Err: nil},
			},
			ts,
		)
	}

	// Send out a few invalid code reviews.
	{
		newOid, packContents := createCommit(
			t,
			tmpDir,
			problemAlias,
			getReference(t, problemAlias, "refs/meta/review", ts),
			map[string]io.Reader{},
			"Initial commit",
			log,
		)
		push(
			t,
			tmpDir,
			editorAuthorization,
			problemAlias,
			"refs/meta/review",
			getReference(t, problemAlias, "refs/meta/review", ts),
			newOid,
			packContents,
			[]githttp.PktLineResponse{
				{Line: "unpack ok\n", Err: nil},
				{Line: "ng refs/meta/review review-bad-layout: iteration uuid in commit message missing or malformed\n", Err: nil},
			},
			ts,
		)

		newOid, packContents = createCommit(
			t,
			tmpDir,
			problemAlias,
			getReference(t, problemAlias, "refs/meta/review", ts),
			map[string]io.Reader{
				"should/not/have/had/trees": strings.NewReader("\n"),
			},
			"Foo\n\nIteration: 00000000-0000-0000-0000-000000000000",
			log,
		)
		push(
			t,
			tmpDir,
			editorAuthorization,
			problemAlias,
			"refs/meta/review",
			getReference(t, problemAlias, "refs/meta/review", ts),
			newOid,
			packContents,
			[]githttp.PktLineResponse{
				{Line: "unpack ok\n", Err: nil},
				{Line: "ng refs/meta/review review-bad-layout: refs/meta/review must have a flat tree\n", Err: nil},
			},
			ts,
		)

		newOid, packContents = createCommit(
			t,
			tmpDir,
			problemAlias,
			getReference(t, problemAlias, "refs/meta/review", ts),
			map[string]io.Reader{
				"ledger": strings.NewReader("missing trailing newline"),
			},
			"Foo\n\nIteration: 00000000-0000-0000-0000-000000000000",
			log,
		)
		push(
			t,
			tmpDir,
			editorAuthorization,
			problemAlias,
			"refs/meta/review",
			getReference(t, problemAlias, "refs/meta/review", ts),
			newOid,
			packContents,
			[]githttp.PktLineResponse{
				{Line: "unpack ok\n", Err: nil},
				{Line: "ng refs/meta/review review-bad-layout: ledger does not end in newline\n", Err: nil},
			},
			ts,
		)

		reviewCommitHash := getReference(t, problemAlias, "refs/changes/initial2", ts).String()
		newOid, packContents = createCommit(
			t,
			tmpDir,
			problemAlias,
			getReference(t, problemAlias, "refs/meta/review", ts),
			map[string]io.Reader{
				reviewCommitHash: strings.NewReader("{}\n"),
			},
			"Foo\n\nIteration: 00000000-0000-0000-0000-000000000000",
			log,
		)
		push(
			t,
			tmpDir,
			editorAuthorization,
			problemAlias,
			"refs/meta/review",
			getReference(t, problemAlias, "refs/meta/review", ts),
			newOid,
			packContents,
			[]githttp.PktLineResponse{
				{Line: "unpack ok\n", Err: nil},
				{Line: "ng refs/meta/review review-bad-layout: missing ledger file\n", Err: nil},
			},
			ts,
		)

		newOid, packContents = createCommit(
			t,
			tmpDir,
			problemAlias,
			getReference(t, problemAlias, "refs/meta/review", ts),
			map[string]io.Reader{
				"ledger": strings.NewReader("non-JSON ledger\n"),
			},
			"Foo\n\nIteration: 00000000-0000-0000-0000-000000000000",
			log,
		)
		push(
			t,
			tmpDir,
			editorAuthorization,
			problemAlias,
			"refs/meta/review",
			getReference(t, problemAlias, "refs/meta/review", ts),
			newOid,
			packContents,
			[]githttp.PktLineResponse{
				{Line: "unpack ok\n", Err: nil},
				{Line: "ng refs/meta/review json-parse-error: appended ledger contents: invalid character 'o' in literal null (expecting 'u')\n", Err: nil},
			},
			ts,
		)

		newOid, packContents = createCommit(
			t,
			tmpDir,
			problemAlias,
			getReference(t, problemAlias, "refs/meta/review", ts),
			map[string]io.Reader{
				"ledger": strings.NewReader("{}\n"),
			},
			"Foo\n\nIteration: 00000000-0000-0000-0000-000000000000",
			log,
		)
		push(
			t,
			tmpDir,
			editorAuthorization,
			problemAlias,
			"refs/meta/review",
			getReference(t, problemAlias, "refs/meta/review", ts),
			newOid,
			packContents,
			[]githttp.PktLineResponse{
				{Line: "unpack ok\n", Err: nil},
				{Line: "ng refs/meta/review review-bad-layout: invalid iteration uuid in ledger entry\n", Err: nil},
			},
			ts,
		)

		newOid, packContents = createCommit(
			t,
			tmpDir,
			problemAlias,
			getReference(t, problemAlias, "refs/meta/review", ts),
			map[string]io.Reader{
				"ledger": strings.NewReader("{\"uuid\":\"00000000-0000-0000-0000-000000000001\",\"author\":\"foo\",\"date\":0,\"Summary\":\"Good!\"}\n"),
			},
			"Foo\n\nIteration: 00000000-0000-0000-0000-000000000000",
			log,
		)
		push(
			t,
			tmpDir,
			editorAuthorization,
			problemAlias,
			"refs/meta/review",
			getReference(t, problemAlias, "refs/meta/review", ts),
			newOid,
			packContents,
			[]githttp.PktLineResponse{
				{Line: "unpack ok\n", Err: nil},
				{Line: "ng refs/meta/review review-bad-layout: invalid iteration uuid in ledger entry\n", Err: nil},
			},
			ts,
		)

		newOid, packContents = createCommit(
			t,
			tmpDir,
			problemAlias,
			getReference(t, problemAlias, "refs/meta/review", ts),
			map[string]io.Reader{
				"ledger":         strings.NewReader("{\"uuid\":\"00000000-0000-0000-0000-000000000000\",\"author\":\"foo\",\"date\":0,\"Summary\":\"Good!\"}\n"),
				reviewCommitHash: strings.NewReader("non-JSON entry\n"),
			},
			"Foo\n\nIteration: 00000000-0000-0000-0000-000000000000",
			log,
		)
		push(
			t,
			tmpDir,
			editorAuthorization,
			problemAlias,
			"refs/meta/review",
			getReference(t, problemAlias, "refs/meta/review", ts),
			newOid,
			packContents,
			[]githttp.PktLineResponse{
				{Line: "unpack ok\n", Err: nil},
				{
					Line: fmt.Sprintf(
						"ng refs/meta/review review-bad-layout: malformed appended comment in %s: invalid character 'o' in literal null (expecting 'u')\n",
						reviewCommitHash,
					),
					Err: nil,
				},
			},
			ts,
		)

		newOid, packContents = createCommit(
			t,
			tmpDir,
			problemAlias,
			getReference(t, problemAlias, "refs/meta/review", ts),
			map[string]io.Reader{
				"ledger":         strings.NewReader("{\"uuid\":\"00000000-0000-0000-0000-000000000000\",\"author\":\"foo\",\"date\":0,\"Summary\":\"Good!\"}\n"),
				reviewCommitHash: strings.NewReader("{\"author\":\"bar\",\"date\":0,\"done\":false,\"filename\":\"cases/0.in\",\"iterationUuid\":\"00000000-0000-0000-0000-000000000000\",\"message\":\"Good!\",\"uuid\":\"00000000-0000-0000-0000-000000000001\"}\n"),
			},
			"Foo\n\nIteration: 00000000-0000-0000-0000-000000000000",
			log,
		)
		push(
			t,
			tmpDir,
			editorAuthorization,
			problemAlias,
			"refs/meta/review",
			getReference(t, problemAlias, "refs/meta/review", ts),
			newOid,
			packContents,
			[]githttp.PktLineResponse{
				{Line: "unpack ok\n", Err: nil},
				{Line: fmt.Sprintf("ng refs/meta/review review-bad-layout: invalid author in %s\n", reviewCommitHash), Err: nil},
			},
			ts,
		)

		newOid, packContents = createCommit(
			t,
			tmpDir,
			problemAlias,
			getReference(t, problemAlias, "refs/meta/review", ts),
			map[string]io.Reader{
				"ledger":         strings.NewReader("{\"uuid\":\"00000000-0000-0000-0000-000000000000\",\"author\":\"foo\",\"date\":0,\"Summary\":\"Good!\"}\n"),
				reviewCommitHash: strings.NewReader("{\"author\":\"foo\",\"date\":0,\"done\":false,\"filename\":\"cases/0.in\",\"message\":\"Good!\",\"uuid\":\"00000000-0000-0000-0000-000000000001\"}\n"),
			},
			"Foo\n\nIteration: 00000000-0000-0000-0000-000000000000",
			log,
		)
		push(
			t,
			tmpDir,
			editorAuthorization,
			problemAlias,
			"refs/meta/review",
			getReference(t, problemAlias, "refs/meta/review", ts),
			newOid,
			packContents,
			[]githttp.PktLineResponse{
				{Line: "unpack ok\n", Err: nil},
				{Line: fmt.Sprintf("ng refs/meta/review review-bad-layout: invalid iteration uuid in %s\n", reviewCommitHash), Err: nil},
			},
			ts,
		)

		newOid, packContents = createCommit(
			t,
			tmpDir,
			problemAlias,
			getReference(t, problemAlias, "refs/meta/review", ts),
			map[string]io.Reader{
				"ledger":         strings.NewReader("{\"uuid\":\"00000000-0000-0000-0000-000000000000\",\"author\":\"foo\",\"date\":0,\"Summary\":\"Good!\"}\n"),
				reviewCommitHash: strings.NewReader("{\"author\":\"foo\",\"date\":0,\"done\":false,\"filename\":\"cases/0.in\",\"iterationUuid\":\"00000000-0000-0000-0000-000000000000\",\"message\":\"Good!\"}\n"),
			},
			"Foo\n\nIteration: 00000000-0000-0000-0000-000000000000",
			log,
		)
		push(
			t,
			tmpDir,
			editorAuthorization,
			problemAlias,
			"refs/meta/review",
			getReference(t, problemAlias, "refs/meta/review", ts),
			newOid,
			packContents,
			[]githttp.PktLineResponse{
				{Line: "unpack ok\n", Err: nil},
				{Line: fmt.Sprintf("ng refs/meta/review review-bad-layout: missing or malformed comment uuid in %s\n", reviewCommitHash), Err: nil},
			},
			ts,
		)

		newOid, packContents = createCommit(
			t,
			tmpDir,
			problemAlias,
			getReference(t, problemAlias, "refs/meta/review", ts),
			map[string]io.Reader{
				"ledger":         strings.NewReader("{\"uuid\":\"00000000-0000-0000-0000-000000000000\",\"author\":\"foo\",\"date\":0,\"Summary\":\"Good!\"}\n"),
				reviewCommitHash: strings.NewReader("{\"author\":\"foo\",\"date\":0,\"done\":false,\"filename\":\"cases/0.in\",\"iterationUuid\":\"00000000-0000-0000-0000-000000000000\",\"message\":\"Good!\",\"uuid\":\"00000000-0000-0000-0000-000000000001\"}\n{\"author\":\"foo\",\"date\":0,\"done\":false,\"filename\":\"cases/0.in\",\"iterationUuid\":\"00000000-0000-0000-0000-000000000000\",\"message\":\"Good!\",\"uuid\":\"00000000-0000-0000-0000-000000000001\"}\n"),
			},
			"Foo\n\nIteration: 00000000-0000-0000-0000-000000000000",
			log,
		)
		push(
			t,
			tmpDir,
			editorAuthorization,
			problemAlias,
			"refs/meta/review",
			getReference(t, problemAlias, "refs/meta/review", ts),
			newOid,
			packContents,
			[]githttp.PktLineResponse{
				{Line: "unpack ok\n", Err: nil},
				{Line: fmt.Sprintf("ng refs/meta/review review-bad-layout: duplicate comment uuid in %s\n", reviewCommitHash), Err: nil},
			},
			ts,
		)

		newOid, packContents = createCommit(
			t,
			tmpDir,
			problemAlias,
			getReference(t, problemAlias, "refs/meta/review", ts),
			map[string]io.Reader{
				"ledger":         strings.NewReader("{\"uuid\":\"00000000-0000-0000-0000-000000000000\",\"author\":\"foo\",\"date\":0,\"Summary\":\"Good!\"}\n"),
				reviewCommitHash: strings.NewReader("{\"author\":\"foo\",\"date\":0,\"done\":false,\"filename\":\"missing\",\"iterationUuid\":\"00000000-0000-0000-0000-000000000000\",\"message\":\"Good!\",\"uuid\":\"00000000-0000-0000-0000-000000000001\"}\n"),
			},
			"Foo\n\nIteration: 00000000-0000-0000-0000-000000000000",
			log,
		)
		push(
			t,
			tmpDir,
			editorAuthorization,
			problemAlias,
			"refs/meta/review",
			getReference(t, problemAlias, "refs/meta/review", ts),
			newOid,
			packContents,
			[]githttp.PktLineResponse{
				{Line: "unpack ok\n", Err: nil},
				{Line: fmt.Sprintf("ng refs/meta/review review-bad-layout: file 'missing' not found in %s: the path 'missing' does not exist in the given tree\n", reviewCommitHash), Err: nil},
			},
			ts,
		)

		newOid, packContents = createCommit(
			t,
			tmpDir,
			problemAlias,
			getReference(t, problemAlias, "refs/meta/review", ts),
			map[string]io.Reader{
				"ledger":         strings.NewReader("{\"uuid\":\"00000000-0000-0000-0000-000000000000\",\"author\":\"foo\",\"date\":0,\"Summary\":\"Good!\"}\n"),
				reviewCommitHash: strings.NewReader("{\"author\":\"foo\",\"date\":0,\"done\":false,\"filename\":\"cases/0.in\",\"iterationUuid\":\"00000000-0000-0000-0000-000000000000\",\"message\":\"Good!\",\"uuid\":\"00000000-0000-0000-0000-000000000001\",\"parentUuid\":\"\"}\n"),
			},
			"Foo\n\nIteration: 00000000-0000-0000-0000-000000000000",
			log,
		)
		push(
			t,
			tmpDir,
			editorAuthorization,
			problemAlias,
			"refs/meta/review",
			getReference(t, problemAlias, "refs/meta/review", ts),
			newOid,
			packContents,
			[]githttp.PktLineResponse{
				{Line: "unpack ok\n", Err: nil},
				{Line: fmt.Sprintf("ng refs/meta/review review-bad-layout: parent uuid missing in %s\n", reviewCommitHash), Err: nil},
			},
			ts,
		)

		newOid, packContents = createCommit(
			t,
			tmpDir,
			problemAlias,
			getReference(t, problemAlias, "refs/meta/review", ts),
			map[string]io.Reader{
				"ledger":         strings.NewReader("{\"uuid\":\"00000000-0000-0000-0000-000000000000\",\"author\":\"foo\",\"date\":0,\"Summary\":\"Good!\"}\n"),
				reviewCommitHash: strings.NewReader("{\"author\":\"foo\",\"date\":0,\"done\":false,\"filename\":\"cases/0.in\",\"iterationUuid\":\"00000000-0000-0000-0000-000000000000\",\"message\":\"Good!\",\"uuid\":\"00000000-0000-0000-0000-000000000001\"}\n{\"author\":\"foo\",\"date\":0,\"done\":false,\"filename\":\"cases/0.in\",\"iterationUuid\":\"00000000-0000-0000-0000-000000000000\",\"message\":\"Good!\",\"uuid\":\"00000000-0000-0000-0000-000000000002\",\"parentUuid\":\"00000000-0000-0000-0000-000000000001\",\"range\":{\"lineStart\":0,\"lineEnd\":0,\"colStart\":0,\"colEnd\":0}}\n"),
			},
			"Foo\n\nIteration: 00000000-0000-0000-0000-000000000000",
			log,
		)
		push(
			t,
			tmpDir,
			editorAuthorization,
			problemAlias,
			"refs/meta/review",
			getReference(t, problemAlias, "refs/meta/review", ts),
			newOid,
			packContents,
			[]githttp.PktLineResponse{
				{Line: "unpack ok\n", Err: nil},
				{Line: fmt.Sprintf("ng refs/meta/review review-bad-layout: cannot specify both parentUuid and range in %s\n", reviewCommitHash), Err: nil},
			},
			ts,
		)

		newOid, packContents = createCommit(
			t,
			tmpDir,
			problemAlias,
			getReference(t, problemAlias, "refs/meta/review", ts),
			map[string]io.Reader{
				"ledger":         strings.NewReader("{\"uuid\":\"00000000-0000-0000-0000-000000000000\",\"author\":\"foo\",\"date\":0,\"Summary\":\"Good!\"}\n"),
				reviewCommitHash: strings.NewReader("{\"author\":\"foo\",\"date\":0,\"done\":false,\"filename\":\"cases/0.in\",\"iterationUuid\":\"00000000-0000-0000-0000-000000000000\",\"message\":\"\",\"uuid\":\"00000000-0000-0000-0000-000000000001\"}\n"),
			},
			"Foo\n\nIteration: 00000000-0000-0000-0000-000000000000",
			log,
		)
		push(
			t,
			tmpDir,
			editorAuthorization,
			problemAlias,
			"refs/meta/review",
			getReference(t, problemAlias, "refs/meta/review", ts),
			newOid,
			packContents,
			[]githttp.PktLineResponse{
				{Line: "unpack ok\n", Err: nil},
				{Line: fmt.Sprintf("ng refs/meta/review review-bad-layout: empty comment message in %s\n", reviewCommitHash), Err: nil},
			},
			ts,
		)

		newOid, packContents = createCommit(
			t,
			tmpDir,
			problemAlias,
			getReference(t, problemAlias, "refs/meta/review", ts),
			map[string]io.Reader{
				"ledger":         strings.NewReader("{\"uuid\":\"00000000-0000-0000-0000-000000000000\",\"author\":\"foo\",\"date\":0,\"Summary\":\"Good!\"}\n"),
				reviewCommitHash: strings.NewReader("{\"author\":\"foo\",\"date\":0,\"done\":false,\"filename\":\"cases/0.in\",\"iterationUuid\":\"00000000-0000-0000-0000-000000000000\",\"message\":\"Good!\",\"uuid\":\"00000000-0000-0000-0000-000000000001\"}\n"),
			},
			"Foo\n\nIteration: 00000000-0000-0000-0000-000000000000",
			log,
		)
		push(
			t,
			tmpDir,
			editorAuthorization,
			problemAlias,
			"refs/meta/review",
			getReference(t, problemAlias, "refs/meta/review", ts),
			newOid,
			packContents,
			[]githttp.PktLineResponse{
				{Line: "unpack ok\n", Err: nil},
				{Line: "ok refs/meta/review\n", Err: nil},
			},
			ts,
		)

		newOid, packContents = createCommit(
			t,
			tmpDir,
			problemAlias,
			getReference(t, problemAlias, "refs/meta/review", ts),
			map[string]io.Reader{
				"ledger": strings.NewReader("{\"uuid\":\"00000000-0000-0000-0000-000000000000\",\"author\":\"foo\",\"date\":0,\"Summary\":\"Good!\"}\n" +
					"{\"uuid\":\"00000000-0000-0000-0000-000000000001\",\"author\":\"bar\",\"date\":1,\"Summary\":\"Good!\"}\n"),
			},
			"Foo\n\nIteration: 00000000-0000-0000-0000-000000000001",
			log,
		)
		push(
			t,
			tmpDir,
			editorAuthorization,
			problemAlias,
			"refs/meta/review",
			getReference(t, problemAlias, "refs/meta/review", ts),
			newOid,
			packContents,
			[]githttp.PktLineResponse{
				{Line: "unpack ok\n", Err: nil},
				{
					Line: fmt.Sprintf("ng refs/meta/review review-bad-layout: failed to find %s in review iteration\n", reviewCommitHash),
					Err:  nil,
				},
			},
			ts,
		)

		newOid, packContents = createCommit(
			t,
			tmpDir,
			problemAlias,
			getReference(t, problemAlias, "refs/meta/review", ts),
			map[string]io.Reader{
				"ledger": strings.NewReader("{\"uuid\":\"00000000-0000-0000-0000-000000000000\",\"author\":\"foo\",\"date\":0,\"Summary\":\"Good!\"}\n" +
					"{\"uuid\":\"00000000-0000-0000-0000-000000000001\",\"author\":\"bar\",\"date\":1,\"Summary\":\"Good!\"}\n"),
				reviewCommitHash: strings.NewReader("{\"author\":\"foo\",\"date\":0,\"done\":false,\"filename\":\"cases/0.in\",\"iterationUuid\":\"00000000-0000-0000-0000-000000000000\",\"message\":\"gaslighting!\",\"uuid\":\"00000000-0000-0000-0000-000000000001\"}\n" +
					"{\"author\":\"bar\",\"date\":0,\"done\":true,\"filename\":\"cases/0.in\",\"iterationUuid\":\"00000000-0000-0000-0000-000000000001\",\"message\":\"Good!\",\"uuid\":\"00000000-0000-0000-0000-000000000002\",\"parentUuid\":\"00000000-0000-0000-0000-000000000001\"}\n"),
			},
			"Foo\n\nIteration: 00000000-0000-0000-0000-000000000001",
			log,
		)
		push(
			t,
			tmpDir,
			editorAuthorization,
			problemAlias,
			"refs/meta/review",
			getReference(t, problemAlias, "refs/meta/review", ts),
			newOid,
			packContents,
			[]githttp.PktLineResponse{
				{Line: "unpack ok\n", Err: nil},
				{
					Line: fmt.Sprintf("ng refs/meta/review review-bad-layout: unexpected non-append to %s\n", reviewCommitHash),
					Err:  nil,
				},
			},
			ts,
		)

		newOid, packContents = createCommit(
			t,
			tmpDir,
			problemAlias,
			getReference(t, problemAlias, "refs/meta/review", ts),
			map[string]io.Reader{
				"ledger": strings.NewReader("{\"uuid\":\"00000000-0000-0000-0000-000000000000\",\"author\":\"foo\",\"date\":0,\"Summary\":\"Good!\"}\n" +
					"{\"uuid\":\"00000000-0000-0000-0000-000000000001\",\"author\":\"bar\",\"date\":1,\"Summary\":\"Good!\"}\n"),
				reviewCommitHash: strings.NewReader("{\"author\":\"foo\",\"date\":0,\"done\":false,\"filename\":\"cases/0.in\",\"iterationUuid\":\"00000000-0000-0000-0000-000000000000\",\"message\":\"Good!\",\"uuid\":\"00000000-0000-0000-0000-000000000001\"}\n" +
					"{\"author\":\"bar\",\"date\":0,\"done\":true,\"filename\":\"cases/0.in\",\"iterationUuid\":\"00000000-0000-0000-0000-000000000001\",\"message\":\"Good!\",\"uuid\":\"00000000-0000-0000-0000-000000000002\",\"parentUuid\":\"00000000-0000-0000-0000-000000000001\"}\n"),
			},
			"Foo\n\nIteration: 00000000-0000-0000-0000-000000000001",
			log,
		)
		push(
			t,
			tmpDir,
			editorAuthorization,
			problemAlias,
			"refs/meta/review",
			getReference(t, problemAlias, "refs/meta/review", ts),
			newOid,
			packContents,
			[]githttp.PktLineResponse{
				{Line: "unpack ok\n", Err: nil},
				{Line: "ok refs/meta/review\n", Err: nil},
			},
			ts,
		)
	}

	// Try a few more invalid publish paths
	{
		push(
			t,
			tmpDir,
			adminAuthorization,
			problemAlias,
			"refs/heads/published",
			getReference(t, problemAlias, "refs/heads/published", ts),
			getReference(t, problemAlias, "refs/changes/initial2", ts),
			githttp.EmptyPackfile,
			[]githttp.PktLineResponse{
				{Line: "unpack ok\n", Err: nil},
				{Line: "ng refs/heads/published published-must-point-to-commit-in-master\n", Err: nil},
			},
			ts,
		)
	}

	// Publish second version
	{
		push(
			t,
			tmpDir,
			adminAuthorization,
			problemAlias,
			"refs/heads/master",
			getReference(t, problemAlias, "refs/heads/master", ts),
			getReference(t, problemAlias, "refs/changes/initial2", ts),
			githttp.EmptyPackfile,
			[]githttp.PktLineResponse{
				{Line: "unpack ok\n", Err: nil},
				{Line: "ok refs/heads/master\n", Err: nil},
			},
			ts,
		)
	}
}

func TestPushGitbomb(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", t.Name())
	if err != nil {
		t.Fatalf("Failed to create directory: %v", err)
	}
	if os.Getenv("PRESERVE") == "" {
		defer os.RemoveAll(tmpDir)
	}
	ctx := context.Background()

	log, err := log15.New("info", false)
	if err != nil {
		t.Fatalf("Failed to create log: %v", err)
	}
	ts := httptest.NewServer(NewGitHandler(GitHandlerOpts{
		RootPath: tmpDir,
		Protocol: NewGitProtocol(GitProtocolOpts{
			GitProtocolOpts: githttp.GitProtocolOpts{
				AuthCallback: authorize,
				Log:          log,
			},
			HardOverallWallTimeLimit:    OverallWallTimeHardLimit,
			InteractiveSettingsCompiler: fakeInteractiveSettingsCompiler,
		}),
		Log: log,
	}))
	defer ts.Close()

	problemAlias := "sumas"

	{
		repo, err := InitRepository(ctx, path.Join(tmpDir, problemAlias))
		if err != nil {
			t.Fatalf("Failed to initialize git repository: %v", err)
		}
		repo.Free()
	}

	repo, err := git.OpenRepository(path.Join(tmpDir, problemAlias))
	if err != nil {
		t.Fatalf("Failed to open repository: %v", err)
	}
	defer repo.Free()

	odb, err := repo.Odb()
	if err != nil {
		t.Fatalf("Failed to open odb: %v", err)
	}
	defer odb.Free()

	mempack, err := git.NewMempack(odb)
	if err != nil {
		t.Fatalf("Failed to create mempack: %v", err)
	}

	oid, err := repo.CreateBlobFromBuffer([]byte{})
	if err != nil {
		t.Fatalf("Failed to create blob: %v", err)
	}

	fileMode := git.Filemode(0100644)
	for i := 0; i < 24; i++ {
		log.Debug(
			"Creating gitbomb",
			map[string]any{
				"iteration": i,
			},
		)
		treebuilder, err := repo.TreeBuilder()
		if err != nil {
			t.Fatalf("Failed to create TreeBuilder: %v", err)
		}

		for _, filename := range []string{"0", "1"} {
			if err = treebuilder.Insert(filename, oid, fileMode); err != nil {
				t.Fatalf("Failed to insert into TreeBuilder: %v", err)
			}
		}
		oid, err = treebuilder.Write()
		if err != nil {
			t.Fatalf("Failed to write tree: %v", err)
		}
		treebuilder.Free()
		fileMode = 040000
	}

	tree, err := repo.LookupTree(oid)
	if err != nil {
		t.Fatalf("Failed to lookup tree: %v", err)
	}

	log.Debug("Tree looked up", nil)

	newCommitID, err := repo.CreateCommit(
		"",
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
		"Initial commit",
		tree,
	)
	if err != nil {
		t.Fatalf("Failed to create commit: %v", err)
	}

	packContents, err := mempack.Dump(repo)
	if err != nil {
		t.Fatalf("Failed to create mempack: %v", err)
	}
	push(
		t,
		tmpDir,
		editorAuthorization,
		problemAlias,
		"refs/changes/initial",
		&git.Oid{}, newCommitID,
		packContents,
		[]githttp.PktLineResponse{
			{Line: "unpack ok\n", Err: nil},
			{Line: "ng refs/changes/initial too-many-objects-in-packfile\n", Err: nil},
		},
		ts,
	)
}

func TestConfig(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", t.Name())
	if err != nil {
		t.Fatalf("Failed to create directory: %v", err)
	}
	if os.Getenv("PRESERVE") == "" {
		defer os.RemoveAll(tmpDir)
	}
	ctx := context.Background()

	log, err := log15.New("info", false)
	if err != nil {
		t.Fatalf("Failed to create log: %v", err)
	}
	ts := httptest.NewServer(NewGitHandler(GitHandlerOpts{
		RootPath: tmpDir,
		Protocol: NewGitProtocol(GitProtocolOpts{
			GitProtocolOpts: githttp.GitProtocolOpts{
				AuthCallback: authorize,
				Log:          log,
			},
			HardOverallWallTimeLimit:    OverallWallTimeHardLimit,
			InteractiveSettingsCompiler: fakeInteractiveSettingsCompiler,
		}),
		Log: log,
	}))
	defer ts.Close()

	problemAlias := "sumas"

	{
		repo, err := InitRepository(ctx, path.Join(tmpDir, problemAlias))
		if err != nil {
			t.Fatalf("Failed to initialize git repository: %v", err)
		}
		repo.Free()
	}

	// Normal mirror update.
	oldOid := &git.Oid{}
	newOid, packContents := createCommit(
		t,
		tmpDir,
		problemAlias,
		oldOid,
		map[string]io.Reader{
			"config.json": strings.NewReader(`{
				"publishing":{
					"mode":"mirror",
					"repository":"https://github.com/omegaup/test.git"
				}
			}`),
		},
		"Initial commit",
		log,
	)
	push(
		t,
		tmpDir,
		editorAuthorization,
		problemAlias,
		"refs/meta/config",
		oldOid, newOid,
		packContents,
		[]githttp.PktLineResponse{
			{Line: "unpack ok\n", Err: nil},
			{Line: "ng refs/meta/config restricted-ref\n", Err: nil},
		},
		ts,
	)
	push(
		t,
		tmpDir,
		adminAuthorization,
		problemAlias,
		"refs/meta/config",
		oldOid, newOid,
		packContents,
		[]githttp.PktLineResponse{
			{Line: "unpack ok\n", Err: nil},
			{Line: "ok refs/meta/config\n", Err: nil},
		},
		ts,
	)

	// Normal subdirectory update.
	oldOid = getReference(t, problemAlias, "refs/meta/config", ts)
	newOid, packContents = createCommit(
		t,
		tmpDir,
		problemAlias,
		oldOid,
		map[string]io.Reader{
			"config.json": strings.NewReader(`{
				"publishing":{
					"mode":"subdirectory",
					"repository":"https://github.com/omegaup/test.git",
					"target":"subdirectory"
				}
			}`),
		},
		"Initial commit",
		log,
	)
	push(
		t,
		tmpDir,
		adminAuthorization,
		problemAlias,
		"refs/meta/config",
		oldOid, newOid,
		packContents,
		[]githttp.PktLineResponse{
			{Line: "unpack ok\n", Err: nil},
			{Line: "ok refs/meta/config\n", Err: nil},
		},
		ts,
	)

	// Empty tree.
	oldOid = getReference(t, problemAlias, "refs/meta/config", ts)
	newOid, packContents = createCommit(
		t,
		tmpDir,
		problemAlias,
		oldOid,
		map[string]io.Reader{},
		"Initial commit",
		log,
	)
	push(
		t,
		tmpDir,
		adminAuthorization,
		problemAlias,
		"refs/meta/config",
		oldOid, newOid,
		packContents,
		[]githttp.PktLineResponse{
			{Line: "unpack ok\n", Err: nil},
			{Line: "ok refs/meta/config\n", Err: nil},
		},
		ts,
	)

	// Extra files.
	oldOid = getReference(t, problemAlias, "refs/meta/config", ts)
	newOid, packContents = createCommit(
		t,
		tmpDir,
		problemAlias,
		oldOid,
		map[string]io.Reader{
			"garbage.txt": strings.NewReader(""),
			"config.json": strings.NewReader(`{
				"publishing":{
					"mode":"mirror",
					"repository":"https://github.com/omegaup/test.git"
				}
			}`),
		},
		"Initial commit",
		log,
	)
	push(
		t,
		tmpDir,
		adminAuthorization,
		problemAlias,
		"refs/meta/config",
		oldOid, newOid,
		packContents,
		[]githttp.PktLineResponse{
			{Line: "unpack ok\n", Err: nil},
			{Line: "ng refs/meta/config config-bad-layout: refs/meta/config can only contain a single config.json file\n", Err: nil},
		},
		ts,
	)

	// Wrong filename.
	oldOid = getReference(t, problemAlias, "refs/meta/config", ts)
	newOid, packContents = createCommit(
		t,
		tmpDir,
		problemAlias,
		oldOid,
		map[string]io.Reader{
			"config.txt": strings.NewReader(`{
				"publishing":{
					"mode":"mirror",
					"repository":"https://github.com/omegaup/test.git"
				}
			}`),
		},
		"Initial commit",
		log,
	)
	push(
		t,
		tmpDir,
		adminAuthorization,
		problemAlias,
		"refs/meta/config",
		oldOid, newOid,
		packContents,
		[]githttp.PktLineResponse{
			{Line: "unpack ok\n", Err: nil},
			{Line: "ng refs/meta/config config-bad-layout: refs/meta/config can only contain a single config.json file\n", Err: nil},
		},
		ts,
	)

	// Wrong format.
	oldOid = getReference(t, problemAlias, "refs/meta/config", ts)
	newOid, packContents = createCommit(
		t,
		tmpDir,
		problemAlias,
		oldOid,
		map[string]io.Reader{
			"config.json": strings.NewReader("invalid json"),
		},
		"Initial commit",
		log,
	)
	push(
		t,
		tmpDir,
		adminAuthorization,
		problemAlias,
		"refs/meta/config",
		oldOid, newOid,
		packContents,
		[]githttp.PktLineResponse{
			{Line: "unpack ok\n", Err: nil},
			{Line: "ng refs/meta/config json-parse-error: config.json: invalid character 'i' looking for beginning of value\n", Err: nil},
		},
		ts,
	)

	// Wrong publishing mode.
	oldOid = getReference(t, problemAlias, "refs/meta/config", ts)
	newOid, packContents = createCommit(
		t,
		tmpDir,
		problemAlias,
		oldOid,
		map[string]io.Reader{
			"config.json": strings.NewReader(`{
				"publishing":{
					"mode":"invalid"
				}
			}`),
		},
		"Initial commit",
		log,
	)
	push(
		t,
		tmpDir,
		adminAuthorization,
		problemAlias,
		"refs/meta/config",
		oldOid, newOid,
		packContents,
		[]githttp.PktLineResponse{
			{Line: "unpack ok\n", Err: nil},
			{Line: "ng refs/meta/config config-invalid-publishing-mode\n", Err: nil},
		},
		ts,
	)

	// Repository is not an absolute URL.
	oldOid = getReference(t, problemAlias, "refs/meta/config", ts)
	newOid, packContents = createCommit(
		t,
		tmpDir,
		problemAlias,
		oldOid,
		map[string]io.Reader{
			"config.json": strings.NewReader(`{
				"publishing":{
					"mode":"mirror",
					"repository":"invalid"
				}
			}`),
		},
		"Initial commit",
		log,
	)
	push(
		t,
		tmpDir,
		adminAuthorization,
		problemAlias,
		"refs/meta/config",
		oldOid, newOid,
		packContents,
		[]githttp.PktLineResponse{
			{Line: "unpack ok\n", Err: nil},
			{Line: "ng refs/meta/config config-repository-not-absolute-url\n", Err: nil},
		},
		ts,
	)

	// Missing target for subdirectory.
	oldOid = getReference(t, problemAlias, "refs/meta/config", ts)
	newOid, packContents = createCommit(
		t,
		tmpDir,
		problemAlias,
		oldOid,
		map[string]io.Reader{
			"config.json": strings.NewReader(`{
				"publishing":{
					"mode":"subdirectory",
					"repository":"https://github.com/omegaup/test.git"
				}
			}`),
		},
		"Initial commit",
		log,
	)
	push(
		t,
		tmpDir,
		adminAuthorization,
		problemAlias,
		"refs/meta/config",
		oldOid, newOid,
		packContents,
		[]githttp.PktLineResponse{
			{Line: "unpack ok\n", Err: nil},
			{Line: "ng refs/meta/config config-subdirectory-missing-target\n", Err: nil},
		},
		ts,
	)
}

func getProblemDistribSettings(repo *git.Repository, tree *git.Tree) (*common.LiteralInput, error) {
	settingsJSONEntry, err := tree.EntryByPath("settings.distrib.json")
	if err != nil {
		return nil, err
	}
	settingsJSONBlob, err := repo.LookupBlob(settingsJSONEntry.Id)
	if err != nil {
		return nil, err
	}
	defer settingsJSONBlob.Free()

	var settings common.LiteralInput
	if err := json.Unmarshal(settingsJSONBlob.Contents(), &settings); err != nil {
		return nil, err
	}
	return &settings, nil
}

func TestInteractive(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", t.Name())
	if err != nil {
		t.Fatalf("Failed to create directory: %v", err)
	}
	if os.Getenv("PRESERVE") == "" {
		defer os.RemoveAll(tmpDir)
	}
	ctx := context.Background()

	log, err := log15.New("info", false)
	if err != nil {
		t.Fatalf("Failed to create log: %v", err)
	}
	ts := httptest.NewServer(NewGitHandler(GitHandlerOpts{
		RootPath: tmpDir,
		Protocol: NewGitProtocol(GitProtocolOpts{
			GitProtocolOpts: githttp.GitProtocolOpts{
				AuthCallback: authorize,
				Log:          log,
			},
			AllowDirectPushToMaster:  true,
			HardOverallWallTimeLimit: OverallWallTimeHardLimit,
			InteractiveSettingsCompiler: &FakeInteractiveSettingsCompiler{
				Settings: &common.InteractiveSettings{
					Interfaces:            map[string]map[string]*common.InteractiveInterface{},
					Templates:             map[string]string{},
					Main:                  "",
					ModuleName:            "",
					ParentLang:            "",
					LibinteractiveVersion: "0.0",
				},
				Err: nil,
			},
		}),
		Log: log,
	}))
	defer ts.Close()

	problemAlias := "sumas"

	repo, err := InitRepository(ctx, path.Join(tmpDir, problemAlias))
	if err != nil {
		t.Fatalf("Failed to initialize git repository: %v", err)
	}
	defer repo.Free()

	{
		newOid, packContents := createCommit(
			t,
			tmpDir,
			problemAlias,
			&git.Oid{},
			map[string]io.Reader{
				"settings.json": strings.NewReader(gitservertest.DefaultSettingsJSON),
				"cases/0.in":    strings.NewReader("1 2"),
				"cases/0.out":   strings.NewReader("3"),
				"statements/es.markdown": strings.NewReader(`Sumas

# Examples

||input
Example 1
||output
Example 1
||description
This example won't be copied since there are explicit example files.
||end
`),
				"interactive/sums.idl": strings.NewReader(`// sums.idl
interface Main {
};

interface sums {
	int sums(int a, int b);
};`),
				"interactive/Main.cpp": strings.NewReader(`// Main.cpp
#include <stdio.h>
#include "sums.h"

int main(int argc, char* argv[]) {
	int a, b;
	scanf("%d %d\n", &a, &b);
	printf("%d\n", sums(a, b));
}`),
				"interactive/Main.distrib.cpp": strings.NewReader(`// Main.cpp
#include <stdio.h>
#include "sums.h"

int main(int argc, char* argv[]) {
	// Este es un ejemplo.
	int a, b;
	scanf("%d %d\n", &a, &b);
	printf("%d\n", sums(a, b));
}`),
				"interactive/examples/sample.in":  strings.NewReader("0 1"),
				"interactive/examples/sample.out": strings.NewReader("1"),
			},
			"Initial commit",
			log,
		)
		push(
			t,
			tmpDir,
			adminAuthorization,
			problemAlias,
			"refs/heads/master",
			&git.Oid{}, newOid,
			packContents,
			[]githttp.PktLineResponse{
				{Line: "unpack ok\n", Err: nil},
				{Line: "ok refs/heads/master\n", Err: nil},
			},
			ts,
		)
	}

	masterCommit, err := repo.LookupCommit(
		getReference(t, problemAlias, "refs/heads/master", ts),
	)
	if err != nil {
		t.Fatalf("Failed to lookup commit: %v", err)
	}
	defer masterCommit.Free()
	masterTree, err := masterCommit.Tree()
	if err != nil {
		t.Fatalf("Failed to lookup tree: %v", err)
	}
	defer masterTree.Free()

	problemSettings, err := getProblemSettings(
		ctx,
		repo,
		masterTree,
	)
	if err != nil {
		t.Fatalf("failed to get problem settings: %v", err)
	}
	if problemSettings.Interactive == nil {
		t.Fatalf("Failed to produce interactive settings")
	}

	problemDistribSettings, err := getProblemDistribSettings(
		repo,
		masterTree,
	)
	if err != nil {
		t.Fatalf("failed to get problem distributable settings: %v", err)
	}
	if problemSettings.Limits != *problemDistribSettings.Limits {
		t.Errorf("limits expected %q, got %q", problemSettings.Limits, *problemDistribSettings.Limits)
	}
	if problemDistribSettings.Interactive == nil {
		t.Fatalf("Failed to produce interactive settings")
	}
	expectedExampleCases := map[string]*common.LiteralCaseSettings{
		"sample": {
			Input:          "0 1",
			ExpectedOutput: "1",
			Weight:         big.NewRat(1, 1),
		},
	}
	if !reflect.DeepEqual(expectedExampleCases, problemDistribSettings.Cases) {
		t.Errorf(
			"Mismatched example cases. expected %v, got %v",
			expectedExampleCases,
			problemDistribSettings.Cases,
		)
	}
	if "" == problemDistribSettings.Interactive.MainSource {
		t.Errorf("Missing main source file")
	}
}

func TestExampleCases(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", t.Name())
	if err != nil {
		t.Fatalf("Failed to create directory: %v", err)
	}
	if os.Getenv("PRESERVE") == "" {
		defer os.RemoveAll(tmpDir)
	}
	ctx := context.Background()

	log, err := log15.New("info", false)
	if err != nil {
		t.Fatalf("Failed to create log: %v", err)
	}
	ts := httptest.NewServer(NewGitHandler(GitHandlerOpts{
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

	repo, err := InitRepository(ctx, path.Join(tmpDir, problemAlias))
	if err != nil {
		t.Fatalf("Failed to initialize git repository: %v", err)
	}
	defer repo.Free()

	parentOid := &git.Oid{}
	{
		newOid, packContents := createCommit(
			t,
			tmpDir,
			problemAlias,
			parentOid,
			map[string]io.Reader{
				"settings.json":          strings.NewReader(gitservertest.DefaultSettingsJSON),
				"cases/0.in":             strings.NewReader("1 2"),
				"cases/0.out":            strings.NewReader("3"),
				"statements/es.markdown": strings.NewReader("Sumas"),
			},
			"Initial commit",
			log,
		)
		push(
			t,
			tmpDir,
			adminAuthorization,
			problemAlias,
			"refs/heads/master",
			parentOid, newOid,
			packContents,
			[]githttp.PktLineResponse{
				{Line: "unpack ok\n", Err: nil},
				{Line: "ok refs/heads/master\n", Err: nil},
			},
			ts,
		)

		masterCommit, err := repo.LookupCommit(
			getReference(t, problemAlias, "refs/heads/master", ts),
		)
		if err != nil {
			t.Fatalf("Failed to lookup commit: %v", err)
		}
		defer masterCommit.Free()

		parentOid = masterCommit.Id()

		masterTree, err := masterCommit.Tree()
		if err != nil {
			t.Fatalf("Failed to lookup tree: %v", err)
		}
		defer masterTree.Free()

		problemDistribSettings, err := getProblemDistribSettings(
			repo,
			masterTree,
		)
		if err != nil {
			t.Fatalf("failed to get problem distributable settings: %v", err)
		}
		expectedExampleCases := map[string]*common.LiteralCaseSettings{}
		if !reflect.DeepEqual(expectedExampleCases, problemDistribSettings.Cases) {
			t.Errorf(
				"Mismatched example cases. expected %v, got %v",
				expectedExampleCases,
				problemDistribSettings.Cases,
			)
		}
	}
	{
		newOid, packContents := createCommit(
			t,
			tmpDir,
			problemAlias,
			parentOid,
			map[string]io.Reader{
				"settings.json": strings.NewReader(gitservertest.DefaultSettingsJSON),
				"cases/0.in":    strings.NewReader("1 2"),
				"cases/0.out":   strings.NewReader("3"),
				"statements/es.markdown": strings.NewReader(`Sumas

# Examples

||input
1 2
||output
3
||input
2 3
||output
5
||end
`),
			},
			"Initial commit",
			log,
		)
		push(
			t,
			tmpDir,
			adminAuthorization,
			problemAlias,
			"refs/heads/master",
			parentOid, newOid,
			packContents,
			[]githttp.PktLineResponse{
				{Line: "unpack ok\n", Err: nil},
				{Line: "ok refs/heads/master\n", Err: nil},
			},
			ts,
		)

		masterCommit, err := repo.LookupCommit(
			getReference(t, problemAlias, "refs/heads/master", ts),
		)
		if err != nil {
			t.Fatalf("Failed to lookup commit: %v", err)
		}
		defer masterCommit.Free()

		parentOid = masterCommit.Id()

		masterTree, err := masterCommit.Tree()
		if err != nil {
			t.Fatalf("Failed to lookup tree: %v", err)
		}
		defer masterTree.Free()

		problemDistribSettings, err := getProblemDistribSettings(
			repo,
			masterTree,
		)
		if err != nil {
			t.Fatalf("failed to get problem distributable settings: %v", err)
		}
		expectedExampleCases := map[string]*common.LiteralCaseSettings{
			"statement_001": {
				Input:          "1 2",
				ExpectedOutput: "3",
				Weight:         big.NewRat(1, 1),
			},
			"statement_002": {
				Input:          "2 3",
				ExpectedOutput: "5",
				Weight:         big.NewRat(1, 1),
			},
		}
		if !reflect.DeepEqual(expectedExampleCases, problemDistribSettings.Cases) {
			t.Errorf(
				"Mismatched example cases. expected %v, got %v",
				expectedExampleCases,
				problemDistribSettings.Cases,
			)
		}
	}
	{
		newOid, packContents := createCommit(
			t,
			tmpDir,
			problemAlias,
			parentOid,
			map[string]io.Reader{
				"settings.json":       strings.NewReader(gitservertest.DefaultSettingsJSON),
				"examples/sample.in":  strings.NewReader("1 2"),
				"examples/sample.out": strings.NewReader("3"),
				"cases/0.in":          strings.NewReader("1 2"),
				"cases/0.out":         strings.NewReader("3"),
				"statements/es.markdown": strings.NewReader(`Sumas

# Examples

||input
1 2
||output
3
||input
2 3
||output
5
||end
`),
			},
			"Initial commit",
			log,
		)
		push(
			t,
			tmpDir,
			adminAuthorization,
			problemAlias,
			"refs/heads/master",
			parentOid, newOid,
			packContents,
			[]githttp.PktLineResponse{
				{Line: "unpack ok\n", Err: nil},
				{Line: "ok refs/heads/master\n", Err: nil},
			},
			ts,
		)

		masterCommit, err := repo.LookupCommit(
			getReference(t, problemAlias, "refs/heads/master", ts),
		)
		if err != nil {
			t.Fatalf("Failed to lookup commit: %v", err)
		}
		defer masterCommit.Free()

		parentOid = masterCommit.Id()

		masterTree, err := masterCommit.Tree()
		if err != nil {
			t.Fatalf("Failed to lookup tree: %v", err)
		}
		defer masterTree.Free()

		problemDistribSettings, err := getProblemDistribSettings(
			repo,
			masterTree,
		)
		if err != nil {
			t.Fatalf("failed to get problem distributable settings: %v", err)
		}
		expectedExampleCases := map[string]*common.LiteralCaseSettings{
			"sample": {
				Input:          "1 2",
				ExpectedOutput: "3",
				Weight:         big.NewRat(1, 1),
			},
		}
		if !reflect.DeepEqual(expectedExampleCases, problemDistribSettings.Cases) {
			t.Errorf(
				"Mismatched example cases. expected %v, got %v",
				expectedExampleCases,
				problemDistribSettings.Cases,
			)
		}
	}
}

func TestExtractExampleCasesFromStatement(t *testing.T) {
	for _, testCase := range []struct {
		statement      string
		expectedOutput map[string]*common.LiteralCaseSettings
	}{
		{
			statement: `Sumas
||input
First input
||output
First output
||description
yeah...
||input
Second input
||output
Second output
||end`,
			expectedOutput: map[string]*common.LiteralCaseSettings{
				"statement_001": {
					Input:          "First input",
					ExpectedOutput: "First output",
					Weight:         big.NewRat(1, 1),
				},
				"statement_002": {
					Input:          "Second input",
					ExpectedOutput: "Second output",
					Weight:         big.NewRat(1, 1),
				},
			},
		},
		{
			statement: `Sumas
||input
Foo
||description
why is this missing an output?
||input
Foo
||input
Another missing output.
||end`,
			expectedOutput: map[string]*common.LiteralCaseSettings{},
		},
		{
			statement: `Sumas
||input
Foo
||output
missing the end thingy`,
			expectedOutput: map[string]*common.LiteralCaseSettings{},
		},
	} {
		actualOutput := extractExampleCasesFromStatement(testCase.statement)
		if !reflect.DeepEqual(testCase.expectedOutput, actualOutput) {
			t.Errorf(
				"Failed to extract examples from %v. expected %v, got %v",
				testCase.statement,
				testCase.expectedOutput,
				actualOutput,
			)
		}
	}
}

func TestStatements(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", t.Name())
	if err != nil {
		t.Fatalf("Failed to create directory: %v", err)
	}
	if os.Getenv("PRESERVE") == "" {
		defer os.RemoveAll(tmpDir)
	}
	ctx := context.Background()

	log, err := log15.New("info", false)
	if err != nil {
		t.Fatalf("Failed to create log: %v", err)
	}
	ts := httptest.NewServer(NewGitHandler(GitHandlerOpts{
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

	repo, err := InitRepository(ctx, path.Join(tmpDir, problemAlias))
	if err != nil {
		t.Fatalf("Failed to initialize git repository: %v", err)
	}
	defer repo.Free()

	for idx, testcase := range []struct {
		name          string
		extraContents map[string]io.Reader
		status        string
	}{
		{
			"statements is missing",
			map[string]io.Reader{},
			"ng refs/heads/master no-statements\n",
		},
		{
			"statements is not a directory",
			map[string]io.Reader{
				"statements": strings.NewReader(""),
			},
			"ng refs/heads/master no-statements: statements/ directory is not a tree\n",
		},
		{
			"statements/es.markdown is missing",
			map[string]io.Reader{
				"statements/en.markdown": strings.NewReader(""),
			},
			"ng refs/heads/master no-es-statement\n",
		},
		{
			"statements/es.markdown is a directory",
			map[string]io.Reader{
				"statements/es.markdown/surprise": strings.NewReader(""),
			},
			"ng refs/heads/master no-es-statement: statements/es.markdown is not a file\n",
		},
	} {
		t.Run(fmt.Sprintf("%d %s", idx, testcase.name), func(t *testing.T) {
			contents := map[string]io.Reader{
				"settings.json": strings.NewReader(gitservertest.DefaultSettingsJSON),
				"cases/0.in":    strings.NewReader("1 2"),
				"cases/0.out":   strings.NewReader("3"),
			}
			for name, r := range testcase.extraContents {
				contents[name] = r
			}
			newOid, packContents := createCommit(
				t,
				tmpDir,
				problemAlias,
				&git.Oid{},
				contents,
				"Initial commit",
				log,
			)
			push(
				t,
				tmpDir,
				adminAuthorization,
				problemAlias,
				"refs/heads/master",
				&git.Oid{}, newOid,
				packContents,
				[]githttp.PktLineResponse{
					{Line: "unpack ok\n", Err: nil},
					{Line: testcase.status, Err: nil},
				},
				ts,
			)
		})
	}
}

func TestTests(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", t.Name())
	if err != nil {
		t.Fatalf("Failed to create directory: %v", err)
	}
	if os.Getenv("PRESERVE") == "" {
		defer os.RemoveAll(tmpDir)
	}
	ctx := context.Background()

	log, err := log15.New("info", false)
	if err != nil {
		t.Fatalf("Failed to create log: %v", err)
	}
	ts := httptest.NewServer(NewGitHandler(GitHandlerOpts{
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

	repo, err := InitRepository(ctx, path.Join(tmpDir, problemAlias))
	if err != nil {
		t.Fatalf("Failed to initialize git repository: %v", err)
	}
	defer repo.Free()

	for idx, testcase := range []struct {
		name          string
		extraContents map[string]io.Reader
		status        string
	}{
		{
			"tests is not a directory",
			map[string]io.Reader{
				"tests": strings.NewReader(""),
			},
			"ng refs/heads/master tests-bad-layout: tests/ directory is not a tree\n",
		},
		{
			"Missing tests/tests.json",
			map[string]io.Reader{
				"tests/foo": strings.NewReader(""),
			},
			"ng refs/heads/master tests-bad-layout: tests/tests.json is missing\n",
		},
		{
			"Corrupt settings.json",
			map[string]io.Reader{
				"tests/tests.json": strings.NewReader(""),
			},
			"ng refs/heads/master json-parse-error: tests/tests.json: EOF\n",
		},
		{
			"Unknown fields",
			map[string]io.Reader{
				"tests/tests.json": strings.NewReader(`{
					"foo": "bar"
				}`),
			},
			"ng refs/heads/master json-parse-error: tests/tests.json: json: unknown field \"foo\"\n",
		},
		{
			"Missing validator",
			map[string]io.Reader{
				"tests/tests.json": strings.NewReader(`{
					"solutions": [
						{
							"filename": "foo.py"
						}
					]
				}`),
			},
			"ng refs/heads/master tests-bad-layout: tests/foo.py is missing: the path 'foo.py' does not exist in the given tree\n",
		},
		{
			"Relative paths",
			map[string]io.Reader{
				"tests/tests.json": strings.NewReader(`{
					"solutions": [
						{
							"filename": "../solutions/foo.py"
						}
					]
				}`),
			},
			"ng refs/heads/master tests-bad-layout: tests/../solutions/foo.py is missing: the path '..' does not exist in the given tree\n",
		},
		{
			"Missing score_range and verdict",
			map[string]io.Reader{
				"tests/tests.json": strings.NewReader(`{
					"solutions": [
						{
							"filename": "foo.py"
						}
					]
				}`),
				"tests/foo.py": strings.NewReader("print 1"),
			},
			"ng refs/heads/master tests-bad-layout: score_range or validator for foo.py in tests/tests.json should be set\n",
		},
		{
			"Missing score_range",
			map[string]io.Reader{
				"tests/tests.json": strings.NewReader(`{
					"solutions": [
						{
							"filename": "foo.py",
							"score_range": [1]
						}
					]
				}`),
				"tests/foo.py": strings.NewReader("print 1"),
			},
			"ng refs/heads/master json-parse-error: tests/tests.json: score_range should be an array with two numbers\n",
		},
		{
			"Bad score_range",
			map[string]io.Reader{
				"tests/tests.json": strings.NewReader(`{
					"solutions": [
						{
							"filename": "foo.py",
							"score_range": [-1, 10]
						}
					]
				}`),
				"tests/foo.py": strings.NewReader("print 1"),
			},
			"ng refs/heads/master json-parse-error: tests/tests.json: values for score_range should be in the interval [0, 1]\n",
		},
		{
			"Bad verdict",
			map[string]io.Reader{
				"tests/tests.json": strings.NewReader(`{
					"solutions": [
						{
							"filename": "foo.py",
							"score_range": [0, 1],
							"verdict": "COOL VERDICT, BRO."
						}
					]
				}`),
				"tests/foo.py": strings.NewReader("print 1"),
			},
			"ng refs/heads/master tests-bad-layout: verdict for foo.py in tests/tests.json is not valid\n",
		},
		{
			"Bad validator",
			map[string]io.Reader{
				"tests/tests.json": strings.NewReader(`{
					"solutions": [
						{
							"filename": "solutions/foo.py",
							"verdict": "AC"
						}
					],
					"inputs": {
						"filename": "test-validator.py"
					}
				}`),
				"tests/solutions/foo.py": strings.NewReader("print 1"),
			},
			"ng refs/heads/master tests-bad-layout: tests/test-validator.py is missing: the path 'test-validator.py' does not exist in the given tree\n",
		},
		{
			"Valid",
			map[string]io.Reader{
				"tests/tests.json": strings.NewReader(`{
					"solutions": [
						{
							"filename": "solutions/foo.py",
							"score_range": [1, 1],
							"verdict": "AC"
						}
					]
				}`),
				"tests/solutions/foo.py": strings.NewReader("print 1"),
			},
			"ok refs/heads/master\n",
		},
	} {
		t.Run(fmt.Sprintf("%d %s", idx, testcase.name), func(t *testing.T) {
			contents := map[string]io.Reader{
				"settings.json":          strings.NewReader(gitservertest.DefaultSettingsJSON),
				"cases/0.in":             strings.NewReader("1 2"),
				"cases/0.out":            strings.NewReader("3"),
				"statements/es.markdown": strings.NewReader("Sumas"),
			}
			for name, r := range testcase.extraContents {
				contents[name] = r
			}
			newOid, packContents := createCommit(
				t,
				tmpDir,
				problemAlias,
				&git.Oid{},
				contents,
				"Initial commit",
				log,
			)
			push(
				t,
				tmpDir,
				adminAuthorization,
				problemAlias,
				"refs/heads/master",
				&git.Oid{}, newOid,
				packContents,
				[]githttp.PktLineResponse{
					{Line: "unpack ok\n", Err: nil},
					{Line: testcase.status, Err: nil},
				},
				ts,
			)
		})
	}
}
