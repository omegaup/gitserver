package main

import (
	base "github.com/omegaup/go-base"
	"io/ioutil"
	"os"
	"path"
	"reflect"
	"testing"
)

func TestRoundtrip(t *testing.T) {
	dirName, err := ioutil.TempDir("/tmp", t.Name())
	if err != nil {
		t.Fatalf("GraderContext creation failed with %q", err)
	}
	if os.Getenv("PRESERVE") == "" {
		defer os.RemoveAll(dirName)
	}

	log := base.StderrLog()

	mergedPath := path.Join(dirName, "merged")
	unmergedPath := path.Join(dirName, "unmerged")

	if err := mergeRepository("testdata/sumas.git", mergedPath, log); err != nil {
		t.Fatalf("failed to merge repository: %v", err)
	}
	got, err := unmergeRepository(mergedPath, unmergedPath, log)
	if err != nil {
		t.Fatalf("failed to unmerge repository: %v", err)
	}

	expected := []unmergeResult{
		{
			OriginalCommitID:      "c2be64797d18887307ffd39fe5334b434b3e5e3b",
			NewCommitID:           "c2be64797d18887307ffd39fe5334b434b3e5e3b",
			OriginalPrivateTreeID: "f681044ac3f5618ca2e5de47fd264dc31fcd651e",
			NewPrivateTreeID:      "f681044ac3f5618ca2e5de47fd264dc31fcd651e",
		},
		{
			OriginalCommitID:      "c677d4fc0d8f68a6fb719fc8552bcee230e2be45",
			NewCommitID:           "c677d4fc0d8f68a6fb719fc8552bcee230e2be45",
			OriginalPrivateTreeID: "f681044ac3f5618ca2e5de47fd264dc31fcd651e",
			// private tree not modified, so it's not reported.
		},
		{
			OriginalCommitID:      "10378fcb2306a5b7876afeb9efda074066887fb0",
			NewCommitID:           "10378fcb2306a5b7876afeb9efda074066887fb0",
			OriginalPrivateTreeID: "2eb4e541a48b5cb01cbe4e0151e3c318bb4ad0cf",
			NewPrivateTreeID:      "2eb4e541a48b5cb01cbe4e0151e3c318bb4ad0cf",
			Published:             true,
		},
	}

	if !reflect.DeepEqual(expected, got) {
		t.Errorf("expected %v, got %v", expected, got)
	}
}
