package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/omegaup/go-base/logging/log15/v3"
	"github.com/omegaup/go-base/v3/logging"

	git "github.com/libgit2/git2go/v33"
)

var (
	repositoryPath = flag.String("repository", "", "Repository path")
	commit         = flag.Bool("commit", false, "Add packfiles to the repository")

	log logging.Logger
)

func processOnePackfile(
	odb *git.Odb,
	idx int,
	packfile string,
) {
	f, err := os.Open(packfile)
	if err != nil {
		panic(err)
	}

	indexer, err := git.NewIndexer(".", odb, func(stats git.TransferProgress) error {
		log.Debug(
			"Progress",
			map[string]any{
				"stats": stats,
			},
		)
		return nil
	})
	if err != nil {
		panic(err)
	}
	defer indexer.Free()

	if _, err := io.Copy(indexer, f); err != nil {
		panic(err)
	}

	hash, err := indexer.Commit()
	if err != nil {
		panic(err)
	}
	log.Info(
		"Done!",
		map[string]any{
			"hash": hash,
		},
	)

	if *commit {
		f, err := os.Open(fmt.Sprintf("pack-%s.pack", hash))
		if err != nil {
			panic(err)
		}
		defer f.Close()

		writepack, err := odb.NewWritePack(nil)
		if err != nil {
			panic(err)
		}
		defer writepack.Free()

		if _, err := io.Copy(writepack, f); err != nil {
			panic(err)
		}

		if err = writepack.Commit(); err != nil {
			panic(err)
		}
	} else {
		backend, err := git.NewOdbBackendOnePack(fmt.Sprintf("pack-%s.idx", hash))
		if err != nil {
			backend.Free()
			panic(err)
		}

		if err := odb.AddAlternate(backend, idx+1); err != nil {
			backend.Free()
			panic(err)
		}
	}
}

func processObject(repository *git.Repository, oid *git.Oid, message string) error {
	obj, err := repository.Lookup(oid)
	if err != nil {
		return err
	}
	defer obj.Free()

	var contents string
	switch obj.Type() {
	case git.ObjectBlob:
		blob, err := obj.AsBlob()
		if err != nil {
			return err
		}
		defer blob.Free()
		contents = string(blob.Contents())

	case git.ObjectTree:
		tree, err := obj.AsTree()
		if err != nil {
			return err
		}
		defer tree.Free()
		var fileList []string
		for i := uint64(0); i < tree.EntryCount(); i++ {
			fileList = append(fileList, fmt.Sprintf("%v", *tree.EntryByIndex(i)))
		}
		contents = fmt.Sprintf("[%s]", strings.Join(fileList, ","))

	case git.ObjectCommit:
		commit, err := obj.AsCommit()
		if err != nil {
			return err
		}
		defer commit.Free()
		contents = commit.RawMessage()
	}
	log.Debug(
		"Exists now",
		map[string]any{
			"oid":      oid,
			"type":     obj.Type(),
			"contents": contents,
		},
	)
	return nil
}

func main() {
	flag.Parse()
	var err error
	log, err = log15.New("info", false)
	if err != nil {
		panic(err)
	}

	var repository *git.Repository
	var odb *git.Odb
	if *repositoryPath == "" {
		var err error
		odb, err = git.NewOdb()
		if err != nil {
			panic(err)
		}
		defer odb.Free()

		repository, err = git.NewRepositoryWrapOdb(odb)
		if err != nil {
			panic(err)
		}
		defer repository.Free()
	} else {
		var err error
		repository, err = git.OpenRepository(*repositoryPath)
		if err != nil {
			panic(err)
		}
		defer repository.Free()

		odb, err = repository.Odb()
		if err != nil {
			panic(err)
		}
		defer odb.Free()
	}

	beforeObjectsCount := 0
	beforeObjects := make(map[git.Oid]struct{})
	odb.ForEach(func(oid *git.Oid) error {
		processObject(repository, oid, "Exists previously")
		beforeObjects[*oid] = struct{}{}
		beforeObjectsCount++
		return nil
	})

	for idx, packfile := range flag.Args() {
		processOnePackfile(odb, idx, packfile)
	}

	afterObjects := 0
	odb.ForEach(func(oid *git.Oid) error {
		afterObjects++
		if _, ok := beforeObjects[*oid]; ok {
			return nil
		}
		return processObject(repository, oid, "Exists now")
	})
	log.Info(
		"Done",
		map[string]any{
			"before": beforeObjectsCount,
			"after":  afterObjects,
		},
	)
}
