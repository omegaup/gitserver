package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/url"
	"os"
	"time"

	"github.com/inconshreveable/log15"
	git "github.com/lhchavez/git2go/v32"
	"github.com/omegaup/githttp"
	base "github.com/omegaup/go-base"
	"golang.org/x/crypto/ssh"
)

var (
	repositoryPath    = flag.String("root", "", "Path of the repository")
	repositoryURL     = flag.String("url", "", "URL of remote")
	remoteTarget      = flag.String("target", "", "Subdirectory target")
	remoteBranch      = flag.String("branch", "master", "Target branch")
	commitHash        = flag.String("commit", "", "Commit to push")
	sshPrivateKeyPath = flag.String("ssh-key", "omegaup-bot.key", "Private SSH key")
	log               log15.Logger
)

func readPrivateKey(path string) (ssh.Signer, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, f); err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(buf.Bytes())
}

func forcePushToBranch(remote *url.URL) error {
	signer, err := readPrivateKey(*sshPrivateKeyPath)
	if err != nil {
		return err
	}
	repository, err := git.OpenRepository(*repositoryPath)
	if err != nil {
		return err
	}
	defer repository.Free()

	newOid, err := git.NewOid(*commitHash)
	if err != nil {
		return err
	}
	commit, err := repository.LookupCommit(newOid)
	if err != nil {
		return err
	}
	defer commit.Free()

	pb, err := repository.NewPackbuilder()
	if err != nil {
		return err
	}
	defer pb.Free()

	config := &ssh.ClientConfig{
		User:            remote.User.Username(),
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}
	conn, err := ssh.Dial("tcp", remote.Host, config)
	if err != nil {
		return err
	}
	defer conn.Close()

	session, err := conn.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	stdin, err := session.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		return err
	}

	go func() {
		io.Copy(os.Stderr, stderr)
	}()
	go func() {
		defer stdin.Close()
		pw := githttp.NewPktLineWriter(stdin)
		discovery, err := githttp.DiscoverReferences(stdout)
		if err != nil {
			log.Error("Error discovering references", "err", err)
			return
		}
		log.Debug("Remote", "discovery", discovery)
		refName := fmt.Sprintf("refs/heads/%s", *remoteBranch)
		var oldOid git.Oid
		if oid, ok := discovery.References[refName]; ok {
			oldOid = oid
		}

		descendant, err := repository.DescendantOf(&oldOid, newOid)
		if err != nil {
			if !git.IsErrorCode(err, git.ErrorCodeNotFound) {
				// Not found is normal. We're doing a force-push anyways.
				descendant = false
			} else {
				log.Error("Error getting descendantness", "err", err)
				pw.Flush()
				return
			}
		}

		line := fmt.Sprintf(
			"%s %s %s\x00agent=gohttp atomic ofs-delta report-status\n",
			oldOid.String(),
			newOid.String(),
			refName,
		)
		log.Debug("Pushing", "oldOid", oldOid.String(), "newOid", newOid.String(), "line", line)
		if err := pw.WritePktLine([]byte(line)); err != nil {
			log.Error("Error sending pktline", "err", err)
			return
		}
		if err := pw.Flush(); err != nil {
			log.Error("Error flushing", "err", err)
			return
		}

		// If oldOid is descendant of newOid, there is nothing to pack.
		if !descendant {
			for current := commit; current != nil; current = current.Parent(0) {
				if current != commit {
					defer current.Free()
				}
				if *current.Id() == oldOid {
					break
				}
				log.Debug("Inserting commit", "commit", current.Id())
				if err := pb.InsertCommit(current.Id()); err != nil {
					log.Error("Error building pack", "err", err)
					break
				}
			}
		}

		if err := pb.Write(stdin); err != nil {
			log.Error("Error writing pack", "err", err)
		}

		pr := githttp.NewPktLineReader(stdout)
		for {
			line, err := pr.ReadPktLine()
			if err == githttp.ErrFlush {
				break
			} else if err != nil {
				log.Error("Error reading remote response", "err", err)
				break
			}
			log.Debug("Line", "line", string(line))
		}
	}()

	cmd := fmt.Sprintf("git-receive-pack '%s'", remote.Path)
	log.Info("Sending command", "command", cmd)
	return session.Run(cmd)
}

func pushToSubdirectory(remote *url.URL) error {
	signer, err := readPrivateKey(*sshPrivateKeyPath)
	if err != nil {
		return err
	}
	repository, err := git.OpenRepository(*repositoryPath)
	if err != nil {
		return err
	}
	defer repository.Free()
	odb, err := repository.Odb()
	if err != nil {
		return err
	}
	defer odb.Free()
	tmpDir, err := ioutil.TempDir("", "packfile")
	if err != nil {
		log.Error("Could not create temporary directory for packfile", "err", err)
		return err
	}
	defer os.RemoveAll(tmpDir)

	newOid, err := git.NewOid(*commitHash)
	if err != nil {
		return err
	}
	commit, err := repository.LookupCommit(newOid)
	if err != nil {
		return err
	}
	defer commit.Free()

	pb, err := repository.NewPackbuilder()
	if err != nil {
		return err
	}
	defer pb.Free()

	config := &ssh.ClientConfig{
		User:            remote.User.Username(),
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}
	conn, err := ssh.Dial("tcp", remote.Host, config)
	if err != nil {
		return err
	}
	defer conn.Close()

	session, err := conn.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	stdin, err := session.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		return err
	}

	var done chan struct{}

	go func() {
		io.Copy(os.Stderr, stderr)
		done <- struct{}{}
	}()
	go func() {
		defer stdin.Close()
		defer func() { done <- struct{}{} }()

		pw := githttp.NewPktLineWriter(stdin)
		discovery, err := githttp.DiscoverReferences(stdout)
		if err != nil {
			log.Error("Error discovering references", "err", err)
			return
		}
		log.Debug("Remote", "discovery", discovery)
		refName := fmt.Sprintf("refs/heads/%s", *remoteBranch)
		if oid, ok := discovery.References[refName]; ok {
			line := fmt.Sprintf("want %s\x00agent=gohttp ofs-delta shallow\n", oid.String())
			log.Debug("Pulling", "line", line)
			if err := pw.WritePktLine([]byte(line)); err != nil {
				log.Error("Error sending pktline", "err", err)
				return
			}
			if err := pw.WritePktLine([]byte("deepen 1")); err != nil {
				log.Error("Error sending pktline", "err", err)
				return
			}
			if err := pw.Flush(); err != nil {
				log.Error("Error flushing", "err", err)
				return
			}
		}

		pr := githttp.NewPktLineReader(stdout)
		for {
			line, err := pr.ReadPktLine()
			if err == githttp.ErrFlush {
				break
			} else if err != nil {
				log.Error("Error reading shallow negotiation", "err", err)
				break
			}
			log.Debug("Line", "line", string(line))
		}

		if err := pw.WritePktLine([]byte("done\n")); err != nil {
			log.Error("Error sending pktline", "err", err)
			return
		}
		stdin.Close()

		line, err := pr.ReadPktLine()
		if err != nil {
			log.Error("Error reading ACK/NAK response", "err", err)
			return
		}
		if string(line) != "NAK\n" {
			log.Error("Server did not reply with NAK")
			return
		}

		log.Debug("Reading packfile")

		_, packPath, err := githttp.UnpackPackfile(odb, stdout, tmpDir, nil)
		if err != nil {
			log.Error("Error reading packfile", "err", err)
			return
		}

		log.Info("Wrote packfile", "packPath", packPath)
	}()

	cmd := fmt.Sprintf("git-upload-pack '%s'", remote.Path)
	log.Info("Sending command", "command", cmd)
	if err := session.Run(cmd); err != nil {
		<-done
		<-done
		return err
	}

	log.Info("Command finished running, waiting for packfile processing")
	<-done
	<-done
	log.Info("All done!")

	return nil
}

func main() {
	flag.Parse()
	log = base.StderrLog()

	if *commitHash == "" {
		panic(errors.New("Must provide a -commit flag"))
	}

	if *repositoryURL == "" {
		panic(errors.New("Must provide a -url flag"))
	}
	url, err := url.Parse(*repositoryURL)
	if err != nil {
		panic(err)
	}

	if *repositoryPath == "" {
		panic(errors.New("Must provide a -root flag"))
	}

	if *remoteTarget == "" {
		if err := forcePushToBranch(url); err != nil {
			panic(err)
		}
	} else {
		if err := pushToSubdirectory(url); err != nil {
			panic(err)
		}
	}
}
