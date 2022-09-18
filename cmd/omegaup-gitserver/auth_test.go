package main

import (
	"encoding/base64"
	"testing"

	"github.com/omegaup/go-base/logging/log15/v3"

	"golang.org/x/crypto/ed25519"
)

const (
	expiredToken = "v2.public.eyJwcm9ibGVtIjoiYTA5NGY3MWI0ZmEzZmY4YmVhZmY0MDZiNTQ1YTU1NzgiLCJleHAiOiIyMDE5LTAxLTA0VDA1OjAzOjA0KzAwOjAwIiwiaXNzIjoib21lZ2FVcCBmcm9udGVuZCIsInN1YiI6IjBiOGJhM2FjN2M2MzVkM2U2OTg5MWU4ODAzYzc4YTJmIn0VXEbZ414QQ7qEY9MFa2gGgeJqc-T1Ff7fPM3ZQ_YQudq5I05offZxG819gmdmq3Z1_HeV7bjMRWL5JIkfkHIK"
)

func TestVerifyArgon2idHash(t *testing.T) {
	ok, err := verifyArgon2idHash(
		"omegaup",
		"$argon2id$v=19$m=1024,t=2,p=1$7IYovf67Xtv0EAvZnKTIsQ$VgdbmwOXz9QtoM/tbx6pKyjbdrMEmotTDJE+NzRNyK0",
	)
	if err != nil {
		t.Fatalf("failed to verify hash: %v", err)
	}
	if !ok {
		t.Errorf("expected the hash to match, didn't")
	}
}

func TestParseBearerAuth(t *testing.T) {
	log, err := log15.New("info", true)
	if err != nil {
		t.Fatalf("Failed to create log: %v", err)
	}
	keyBytes, err := base64.StdEncoding.DecodeString(DefaultConfig().Gitserver.PublicKey)
	if err != nil {
		t.Fatalf("failed to parse shared key: %v", err)
	}
	auth := omegaupAuthorization{
		log:       log,
		publicKey: ed25519.PublicKey(keyBytes),
	}

	_, _, ok := auth.parseBearerToken(expiredToken)
	if ok {
		t.Errorf("expired token was passed as valid")
	}
}
