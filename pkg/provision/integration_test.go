//go:build integration

package provision

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	project "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/project/v2"
)

type recordingStore struct{ results []Result }

func (s *recordingStore) Put(_ context.Context, _ string, r Result) error {
	s.results = append(s.results, r)
	return nil
}
func TestEnsureLiveIdempotent(t *testing.T) {
	for _, name := range []string{"IDENTITY_DOMAIN", "IDENTITY_ADDRESS", "IDENTITY_ADMIN_PAT_FILE"} {
		if os.Getenv(name) == "" {
			t.Fatalf("%s is required for live integration tests", name)
		}
	}
	raw, err := os.ReadFile(os.Getenv("IDENTITY_ADMIN_PAT_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	store := &recordingStore{}
	c, err := ConnectToken(ctx, os.Getenv("IDENTITY_DOMAIN"), os.Getenv("IDENTITY_ADDRESS"), strings.TrimSpace(string(raw)), store)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	name := fmt.Sprintf("identity-integration-%d", time.Now().UnixNano())
	s := Spec{Org: "AlphaBravo", Project: name, App: name, Roles: []string{"viewer", "admin"}, RedirectURIs: []string{"https://wolf.example.com/callback"}, LoginBaseURI: "https://" + os.Getenv("IDENTITY_DOMAIN") + "/signin"}
	start := time.Now()
	first, err := c.Ensure(ctx, s)
	if err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	defer func() {
		_, err := c.engine.ProjectServiceV2().DeleteProject(context.Background(), &project.DeleteProjectRequest{ProjectId: first.ProjectID})
		if err != nil {
			t.Errorf("cleanup: %v", err)
		}
	}()
	second, err := c.Ensure(ctx, s)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Created || second.Created || first.ClientID != second.ClientID || len(store.results) != 1 || store.results[0].ClientSecret == "" {
		t.Fatal("Ensure did not persist create-only credentials exactly once or changed client ID")
	}
	t.Logf("created in %s; second Ensure retained client ID; durable store writes=%d", elapsed, len(store.results))
}
