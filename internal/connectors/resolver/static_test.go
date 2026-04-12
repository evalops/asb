package resolver_test

import (
	"context"
	"testing"

	"github.com/evalops/asb/internal/connectors/github"
	"github.com/evalops/asb/internal/connectors/resolver"
)

func TestStaticResolver_ResolvesByResourceRef(t *testing.T) {
	t.Parallel()

	res := resolver.NewStaticResolver(
		resolver.WithGitHub(github.NewConnector(github.Config{})),
	)

	connector, err := res.Resolve(context.Background(), "repo.read", "github:repo:acme/widgets")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if connector.Kind() != "github" {
		t.Fatalf("connector kind = %q, want github", connector.Kind())
	}
}
