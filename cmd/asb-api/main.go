package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/haasonsaas/asb/internal/api/connectapi"
	"github.com/haasonsaas/asb/internal/api/httpapi"
	"github.com/haasonsaas/asb/internal/app"
	auditmemory "github.com/haasonsaas/asb/internal/audit/memory"
	"github.com/haasonsaas/asb/internal/authn/delegationjwt"
	"github.com/haasonsaas/asb/internal/authn/k8s"
	"github.com/haasonsaas/asb/internal/authz/policy"
	"github.com/haasonsaas/asb/internal/authz/toolregistry"
	browserconnector "github.com/haasonsaas/asb/internal/connectors/browser"
	githubconnector "github.com/haasonsaas/asb/internal/connectors/github"
	"github.com/haasonsaas/asb/internal/connectors/resolver"
	"github.com/haasonsaas/asb/internal/connectors/vaultdb"
	"github.com/haasonsaas/asb/internal/core"
	"github.com/haasonsaas/asb/internal/crypto/sessionjwt"
	proxydelivery "github.com/haasonsaas/asb/internal/delivery/proxy"
	wrappeddelivery "github.com/haasonsaas/asb/internal/delivery/wrapped"
	memstore "github.com/haasonsaas/asb/internal/store/memory"
	postgresstore "github.com/haasonsaas/asb/internal/store/postgres"
	redisstore "github.com/haasonsaas/asb/internal/store/redis"
	"github.com/jackc/pgx/v5/pgxpool"
	goredis "github.com/redis/go-redis/v9"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	ctx := context.Background()

	issuer := os.Getenv("ASB_K8S_ISSUER")
	publicKeyFile := os.Getenv("ASB_K8S_PUBLIC_KEY_FILE")
	if issuer == "" || publicKeyFile == "" {
		logger.Error("missing verifier configuration", "required_env", "ASB_K8S_ISSUER, ASB_K8S_PUBLIC_KEY_FILE")
		os.Exit(1)
	}

	publicKey, err := loadPublicKey(publicKeyFile)
	if err != nil {
		logger.Error("load verifier key", "error", err)
		os.Exit(1)
	}

	verifier, err := k8s.NewVerifier(k8s.Config{
		Issuer:   issuer,
		Audience: getenv("ASB_K8S_AUDIENCE", "asb-control-plane"),
		Keyfunc: func(context.Context, *jwt.Token) (any, error) {
			return publicKey, nil
		},
	})
	if err != nil {
		logger.Error("create verifier", "error", err)
		os.Exit(1)
	}

	_, sessionPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		logger.Error("generate session signing key", "error", err)
		os.Exit(1)
	}
	sessionTokens, err := sessionjwt.NewManager(sessionPrivateKey)
	if err != nil {
		logger.Error("create session token manager", "error", err)
		os.Exit(1)
	}

	repository, cleanupRepository, err := newRepository(ctx)
	if err != nil {
		logger.Error("create repository", "error", err)
		os.Exit(1)
	}
	defer cleanupRepository()

	runtimeStore, cleanupRuntime, err := newRuntimeStore(ctx)
	if err != nil {
		logger.Error("create runtime store", "error", err)
		os.Exit(1)
	}
	defer cleanupRuntime()

	auditSink := auditmemory.NewSink()
	tools := toolregistry.New()
	engine := policy.NewEngine()
	connectorOptions := []resolver.Option{
		resolver.WithGitHub(githubconnector.NewConnector(githubconnector.Config{})),
	}
	var githubProxy core.GitHubProxyExecutor

	if token := os.Getenv("ASB_GITHUB_TOKEN"); token != "" {
		githubProxy = githubconnector.NewHTTPExecutor(githubconnector.ExecutorConfig{
			TokenSource: githubconnector.StaticTokenSource(token),
		})
	}

	tenantID := getenv("ASB_DEV_TENANT_ID", "t_dev")
	mustRegisterToolAndPolicy(ctx, logger, tools, engine, tenantID, core.Tool{
		TenantID:             tenantID,
		Tool:                 "github",
		ManifestHash:         "sha256:dev",
		RuntimeClass:         core.RuntimeClassHosted,
		AllowedDeliveryModes: []core.DeliveryMode{core.DeliveryModeProxy},
		AllowedCapabilities:  []string{"repo.read"},
		TrustTags:            []string{"trusted", "github"},
	}, core.Policy{
		TenantID:             tenantID,
		Capability:           "repo.read",
		ResourceKind:         core.ResourceKindGitHubRepo,
		AllowedDeliveryModes: []core.DeliveryMode{core.DeliveryModeProxy},
		DefaultTTL:           10 * time.Minute,
		MaxTTL:               10 * time.Minute,
		ApprovalMode:         core.ApprovalModeNone,
		RequiredToolTags:     []string{"trusted", "github"},
		Condition:            `request.tool == "github"`,
	})

	if origin := os.Getenv("ASB_BROWSER_ORIGIN"); origin != "" {
		username := os.Getenv("ASB_BROWSER_USERNAME")
		password := os.Getenv("ASB_BROWSER_PASSWORD")
		userSelector := getenv("ASB_BROWSER_SELECTOR_USERNAME", "#username")
		passSelector := getenv("ASB_BROWSER_SELECTOR_PASSWORD", "#password")
		connectorOptions = append(connectorOptions, resolver.WithBrowser(browserconnector.NewConnector(browserconnector.Config{
			Credentials: browserconnector.StaticCredentialStore(map[string]browserconnector.Credential{
				origin: {
					Username: username,
					Password: password,
				},
			}),
			SelectorMaps: map[string]browserconnector.SelectorMap{
				origin: {
					Username: userSelector,
					Password: passSelector,
				},
			},
		})))
		mustRegisterToolAndPolicy(ctx, logger, tools, engine, tenantID, core.Tool{
			TenantID:             tenantID,
			Tool:                 "browser",
			ManifestHash:         "sha256:dev-browser",
			RuntimeClass:         core.RuntimeClassBrowser,
			AllowedDeliveryModes: []core.DeliveryMode{core.DeliveryModeWrappedSecret},
			AllowedCapabilities:  []string{"browser.login"},
			TrustTags:            []string{"trusted", "browser"},
		}, core.Policy{
			TenantID:             tenantID,
			Capability:           "browser.login",
			ResourceKind:         core.ResourceKindBrowserOrigin,
			AllowedDeliveryModes: []core.DeliveryMode{core.DeliveryModeWrappedSecret},
			DefaultTTL:           2 * time.Minute,
			MaxTTL:               5 * time.Minute,
			ApprovalMode:         core.ApprovalModeLiveHuman,
			RequiredToolTags:     []string{"trusted", "browser"},
			Condition:            `request.origin == "` + origin + `" && session.tool_context.exists(t, t == "browser")`,
		})
	}

	if vaultAddr := os.Getenv("ASB_VAULT_ADDR"); vaultAddr != "" {
		role := getenv("ASB_VAULT_ROLE", "analytics_ro")
		dsnTemplate := os.Getenv("ASB_VAULT_DSN_TEMPLATE")
		if dsnTemplate != "" {
			vaultClient := vaultdb.NewHTTPClient(vaultdb.HTTPClientConfig{
				BaseURL:   vaultAddr,
				Token:     os.Getenv("ASB_VAULT_TOKEN"),
				Namespace: os.Getenv("ASB_VAULT_NAMESPACE"),
			})
			connectorOptions = append(connectorOptions, resolver.WithVaultDB(vaultdb.NewConnector(vaultdb.Config{
				Client: vaultClient,
				RoleDSNs: map[string]string{
					role: dsnTemplate,
				},
			})))
			mustRegisterToolAndPolicy(ctx, logger, tools, engine, tenantID, core.Tool{
				TenantID:             tenantID,
				Tool:                 "db",
				ManifestHash:         "sha256:dev-db",
				RuntimeClass:         core.RuntimeClassSidecar,
				AllowedDeliveryModes: []core.DeliveryMode{core.DeliveryModeWrappedSecret},
				AllowedCapabilities:  []string{"db.read"},
				TrustTags:            []string{"trusted", "db"},
			}, core.Policy{
				TenantID:             tenantID,
				Capability:           "db.read",
				ResourceKind:         core.ResourceKindDBRole,
				AllowedDeliveryModes: []core.DeliveryMode{core.DeliveryModeWrappedSecret},
				DefaultTTL:           10 * time.Minute,
				MaxTTL:               30 * time.Minute,
				ApprovalMode:         core.ApprovalModeNone,
				RequiredToolTags:     []string{"trusted", "db"},
				Condition:            `true`,
			})
		}
	}

	var delegationValidator core.DelegationValidator
	if issuer := os.Getenv("ASB_DELEGATION_ISSUER"); issuer != "" && os.Getenv("ASB_DELEGATION_PUBLIC_KEY_FILE") != "" {
		publicKey, err := loadEd25519PublicKey(os.Getenv("ASB_DELEGATION_PUBLIC_KEY_FILE"))
		if err != nil {
			logger.Error("load delegation verifier key", "error", err)
			os.Exit(1)
		}
		delegationValidator, err = delegationjwt.NewValidator(delegationjwt.Config{
			Issuers: map[string]ed25519.PublicKey{
				issuer: publicKey,
			},
		})
		if err != nil {
			logger.Error("create delegation validator", "error", err)
			os.Exit(1)
		}
	}

	svc, err := app.NewService(app.Config{
		Repository:          repository,
		Verifier:            verifier,
		DelegationValidator: delegationValidator,
		SessionTokens:       sessionTokens,
		Policy:              engine,
		Tools:               tools,
		Connectors:          resolver.NewStaticResolver(connectorOptions...),
		Deliveries: map[core.DeliveryMode]core.DeliveryAdapter{
			core.DeliveryModeProxy:         proxydelivery.NewAdapter(),
			core.DeliveryModeWrappedSecret: wrappeddelivery.NewAdapter(),
		},
		Audit:       auditSink,
		Runtime:     runtimeStore,
		GitHubProxy: githubProxy,
	})
	if err != nil {
		logger.Error("create service", "error", err)
		os.Exit(1)
	}

	addr := getenv("ASB_ADDR", ":8080")
	mux := http.NewServeMux()
	mux.Handle("/v1/", httpapi.NewServer(svc))
	connectPath, connectHandler := connectapi.NewHandler(svc)
	mux.Handle(connectPath, connectHandler)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	logger.Info("starting asb api", "addr", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		logger.Error("server exited", "error", err)
		os.Exit(1)
	}
}

func getenv(key string, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func loadPublicKey(path string) (any, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(contents)
	if block == nil {
		return nil, fmt.Errorf("decode pem: no PEM block found")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err == nil {
		return key, nil
	}
	cert, certErr := x509.ParseCertificate(block.Bytes)
	if certErr == nil {
		return cert.PublicKey, nil
	}
	return nil, fmt.Errorf("parse public key: %w", err)
}

func loadEd25519PublicKey(path string) (ed25519.PublicKey, error) {
	key, err := loadPublicKey(path)
	if err != nil {
		return nil, err
	}
	publicKey, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is %T, want ed25519.PublicKey", key)
	}
	return publicKey, nil
}

func newRepository(ctx context.Context) (core.Repository, func(), error) {
	if dsn := os.Getenv("ASB_POSTGRES_DSN"); dsn != "" {
		pool, err := pgxpool.New(ctx, dsn)
		if err != nil {
			return nil, nil, err
		}
		return postgresstore.NewRepository(pool), pool.Close, nil
	}
	return memstore.NewRepository(), func() {}, nil
}

func newRuntimeStore(ctx context.Context) (core.RuntimeStore, func(), error) {
	if addr := os.Getenv("ASB_REDIS_ADDR"); addr != "" {
		client := goredis.NewClient(&goredis.Options{
			Addr:     addr,
			Password: os.Getenv("ASB_REDIS_PASSWORD"),
			DB:       0,
		})
		if err := client.Ping(ctx).Err(); err != nil {
			return nil, nil, err
		}
		return redisstore.NewRuntimeStore(client), func() { _ = client.Close() }, nil
	}
	return memstore.NewRuntimeStore(), func() {}, nil
}

func mustRegisterToolAndPolicy(ctx context.Context, logger *slog.Logger, tools *toolregistry.Registry, engine *policy.Engine, tenantID string, tool core.Tool, pol core.Policy) {
	if err := tools.Put(ctx, tool); err != nil {
		logger.Error("register tool", "tenant_id", tenantID, "tool", tool.Tool, "error", err)
		os.Exit(1)
	}
	if err := engine.Put(pol); err != nil {
		logger.Error("register policy", "tenant_id", tenantID, "capability", pol.Capability, "error", err)
		os.Exit(1)
	}
}
