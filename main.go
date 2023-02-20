package main

import (
	"context"
	"crypto/subtle"
	"github.com/hashicorp/go-hclog"
	"github.com/pkg/errors"
	"log"
	"os"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/plugin"
)

func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	flags.Parse(os.Args[1:])

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

	factory := Factory{Version: "1.0.0"}
	if err := plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: factory.Factory,
		TLSProviderFunc:    tlsProviderFunc,
	}); err != nil {
		log.Fatal(err)
	}
}

type Factory struct {
	Version            string
	VaultClientFactory VaultClientFactory
	VaultSysLink       *VaultSysLink
}

type AuthBackend struct {
	*framework.Backend
	version string
}

const PathLoginSlauthToken = "login/slauthtoken" //#nosec

func (b *AuthBackend) pathsSpecial() *logical.Paths {
	return &logical.Paths{
		Unauthenticated: []string{PathLoginSlauthToken},
	}
}

func (b *AuthBackend) backendPaths() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "login",
			Fields: map[string]*framework.FieldSchema{
				"password": {
					Type: framework.TypeString,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathAuthLogin,
				},
			},
		},
	}
}

func (b *AuthBackend) pathAuthLogin(_ context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	password := d.Get("password").(string)

	if subtle.ConstantTimeCompare([]byte(password), []byte("super-secret-password")) != 1 {
		return nil, logical.ErrPermissionDenied
	}

	// Compose the response
	return &logical.Response{
		Auth: &logical.Auth{
			InternalData: map[string]interface{}{
				"secret_value": "abcd1234",
			},
			Policies: []string{"my-policy", "other-policy"},
			Metadata: map[string]string{
				"fruit": "banana",
			},
			LeaseOptions: logical.LeaseOptions{
				TTL:       30 * time.Second,
				MaxTTL:    60 * time.Minute,
				Renewable: true,
			},
		},
	}, nil
}

func (b *AuthBackend) pathAuthRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if req.Auth == nil {
		return nil, errors.New("request auth was nil")
	}

	secretValue := req.Auth.InternalData["secret_value"].(string)
	if secretValue != "abcd1234" {
		return nil, errors.New("internal data does not match")
	}

	return framework.LeaseExtend(30*time.Second, 60*time.Minute, b.System())(ctx, req, d)
}

func (h *Factory) Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := &AuthBackend{
		version: h.Version,
	}

	b.Backend = &framework.Backend{
		BackendType:  logical.TypeCredential,
		PathsSpecial: b.pathsSpecial(),
		Paths:        b.backendPaths(),
	}

	if conf.Logger == nil {
		conf.Logger = hclog.New(&hclog.LoggerOptions{Level: hclog.LevelFromString(conf.Config["log_level"])})
	}

	clientFactory := h.VaultClientFactory
	if clientFactory == nil {
		clientFactory = DefaultClientFactory
	}

	if h.VaultSysLink == nil {
		sysLink, err := NewVaultSysLink(ctx, conf, clientFactory)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to obtain sys link to vault backend")
		}
		h.VaultSysLink = sysLink
	}

	return b, nil
}
