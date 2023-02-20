package main

import (
	"github.com/hashicorp/vault/api"
	"github.com/pkg/errors"
	"net/url"
)

type VaultClientFactory func(vaultAddr string, token string) (VaultClient, error)

type Data map[string]interface{}

type VaultClient interface {
	PutPolicy(name, rules string) error
	DeletePolicy(name string) error
	GetPolicy(name string) (string, error)
	Read(path string) (*api.Secret, error)
	List(path string) (*api.Secret, error)
	Write(path string, data Data) (*api.Secret, error)
	Delete(path string) (*api.Secret, error)
}

var DefaultClientFactory = NewClient

type defaultVaultClient struct {
	addrUrl *url.URL
	client  *api.Client
}

// NewClient initializes new Vault client
func NewClient(vaultAddr string, token string) (VaultClient, error) {
	vaultUrl, err := url.Parse(vaultAddr)
	if err != nil {
		return nil, errors.Wrapf(err, "incorrect vault address provided")
	}

	clientCfg := api.DefaultConfig()
	clientCfg.Address = vaultAddr
	client, err := api.NewClient(clientCfg)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to init vault client")
	}
	client.SetToken(token)

	return &defaultVaultClient{
		addrUrl: vaultUrl,
		client:  client,
	}, nil
}

func (c *defaultVaultClient) PutPolicy(name, rules string) error {
	return c.client.Sys().PutPolicy(name, rules)
}

func (c *defaultVaultClient) DeletePolicy(name string) error {
	return c.client.Sys().DeletePolicy(name)
}

func (c *defaultVaultClient) GetPolicy(name string) (string, error) {
	return c.client.Sys().GetPolicy(name)
}

func (c *defaultVaultClient) Read(path string) (*api.Secret, error) {
	return c.client.Logical().Read(path)
}

func (c *defaultVaultClient) List(path string) (*api.Secret, error) {
	return c.client.Logical().List(path)
}

func (c *defaultVaultClient) Delete(path string) (*api.Secret, error) {
	return c.client.Logical().Delete(path)
}

func (c *defaultVaultClient) Write(path string, data Data) (*api.Secret, error) {
	return c.client.Logical().Write(path, data)
}
