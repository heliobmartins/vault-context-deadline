package main

import (
	"context"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/pkg/errors"
	"os"
)

type VaultSysLink struct {
	token         string
	addr          string
	client        VaultClient
	logger        hclog.Logger
	runCtx        context.Context
	clientFactory VaultClientFactory
}

const (
	defaultVaultAddr      = "https://127.0.0.1:8200"
	ParamVaultToken       = "vault_token"
	StorageKeyClientToken = "client_token"       //#nosec
	ParamAppRoleSecretId  = "app_role_secret_id" //#nosec
	ParamAppRoleRoleId    = "app_role_role_id"
)

func NewVaultSysLink(ctx context.Context, conf *logical.BackendConfig, clientFactory VaultClientFactory) (*VaultSysLink, error) {
	vaultAddr := os.Getenv("VAULT_ADDR")
	vaultToken := os.Getenv("VAULT_TOKEN")

	if conf.Logger == nil {
		return nil, errors.Errorf("logger is nil")
	}
	logger := conf.Logger

	// if vault addr is set in config
	if vaultAddrCfgVal, ok := conf.Config["vault_addr"]; ok {
		logger.Debug("vault_addr is set in config", "vault_addr", vaultAddrCfgVal)
		vaultAddr = vaultAddrCfgVal
	}
	// set default if empty
	if vaultAddr == "" {
		logger.Debug("using default vault_addr", "vault_addr", defaultVaultAddr)
		vaultAddr = defaultVaultAddr
	}

	// if vault token is passed as param, trying to use it right away
	if vaultTokenCfgVal, ok := conf.Config[ParamVaultToken]; ok {
		logger.Debug("vault token is passed as parameter", "vault_token", vaultTokenCfgVal)
		vaultToken = vaultTokenCfgVal
	}

	vaultClient, err := clientFactory(vaultAddr, vaultToken)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to init vault client")
	}

	var storedRoleId string
	// trying to restore token value from internal storage
	if conf.StorageView != nil {
		logger.Info("trying to restore token from internal storage")
		entry, err := conf.StorageView.Get(ctx, StorageKeyClientToken)
		if err != nil {
			logger.Error("failed to read internal storage", "error", err.Error())
		} else if entry == nil {
			logger.Debug("read nil from internal storage")
		} else {
			vaultToken = string(entry.Value)
			logger.Debug("token value restored from internal storage", "token", vaultToken)
		}
		entry, err = conf.StorageView.Get(ctx, ParamAppRoleRoleId)
		if err == nil && entry != nil {
			storedRoleId = string(entry.Value)
		} else {
			logger.Debug("stored role id not found")
		}
		vaultClient, err = clientFactory(vaultAddr, vaultToken)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to init vault client")
		}
	} else {
		logger.Warn("configured storage is nil, skipping token restore")
	}

	// if approle is provided (and different from the last stored one), trying to log-in using
	// secret_id & role_id to update token value
	appRoleId, ok := conf.Config[ParamAppRoleRoleId]
	logger.Debug("check if we need to regenerate token from app role", "provided_role_id", appRoleId, "stored_role_id", storedRoleId)
	if ok && appRoleId != storedRoleId {
		logger.Debug("app role id is specified and differs from the stored one", "provided_role_id", appRoleId, "stored_role_id", storedRoleId)
		vaultToken, err = generateNewAppRoleToken(conf, appRoleId, vaultClient)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to generate new vault app role token")
		}
		// update current vault client
		vaultClient, err = clientFactory(vaultAddr, vaultToken)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to init vault client")
		}
	} else {
		appRoleId = storedRoleId
	}

	return nil, nil
}

func generateNewAppRoleToken(conf *logical.BackendConfig, appRoleId string, vaultClient VaultClient) (string, error) {
	appRoleSecretId := conf.Config[ParamAppRoleSecretId]
	conf.Logger.Debug("trying to auth with app role parameters", "app_role_id", appRoleId, "app_role_secret_id", appRoleSecretId)
	res, err := vaultClient.Write("auth/approle/login", Data{"role_id": appRoleId, "secret_id": appRoleSecretId})
	if err != nil {
		return "", errors.Wrapf(err, "invalid app role provided")
	}
	vaultToken := res.Auth.ClientToken
	conf.Logger.Debug("generated new token with app role", "app_role_id", appRoleId, "token", vaultToken)
	return vaultToken, nil
}
