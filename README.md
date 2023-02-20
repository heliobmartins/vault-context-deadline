## Requirements

Make sure you have `vault` cli installed running any version from `1.12.x`.

[Installing Vault CLI From Homebrew](https://formulae.brew.sh/formula/vault)


## Reproducing the issue:

1. Clone the Repository
2. Create folder on `/tmp/vault/plugins`. The folder will be used to add the binary of the plugin.
3. Create `vault.hcl` with the content `plugin_directory = "/private/tmp/vault/plugins"`. _Make sure to add `/private`, this seems to required if you're running MacOS_.
4. On the cloned repository folder, run `go build -o /tmp/vault/plugins/slauth`. This will generate and copy the binary to generated folder in step 1. 
5. Run Vault locally with `VAULT_LOG_LEVEL=trace vault server -dev -dev-root-token-id="root" -config=/tmp/vault.hcl`
6. Extract the binary SHASUM with `SHASUM=$(shasum -a 256 "/tmp/vault/plugins/slauth" | cut -d " " -f1)`
7. Register the plugin with: `vault plugin register -sha256="${SHASUM}" -command="slauth" auth slauth`
8. Enabled AppRole: `vault auth enable approle`
9. Create Slauth AppRole role: `vault write auth/approle/role/slauth token_ttl=24h`
10. Extract ROLE_ID with: `ROLE_ID=$(vault read auth/approle/role/slauth/role-id -format=json | jq -r .data.role_id)`
11. Extract SECRET_ID with: `SECRET_ID=$(vault write -f auth/approle/role/slauth/secret-id -format=json | jq -r .data.secret_id)`
12. Try enabling the plugin: `vault auth enable -options=app_role_role_id=${ROLE_ID} -options=app_role_secret_id=${SECRET_ID} -options='vault_addr=http://127.0.0.1:8200' slauth`


### Notes:
After registering the plugin (step 7), you are going to notice:
```aidl
[DEBUG] core: attempting to load backend plugin: name=slauth
[DEBUG] core: spawning a new plugin process: plugin_name=slauth id=T1mzUm2C5P
[DEBUG] core: successfully dispensed v5 backend plugin: name=slauth
[DEBUG] core: removed plugin client connection: id=T1mzUm2C5P
[DEBUG] core: killed external plugin process: path=/private/tmp/vault/plugins/vault-auth-example pid=38055
```

### Actual problem
After running the step 12, you will notice that the request is going to be terminated prior 1m. This is because of the default timeouts. Increasing the value, will not help to mitigate the issue.

The following errors will be thrown:
```aidl
[TRACE] auth.slauth.auth_slauth_ab98e3b9.slauth: setup: transport=gRPC status=finished err="rpc error: code = Canceled desc = context canceled" took=59.880442291s
[ERROR] secrets.system.system_196362d9: error occurred during enable credential: path=slauth/ error="rpc error: code = Canceled desc = context canceled"
```
