# Variables

Every variable can be set as an environment variable. Variables that have an nginx name can also be set with `set $<nginx variable> '<value>';` in a `server` or `location` block (in `demoapps` mode, in the app's `.conf` file). When both are set, a non-empty nginx variable wins over the environment variable.

Defaults come from the [Dockerfile](Dockerfile).

## NGINX

| Environment     | nginx variable | Default   | Example              | Description                                                                                       |
|-----------------|----------------|-----------|----------------------|---------------------------------------------------------------------------------------------------|
| NGINX_RESOLVER  |                | `8.8.8.8` | `127.0.0.11 valid=5s`| DNS server used by nginx to resolve the IdP and upstream hostnames. Use `127.0.0.11` inside Docker |
| NGINX_LOG_LEVEL |                | `warn`    | `debug`              | nginx `error_log` level: `debug`, `info`, `notice`, `warn`, `error`, `crit`, `alert`, `emerg`      |

## IPAx

| Environment       | nginx variable    | Default            | Example                      | Description                                                                                                                                                      |
|-------------------|-------------------|--------------------|------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| IPAX_MODE         |                   | `proxy`            | `single`                     | Execution mode: `proxy`, `single`, `spa` or `demoapps`. See [README.md](README.md#execution-modes)                                                                       |
| IPAX_APP_NAME     | ipax_app_name     | `ipax`             | `demoapp1`                   | Internal app name. It prefixes the session cookies (`<name>_session`, `<name>_remember`) and the Lua shared dictionaries. In `demoapps` mode it must match the `.conf` file name |
| IPAX_DISPLAY_NAME | ipax_display_name | `IPAx`             | `DemoApp1`                   | App name shown on the landing and info pages                                                                                                                     |
| IPAX_BASE_URL     | ipax_base_url     | `http://localhost` | `https://demoapp1.example.com` | External URL of the app, without a trailing slash. Prefix for `OIDC_REDIRECT_URI` and `OIDC_POST_LOGOUT_REDIRECT_URI`. In `demoapps` mode, include the app path (`http://demoapps/demoapp1`) |
| API_BASE_URL      | api_base_url      |                    | `http://api.internal:8080`   | Upstream API (scheme, host and port, no path) that receives `/api/` requests with the user's access token as a `Bearer` token. Used in `spa` mode   |

## OIDC (lua-resty-openidc)

| Environment                   | nginx variable                | lua-resty-openidc option           | Default                 | Example                                                             | Description                                                                                                                                  |
|-------------------------------|-------------------------------|------------------------------------|-------------------------|---------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------|
| OIDC_DISCOVERY                | oidc_discovery                | oidc_opts.discovery                |                         | `http://idp:8080/realms/demorealm/.well-known/openid-configuration` | OIDC discovery URL of the IdP                                                                                                                |
| OIDC_SSL_VERIFY               | oidc_ssl_verify               | oidc_opts.ssl_verify               | `yes`                   | `no`                                                                | Verify the IdP's TLS certificate (`yes` / `no`). Use `no` only for testing                                                                   |
| OIDC_CLIENT_ID                | oidc_client_id                | oidc_opts.client_id                |                         | `demoapp1_client_id`                                                | Client ID registered in the IdP                                                                                                              |
| OIDC_CLIENT_SECRET            | oidc_client_secret            | oidc_opts.client_secret            |                         | `demoapp1_client_secret`                                            | Client secret, for a confidential client. Leave empty for a public client (with PKCE)                                                       |
| OIDC_USE_PKCE                 | oidc_use_pkce                 | oidc_opts.use_pkce                 | `false`                 | `true`                                                              | Use PKCE in the Authorization Code flow (`true` / `false`)                                                                                   |
| OIDC_SCOPE                    | oidc_scope                    | oidc_opts.scope                    | `openid profile`        | `openid profile email`                                              | Scopes requested, separated by spaces                                                                                                        |
| OIDC_REDIRECT_URI             | oidc_redirect_uri             | oidc_opts.redirect_uri             | `/private/redirect_uri` | `http://demoapp1/private/redirect_uri`                              | Redirect URI. The environment variable is a **path**, appended to `IPAX_BASE_URL`. The nginx variable is a **full URL**, used as is          |
| OIDC_LOGOUT_PATH              | oidc_logout_path              | oidc_opts.logout_path              | `/private/logout`       | `/private/logout`                                                   | Path that ends the session and starts logout at the IdP. In `demoapps` mode IPAx adds `/<IPAX_APP_NAME>` in front                            |
| OIDC_POST_LOGOUT_REDIRECT_URI | oidc_post_logout_redirect_uri | oidc_opts.post_logout_redirect_uri | `/logoutSuccess.html`   | `http://demoapp1/logoutSuccess.html`                                | Where the IdP sends the user after logout. The environment variable is a **path**, appended to `IPAX_BASE_URL`. The nginx variable is a **full URL** |
| OIDC_PROMPT                   | oidc_prompt                   | oidc_opts.prompt                   |                         | `login`                                                             | `prompt` parameter: `none`, `login`, `consent` or `select_account`. With `none`, users without an IdP session go to `/loginRequired.html`     |
| OIDC_ACR_VALUES               | oidc_acr_values               | oidc_opts.authorization_params     |                         | `mfa`                                                               | `acr_values` parameter sent to the IdP, to request an authentication level                                                                   |
| QUERY_PARAMS                  | query_params                  | oidc_opts.authorization_params     |                         | `kc_idp_hint=google&ui_locales=es`                                  | Extra parameters (`k1=v1&k2=v2`) added to the IdP login redirect                                                                              |

## Session (lua-resty-session)

| Environment              | nginx variable           | lua-resty-session option      | Default               | Example                 | Description                                                                                         |
|--------------------------|--------------------------|-------------------------------|-----------------------|-------------------------|-----------------------------------------------------------------------------------------------------|
| SESSION_COOKIE_SAME_SITE | session_cookie_same_site | session_opts.cookie_same_site | `Lax`                 | `Strict`                | SameSite attribute of the session cookie: `Lax`, `Strict`, `None` or `Default`                      |
| SESSION_COOKIE_SECURE    | session_cookie_secure    | session_opts.cookie_secure    | `false`               | `true`                  | Send the session cookie over HTTPS only (`true` / `false`). Set `true` when IPAx is served over HTTPS |
| SESSION_IDLING_TIMEOUT   | session_idling_timeout   | session_opts.idling_timeout   | `86400`               | `1800`                  | Seconds without activity before the session expires                                                 |
| SESSION_REMEMBER         | session_remember         | session_opts.remember         | `false`               | `true`                  | Keep a persistent "remember me" cookie (`<IPAX_APP_NAME>_remember`) so the session survives a browser restart |
| SESSION_SECRET           | session_secret           | session_opts.secret           | `ipax_default_secret` | `9f3c1e7a2b...`         | Secret used to protect the session cookie, combined with `IPAX_BASE_URL`. **Change it in production**   |

## Keycloak Application Initiated Actions

When an `*_ACTION` variable is set, the info page (`/private/info`) shows a button that sends the user to Keycloak with `kc_action=<value>`. The matching `*_LABEL` variable sets the button text.

| Environment                | nginx variable             | Default            | Example                          | Description                                    |
|----------------------------|----------------------------|--------------------|----------------------------------|------------------------------------------------|
| KC_DELETE_ACCOUNT_ACTION   | kc_delete_account_action   |                    | `delete_account`                 | Keycloak action to delete the user's account   |
| KC_DELETE_ACCOUNT_LABEL    | kc_delete_account_label    | `Delete account`   | `Delete user`                    | Text of the delete account button              |
| KC_UPDATE_EMAIL_ACTION     | kc_update_email_action     |                    | `UPDATE_EMAIL`                   | Keycloak action to update the user's email     |
| KC_UPDATE_EMAIL_LABEL      | kc_update_email_label      | `Update email`     | `Change email`                   | Text of the update email button                |
| KC_UPDATE_PASSWORD_ACTION  | kc_update_password_action  |                    | `UPDATE_PASSWORD`                | Keycloak action to update the user's password  |
| KC_UPDATE_PASSWORD_LABEL   | kc_update_password_label   | `Update password`  | `Change password`                | Text of the update password button             |
| KC_ENROL_BIOMETRICS_ACTION | kc_enrol_biometrics_action |                    | `enrol_biometrics`               | Keycloak action to enrol biometrics            |
| KC_ENROL_BIOMETRICS_LABEL  | kc_enrol_biometrics_label  | `Enrol biometrics` | `Register fingerprint`           | Text of the enrol biometrics button            |
| KC_ADD_PASSKEY_ACTION      | kc_add_passkey_action      |                    | `webauthn-register-passwordless` | Keycloak action to register a passkey          |
| KC_ADD_PASSKEY_LABEL       | kc_add_passkey_label       | `Add Passkey`      | `Add a passkey`                  | Text of the add passkey button                 |
