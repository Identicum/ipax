# Variables

| Description        | Environment                   | nginx variable           | lua_resty_openidc variable         |
|--------------------|-------------------------------|--------------------------|------------------------------------|
| OIDC discovery URL | OIDC_DISCOVERY                | oidc_discovery           | oidc_opts.discovery                |
|                    | OIDC_SSL_VERIFY               |                          | oidc_opts.ssl_verify               |
|                    | OIDC_CLIENT_ID                | client_id                | oidc_opts.client_id                |
|                    | OIDC_USE_PKCE                 | use_pkce                 | oidc_opts.use_pkce                 |
|                    | OIDC_CLIENT_SECRET            | client_secret            | oidc_opts.client_secret            |
|                    | OIDC_SCOPE                    | scope                    | oidc_opts.scope                    |
|                    | OIDC_REDIRECT_URI             |                          | oidc_opts.redirect_uri             |
|                    | OIDC_LOGOUT_URI               |                          | oidc_opts.logout_path              |
|                    | OIDC_POST_LOGOUT_REDIRECT_URI | post_logout_redirect_uri | oidc_opts.post_logout_redirect_uri |
|                    | OIDC_PROMPT                   | oidc_prompt              | oidc_opts.prompt                   |
|                    | OIDC_ACR_VALUES               | acr_values               | oidc_opts.authorization_params     |
|                    | SESSION_SECRET                | session_secret           | session_opts.secret                |
|                    | SESSION_COOKIE_REMEMBER       | session_cookie_remember  | session_opts.remember              |
|                    | SESSION_COOKIE_SAMESITE       | session_cookie_samesite  | session_opts.cookie_samesite       |
|                    | SESSION_COOKIE_SECURE         | session_cookie_secure    | session_opts.cookie_secure         |
|                    | SESSION_IDLETIMEOUT           | session_idle_timeout     | session_opts.idling_timeout        |
|                    | IPAX_APP_NAME                 |                          |                                    |
|                    | IPAX_BASEURL                  |                          |                                    |
|                    | API_BASEURL                   |                          |                                    |
|                    | KC_DELETE_ACCOUNT_ACTION      |                          |                                    |
|                    | KC_DELETE_ACCOUNT_LABEL       |                          |                                    |
|                    | KC_UPDATE_EMAIL_ACTION        |                          |                                    |
|                    | KC_UPDATE_EMAIL_LABEL         |                          |                                    |
|                    | KC_UPDATE_PASSWORD_ACTION     |                          |                                    |
|                    | KC_UPDATE_PASSWORD_LABEL      |                          |                                    |
|                    | KC_ENROL_BIOMETRICS_ACTION    |                          |                                    |
|                    | KC_ENROL_BIOMETRICS_LABEL     |                          |                                    |
