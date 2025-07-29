# Variables

| Environment                   | nginx variable                | lua_resty_openidc variable         | Description        |
|-------------------------------|-------------------------------|------------------------------------|--------------------|
| NGINX_RESOLVER                |                               |                                    |                    |
| NGINX_LOG_LEVEL               |                               |                                    |                    |
| OIDC_DISCOVERY                | oidc_discovery                | oidc_opts.discovery                | OIDC discovery URL |
| OIDC_SSL_VERIFY               | oidc_ssl_verify               | oidc_opts.ssl_verify               |                    |
| OIDC_CLIENT_ID                | oidc_client_id                | oidc_opts.client_id                |                    |
| OIDC_USE_PKCE                 | oidc_use_pkce                 | oidc_opts.use_pkce                 |                    |
| OIDC_CLIENT_SECRET            | oidc_client_secret            | oidc_opts.client_secret            |                    |
| OIDC_SCOPE                    | oidc_scope                    | oidc_opts.scope                    |                    |
| OIDC_REDIRECT_URI             | oidc_redirect_uri             | oidc_opts.redirect_uri             |                    |
| OIDC_LOGOUT_PATH              | oidc_logout_path              | oidc_opts.logout_path              |                    |
| OIDC_POST_LOGOUT_REDIRECT_URI | oidc_post_logout_redirect_uri | oidc_opts.post_logout_redirect_uri |                    |
| OIDC_PROMPT                   | oidc_prompt                   | oidc_opts.prompt                   |                    |
| OIDC_ACR_VALUES               | oidc_acr_values               | oidc_opts.authorization_params     |                    |
| SESSION_COOKIE_NAME           | session_cookie_name           | session_opts.cookie_name           |                    |
| SESSION_COOKIE_SAMESITE       | session_cookie_samesite       | session_opts.cookie_samesite       |                    |
| SESSION_COOKIE_SECURE         | session_cookie_secure         | session_opts.cookie_secure         |                    |
| SESSION_IDLING_TIMEOUT        | session_idling_timeout        | session_opts.idling_timeout        |                    |
| SESSION_REMEMBER              | session_remember              | session_opts.remember              |                    |
| SESSION_REMEMBER_COOKIE_NAME  | session_remember_cookie_name  | session_opts.remember_cookie_name  |                    |
| SESSION_SECRET                | session_secret                | session_opts.secret                |                    |
| IPAX_DEMOAPP_NAME             | ipax_demoapp_name             |                                    |                    |
| IPAX_DISPLAY_NAME             | ipax_display_name             |                                    |                    |
| IPAX_BASE_URL                 | ipax_base_url                 |                                    |                    |
| API_BASE_URL                  | api_base_url                  |                                    |                    |
| KC_DELETE_ACCOUNT_ACTION      | kc_delete_account_action      |                                    |                    |
| KC_DELETE_ACCOUNT_LABEL       |                               |                                    |                    |
| KC_UPDATE_EMAIL_ACTION        |                               |                                    |                    |
| KC_UPDATE_EMAIL_LABEL         |                               |                                    |                    |
| KC_UPDATE_PASSWORD_ACTION     |                               |                                    |                    |
| KC_UPDATE_PASSWORD_LABEL      |                               |                                    |                    |
| KC_ENROL_BIOMETRICS_ACTION    |                               |                                    |                    |
| KC_ENROL_BIOMETRICS_LABEL     |                               |                                    |                    |

