FROM openresty/openresty:1.25.3.2-alpine-fat

RUN luarocks install lua-resty-http 0.17.2
RUN luarocks install lua-resty-session 4.0.5
RUN luarocks install lua-resty-jwt 0.2.3
RUN luarocks install lua-resty-openidc 1.8.0
RUN luarocks install lua-resty-template 2.0

COPY conf /var/ipax/conf/
COPY lua /var/ipax/lua/
COPY html /var/ipax/html
COPY templates /var/ipax/templates

ENV NGINX_LOG_LEVEL=warn \
    NGINX_RESOLVER=8.8.8.8 \
    OIDC_DISCOVERY="" \
    OIDC_SSL_VERIFY="yes" \
    OIDC_CLIENT_ID="" \
    OIDC_USE_PKCE="false" \
    OIDC_CLIENT_SECRET="" \
    OIDC_SCOPE="openid profile" \
    OIDC_REDIRECT_URI="/private/redirect_uri" \
    OIDC_LOGOUT_PATH="/private/logout" \
    OIDC_POST_LOGOUT_REDIRECT_URI="/logoutSuccess.html" \
    OIDC_PROMPT="" \
    OIDC_ACR_VALUES="" \
    SESSION_COOKIE_SAME_SITE="Lax" \
    SESSION_COOKIE_SECURE="false" \
    SESSION_IDLING_TIMEOUT="86400" \
    SESSION_REMEMBER="false" \
    SESSION_SECRET="ipax_default_secret" \
    IPAX_APP_NAME="ipax" \
    IPAX_DISPLAY_NAME="IPAx" \
    IPAX_BASE_URL="http://localhost" \
    IPAX_MODE="demoapp" \
    API_BASE_URL="" \
    KC_DELETE_ACCOUNT_ACTION="" \
    KC_DELETE_ACCOUNT_LABEL="Delete account" \
    KC_UPDATE_EMAIL_ACTION="" \
    KC_UPDATE_EMAIL_LABEL="Update email" \
    KC_UPDATE_PASSWORD_ACTION="" \
    KC_UPDATE_PASSWORD_LABEL="Update password" \
    KC_ENROL_BIOMETRICS_ACTION="" \
    KC_ENROL_BIOMETRICS_LABEL="Enrol biometrics" \
    KC_ADD_PASSKEY_ACTION="" \
    KC_ADD_PASSKEY_LABEL="Add Passkey" \
    LUA_SHARED_DICT_PATH="/var/ipax/conf/lua_shared_dict" \
    DEMOAPPS_VARIABLES_CONFIG_PATH="/var/ipax/conf/demoapps" \
    DEMOAPPS_CONFIG_PATH="/var/ipax/conf/location_conf.d"

WORKDIR /usr/local/openresty/nginx

# HEALTHCHECK --interval=60s --timeout=1s --start-period=5s --retries=3 CMD [ "curl", "-f", "http://localhost/ipax/health" ]

CMD [ ]
COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT [ "/bin/bash", "/entrypoint.sh" ]
