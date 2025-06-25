FROM openresty/openresty:1.25.3.2-alpine-fat

RUN luarocks install lua-resty-http 0.17.2
RUN luarocks install lua-resty-session 4.0.5
RUN luarocks install lua-resty-jwt 0.2.3
RUN luarocks install lua-resty-openidc 1.8.0
RUN luarocks install lua-resty-template 2.0

COPY conf/ /usr/local/openresty/nginx/conf/
COPY lua/ /etc/ipax/lua/
COPY html /var/ipax/html
COPY templates /var/ipax/templates

ENV NGINX_LOG_LEVEL=warn \
    NGINX_RESOLVER=8.8.8.8 \
    SESSION_SECRET="ipax_default_secret" \
    SESSION_COOKIE_REMEMBER="true" \
    SESSION_COOKIE_SAMESITE="Lax" \
    SESSION_COOKIE_SECURE="false" \
    SESSION_IDLETIMEOUT="86400" \
    OIDC_DISCOVERY="" \
    OIDC_SSL_VERIFY="yes" \
    OIDC_CLIENT_ID="" \
    OIDC_USE_PKCE=false \
    OIDC_CLIENT_SECRET="" \
    OIDC_SCOPE="openid profile" \
    OIDC_REDIRECT_URI="/private/redirect_uri" \
    OIDC_LOGOUT_URI="/private/logout" \
    OIDC_POST_LOGOUT_REDIRECT_URI="/auth" \
    OIDC_PROMPT="" \
    OIDC_ACR_VALUES="" \
    KC_DELETE_ACCOUNT_ACTION="" \
    KC_DELETE_ACCOUNT_LABEL="Delete account" \
    KC_UPDATE_EMAIL_ACTION="" \
    KC_UPDATE_EMAIL_LABEL="Update email" \
    KC_UPDATE_PASSWORD_ACTION="" \
    KC_UPDATE_PASSWORD_LABEL="Update password" \
    KC_ENROL_BIOMETRICS_ACTION="" \
    KC_ENROL_BIOMETRICS_LABEL="Enrol biometrics" \
    IPAX_APP_NAME="IPAx" \
    IPAX_BASEURL="http://localhost" \
    API_BASEURL=""

WORKDIR /usr/local/openresty/nginx

HEALTHCHECK --interval=30s --timeout=1s --start-period=5s --retries=3 CMD [ "curl", "-f", "http://localhost/ipax/health" ]

CMD ["sh", "-c", "envsubst < /etc/ipax/conf/nginx.conf.template > conf/nginx.conf && /usr/local/openresty/bin/openresty -g 'daemon off;'"]
