FROM openresty/openresty:1.25.3.1-alpine-fat

RUN luarocks install lua-resty-openidc
RUN luarocks install lua-resty-template

COPY conf/ /usr/local/openresty/nginx/conf/
COPY lua/ /etc/ipax/lua/
COPY html /var/ipax/html
COPY templates /var/ipax/templates

ENV NGINX_LOG_LEVEL=warn \
    NGINX_RESOLVER=8.8.8.8 \
    SESSION_SECRET="ipax_default_secret" \
    SESSION_COOKIE_PERSISTENT=off \
    SESSION_COOKIE_LIFETIME=86400 \
    OIDC_DISCOVERY="" \
    OIDC_SSL_VERIFY="yes" \
    OIDC_CLIENT_ID="" \
    OIDC_USE_PKCE=false \
    OIDC_CLIENT_SECRET="" \
    OIDC_SCOPE="openid profile" \
    OIDC_REDIRECT_URI="/private/redirect_uri" \
    OIDC_LOGOUT_URI="/private/logout" \
    OIDC_POST_LOGOUT_REDIRECT_URI="/auth" \
    OIDC_ACR_VALUES="" \
    KC_DELETE_ACCOUNT_ACTION="" \
    KC_DELETE_ACCOUNT_LABEL="Delete account" \
    KC_UPDATE_EMAIL_ACTION="" \
    KC_UPDATE_EMAIL_LABEL="Update email" \
    KC_UPDATE_PASSWORD_ACTION="" \
    KC_UPDATE_PASSWORD_LABEL="Update password" \
    IPAX_APP_NAME="IPAx"

WORKDIR /usr/local/openresty/nginx

CMD ["sh", "-c", "envsubst < conf/nginx.conf.template > conf/nginx.conf && /usr/local/openresty/bin/openresty -g 'daemon off;'"]
