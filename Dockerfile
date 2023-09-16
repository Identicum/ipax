FROM openresty/openresty:1.21.4.2-centos7

RUN luarocks install lua-resty-openidc
RUN luarocks install lua-resty-template

COPY conf/ /usr/local/openresty/nginx/conf/
COPY lua/ /etc/ipax/lua/
COPY html /var/ipax/html

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
    OIDC_REDIRECT_URI="/ipax/redirect_uri" \
    OIDC_LOGOUT_URI="/ipax/logout" \
    OIDC_POST_LOGOUT_REDIRECT_URI="/auth" \
    OIDC_ACR_VALUES="" \
    KC_UPDATE_PASSWORD_ACTION="" \
    KC_DELETE_ACCOUNT_ACTION=""

WORKDIR /usr/local/openresty/nginx

CMD ["sh", "-c", "envsubst < conf/nginx.conf.template > conf/nginx.conf && /usr/bin/openresty -g 'daemon off;'"]
