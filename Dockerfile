FROM openresty/openresty:1.19.9.1-centos7

RUN opm install zmartzone/lua-resty-openidc

COPY conf/ /usr/local/openresty/nginx/conf/
COPY lua/ /etc/ipax/lua/
COPY html/ /var/ipax/html/

ENV NGINX_LOG_LEVEL=warn \
    NGINX_RESOLVER=8.8.8.8 \
    SESSION_SECRET="" \
    SESSION_COOKIE_PERSISTENT=off \
    SESSION_COOKIE_LIFETIME=86400 \
    OIDC_DISCOVERY="" \
    OIDC_CLIENT_ID="" \
    OIDC_CLIENT_SECRET="" \
    OIDC_SCOPE="openid profile" \
    OIDC_REDIRECT_URI="/redirect_uri" \
    OIDC_POST_LOGOUT_REDIRECT_URI="/auth"

WORKDIR /usr/local/openresty/nginx

CMD ["sh", "-c", "envsubst < conf/nginx.conf.template > conf/nginx.conf && /usr/bin/openresty -g 'daemon off;'"]
