FROM openresty/openresty:1.19.3.1-8-centos7

RUN opm install zmartzone/lua-resty-openidc

COPY conf/ /usr/local/openresty/nginx/conf/
COPY lua/ /etc/ipax/lua/
COPY html/ /var/ipax/html/

ENV NGINX_LOG_LEVEL=warn \
    OIDC_DISCOVERY="" \
    OIDC_CLIENT_ID="" \
    OIDC_CLIENT_SECRET="" \
    OIDC_SCOPE="" \
    OIDC_REDIRECT_URI="" \
    OIDC_SESSION_SECRET=""

WORKDIR /usr/local/openresty/nginx

CMD ["sh", "-c", "envsubst < conf/nginx.conf.template > conf/nginx.conf && /usr/bin/openresty -g 'daemon off;'"]
