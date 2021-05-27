FROM openresty/openresty:1.19.3.1-8-centos7

RUN opm install zmartzone/lua-resty-openidc

COPY nginx.conf /usr/local/openresty/nginx/conf/
COPY html/ /var/ipax/html/
