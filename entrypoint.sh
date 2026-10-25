#!/bin/bash

get_demoapps_list() {
  local demoapps_list=""
  for demoapp_conf_file in /var/ipax/demoapps/*.conf; do
    # no .conf files: the glob is not expanded
    [ -e "$demoapp_conf_file" ] || continue
    demoapp_name=$(basename "$demoapp_conf_file" .conf)
    demoapps_list+="$demoapp_name "
  done
  # Trim trailing space and print
  echo "${demoapps_list%% }"
}

delete_lua_shared_dict() {
    echo "Deleting existing /var/ipax/lua_shared_dict/*.conf"
    rm -f /var/ipax/lua_shared_dict/*.conf
}

create_lua_shared_dict_file() {
    local demoapp_name="$1"
    local lua_shared_dict_path="/var/ipax/lua_shared_dict/${demoapp_name}.conf"
    echo "Creating ${lua_shared_dict_path}"
    echo "lua_shared_dict ${demoapp_name}_jwks 1m;" > ${lua_shared_dict_path}
    echo "lua_shared_dict ${demoapp_name}_discovery 1m;" >> ${lua_shared_dict_path}
    echo "lua_shared_dict ${demoapp_name}_oidc_state 1m;" >> ${lua_shared_dict_path}
    echo "lua_shared_dict ${demoapp_name}_oidc_access_tokens 1m;" >> ${lua_shared_dict_path}
    echo "lua_shared_dict ${demoapp_name}_oidc_refresh_tokens 1m;" >> ${lua_shared_dict_path}
    echo "lua_shared_dict ${demoapp_name}_oidc_id_tokens 1m;" >> ${lua_shared_dict_path}
}

delete_multi_configs() {
    echo "Deleting existing /var/ipax/location_conf.d/*.conf"
    rm -f /var/ipax/location_conf.d/*.conf
}

create_multi_config_file() {
    local demoapp_name="$1"
    local demoapps_config_path="/var/ipax/location_conf.d/${demoapp_name}.conf"
    echo "Creating ${demoapps_config_path}"
    cat /var/ipax/conf/demoapp_template.conf > ${demoapps_config_path}
    sed -i "s#include /var/ipax/conf/default_variables.conf;#include /var/ipax/conf/default_variables.conf;\n		include /var/ipax/demoapps/${demoapp_name}.conf;#g" ${demoapps_config_path}
    sed -i "s#location /#location /${demoapp_name}/#g" ${demoapps_config_path}
    sed -i "s#root /var/ipax/html/#alias /var/ipax/html/#g" ${demoapps_config_path}
    # "/demoapp1" (without trailing slash) doesn't match "location /demoapp1/"
    echo "	location = /${demoapp_name} { return 301 /${demoapp_name}/; }" >> ${demoapps_config_path}
}

get_demoapp_display_name() {
    local demoapp_name="$1"
    local quote="['\"]"
    local display_name=$(sed -nE "s/^[[:space:]]*set[[:space:]]+\\\$ipax_display_name[[:space:]]+${quote}([^'\"]*)${quote}.*/\\1/p" "/var/ipax/demoapps/${demoapp_name}.conf" | head -1)
    echo "${display_name:-$demoapp_name}"
}

json_escape() {
    echo "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

create_demoapps_index_file() {
    local demoapps_index_path="/var/ipax/demoapps.json"
    echo "Creating ${demoapps_index_path}"
    local json=""
    for demoapp_name in "$@"; do
        local display_name=$(json_escape "$(get_demoapp_display_name "${demoapp_name}")")
        json+="{\"name\":\"$(json_escape "${demoapp_name}")\",\"display_name\":\"${display_name}\"},"
    done
    echo "[${json%,}]" > ${demoapps_index_path}
}

NGINX_CONF_TEMPLATE="/var/ipax/conf/nginx.conf.template"
NGINX_CONF="/usr/local/openresty/nginx/conf/nginx.conf"
echo "Replacing variables in ${NGINX_CONF_TEMPLATE} to generate ${NGINX_CONF}"
envsubst < ${NGINX_CONF_TEMPLATE} > ${NGINX_CONF}

echo "IPAX_MODE: '${IPAX_MODE}'"
if [ "$IPAX_MODE" = "proxy" ]; then
    cp /var/ipax/conf/server/proxy.conf /usr/local/openresty/nginx/conf/server.conf
    delete_lua_shared_dict
    create_lua_shared_dict_file "${IPAX_APP_NAME}"
fi

if [ "$IPAX_MODE" = "single" ]; then
    cp /var/ipax/conf/server/demoapp.conf /usr/local/openresty/nginx/conf/server.conf
    delete_lua_shared_dict
    create_lua_shared_dict_file "${IPAX_APP_NAME}"
fi

if [ "$IPAX_MODE" = "spa" ]; then
    cp /var/ipax/conf/server/spa.conf /usr/local/openresty/nginx/conf/server.conf
    delete_lua_shared_dict
    create_lua_shared_dict_file "${IPAX_APP_NAME}"
fi

if [ "$IPAX_MODE" = "demoapps" ]; then
    cp /var/ipax/conf/server/demoapps.conf /usr/local/openresty/nginx/conf/server.conf
    delete_lua_shared_dict
    delete_multi_configs
    demoapps_list=$(get_demoapps_list)
    for demoapp_name in $demoapps_list; do
        echo "Processing demoapp: '${demoapp_name}'"
        create_lua_shared_dict_file "${demoapp_name}"
        create_multi_config_file "${demoapp_name}"
    done
    create_demoapps_index_file $demoapps_list
    echo "Finished processing demoapps"
fi

# troubleshooting
# tail -f /etc/alpine-release

echo "Starting nginx..."
/usr/local/openresty/bin/openresty -g 'daemon off;'
