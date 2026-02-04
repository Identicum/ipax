#!/bin/bash

get_demoapps_list() {
  local demoapps_list=""
  for demoapp_conf_file in ${DEMOAPPS_VARIABLES_CONFIG_PATH}/*.conf; do
    demoapp_name=$(basename "$demoapp_conf_file" .conf)
    demoapps_list+="$demoapp_name "
  done
  # Trim trailing space and print
  echo "${demoapps_list%% }"
}

delete_lua_shared_dict() {
    echo "Deleting existing ${LUA_SHARED_DICT_PATH}/*.conf"
    rm -f ${LUA_SHARED_DICT_PATH}/*.conf
}

create_lua_shared_dict_file() {
    local demoapp_name="$1"
    local lua_shared_dict_path="${LUA_SHARED_DICT_PATH}/${demoapp_name}.conf"
    echo "Creating ${lua_shared_dict_path}"
    echo "lua_shared_dict ${demoapp_name}_jwks 1m;" > ${lua_shared_dict_path}
    echo "lua_shared_dict ${demoapp_name}_discovery 1m;" >> ${lua_shared_dict_path}
    echo "lua_shared_dict ${demoapp_name}_oidc_state 1m;" >> ${lua_shared_dict_path}
    echo "lua_shared_dict ${demoapp_name}_oidc_access_tokens 1m;" >> ${lua_shared_dict_path}
    echo "lua_shared_dict ${demoapp_name}_oidc_refresh_tokens 1m;" >> ${lua_shared_dict_path}
    echo "lua_shared_dict ${demoapp_name}_oidc_id_tokens 1m;" >> ${lua_shared_dict_path}
}

delete_multi_configs() {
    echo "Deleting existing ${DEMOAPPS_CONFIG_PATH}/*.conf"
    rm -f ${DEMOAPPS_CONFIG_PATH}/*.conf
}

create_multi_config_file() {
    local demoapp_name="$1"
    local demoapps_config_path="${DEMOAPPS_CONFIG_PATH}/${demoapp_name}.conf"
    echo "Creating ${demoapps_config_path}"
    cat /var/ipax/conf/demoapp_template.conf > ${demoapps_config_path}
    sed -i "s#include /var/ipax/conf/default_variables.conf;#include /var/ipax/conf/default_variables.conf;\n		include ${DEMOAPPS_VARIABLES_CONFIG_PATH}/${demoapp_name}.conf;#g" ${demoapps_config_path}
    sed -i "s#location /#location /${demoapp_name}/#g" ${demoapps_config_path}
    sed -i "s#root /var/ipax/html/#alias /var/ipax/html/#g" ${demoapps_config_path}
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
    echo "Finished processing demoapps"
fi

# troubleshooting
# tail -f /etc/alpine-release

echo "Starting nginx..."
/usr/local/openresty/bin/openresty -g 'daemon off;'
