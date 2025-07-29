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

delete_multipath_config() {
    echo "Deleting existing ${DEMOAPPS_MULTI_PATH_CONFIG_PATH}/*.conf"
    rm -f ${DEMOAPPS_MULTI_PATH_CONFIG_PATH}/*.conf
}

create_multipath_config_file() {
    local demoapp_name="$1"
    local multipath_config_path="${DEMOAPPS_MULTI_PATH_CONFIG_PATH}/${demoapp_name}.conf"
    echo "Creating ${multipath_config_path}"
    cat /var/ipax/conf/demoapp_template.conf > ${multipath_config_path}
    sed -i "s#include /var/ipax/conf/default_variables.conf;#include /var/ipax/conf/default_variables.conf;\n		include ${DEMOAPPS_VARIABLES_CONFIG_PATH}/${demoapp_name}.conf;#g" ${multipath_config_path}
    sed -i "s#location /#location /${demoapp_name}/#g" ${multipath_config_path}
    sed -i "s#root /var/ipax/html/#alias /var/ipax/html/#g" ${multipath_config_path}
}

delete_multihost_config() {
    echo "Deleting existing ${DEMOAPPS_MULTI_HOST_CONFIG_PATH}/*.conf"
    rm -f ${DEMOAPPS_MULTI_HOST_CONFIG_PATH}/*.conf
}

create_multihost_config_file() {
    local demoapp_name="$1"
    local multihost_config_path="${DEMOAPPS_MULTI_HOST_CONFIG_PATH}/${demoapp_name}"
    echo "Creating ${multihost_config_path}"
    echo "server {" > ${multihost_config_path}
    echo "	listen 80;" >> ${multihost_config_path}
    echo "	server_name ${demoapp_name};" >> ${multihost_config_path}
    cat /var/ipax/conf/demoapp_template.conf >> ${multihost_config_path}
    echo "}" >> ${multihost_config_path}
    sed -i "s#include /var/ipax/conf/default_variables.conf;#include /var/ipax/conf/default_variables.conf;\n		include ${DEMOAPPS_VARIABLES_CONFIG_PATH}/${demoapp_name}.conf;#g" ${multihost_config_path}
}

NGINX_CONF_TEMPLATE="/var/ipax/conf/nginx.conf.template"
NGINX_CONF="/usr/local/openresty/nginx/conf/nginx.conf"
echo "Replacing variables in ${NGINX_CONF_TEMPLATE} to generate ${NGINX_CONF}"
envsubst < ${NGINX_CONF_TEMPLATE} > ${NGINX_CONF}

echo "IPAX_DEMOAPPS_MODE: '${IPAX_DEMOAPPS_MODE}'"
if [ "$IPAX_DEMOAPPS_MODE" = "proxy" ]; then
    delete_lua_shared_dict
    create_lua_shared_dict_file "${IPAX_DEMOAPP_NAME}"
fi

if [ "$IPAX_DEMOAPPS_MODE" = "single" ]; then
    cp /var/ipax/conf/server/demoapps_single.conf /usr/local/openresty/nginx/conf/server.conf
    delete_lua_shared_dict
    create_lua_shared_dict_file "${IPAX_DEMOAPP_NAME}"
fi

if [ "$IPAX_DEMOAPPS_MODE" = "multi_path" ]; then
    cp /var/ipax/conf/server/demoapps_multi_path.conf /usr/local/openresty/nginx/conf/server.conf
    delete_lua_shared_dict
    delete_multipath_config
    demoapps_list=$(get_demoapps_list)
    for demoapp_name in $demoapps_list; do
        echo "Processing demoapp: '${demoapp_name}'"
        create_lua_shared_dict_file "${demoapp_name}"
        create_multipath_config_file "${demoapp_name}"
    done
    echo "Finished processing demoapps"
fi

if [ "$IPAX_DEMOAPPS_MODE" = "multi_host" ]; then
    cp /var/ipax/conf/server/demoapps_multi_host.conf /usr/local/openresty/nginx/conf/server.conf
    delete_lua_shared_dict
    delete_multihost_config
    demoapps_list=$(get_demoapps_list)
    for demoapp_name in $demoapps_list; do
        echo "Processing demoapp: '${demoapp_name}'"
        create_lua_shared_dict_file "${demoapp_name}"
        create_multihost_config_file "${demoapp_name}"
    done
    echo "Finished processing demoapps"
fi

# troubleshooting
# tail -f /etc/alpine-release

echo "Starting nginx..."
/usr/local/openresty/bin/openresty -g 'daemon off;'
