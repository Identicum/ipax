#!/bin/bash

get_demoapps_list() {
    find "${DEMOAPPS_VARIABLES_CONFIG_PATH}" -name "*.conf" -type f
}

delete_lua_shared_dict() {
    echo "Deleting existing ${LUA_SHARED_DICT_PATH}/**/*.conf"
    find "${LUA_SHARED_DICT_PATH}" -name "*.conf" -type f -delete
}

create_lua_shared_dict_file() {
    local demoapp_name="$1"
    local demoapp_conf_file="$2"
    local relative_path="${demoapp_conf_file#${DEMOAPPS_VARIABLES_CONFIG_PATH}/}"
    local subdir
    subdir=$(dirname "$relative_path")
    local lua_shared_dict_path
    if [ "$subdir" = "." ]; then
        lua_shared_dict_path="${LUA_SHARED_DICT_PATH}/${demoapp_name}.conf"
    else
        lua_shared_dict_path="${LUA_SHARED_DICT_PATH}/${subdir}/${demoapp_name}.conf"
    fi

    echo "Creating ${lua_shared_dict_path}"
    mkdir -p "$(dirname "$lua_shared_dict_path")"
    echo "lua_shared_dict ${demoapp_name}_jwks 1m;" > ${lua_shared_dict_path}
    echo "lua_shared_dict ${demoapp_name}_discovery 1m;" >> ${lua_shared_dict_path}
    echo "lua_shared_dict ${demoapp_name}_oidc_state 1m;" >> ${lua_shared_dict_path}
    echo "lua_shared_dict ${demoapp_name}_oidc_access_tokens 1m;" >> ${lua_shared_dict_path}
    echo "lua_shared_dict ${demoapp_name}_oidc_refresh_tokens 1m;" >> ${lua_shared_dict_path}
    echo "lua_shared_dict ${demoapp_name}_oidc_id_tokens 1m;" >> ${lua_shared_dict_path}
}

delete_multi_configs() {
    echo "Deleting existing ${DEMOAPPS_CONFIG_PATH}/**/*.conf"
    find "${DEMOAPPS_CONFIG_PATH}" -name "*.conf" -type f -delete
}

create_multi_config_file() {
    local demoapp_name="$1"
    local demoapp_conf_file="$2"
    local relative_path="${demoapp_conf_file#${DEMOAPPS_VARIABLES_CONFIG_PATH}/}"
    local subdir=$(dirname "$relative_path")
    local demoapps_config_path
    if [ "$subdir" = "." ]; then
        demoapps_config_path="${DEMOAPPS_CONFIG_PATH}/${demoapp_name}.conf"
    else
        demoapps_config_path="${DEMOAPPS_CONFIG_PATH}/${subdir}/${demoapp_name}.conf"
    fi
    echo "Creating ${demoapps_config_path}"
    mkdir -p "$(dirname "$demoapps_config_path")"
    cat /var/ipax/conf/demoapp_template.conf > ${demoapps_config_path}
    sed -i "s#include /var/ipax/conf/default_variables.conf;#include /var/ipax/conf/default_variables.conf;\n		include ${demoapp_conf_file};#g" "${demoapps_config_path}"
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
    while IFS= read -r demoapp_conf_file; do
        demoapp_name=$(basename "$demoapp_conf_file" .conf)
        echo "Processing demoapp: '${demoapp_conf_file}'"
        create_lua_shared_dict_file "${demoapp_name}" "${demoapp_conf_file}"
        create_multi_config_file "${demoapp_name}" "${demoapp_conf_file}"
    done < <(get_demoapps_list)
    echo "Finished processing demoapps"
fi

# troubleshooting
# tail -f /etc/alpine-release

echo "Starting nginx..."
/usr/local/openresty/bin/openresty -g 'daemon off;'
