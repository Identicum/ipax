
| Container path                              | Content source                  | Description                                                |
|---------------------------------------------|---------------------------------|------------------------------------------------------------|
| /entrypoint.sh                              | {repo}/entrypoint.sh            | IPAX initialization script                                 |
| /var/ipax/conf/                             | {repo}/conf/                    | IPAX image configuration files                             |
| /var/ipax/html/                             | {repo}/html/                    | IPAX image HTML content                                    |
| /var/ipax/lua/                              | {repo}/lua/                     | IPAX image LUA scripts                                     |
| /var/ipax/templates/                        | {repo}/templates/               | IPAX image HTML templates                                  |
|---------------------------------------------|---------------------------------|------------------------------------------------------------|
| /usr/local/openresty/nginx/conf/nginx.conf  | Execution of /entrypoint.sh     | Using /var/ipax/conf/nginx.conf.template and env variables |
| /usr/local/openresty/nginx/conf/server.conf | Execution of /entrypoint.sh     | Using /var/ipax/conf/server/{IPAX_MODE}.conf               |
| /var/ipax/lua_shared_dict/                  | Execution of /entrypoint.sh     | LUA shared dictionaries                                    |
|---------------------------------------------|---------------------------------|------------------------------------------------------------|
| /var/ipax/proxy_conf.d/                     | Locally mounted                 | nginx .conf files ("proxy" mode)                           |
| /var/ipax/ssl_conf/                         | Locally mounted                 | ssl settings re-used in .conf files                        |
| /var/ipax/certs/                            | Locally mounted                 | certificate files                                          |
|---------------------------------------------|---------------------------------|------------------------------------------------------------|
| /var/ipax/demoapps/                         | Locally mounted                 | .conf files with variables ("demoapps" mode)               |
| /var/ipax/location_conf.d/                  | Execution of /entrypoint.sh     | nginx .conf files ("demoapps" mode)                        |

