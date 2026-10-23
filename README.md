# IPAx

Identity-aware proxy based on NGINX, [OpenResty](https://openresty.org/) and [lua-resty-openidc](https://github.com/zmartzone/lua-resty-openidc).

IPAx adds OpenID Connect authentication in front of web applications that don't do it themselves, and it can also run as a ready-made OIDC demo application to test an Identity Provider (IdP). It is shipped as a container image:

```sh
docker pull ghcr.io/identicum/ipax:latest
```

## Features

- OIDC Authorization Code flow, with a client secret (confidential client) or PKCE (public client).
- Session handling with [lua-resty-session](https://github.com/bungle/lua-resty-session): idle timeout, "remember me", SameSite/Secure cookies and token renewal on expiry.
- Custom authorization request parameters: `prompt`, `acr_values` and any extra query parameter (for example `kc_idp_hint` or `ui_locales`).
- A demo info page that shows the ID token, access token, refresh token, userinfo response and request headers.
- Buttons for Keycloak [Application Initiated Actions](https://www.keycloak.org/docs/latest/server_admin/#con-aia_server_administration_guide) (update password, update email, delete account, add passkey, …).
- Lua helpers to authorize by claim and to pass user data to the upstream app as headers.
- `/ipax/health` health-check endpoint and a `robots.txt` that blocks all crawlers.

## Configuration

IPAx is configured with **environment variables**. Most of them can also be set as an **nginx variable** (`set $oidc_client_id '...';`) inside a `server` or `location` block. When both are present, a non-empty nginx variable wins. This lets one IPAx instance protect several apps, each with its own OIDC client.

See [VARIABLES.md](VARIABLES.md) for the full list of variables, their defaults and example values.
See [FILESYSTEM.md](FILESYSTEM.md) for the container's file layout and what to mount where.

## Execution modes

`IPAX_MODE` selects how IPAx runs:

| Mode       | `IPAX_MODE` | What it does                                               | Mount your config at     |
|------------|-------------|------------------------------------------------------------|--------------------------|
| Proxy      | `proxy`     | Protects one or more upstream apps (reverse proxy)         | `/var/ipax/proxy_conf.d/`|
| Single     | `single`    | Runs one demo app, configured only with env variables      | (none)                   |
| Multi      | `demoapps`  | Runs several demo apps on one host, one per URL path       | `/var/ipax/demoapps/`    |

At startup, [entrypoint.sh](entrypoint.sh) generates `nginx.conf` from [conf/nginx.conf.template](conf/nginx.conf.template), copies the server config for the selected mode from [conf/server/](conf/server/), creates the Lua shared dictionaries each app needs, and starts OpenResty.

Each mode has a ready-to-run example under [localhost/](localhost/). See [Running the local examples](#running-the-local-examples).

### Proxy mode (`proxy`)

IPAx sits in front of your apps. Each protected app is an nginx `server` block (a `.conf` file) mounted in `/var/ipax/proxy_conf.d/`. The request is authenticated in `access_by_lua_block`, and then forwarded with `proxy_pass`.

OIDC settings shared by all apps go in environment variables. Settings specific to one app (for example the redirect URI for its hostname) go as nginx variables in its `server` block.

```nginx
server {
	include /var/ipax/conf/location_norobots.conf;
	server_name demoapp1;
	set $oidc_redirect_uri 'http://demoapp1/private/redirect_uri';

	location / {
		access_by_lua_block {
			local ipax = require "ipax"
			local oidc_opts = ipax.get_oidc_opts()
			local session_opts = ipax.get_session_opts()
			ngx.ctx.res = ipax.get_res(oidc_opts, session_opts);
			local user = ipax.get_user(ngx.ctx.res)
		}
		proxy_pass http://app1:80/;
		proxy_set_header Host $host;
		proxy_set_header X-Forwarded-Proto $scheme;
		proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

		# don't forward the IPAx session cookies to the app (avoids HTTP 413 on large cookies)
		proxy_set_header Cookie $filtered_cookie;
	}
}
```

Inside `access_by_lua_block` you can use these helpers from [lua/ipax.lua](lua/ipax.lua):

| Function                                                   | Use                                                               |
|------------------------------------------------------------|-------------------------------------------------------------------|
| `get_oidc_opts()` / `get_session_opts()`                   | Build the lua-resty-openidc / lua-resty-session options           |
| `get_res(oidc_opts, session_opts)`                         | Authenticate the user (redirects to the IdP if there's no session)|
| `get_user(res)`                                            | Userinfo claims, as a Lua table                                   |
| `get_id_token(res)` / `get_access_token(res)`              | Tokens, for example to send a `Bearer` token to an API            |
| `check_multivalued_user_claim(values, required)`           | Returns HTTP 403 if `required` is not in the claim `values`       |
| `get_ldap_object_names(dns, separator)`                    | Turns a list of LDAP DNs (e.g. `member_of`) into a list of names  |

For example, to pass user data to the app as headers:

```lua
local user = ipax.get_user(ngx.ctx.res)
ngx.req.set_header("IPAx-USERNAME", user.preferred_username)
ngx.req.set_header("IPAx-EMAIL", user.email)
```

[conf/samples/](conf/samples/) has more examples: authorization by group, header injection, an SPA calling an API with the access token, and an HTTP to HTTPS redirect.

For HTTPS, mount your certificate and key as `/var/ipax/certs/public.pem` and `/var/ipax/certs/private.pem`, and add `include /var/ipax/conf/ssl/default.settings;` to your `server` block.

### Single demo app (`single`)

IPAx runs as a single OIDC demo application, with no upstream. It needs no config files: set the environment variables only.

```yaml
services:
  ipax:
    image: ghcr.io/identicum/ipax:latest
    ports:
      - 80:80
    environment:
      IPAX_MODE: single
      IPAX_DISPLAY_NAME: My demo app
      IPAX_BASE_URL: http://demoapp1
      OIDC_DISCOVERY: http://idp:8080/realms/demorealm/.well-known/openid-configuration
      OIDC_CLIENT_ID: ipax_client_id
      OIDC_CLIENT_SECRET: ipax_client_secret
      OIDC_SCOPE: openid profile email
      KC_UPDATE_PASSWORD_ACTION: UPDATE_PASSWORD
```

Register `${IPAX_BASE_URL}/private/redirect_uri` as a redirect URI of the client in your IdP.

The app has these pages:

- `/` and `/landing`: public landing page with a **Login** button.
- `/private/info`: protected page. It shows the user's tokens, userinfo claims and request headers, the configured Keycloak action buttons, and a **Logout** button.
- `/private/logout`: ends the session and logs out at the IdP (RP-initiated logout), then redirects to `/logoutSuccess.html`.

### Multi demo apps (`demoapps`)

IPAx runs several demo apps on the same host, each one under its own path (`/demoapp1/`, `/demoapp2/`, …) and each with its own OIDC client. Use it to test several clients side by side, for example SSO between apps, or a confidential client next to a PKCE one.

Mount one `.conf` file per app in `/var/ipax/demoapps/`. Each file only sets nginx variables:

```nginx
# /var/ipax/demoapps/demoapp1.conf
set $ipax_app_name 'demoapp1';
set $ipax_display_name 'DemoApp1';
set $ipax_base_url 'http://demoapps/demoapp1';

set $oidc_discovery 'http://idp:8080/realms/demorealm/.well-known/openid-configuration';
set $oidc_client_id 'demoapp1_client_id';
set $oidc_client_secret 'demoapp1_client_secret';

set $kc_update_password_action 'UPDATE_PASSWORD';
```

For each file, the entrypoint creates the same pages as the single demo app, under `/<file name>/`. Keep these rules:

- `$ipax_app_name` must be the same as the file name (without `.conf`). IPAx uses it to find the app's Lua shared dictionaries, and to build the logout path.
- `$ipax_base_url` must include the app's path (`http://demoapps/demoapp1`).
- Anything you don't set falls back to the environment variable, so shared values (for example `OIDC_DISCOVERY`) can go in the container environment.

## Running the local examples

Each folder under [localhost/](localhost/) has a `compose.yaml` that starts IPAx in one mode, together with a Keycloak IdP preloaded with a `demorealm` realm. The examples mount the files of this repo into the container, so you can edit them and restart the container without rebuilding the image.

1. Add these hostnames to `/etc/hosts`. The browser and IPAx must both reach Keycloak at `idp:8080`:

   ```
   127.0.0.1 idp demoapps demoapp1 demoapp2 demoapp3
   ```

2. Start the example:

   ```sh
   cd localhost/single      # or localhost/demoapps, localhost/proxy
   docker compose up -d
   ```

3. Open the app and log in with user `demo`, password `demo`:

   | Example              | URL                                                             |
   |----------------------|-----------------------------------------------------------------|
   | `localhost/single`   | http://demoapp1                                                 |
   | `localhost/demoapps` | http://demoapps/demoapp1/, http://demoapps/demoapp2/, http://demoapps/demoapp3/ |
   | `localhost/proxy`    | http://demoapp1, http://demoapp2, http://demoapp3               |

Other services in the examples:

- Keycloak admin console: http://localhost:8080 (`admin` / `admin`).
- Mailcatcher, to read the emails Keycloak sends (`single` and `demoapps` only): http://localhost:1080.

## Building the image

```sh
docker build -t ipax .
```

## Notes

> To use PKCE, remove `OIDC_CLIENT_SECRET` and add `OIDC_USE_PKCE` with value "true".
