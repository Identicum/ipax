# IPAx
Identity-aware proxy based on NGINX, OpenResty and [lua-resty-openidc](https://github.com/zmartzone/lua-resty-openidc).

## IDP
Create an OpenID Connect Client in your IDP using the following information:
- Client Name: IPAx
- Scopes: profile, openid
- Grant Types: authorization_code
- Redirect URIs: Include values like: "https://myapp.identicum.com/ipax/redirect_uri" (suffix is handled by `lua-resty-openidc`, can be adjusted using the `OIDC_REDIRECT_URI` environment variable)

## Configuration files
Samples are provided in the [conf.samples](./conf.samples/) folder.
Customize your files and put them into your local `./conf.d/` directory.

## Run the container

Run the image, mounting a local directory for configuration:

```sh
docker run  -d \
    -p 80:80 \
    -e OIDC_DISCOVERY="https://idp.identicum.com/.well-known/openid-configuration" \
    -e OIDC_CLIENT_ID="my_client_id" \
    -e OIDC_CLIENT_SECRET="my_client_secret" \
    -e OIDC_SCOPE="openid profile" \
    -e OIDC_REDIRECT_URI="/ipax/redirect_uri" \
    -e OIDC_SESSION_SECRET="some_uuid_secret" \
    -e OIDC_POST_LOGOUT_REDIRECT_URI="https://myapp.identicum.com/logoutSuccess.html" \
    -e OIDC_ACR_VALUES="loa-3" \
    -v $(pwd)/conf.d/:/etc/ipax/conf.d/:ro \
    identicum/ipax:latest
```

> To use PKCE, remove `OIDC_CLIENT_SECRET` and add `OIDC_USE_PKCE` with value "true"

## Certificates (optional)
Issue as many certificates as necessary to be used in your reverse proxy.
IPAx supports [wildcard certificates](https://en.wikipedia.org/wiki/Wildcard_certificate) and [SNI](https://en.wikipedia.org/wiki/Server_Name_Indication).

If you want to use HTTPS, add mapping for port 443 and mount volume `./certs/` as /etc/ipax/certs/

### Self-signed certificate
To test using a self-signed certificate, run the following command (replace with your domain):
```sh
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout wildcard_identicum_com.key -out wildcard_identicum_com.cer
```

    Country Name (2 letter code) [XX]: `AR`
    State or Province Name (full name) []: `CABA`
    Locality Name (eg, city) [Default City]: `Buenos Aires`
    Organization Name (eg, company) [Default Company Ltd]: `Identicum`
    Organizational Unit Name (eg, section) []: ` `
    Common Name (eg, your name or your server hostname) []: `*.identicum.com`
    Email Address []: `no-reply@identicum.com`

Put the generated certificate files into your local `./certs/` directory.