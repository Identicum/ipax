# Certificates

```sh
docker run -it --rm --name certbot -v "$(pwd)/letsencrypt/etc/:/etc/letsencrypt/" -v "$(pwd)/letsencrypt/var_lib/:/var/lib/letsencrypt" certbot/certbot certonly --manual -d '*.idsherpa.com'

cp ./letsencrypt/etc/live/idsherpa.com/fullchain.pem public.pem
cp ./letsencrypt/etc/live/idsherpa.com/privkey.pem private.pem
```
