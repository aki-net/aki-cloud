# OpenResty edge proxy

OpenResty container providing HTTP edge services for proxied domains.

- Based on `openresty/openresty:1.21.4.2-alpine` with `inotify-tools` for on-the-fly reloads.
- Entry script `openresty-start.sh` watches `/data/openresty` (nginx.conf + sites-enabled/) and issues `openresty -s reload` when configs change.
- Backends are plain HTTP upstreams pointing to domain origin IPs; TLS wiring can be added later.

## Config layout

- `/data/openresty/nginx.conf` – rendered from `openresty/nginx.conf.tmpl` by the generator.
- `/data/openresty/sites-enabled/*.conf` – per-domain server blocks rendered from `openresty/sites.tmpl`.

## Manual run

```bash
docker build -t aki-openresty .
docker run --rm --network host -v $(pwd)/../data:/data aki-openresty
```

Ensure generated configs exist beforehand. The container listens only on the IPs that are not marked as NS in node metadata.
