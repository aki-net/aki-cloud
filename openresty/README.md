# OpenResty edge proxy

OpenResty container providing HTTP and HTTPS edge services for proxied domains.

- Based on `openresty/openresty:1.21.4.2-alpine` with `inotify-tools` for on-the-fly reloads.
- Entry script `openresty-start.sh` watches `/data/openresty` (nginx.conf + sites-enabled/) and issues `openresty -s reload` when configs change.
- TLS certificates and keys are rendered into `/data/openresty/certs`. Client origin-pull material lives under `/data/openresty/origin-pull`.
- ACME HTTP-01 challenge responses are published via `/data/openresty/challenges/<domain>/<token>` and served directly by OpenResty.
- Upstream origin connections honour the configured encryption mode (`flexible`, `full`, `full_strict`, `strict_origin_pull`) with appropriate `proxy_ssl_*` directives.

## Config layout

- `/data/openresty/nginx.conf` – rendered from `openresty/nginx.conf.tmpl` by the generator.
- `/data/openresty/sites-enabled/*.conf` – per-domain server blocks rendered from `openresty/sites.tmpl`.
- `/data/openresty/certs/` – auto-issued edge certificates.
- `/data/openresty/challenges/` – ACME http-01 tokens replicated across nodes.
- `/data/openresty/origin-pull/` – client cert/key pairs for strict origin pull mode.

## Manual run

```bash
docker build -t aki-openresty .
docker run --rm --network host -v $(pwd)/../data:/data aki-openresty
```

Ensure generated configs exist beforehand. The container listens only on the IPs that are not marked as NS in node metadata.
