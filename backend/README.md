# Backend service

Go API + sync daemon providing:

- JWT auth, users/domains/nodes CRUD.
- File-backed stores under `/data` with atomic writes.
- Config generation via `/app/bin/generate` binary.
- Node-to-node sync (digest/pull/push) using cluster shared secret.

## Running standalone

Environment variables (typically injected via `.env`):

| Variable | Description | Default |
| --- | --- | --- |
| `DATA_DIR` | Data root (mounted volume) | `/data` |
| `PORT` | API port | `8080` |
| `NODE_ID`, `NODE_NAME` | Node identity | required |
| `CLUSTER_SECRET_FILE` | Path to cluster secret | `/data/cluster/secret` |
| `JWT_SECRET_FILE` | Path to JWT secret | `/data/cluster/jwt_secret` |
| `SYNC_INTERVAL_SECONDS` | Peer sync cadence | `15` |
| `RELOAD_DEBOUNCE_MS` | Config regen debounce | `1500` |

### Local build & run

```bash
cd backend
go build ./cmd/server
DATA_DIR=../data PORT=8080 NODE_ID=$(uuidgen) NODE_NAME=dev \
  CLUSTER_SECRET_FILE=../data/cluster/secret JWT_SECRET_FILE=../data/cluster/jwt_secret \
  ./server
```

### Tests & lint

```bash
go test ./...
```

## Config generation CLI

`cmd/generate` builds the `/app/bin/generate` tool used by scripts and install flow.

```bash
./bin/generate all --data-dir /data \
  --coredns-template /app/coredns/Corefile.tmpl \
  --nginx-template /app/openresty/nginx.conf.tmpl \
  --sites-template /app/openresty/sites.tmpl \
  --openresty-output /data/openresty
```

Targets:

- `coredns` – render Corefile + zone files into `/data/dns`.
- `openresty` – render NGINX configs into `/data/openresty`.
- `all` – both.

## API summary

- `POST /auth/login`
- `/api/v1/domains` – CRUD (admin sees all, user limited to own domains).
- `/api/v1/admin/users` – admin-only user management.
- `/api/v1/admin/nodes` – admin-only node metadata.
- `/api/v1/infra/nameservers` & `/infra/edges` – computed views.
- `/api/v1/admin/ops/rebuild` – synchronous CoreDNS/OpenResty regeneration.
- `/api/v1/sync/*` – inter-node sync (protected by cluster secret).

Health probes: `/healthz`, `/readyz`.
