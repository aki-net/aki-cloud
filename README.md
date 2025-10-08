# aki-cloud edge platform

aki-cloud is a self-hostable, multi-node DNS + HTTP proxy control plane inspired by Cloudflare. It provides authoritative DNS through CoreDNS, HTTP edge proxying via OpenResty, a Go backend for orchestration and node synchronisation, and a React frontend for day-to-day operations.

## Stack overview

- **Backend**: Go HTTP API, file-based data stores, node-to-node sync, config generation (`backend/`).
- **DNS**: CoreDNS (authoritative only) rendered from data under `./data/dns` (`coredns/`).
- **HTTP proxy**: OpenResty with templated vhosts for proxied zones (`openresty/`).
- **Frontend**: React + Vite single-page app (`frontend/`).
- **Runtime**: Docker Compose; host networking for CoreDNS/OpenResty; persistent state in `./data`.

## Repository layout

```
.
├── backend/             # Go services, generators, tests
├── coredns/             # CoreDNS Dockerfile + templates
├── frontend/            # React control plane UI
├── openresty/          # OpenResty Dockerfile + templates
├── scripts/            # Config generation + reload helpers
├── data/               # Runtime state (created at install, gitignored)
├── docker-compose.yml  # Runtime topology
├── install.sh          # Interactive / scripted installer & join helper
├── Makefile            # Common ops shortcuts
└── README.md           # This document
```

Only `README.md` files serve as documentation as required.

## Prerequisites

- Linux host (WSL/Debian tested) with Docker Engine + Compose plugin.
- `openssl`, `python3`, `uuidgen` (or Python fallback), and `curl` available on the host.
- Ports 53/UDP+TCP, 80/TCP, and 443/TCP free on the IPs you configure for CoreDNS/OpenResty.

## Installation

Run the installer from the project root. It supports fully-interactive and flag-driven modes.

### Fresh install

```bash
./install.sh --mode fresh \
  --node-name node-1 \
  --ips 203.0.113.10,203.0.113.11 \
  --ns-ips 203.0.113.10 \
  --api-endpoint http://203.0.113.10:8080 \
  --ns-label dns \
  --ns-base-domain aki.cloud \
  --admin-email admin@example.com \
  --admin-pass 'StrongPassword!'
```

Key outputs/live artefacts:

- `.env` – docker-compose configuration (ports, node metadata, feature toggles).
- `./data/cluster/secret` – cluster shared secret (hex); never check into git.
- `./data/cluster/jwt_secret` – JWT signing secret.
- `./data/users/users.json` – initial admin user (bcrypt hashed password).
- `docker compose up -d` – started automatically.

### Joining an existing cluster

```bash
./install.sh --mode join \
  --node-name node-2 \
  --ips 198.51.100.20,198.51.100.21 \
  --ns-ips 198.51.100.20 \
  --api-endpoint http://198.51.100.20:8080 \
  --ns-label dns \
  --ns-base-domain aki.cloud \
  --seed http://203.0.113.10:8080 \
  --cluster-secret <secret-from-initial-node> \
  --jwt-secret <jwt-secret-from-initial-node>
```

The installer pulls a snapshot over the `/api/v1/sync/pull` endpoint, writes local metadata, renders configs, and then starts the services. Join mode never mutates the cluster’s admin user list unless the snapshot contains changes.

### Flags (non-interactive)

- `--mode fresh|join`
- `--node-name`, `--ips`, `--ns-ips`, `--ns-label`, `--ns-base-domain`, `--api-endpoint`
- `--admin-email`, `--admin-pass`, `--admin-pass-file`
- `--seed`, `--cluster-secret`, `--jwt-secret`
- `--backend-port`, `--frontend-port`
- `--enable-coredns true|false`, `--enable-openresty true|false`

Install script behaviour is idempotent; re-running it safely reuses existing secrets and configuration unless you supply overrides.

## Operations

- `make up` – start / refresh containers in detached mode.
- `make down` – stop the stack.
- `make logs` – follow aggregated service logs.
- `make up-force` – rebuild images without cache and restart.
- `make test` – backend unit tests + frontend vitest suite.
- `scripts/healthcheck.sh` – quick backend health probe.
- `docker compose logs -f <service>` – individual service logs (CoreDNS/OpenResty/backend/frontend).

Data persistence: All state lives under `./data`. Keep regular backups of this directory (sans secrets if desired) to recover zones, users, infra definitions, and version clocks.

## Service notes

- **Backend** (`backend/`) mounts `./data`, `./scripts`, `./coredns`, and `./openresty`. It renders configs via `/app/bin/generate` and triggers reloads by touching sentinel files.
- **CoreDNS** listens only on declared NS IPs using host networking; config resides in `data/dns/Corefile` and zone files under `data/dns/zones/`.
- **OpenResty** listens on non-NS IPs, with config in `data/openresty`. An inotify loop reloads NGINX when configs change. Auto-issued edge certificates live under `data/openresty/certs`, ACME challenges under `data/openresty/challenges`, and origin-pull client material under `data/openresty/origin-pull`.
- **Frontend** is served by `nginx` (static build) on the host port specified in `.env`.

## TLS automation

- Supported encryption modes mirror Cloudflare: `off`, `flexible`, `full`, `full_strict`, and `strict_origin_pull`.
- HTTP-01 ACME challenges are published across nodes and answered from `/data/openresty/challenges`.
- Certificates are renewed automatically ~30 days before expiry with configurable retry back-off.
- Strict origin pull mode provisions mutual TLS material so origins can require client authentication from the edge.

## Backend API highlights

- `POST /auth/login`
- Domain CRUD: `/api/v1/domains`
- Admin Users CRUD: `/api/v1/admin/users`
- Admin Nodes CRUD: `/api/v1/admin/nodes` (name, IPs, NS tagging, API endpoint for peer sync)
- Infra insights: `/api/v1/infra/nameservers`, `/infra/edges`
- Ops: `/api/v1/admin/ops/rebuild`
- Sync: `/api/v1/sync/digest`, `/pull`, `/push` (cluster-authenticated).

JWT bearer tokens are required for authenticated routes. Backend health endpoints: `/healthz`, `/readyz`.

## Testing & validation

Automated checks (run via `make test`):

1. `go test ./...` – file store atomicity and sync merge tests.
2. `npm run test` – vitest React component coverage.

Manual validation checklist (local or staging):

1. `docker compose up -d`
2. Login to frontend (`http://localhost:<FRONTEND_PORT>`) as admin.
3. Create user + domain `example.test` with origin `127.0.0.1`, `proxied=false`.
4. Run `dig @<ns-ip> example.test A` – expect origin IP.
5. Toggle to `proxied=true` in UI. Run `dig` again – expect edge IP(s).
6. `curl -H 'Host: example.test' -H 'User-Agent: aki-probe/1.0' http://<edge-ip>` – expect origin response.
7. Restart stack (`make down && make up`) – state must persist.
8. Provision a second node with `install.sh --mode join ...` – records converge within sync interval.

## Production cutover checklist

1. Verify all four nodes online: `docker compose ps` on each host.
2. Confirm admin UI shows expected nodes, users, and domain inventory.
3. For each delegated domain, run:
   ```bash
   dig @<ns-ip> example.com SOA
   dig @<ns-ip> example.com A
   dig @<ns-ip> example.com NS
   ```
   Ensure responses match expected NS hostnames/IPs.
4. For proxied domains, test from multiple edges:
   ```bash
   curl -H 'Host: example.com' -H 'User-Agent: aki-cutover/1.0' http://<edge-ip>
   ```
5. Update registrar NS glue records to new NS hostnames (performed manually by operator).
6. After delegation, re-run the `dig`/`curl` checks externally.
7. Capture `docker compose logs --tail=200 backend` to confirm config regeneration events.

## Security considerations

- Secrets (`cluster/secret`, `cluster/jwt_secret`) are generated locally and stored only on disk; never commit them.
- Passwords are hashed using bcrypt before storage.
- Sync traffic is authorised using the cluster secret (Authorization bearer header).
- Host network binding means the host firewall must restrict unwanted access on 53/80/443.
- ACME account keys live in `data/cluster/acme_account.json`, and edge API responses redact private key material before returning domain records.

## Contributing workflow (local)

1. Modify code.
2. Run `make test` to validate.
3. Regenerate configs if needed via `docker compose run --rm backend /app/bin/generate all ...`.
4. Review `git status` ensuring no unintended secrets or `data/` files are staged.

## Troubleshooting

- **Install script errors**: ensure Docker daemon is running and the Compose plugin is available (`docker compose version`).
- **CoreDNS not answering**: confirm `ENABLE_COREDNS=true` and that the NS IPs are bound on the host; inspect `docker compose logs coredns`.
- **OpenResty not proxying**: ensure edge IPs exist in node metadata; check `data/openresty/sites-enabled/` for generated configs.
- **Sync stalls**: ensure every node record has a valid `api_endpoint`; `data/cluster/peers.json` is auto-generated from these endpoints, so inspect it and confirm ports are open between nodes.

All components are documented within their respective `README.md` files for deeper operational notes.
