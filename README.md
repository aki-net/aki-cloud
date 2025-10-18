# aki-cloud edge platform

aki-cloud is a self-hostable, multi-node DNS + HTTP proxy control plane inspired by Cloudflare. It provides authoritative DNS through CoreDNS, HTTP edge proxying via OpenResty, a Go backend for orchestration and node synchronisation, and a React frontend for day-to-day operations.

## Stack overview

- **Backend**: Go HTTP API, file-based data stores, node-to-node sync, config generation (`backend/`).
- **DNS**: CoreDNS (authoritative only) rendered from data under `./data/dns` (`coredns/`).
- **HTTP proxy**: OpenResty with templated vhosts for proxied zones (`openresty/`).
- **Frontend**: React + Vite single-page app (`frontend/`).
- **Runtime**: Docker Compose; host networking for CoreDNS/OpenResty; persistent state in `./data`.
- **Disaster recovery**: Per-node backup scheduler + Mega.nz uploader (`backend/internal/backup`).

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

- Linux host (Debian/Ubuntu tested). The installer will automatically install Docker Engine + Compose plugin if not present.
- `curl` or `wget` to download the installer.
- `python3` for configuration generation (installed automatically if not present).
- Ports 53/UDP+TCP, 80/TCP, and 443/TCP free on the IPs you configure for CoreDNS/OpenResty.

## Installation

### Download and prepare the installer

First, download the installation script and make it executable:

```bash
# Download the installer
curl -s https://raw.githubusercontent.com/aki-net/aki-cloud/main/install.sh -o install.sh
# OR
wget https://raw.githubusercontent.com/aki-net/aki-cloud/main/install.sh

# Make it executable
chmod +x install.sh

# Run the installer as root
./install.sh

# Or use with flags (see below)
```

The installer supports both fully-interactive and flag-driven modes.

### Fresh install

```bash
./install.sh --mode fresh \
  --node-name node-1 \
  --ips 203.0.113.10,203.0.113.11 \
  --ns-ips 203.0.113.10 \
  --edge-ips 203.0.113.10,203.0.113.11 \
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
  --edge-ips 198.51.100.20,198.51.100.21 \
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
- `--node-name`, `--ips`, `--ns-ips`, `--edge-ips`, `--ns-label`, `--ns-base-domain`, `--api-endpoint`
- `--admin-email`, `--admin-pass`, `--admin-pass-file`
- `--seed`, `--cluster-secret`, `--jwt-secret`
- `--backend-port`, `--frontend-port`

Install script behaviour is idempotent; re-running it safely reuses existing secrets and configuration unless you supply overrides.

## Operations

- `make up` – rebuild images when needed (with cache) and start / refresh containers in detached mode.
- `make down` – stop the stack.
- `make logs` – follow aggregated service logs.
- `make up-force` – rebuild images without cache and restart.
- `make update` – run the Ansible rollout with cached rebuilds (`ansible/playbooks/update.yml`).
- `make update-force` – same as above but with `make up-force` on the nodes.
- `make test` – backend unit tests + frontend vitest suite.
- `scripts/healthcheck.sh` – quick backend health probe.
- `docker compose logs -f <service>` – individual service logs (CoreDNS/OpenResty/backend/frontend).

### Remote updates via Ansible

- The playbooks read `data/infra/nodes.json` by default, picking the first available connection IP (`ssh_host`, `ips`, `edge_ips`, `ns_ips`) and `project_root` (defaults to `/opt/aki-cloud`). You can override this with your own inventory if needed.
- For a handwritten inventory, copy `ansible/inventory.example.yml`, list hosts under the `aki_nodes` group, and pass `-i ansible/inventory.yml`.
- Run `make update` (or `ANSIBLE_FLAGS="-i ansible/inventory.yml" make update`) for the cached rollout; use `make update-force` for the no-cache variant.
- CLI equivalent: `ansible-playbook ansible/playbooks/update.yml` or `ansible/playbooks/update-force.yml`.
- Each run prompts for any missing root password, executes `git pull --ff-only`, and then `make up` / `make up-force` inside `project_root`.
- Store credentials once in `ansible/credentials/root-passwords.yml` (YAML map of host name → password) or let the playbook write it after the first run when prompted.
- Long-running `make` calls run asynchronously across hosts by default; tune with `aki_make_async` (true/false), `aki_make_async_timeout` (seconds), and `aki_make_async_poll` (seconds between status checks).
- Useful extra vars: `aki_target_group` (inventory group name), `aki_project_root_default` (default repo path), `aki_git_pull_cmd` (custom git command), `aki_nodes_state_file` (alternate path to `nodes.json`), `aki_root_password_file` (alternate credential store), plus the async knobs above.

Data persistence: All state lives under `./data`. Keep regular backups of this directory (sans secrets if desired) to recover zones, users, infra definitions, and version clocks.

## Service notes

- **Backend** (`backend/`) mounts `./data`, `./scripts`, `./coredns`, and `./openresty`. It renders configs via `/app/bin/generate` and triggers reloads by touching sentinel files.
- **CoreDNS** listens only on declared NS IPs using host networking; config resides in `data/dns/Corefile` and zone files under `data/dns/zones/`.
- **OpenResty** listens on non-NS IPs, with config in `data/openresty`. An inotify loop reloads NGINX when configs change. Auto-issued edge certificates live under `data/openresty/certs`, ACME challenges under `data/openresty/challenges`, and origin-pull client material under `data/openresty/origin-pull`.
- **Frontend** is served by `nginx` (static build) on the host port specified in `.env`.

## Disaster recovery backups

- Configure the **Mega Backups** extension from the admin UI (`/extensions` → “Disaster Recovery Backups”). Per-node settings accept Mega.nz credentials, dataset toggles, retention, and schedule overrides. Credentials live alongside other extension state on disk; the API/UI only surface a “password set” hint for safety.
- The backend scheduler (`backend/internal/backup`) produces gzipped JSON bundles containing at least domain state, TLS material, and optional datasets (users, extensions, infra, edge health). Bundles are uploaded to Mega under `/<ns_base_domain>/<ns_label>/<node_name>/`.
- Manual `Run backup now` and `Restore` actions are available from the extension card. Restores default to wiping and repopulating domain state so a fresh node can be refilled without conflicts.
- Status and history endpoints live under `/api/v1/admin/backups/*` (`GET /status`, `GET /`, `POST /run`, `POST /restore`). CLI operators can trigger a run with `curl -X POST /api/v1/admin/backups/run` using the admin JWT.
- Local staging artefacts live under `data/backups/` and the scheduler tracks last-run metadata via `data/cluster/backups/status.json`. Retention limits are enforced on Mega after each successful upload.

## TLS automation

- Supported encryption modes mirror Cloudflare: `off`, `flexible`, `full`, `full_strict`, and `strict_origin_pull`.
- HTTP-01 ACME challenges are published across nodes and answered from `/data/openresty/challenges`.
- Certificates are renewed automatically ~30 days before expiry with configurable retry back-off.
- Strict origin pull mode provisions mutual TLS material so origins can require client authentication from the edge.
- Issuance is deferred until delegated DNS records resolve to the edge IPs; domains show an `awaiting_dns` status in this interim.
- Issuance attempts are throttled via `SSL_ACME_MAX_PER_CYCLE`, `SSL_ACME_WINDOW_LIMIT`, and `SSL_ACME_WINDOW_SECONDS` to avoid exhausting ACME rate limits during large imports.
- TLS automation only runs for proxied domains; DNS-only zones are forced to `off` mode automatically.

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
9. For large batches, use the UI bulk add/update forms; domains will report `awaiting_dns` until public resolvers return the edge IPs.

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
