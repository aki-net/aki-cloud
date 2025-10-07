# Frontend control plane

React + Vite single-page application for managing domains, users, and nodes.

## Development

```bash
cd frontend
npm install
npm run dev -- --host
```

Environment variables:

- `VITE_API_BASE` – backend base URL (default: `http://localhost:8080`).

## Build

```bash
npm run build
```

The Dockerfile produces a static build served via `nginx`, matching the deployment used in compose.

## Tests & lint

```bash
npm run test      # vitest (jsdom)
npm run lint      # eslint (optional)
```

## Features

- Login form (JWT stored in local storage, attached to API requests).
- User dashboard: list domains, create/update/delete, proxied toggle with optimistic updates.
- Admin dashboard: users CRUD, nodes CRUD (IPs + NS tagging + API endpoints), live nameserver and edge views, “Rebuild services” trigger.
- Non-blocking propagation alerts to remind operators of sync delay.
