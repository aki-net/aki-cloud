COMPOSE ?= docker compose

.PHONY: up down logs up-force test fmt

up:
	$(COMPOSE) up -d

down:
	$(COMPOSE) down

logs:
	$(COMPOSE) logs -f --tail=200

up-force:
	$(MAKE) down
	$(COMPOSE) build --no-cache
	$(MAKE) up

test:
	cd backend && go test ./...
	cd frontend && npm install && npm run test -- --watch=false

fmt:
	cd backend && gofmt -w ./
