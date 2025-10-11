COMPOSE ?= docker compose

.PHONY: up down logs up-force update update-force test fmt

up:
	$(COMPOSE) up --build -d
	@$(MAKE) firewall

down:
	$(COMPOSE) down

logs:
	$(COMPOSE) logs -f --tail=200

up-force:
	$(MAKE) down
	$(COMPOSE) build --no-cache
	$(MAKE) up

firewall:
	@if [ "$$(id -u)" -eq 0 ]; then \
		DATA_DIR=$(PWD)/data AUTO_FIREWALL=$${AUTO_FIREWALL:-auto} ./scripts/configure_firewall.sh; \
	else \
		sudo DATA_DIR=$(PWD)/data AUTO_FIREWALL=$${AUTO_FIREWALL:-auto} ./scripts/configure_firewall.sh; \
	fi

update:
	ansible-playbook $(ANSIBLE_FLAGS) ansible/playbooks/update.yml

update-force:
	ansible-playbook $(ANSIBLE_FLAGS) ansible/playbooks/update-force.yml

test:
	cd backend && go test ./...
	cd frontend && npm install && npm run test -- --watch=false

fmt:
	cd backend && gofmt -w ./
