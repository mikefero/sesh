# --------------------------------------------------
# Docker tooling
# --------------------------------------------------

# Determine docker compose command
ifeq (, $(shell which docker compose 2> /dev/null))
  ifeq (, $(shell which docker-compose 2> /dev/null))
    $(error "Neither 'docker compose' nor 'docker-compose' found in PATH. Please install Docker Compose.")
  else
    DOCKER_COMPOSE = docker-compose
  endif
else
  DOCKER_COMPOSE = docker compose
endif

# Check for cURL
ifeq (, $(shell which curl 2> /dev/null))
  $(error "cURL not found in PATH. Please install cURL.")
endif

DOCKER_COMPOSE_FILE = $(APP_DIR)/internal/docker/docker-compose.yml

.PHONY: seq-start
seq-start: ## Start Seq logging server and wait for it to be ready
	@$(DOCKER_COMPOSE) -f $(DOCKER_COMPOSE_FILE) up -d seq
	@echo "Waiting for Seq to be ready..."
	@until curl -s -f -X POST http://localhost:5480/ingest/clef >/dev/null 2>&1; do \
		echo "Seq not ready, waiting..."; \
		sleep 1; \
	done
	@echo "Seq is ready!"

.PHONY: seq-stop
seq-stop: ## Stop Seq logging server
	@$(DOCKER_COMPOSE) -f $(DOCKER_COMPOSE_FILE) down seq
