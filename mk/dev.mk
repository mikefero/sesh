# --------------------------------------------------
# Development tooling
# --------------------------------------------------

define APP_LDFLAGS_DEV
-X $(APP_PACKAGE).AppName=$(APP_NAME) \
-X $(APP_PACKAGE).Version=$(APP_VERSION) \
-X $(APP_PACKAGE).Commit=dev \
-X $(APP_PACKAGE).OsArch=$(APP_OS_ARCH) \
-X $(APP_PACKAGE).GoVersion=$(APP_GO_VERSION) \
-X $(APP_PACKAGE).BuildDate=$(APP_BUILD_DATE)
endef

PARSE_ARGS ?= --json --pretty --results

.PHONY: version
version: ## Run the version command
	@CGO_ENABLED=0 go run -ldflags "$(APP_LDFLAGS_DEV)" "$(APP_DIR)/cmd/$(APP_NAME)" version

.PHONY: license
license: ## Run the license command
	@CGO_ENABLED=0 go run -ldflags "$(APP_LDFLAGS_DEV)" "$(APP_DIR)/cmd/$(APP_NAME)" license

.PHONY: parse
parse: ## Run the parse command
	@CGO_ENABLED=0 go run -ldflags "$(APP_LDFLAGS_DEV)" "$(APP_DIR)/cmd/$(APP_NAME)" parse $(PARSE_ARGS)
