NAME = pasarguard-node-$(GOOS)-$(GOARCH)

LDFLAGS = -s -w -buildid=
PARAMS = -trimpath -ldflags "$(LDFLAGS)" -v
MAIN = ./cmd/node
PREFIX ?= $(shell go env GOPATH)
XRAY_INSTALLER_URL ?= https://github.com/PasarGuard/scripts/raw/1fce1b19aaa54449ec0abdc4098b49027a170705/install_core.sh
XRAY_OS ?=
XRAY_ARCH ?=
# Xray tag to install; empty resolves the newest release including pre-releases (the WireGuard UserManager API ships only in pre-releases). Set XRAY_TAG=vX.Y.Z to pin.
XRAY_TAG ?=
# Map GOARCH to installer arch flag (pure make vars to avoid shell leakage)
XRAY_ARCH_MAP_amd64   = 64
XRAY_ARCH_MAP_386     = 32
XRAY_ARCH_MAP_arm64   = arm64-v8a
XRAY_ARCH_MAP_armv7   = arm32-v7a
XRAY_ARCH_MAP_arm     = arm32-v7a
XRAY_ARCH_MAP_armv6   = arm32-v6
XRAY_ARCH_MAP_armv5   = arm32-v5
XRAY_ARCH_MAP_mips    = mips32
XRAY_ARCH_MAP_mipsle  = mips32le
XRAY_ARCH_MAP_mips64  = mips64
XRAY_ARCH_MAP_mips64le= mips64le
XRAY_ARCH_MAP_ppc64   = ppc64
XRAY_ARCH_MAP_ppc64le = ppc64le
XRAY_ARCH_MAP_riscv64 = riscv64
XRAY_ARCH_MAP_s390x   = s390x

XRAY_OS_EFFECTIVE   := $(if $(XRAY_OS),$(XRAY_OS),$(GOOS))
XRAY_ARCH_EFFECTIVE := $(if $(XRAY_ARCH),$(XRAY_ARCH),$(XRAY_ARCH_MAP_$(GOARCH)))
XRAY_LATEST_TAG_CMD = curl -fsSL https://github.com/XTLS/Xray-core/releases.atom | grep -o 'releases/tag/[^"&<]*' | head -1 | sed 's|releases/tag/||'
XRAY_RESOLVE_TAG = tag="$(XRAY_TAG)"; if [ -z "$$tag" ]; then tag=$$($(XRAY_LATEST_TAG_CMD)); fi; if [ -z "$$tag" ]; then echo "failed to resolve the latest Xray release tag, set XRAY_TAG" >&2; exit 1; fi; echo "Installing Xray $$tag";
XRAY_INSTALL_ARGS   := $(strip $(if $(XRAY_OS_EFFECTIVE),--os $(XRAY_OS_EFFECTIVE)) $(if $(XRAY_ARCH_EFFECTIVE),--arch $(XRAY_ARCH_EFFECTIVE)))

# Geo files that install_geofiles puts over the geoip.dat/geosite.dat from the Xray zip. Since Xray v26.10.21 the zip
# ships the Xray-rules-dat geoip-lite file (no country codes besides cn, ru and ir), and a rule such as geoip:us then
# stops Xray from starting. Source: Loyalsoldier/v2ray-rules-dat, which the zips shipped through v26.9.30, pinned to a
# release tag plus a sha256 per file. To bump the pin, run `make update_geofiles_pin` and replace these three lines
# with the lines it prints.
GEOFILES_TAG ?= 202610202206
GEOIP_SHA256 ?= 4a1b1eddabf5614fa51dd93ac0498856cb82dd65933cd6d6d5890d8c7bb5e902
GEOSITE_SHA256 ?= 9a4f9f84cf6201cf135afbc9d67190359cdc28e4e02e2e9f3e2b359cac317ed2
GEOFILES_REPO ?= Loyalsoldier/v2ray-rules-dat
# Install dir (the node's default XRAY_ASSETS_PATH), plus the xray binary and the config that check_geofiles uses.
GEOFILES_DIR ?= /usr/local/share/xray
GEOFILES_XRAY ?= /usr/local/bin/xray
GEOFILES_CHECK_CONFIG ?= $(CURDIR)/testdata/geofiles-check.json

ifeq ($(GOOS),windows)
OUTPUT = $(NAME).exe
ADDITION = go build -o w$(NAME).exe -trimpath -ldflags "-H windowsgui $(LDFLAGS)" -v $(MAIN)
else
OUTPUT = $(NAME)
endif

ifeq ($(shell echo "$(GOARCH)" | grep -Eq "(mips|mipsle)" && echo true),true)
ADDITION = GOMIPS=softfloat go build -o $(NAME)_softfloat -trimpath -ldflags "$(LDFLAGS)" -v $(MAIN)
endif

.PHONY: clean build test test-race-wireguard test-integration test-integration-full test-integration-wireguard \
	install_geofiles check_geofiles update_geofiles_pin

build:
	CGO_ENABLED=0 go build -o $(OUTPUT) $(PARAMS) $(MAIN)
	$(ADDITION)

clean:
	go clean -v -i $(PWD)
	rm -f $(NAME)-* w$(NAME)-*.exe

deps:
	go mod download
	go mod tidy

generate_grpc_code:
	protoc \
	--go_out=. \
	--go_opt=paths=source_relative \
	--go-grpc_out=. \
	--go-grpc_opt=paths=source_relative \
	common/service.proto

CN ?= localhost
SAN ?= DNS:localhost,IP:127.0.0.1

generate_server_cert:
	mkdir -p ./certs
	openssl req -x509 -newkey ec \
		-pkeyopt ec_paramgen_curve:P-256 \
		-keyout ./certs/ssl_key.pem \
		-out ./certs/ssl_cert.pem \
		-days 3650 -nodes \
		-subj "/CN=$(CN)" \
		-addext "subjectAltName = $(SAN)"

generate_client_cert:
	mkdir -p ./certs
	openssl req -x509 -newkey ec \
		-pkeyopt ec_paramgen_curve:P-256 \
		-keyout ./certs/ssl_client_key.pem \
		-out ./certs/ssl_client_cert.pem \
		-days 3650 -nodes \
		-subj "/CN=$(CN)" \
		-addext "subjectAltName = $(SAN)"

UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)
DISTRO := $(shell . /etc/os-release 2>/dev/null && echo $$ID || echo "unknown")

update_os:
ifeq ($(UNAME_S),Linux)
	@echo "Detected OS: Linux"
	@echo "Distribution: $(DISTRO)"

	# Debian/Ubuntu
	if [ "$(DISTRO)" = "debian" ] || [ "$(DISTRO)" = "ubuntu" ]; then \
		sudo apt-get update && \
		sudo apt-get install -y curl bash; \
	fi

	# Alpine Linux
	if [ "$(DISTRO)" = "alpine" ]; then \
		apk update && \
		apk add --no-cache curl bash; \
	fi

	# CentOS/RHEL/Fedora
	if [ "$(DISTRO)" = "centos" ] || [ "$(DISTRO)" = "rhel" ] || [ "$(DISTRO)" = "fedora" ]; then \
		sudo yum update -y && \
		sudo yum install -y curl bash; \
	fi

	# Arch Linux
	if [ "$(DISTRO)" = "arch" ]; then \
		sudo pacman -Sy --noconfirm curl bash; \
	fi
else
	@echo "Unsupported operating system: $(UNAME_S)"
	@exit 1
endif

install_xray: update_os
ifeq ($(UNAME_S),Linux)
	@set -e; \
	installer=$$(mktemp); \
	trap 'rm -f "$$installer"' EXIT; \
	curl -fsSL "$(XRAY_INSTALLER_URL)" -o "$$installer"; \
	$(XRAY_RESOLVE_TAG) \
	if [ "$(DISTRO)" = "debian" ] || [ "$(DISTRO)" = "ubuntu" ] || \
	   [ "$(DISTRO)" = "centos" ] || [ "$(DISTRO)" = "rhel" ] || [ "$(DISTRO)" = "fedora" ] || \
	   [ "$(DISTRO)" = "arch" ]; then \
		sudo bash "$$installer" --tag "$$tag" $(XRAY_INSTALL_ARGS); \
	else \
		bash "$$installer" --tag "$$tag" $(XRAY_INSTALL_ARGS); \
	fi
	@$(MAKE) --no-print-directory install_geofiles

else
	@echo "Unsupported operating system: $(UNAME_S)"
	@exit 1
endif

# sudo for install_geofiles, on the same distros where install_xray uses it; set GEOFILES_SUDO= to run without it.
GEOFILES_SUDO ?= $(if $(filter debian ubuntu centos rhel fedora arch,$(DISTRO)),sudo)

# Download the pinned geo files, fail unless each matches its pinned sha256, install them into GEOFILES_DIR
# (overwriting the files from the Xray zip), then run check_geofiles. Needs curl and sha256sum.
install_geofiles:
	@set -e; \
	tmp=$$(mktemp -d); \
	trap 'rm -rf "$$tmp"' EXIT; \
	url="https://github.com/$(GEOFILES_REPO)/releases/download/$(GEOFILES_TAG)"; \
	echo "Installing geo files from $(GEOFILES_REPO) $(GEOFILES_TAG) into $(GEOFILES_DIR)"; \
	fetch() { \
		ok=0; \
		for try in 1 2 3; do \
			if curl -fsSL "$$url/$$1" -o "$$tmp/$$1"; then ok=1; break; fi; \
			sleep 2; \
		done; \
		if [ "$$ok" -ne 1 ]; then \
			echo "error: cannot download $$1 from $(GEOFILES_REPO) $(GEOFILES_TAG)" >&2; \
			exit 1; \
		fi; \
		got=$$(sha256sum "$$tmp/$$1" | cut -d ' ' -f 1); \
		if [ "$$got" != "$$2" ]; then \
			echo "error: $$1 from $(GEOFILES_REPO) $(GEOFILES_TAG) has sha256 $$got, expected $$2" >&2; \
			exit 1; \
		fi; \
		echo "$$1: sha256 OK ($$got)"; \
	}; \
	fetch geoip.dat "$(GEOIP_SHA256)"; \
	fetch geosite.dat "$(GEOSITE_SHA256)"; \
	$(GEOFILES_SUDO) install -d "$(GEOFILES_DIR)"; \
	$(GEOFILES_SUDO) install -m 644 "$$tmp/geoip.dat" "$(GEOFILES_DIR)/geoip.dat"; \
	$(GEOFILES_SUDO) install -m 644 "$$tmp/geosite.dat" "$(GEOFILES_DIR)/geosite.dat"
	@$(MAKE) --no-print-directory check_geofiles

# Fail unless GEOFILES_XRAY prints "Configuration OK" for GEOFILES_CHECK_CONFIG with the files in GEOFILES_DIR.
# The config routes on codes the Xray zip's lite files lack (geoip:us, geosite:gfw, ...) and on the ones nodes use most.
# Skipped for a cross build (GOOS/GOARCH differ from the host), where the binary cannot run here. The geo files do not
# depend on the arch, so the native build checks them for every platform.
check_geofiles:
	@set -e; \
	host_os=$$(go env GOHOSTOS 2>/dev/null || uname -s | tr '[:upper:]' '[:lower:]'); \
	host_arch=$$(go env GOHOSTARCH 2>/dev/null || case "$$(uname -m)" in (x86_64) echo amd64 ;; (aarch64|arm64) echo arm64 ;; (*) uname -m ;; esac); \
	if { [ -n "$(GOOS)" ] && [ "$(GOOS)" != "$$host_os" ]; } || \
	   { [ -n "$(GOARCH)" ] && [ "$(GOARCH)" != "$$host_arch" ]; }; then \
		echo "Skipping the geo files check: cross build for $(GOOS)/$(GOARCH), $(GEOFILES_XRAY) cannot run on this host"; \
		exit 0; \
	fi; \
	status=0; \
	out=$$(XRAY_LOCATION_ASSET="$(GEOFILES_DIR)" "$(GEOFILES_XRAY)" run -test -c "$(GEOFILES_CHECK_CONFIG)" 2>&1) || status=$$?; \
	printf '%s\n' "$$out"; \
	case "$$out" in *"Configuration OK"*) ;; *) status=1 ;; esac; \
	if [ "$$status" -ne 0 ]; then \
		echo "error: $(GEOFILES_XRAY) cannot load $(GEOFILES_CHECK_CONFIG) with the geo files in $(GEOFILES_DIR)" >&2; \
		exit 1; \
	fi; \
	echo "Geo files check passed: $(GEOFILES_DIR)"

# Resolve the newest $(GEOFILES_REPO) release, check its geoip.dat and geosite.dat against the release's own
# .sha256sum files and print the GEOFILES_TAG, GEOIP_SHA256 and GEOSITE_SHA256 lines for the top of this file.
# The bump PR's CI (run-tests.yml runs make install_xray) then runs check_geofiles on the new files.
update_geofiles_pin:
	@set -e; \
	tmp=$$(mktemp -d); \
	trap 'rm -rf "$$tmp"' EXIT; \
	latest=$$(curl -fsSIL -o /dev/null -w '%{url_effective}' "https://github.com/$(GEOFILES_REPO)/releases/latest"); \
	tag=$${latest##*/releases/tag/}; \
	case "$$tag" in ""|*/*) echo "error: cannot resolve the latest $(GEOFILES_REPO) release from $$latest" >&2; exit 1 ;; esac; \
	url="https://github.com/$(GEOFILES_REPO)/releases/download/$$tag"; \
	for name in geoip.dat geosite.dat; do \
		curl -fsSL --retry 3 --retry-connrefused "$$url/$$name" -o "$$tmp/$$name"; \
		curl -fsSL --retry 3 --retry-connrefused "$$url/$$name.sha256sum" -o "$$tmp/$$name.sha256sum"; \
		(cd "$$tmp" && sha256sum -c "$$name.sha256sum") >&2; \
	done; \
	echo "GEOFILES_TAG ?= $$tag"; \
	echo "GEOIP_SHA256 ?= $$(sha256sum "$$tmp/geoip.dat" | cut -d ' ' -f 1)"; \
	echo "GEOSITE_SHA256 ?= $$(sha256sum "$$tmp/geosite.dat" | cut -d ' ' -f 1)"

install_wg: update_os
ifeq ($(UNAME_S),Linux)
	@echo "Installing WireGuard for $(DISTRO)..."
	if [ "$(DISTRO)" = "debian" ] || [ "$(DISTRO)" = "ubuntu" ]; then \
		sudo apt-get update && sudo apt-get install -y wireguard wireguard-tools; \
	elif [ "$(DISTRO)" = "centos" ] || [ "$(DISTRO)" = "rhel" ]; then \
		sudo yum install -y epel-release && sudo yum install -y wireguard-tools; \
	elif [ "$(DISTRO)" = "fedora" ]; then \
		sudo dnf install -y wireguard-tools; \
	elif [ "$(DISTRO)" = "arch" ] || [ "$(DISTRO)" = "manjaro" ]; then \
		sudo pacman -Sy --noconfirm wireguard-tools; \
	elif [ "$(DISTRO)" = "alpine" ]; then \
		apk add --no-cache wireguard-tools; \
	elif [ "$(DISTRO)" = "opensuse" ] || [ "$(DISTRO)" = "opensuse-leap" ] || [ "$(DISTRO)" = "opensuse-tumbleweed" ]; then \
		sudo zypper install -y wireguard-tools; \
	else \
		echo "Unsupported distribution: $(DISTRO)"; \
		exit 1; \
	fi
	@echo "WireGuard installed successfully"
	@wg --version
else
	@echo "Unsupported operating system: $(UNAME_S)"
	@exit 1
endif

test-integration:
	$(MAKE) test-integration-full

test-integration-full:
	GOTOOLCHAIN=auto TEST_INTEGRATION=true go test ./... -v -p 1
	GOTOOLCHAIN=auto go test -tags=integration -v -p 1 ./backend/wireguard

test-integration-wireguard:
	GOTOOLCHAIN=auto go test -tags=integration -v -p 1 ./backend/wireguard

test:
	GOTOOLCHAIN=auto TEST_INTEGRATION=false go test ./... -v -p 1

test-race-wireguard:
	GOTOOLCHAIN=auto CGO_ENABLED=1 go test -race -v -p 1 ./backend/wireguard

serve:
	go run ./cmd/node
