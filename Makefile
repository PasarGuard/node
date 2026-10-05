NAME = pasarguard-node-$(GOOS)-$(GOARCH)

LDFLAGS = -s -w -buildid=
PARAMS = -trimpath -ldflags "$(LDFLAGS)" -v
MAIN = ./cmd/node
PREFIX ?= $(shell go env GOPATH)
XRAY_OS ?=
XRAY_ARCH ?=
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
XRAY_INSTALL_ARGS   := $(strip $(if $(XRAY_OS_EFFECTIVE),--os $(XRAY_OS_EFFECTIVE)) $(if $(XRAY_ARCH_EFFECTIVE),--arch $(XRAY_ARCH_EFFECTIVE)))

ifeq ($(GOOS),windows)
OUTPUT = $(NAME).exe
ADDITION = go build -o w$(NAME).exe -trimpath -ldflags "-H windowsgui $(LDFLAGS)" -v $(MAIN)
else
OUTPUT = $(NAME)
endif

ifeq ($(shell echo "$(GOARCH)" | grep -Eq "(mips|mipsle)" && echo true),true)
ADDITION = GOMIPS=softfloat go build -o $(NAME)_softfloat -trimpath -ldflags "$(LDFLAGS)" -v $(MAIN)
endif

.PHONY: clean build test test-race-wireguard test-integration test-integration-full test-integration-wireguard

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
	# Debian/Ubuntu, CentOS, Fedora, Arch → Use sudo
	if [ "$(DISTRO)" = "debian" ] || [ "$(DISTRO)" = "ubuntu" ] || \
	   [ "$(DISTRO)" = "centos" ] || [ "$(DISTRO)" = "rhel" ] || [ "$(DISTRO)" = "fedora" ] || \
	   [ "$(DISTRO)" = "arch" ]; then \
		curl -L https://github.com/PasarGuard/scripts/raw/main/install_core.sh | sudo bash -s -- $(XRAY_INSTALL_ARGS); \
	else \
		curl -L https://github.com/PasarGuard/scripts/raw/main/install_core.sh | bash -s -- $(XRAY_INSTALL_ARGS); \
	fi

else
	@echo "Unsupported operating system: $(UNAME_S)"
	@exit 1
endif

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

SINGBOX_VERSION ?= 1.14.2

# Install the official sing-box release. Official binaries do NOT include
# v2ray_api (per-user traffic stats); use `make build_singbox_v2api` for a
# stats-capable build (see docs/singbox/README.md).
install_singbox: update_os
ifeq ($(UNAME_S),Linux)
	@echo "Installing sing-box $(SINGBOX_VERSION)..."
	@arch=$$(uname -m); \
	case $$arch in \
		x86_64)  sb_arch=amd64 ;; \
		aarch64) sb_arch=arm64 ;; \
		armv7l)  sb_arch=armv7 ;; \
		*) echo "unsupported architecture: $$arch"; exit 1 ;; \
	esac; \
	curl -fsSL -o /tmp/sing-box.tar.gz "https://github.com/SagerNet/sing-box/releases/download/v$(SINGBOX_VERSION)/sing-box-$(SINGBOX_VERSION)-linux-$$sb_arch.tar.gz" && \
	(tar -xzf /tmp/sing-box.tar.gz -C /tmp || sudo tar -xzf /tmp/sing-box.tar.gz -C /tmp) && \
	(install /tmp/sing-box-$(SINGBOX_VERSION)-linux-$$sb_arch/sing-box /usr/local/bin/sing-box || \
	 sudo install /tmp/sing-box-$(SINGBOX_VERSION)-linux-$$sb_arch/sing-box /usr/local/bin/sing-box) && \
	rm -rf /tmp/sing-box* && \
	sing-box version
else
	@echo "Unsupported operating system: $(UNAME_S)"
	@exit 1
endif

# Build sing-box from source with -tags with_v2ray_api and install it to
# /usr/local/bin/sing-box. Required for per-user traffic stats; needs a Go
# toolchain (>= the version sing-box requires for this tag release).
build_singbox_v2api:
	@echo "Building sing-box $(SINGBOX_VERSION) with with_v2ray_api..."
	rm -rf /tmp/sing-box-src
	git clone --depth 1 --branch v$(SINGBOX_VERSION) https://github.com/SagerNet/sing-box /tmp/sing-box-src
	cd /tmp/sing-box-src && go build \
		-tags "with_v2ray_api,with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api,with_tailscale" \
		-ldflags "-X 'github.com/sagernet/sing-box/constant.Version=$(SINGBOX_VERSION)' -s -w" \
		-o sing-box ./cmd/sing-box
	(install /tmp/sing-box-src/sing-box /usr/local/bin/sing-box || \
	 sudo install /tmp/sing-box-src/sing-box /usr/local/bin/sing-box)
	rm -rf /tmp/sing-box-src
	sing-box version

# Hysteria2 (HyNetworks/hysteria, MIT). Pinned in docs/multi/UPSTREAM.md:15 at
# app/v2.13.0, assets hysteria-linux-amd64 / hysteria-windows-amd64.exe (raw, no
# archive). The sha256 is checked because an unpinned proxy binary on a node is a
# supply-chain hole, not a convenience.
HYSTERIA_VERSION ?= 2.13.0
HYSTERIA_REPO ?= HyNetworks/hysteria
# sha256 of the released asset for this version/arch, from docs/multi/UPSTREAM.md
# (the `?` column there means upstream publishes no checksum file, so these were
# computed by the verifier from the downloaded asset).
HYSTERIA_SHA256_linux_amd64 ?= 907ba8c9693edb104b20582681fb7dc15639d5b64a9cbb616a7b539190a86691
HYSTERIA_SHA256_linux_arm64 ?=
HYSTERIA_SHA256_windows_amd64 ?= 162ef8fe55dc7ec810dda662908f8e65ec36bd6da39cb87c3bd66184ab68f067

# install_hysteria fetches the pinned release and refuses a hash mismatch.
install_hysteria: update_os
ifeq ($(UNAME_S),Linux)
	@echo "Installing hysteria $(HYSTERIA_VERSION) for $(GOARCH)..."
	@arch=$$(uname -m); \
	case $$arch in \
		x86_64)  hy_arch=amd64; hy_sha="$(HYSTERIA_SHA256_linux_amd64)" ;; \
		aarch64) hy_arch=arm64; hy_sha="$(HYSTERIA_SHA256_linux_arm64)" ;; \
		*) echo "unsupported architecture: $$arch"; exit 1 ;; \
	esac; \
	if [ -z "$$hy_sha" ]; then echo "no pinned sha256 for $$hy_arch; refusing to install"; exit 1; fi; \
	curl -fsSL -o /tmp/hysteria "https://github.com/$(HYSTERIA_REPO)/releases/download/app/v$(HYSTERIA_VERSION)/hysteria-linux-$$hy_arch" && \
	echo "$$hy_sha  /tmp/hysteria" | sha256sum -c - && \
	(install /tmp/hysteria /usr/local/bin/hysteria || sudo install /tmp/hysteria /usr/local/bin/hysteria) && \
	rm -f /tmp/hysteria && \
	hysteria version
else
	@echo "Unsupported operating system: $(UNAME_S)"
	@exit 1
endif

# test-hysteria runs the hysteria2 loopback suite against the pinned binary.
# Every test in backend/hysteria skips without HYSTERIA_TEST_BINARY, so this is
# opt-in rather than silently skipped by the default `make test`.
test-hysteria:
	HYSTERIA_TEST_BINARY="$${HYSTERIA_TEST_BINARY:-/usr/local/bin/hysteria}" \
		GOTOOLCHAIN=auto go test -v -p 1 ./backend/hysteria
