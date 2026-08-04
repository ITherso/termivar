#!/bin/bash
# Venom v0.9.0-alpha installer
# Supports: macOS, Linux (Ubuntu/Debian/Arch), Windows (WSL), Docker

set -e

VERSION="0.9.0-alpha"
REPO="ITherso/venom"
GITHUB_API="https://api.github.com/repos/${REPO}"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}🐍 VENOM v${VERSION} Installer${NC}"
echo "════════════════════════════════════════════"

# Detect system
detect_system() {
    local system=$(uname -s)
    local arch=$(uname -m)

    case "${system}" in
        Darwin)
            OS="macos"
            case "${arch}" in
                arm64) ARCH="aarch64" ;;
                x86_64) ARCH="x86_64" ;;
                *) echo -e "${RED}❌ Unsupported architecture: ${arch}${NC}"; exit 1 ;;
            esac
            ;;
        Linux)
            OS="linux"
            case "${arch}" in
                x86_64) ARCH="x86_64" ;;
                aarch64) ARCH="aarch64" ;;
                *) echo -e "${RED}❌ Unsupported architecture: ${arch}${NC}"; exit 1 ;;
            esac

            # Detect Linux distro
            if [ -f /etc/os-release ]; then
                . /etc/os-release
                DISTRO="${ID}"
            else
                DISTRO="unknown"
            fi
            ;;
        MINGW*|MSYS*|CYGWIN*)
            OS="windows"
            ARCH="x86_64"
            ;;
        *)
            echo -e "${RED}❌ Unsupported OS: ${system}${NC}"
            exit 1
            ;;
    esac

    echo -e "${GREEN}✅ Detected: ${OS} ${ARCH}${NC}"
}

# Install via package manager
install_via_package_manager() {
    echo -e "${YELLOW}📦 Installing via package manager...${NC}"

    case "${OS}" in
        macos)
            if command -v brew &> /dev/null; then
                echo -e "${BLUE}Using Homebrew...${NC}"
                brew tap itherso/venom
                brew install venom
            else
                echo -e "${YELLOW}Homebrew not found. Installing via direct download...${NC}"
                install_via_github_release
            fi
            ;;
        linux)
            case "${DISTRO}" in
                ubuntu|debian)
                    echo -e "${BLUE}Using apt...${NC}"
                    sudo apt-get update
                    sudo apt-get install -y venom
                    ;;
                arch)
                    echo -e "${BLUE}Using pacman...${NC}"
                    sudo pacman -S venom
                    ;;
                *)
                    echo -e "${YELLOW}Package manager not supported. Installing via direct download...${NC}"
                    install_via_github_release
                    ;;
            esac
            ;;
        windows)
            if command -v choco &> /dev/null; then
                echo -e "${BLUE}Using Chocolatey...${NC}"
                choco install venom
            elif command -v scoop &> /dev/null; then
                echo -e "${BLUE}Using Scoop...${NC}"
                scoop install venom
            else
                echo -e "${YELLOW}No package manager found. Installing via direct download...${NC}"
                install_via_github_release
            fi
            ;;
    esac
}

# Install via GitHub Release
install_via_github_release() {
    echo -e "${YELLOW}📥 Downloading from GitHub...${NC}"

    # Determine target
    case "${OS}" in
        macos) TARGET="apple-darwin" ;;
        linux) TARGET="unknown-linux-gnu" ;;
        windows) TARGET="pc-windows-msvc" ;;
    esac

    DOWNLOAD_URL="https://github.com/${REPO}/releases/download/v${VERSION}/venom-${VERSION}-${ARCH}-${TARGET}"
    if [ "${OS}" == "windows" ]; then
        DOWNLOAD_URL="${DOWNLOAD_URL}.exe"
    fi

    INSTALL_DIR="${HOME}/.local/bin"
    mkdir -p "${INSTALL_DIR}"

    echo -e "${BLUE}Downloading: ${DOWNLOAD_URL}${NC}"
    curl -fsSL "${DOWNLOAD_URL}" -o "${INSTALL_DIR}/venom"
    chmod +x "${INSTALL_DIR}/venom"

    # Add to PATH
    if [[ ":${PATH}:" != *":${INSTALL_DIR}:"* ]]; then
        echo -e "${YELLOW}Adding ${INSTALL_DIR} to PATH...${NC}"
        echo "export PATH=\"${INSTALL_DIR}:\$PATH\"" >> "${HOME}/.bashrc"
        echo "export PATH=\"${INSTALL_DIR}:\$PATH\"" >> "${HOME}/.zshrc"
        export PATH="${INSTALL_DIR}:${PATH}"
    fi

    echo -e "${GREEN}✅ Installed to: ${INSTALL_DIR}/venom${NC}"
}

# Install via Docker
install_via_docker() {
    echo -e "${BLUE}🐳 Installing Docker image...${NC}"

    if ! command -v docker &> /dev/null; then
        echo -e "${RED}❌ Docker not installed. Please install Docker first.${NC}"
        return 1
    fi

    docker pull "ghcr.io/itherso/venom:${VERSION}"

    # Create wrapper script
    INSTALL_DIR="${HOME}/.local/bin"
    mkdir -p "${INSTALL_DIR}"

    cat > "${INSTALL_DIR}/venom" << 'EOF'
#!/bin/bash
docker run --rm -v $(pwd):/app -p 8080:8080 \
    ghcr.io/itherso/venom:0.9.0-alpha "$@"
EOF

    chmod +x "${INSTALL_DIR}/venom"
    echo -e "${GREEN}✅ Docker image installed${NC}"
}

# Install via Cargo
install_via_cargo() {
    echo -e "${BLUE}📦 Installing via Cargo...${NC}"

    if ! command -v cargo &> /dev/null; then
        echo -e "${RED}❌ Rust/Cargo not installed${NC}"
        return 1
    fi

    cargo install venom
    echo -e "${GREEN}✅ Installed via Cargo${NC}"
}

# Verify installation
verify_installation() {
    echo -e "${YELLOW}🔍 Verifying installation...${NC}"

    if command -v venom &> /dev/null; then
        local installed_version=$(venom --version | grep -oP '\d+\.\d+\.\d+')
        echo -e "${GREEN}✅ VENOM ${installed_version} installed successfully!${NC}"
        return 0
    else
        echo -e "${RED}❌ Installation verification failed${NC}"
        return 1
    fi
}

# Show help
show_help() {
    cat << EOF
${BLUE}VENOM v${VERSION} Installation Methods:${NC}

Usage: ./install.sh [METHOD]

Methods:
  package-manager   Install via system package manager (default)
  github-release    Download binary from GitHub
  docker            Use Docker image
  cargo             Install via Rust Cargo
  help              Show this help message

Examples:
  ./install.sh                    # Auto-detect and use best method
  ./install.sh package-manager    # Use apt/brew/pacman
  ./install.sh docker             # Use Docker image
  ./install.sh cargo              # Install via Cargo

EOF
}

# Main
main() {
    detect_system

    local method="${1:-package-manager}"

    case "${method}" in
        package-manager)
            install_via_package_manager
            ;;
        github-release)
            install_via_github_release
            ;;
        docker)
            install_via_docker
            ;;
        cargo)
            install_via_cargo
            ;;
        help|--help|-h)
            show_help
            exit 0
            ;;
        *)
            echo -e "${RED}❌ Unknown method: ${method}${NC}"
            show_help
            exit 1
            ;;
    esac

    echo ""
    verify_installation

    echo ""
    echo -e "${GREEN}════════════════════════════════════════════${NC}"
    echo -e "${BLUE}🚀 Next steps:${NC}"
    echo "  1. Start the proxy:     venom proxy --addr 0.0.0.0:8080"
    echo "  2. View help:           venom --help"
    echo "  3. Read docs:           https://github.com/ITherso/venom/docs"
    echo ""
}

main "$@"
