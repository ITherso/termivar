# VENOM Distribution & Installation Guide

Planned distribution channels for Venom v0.9.0-alpha.

> **Orchestrated deployment is not currently available.** Venom `0.9.0-alpha`
> ships no supported Helm chart, Terraform stack, or Kubernetes deployment, and
> the container does not expose a working API server. The Kubernetes/Helm and
> multi-service Docker Compose sections below describe *intended* future channels,
> not working ones. See the non-deployable
> [deployment blueprint](experimental/deployment-blueprint.md) for the current
> status and the contracts required before executable manifests may return.

## Installation Overview

```
VENOM Installation Methods
├─ Quick Install (recommended)
│  └─ curl -fsSL https://get.venom.dev/install.sh | bash
├─ Package Managers
│  ├─ Homebrew (macOS)
│  ├─ Apt (Debian/Ubuntu)
│  ├─ Pacman (Arch)
│  ├─ Chocolatey (Windows)
│  └─ Cargo (Rust developers)
├─ Container Images
│  ├─ Docker Hub
│  └─ GitHub Container Registry
│  (Kubernetes/Helm: planned, not currently available)
├─ Cloud Marketplace
│  ├─ AWS AMI
│  ├─ Azure VM Image
│  └─ GCP Custom Image
└─ Manual Download
   ├─ GitHub Releases
   ├─ Signed binaries
   └─ Checksum verification
```

## Quick Installation

### macOS

```bash
# Via Homebrew (recommended)
brew install itherso/venom/venom

# Via direct download
curl -fsSL https://get.venom.dev/install.sh | bash

# Via Cargo
cargo install venom
```

### Linux (Ubuntu/Debian)

```bash
# Via apt
sudo apt-get update
sudo apt-get install venom

# Via snap
sudo snap install venom

# Via direct download
curl -fsSL https://get.venom.dev/install.sh | bash
```

### Linux (Arch)

```bash
# Via pacman
sudo pacman -S venom

# Via AUR
yay -S venom
```

### Windows

```powershell
# Via Chocolatey
choco install venom

# Via Scoop
scoop install venom

# Via direct download
Invoke-WebRequest -Uri "https://get.venom.dev/install.ps1" -OutFile "install.ps1"
.\install.ps1
```

### Docker

```bash
# Pull latest image
docker pull ghcr.io/itherso/venom:latest

# Run container
docker run -p 8080:8080 -p 3000:3000 ghcr.io/itherso/venom:latest

# Run with volume mount
docker run -v $(pwd):/app -p 8080:8080 -p 3000:3000 ghcr.io/itherso/venom:latest
```

### Kubernetes

Not currently available. There is no supported Helm chart or Kubernetes
deployment for `0.9.0-alpha`; the previously tracked manifests were removed
because they could not render or run. See the
[deployment blueprint](experimental/deployment-blueprint.md).

## Package Managers

### Homebrew (macOS)

**Setup:**
```bash
# Add tap
brew tap itherso/venom https://github.com/ITherso/homebrew-venom

# Install
brew install venom

# Upgrade
brew upgrade venom
```

**Formula Location:** `https://github.com/ITherso/homebrew-venom`

### Apt (Ubuntu/Debian)

**Setup:**
```bash
# Add PPA
sudo add-apt-repository ppa:itherso/venom

# Update package list
sudo apt-get update

# Install
sudo apt-get install venom

# Upgrade
sudo apt-get upgrade venom
```

**Repository:** `https://ppa.launchpad.net/itherso/venom/ubuntu`

### Pacman (Arch Linux)

**Setup:**
```bash
# Install from AUR
yay -S venom

# Or manually
git clone https://aur.archlinux.org/venom.git
cd venom
makepkg -si
```

**AUR Package:** `https://aur.archlinux.org/packages/venom`

### Chocolatey (Windows)

**Setup:**
```powershell
# Install package
choco install venom

# Upgrade
choco upgrade venom
```

**Package:** `https://chocolatey.org/packages/venom`

### Cargo (Rust)

**Install:**
```bash
cargo install venom

# Update
cargo install --force venom
```

**Package:** `https://crates.io/crates/venom`

## Container Images

### Docker Hub

**Images:**
```bash
# Latest version
docker pull ghcr.io/itherso/venom:latest

# Specific version
docker pull ghcr.io/itherso/venom:0.9.0-alpha

# Slim image (minimal)
docker pull ghcr.io/itherso/venom:0.9.0-alpha-slim

# Full image (with tools)
docker pull ghcr.io/itherso/venom:0.9.0-alpha-full
```

**Run Examples:**
```bash
# Basic run
docker run ghcr.io/itherso/venom:latest

# With port forwarding
docker run -p 8080:8080 -p 3000:3000 ghcr.io/itherso/venom:latest

# With volume mount
docker run -v ~/venom-data:/app/data ghcr.io/itherso/venom:latest

# With environment variables
docker run -e RUST_LOG=debug ghcr.io/itherso/venom:latest

# Interactive with shell
docker run -it ghcr.io/itherso/venom:latest /bin/bash
```

### Kubernetes / Helm

Not currently available. No Helm chart, autoscaling, ingress, or high-availability
deployment is supported for `0.9.0-alpha`. The contracts that must exist before a
chart can return are listed in the
[deployment blueprint](experimental/deployment-blueprint.md).

### Docker Compose

No supported multi-service stack ships today. The container runs the proxy on
`8080`; it does not provide the previously documented API server on `3000`, and
the scanner/proxy do not integrate a PostgreSQL or Redis runtime dependency. A
supported PostgreSQL/Redis-backed stack is out of scope for `0.9.0-alpha`; see the
[deployment blueprint](experimental/deployment-blueprint.md).

## GitHub Releases

### Binary Downloads

**Available for:**
- macOS (arm64, x86_64)
- Linux (x86_64, aarch64, glibc, musl)
- Windows (x86_64, MSVC)

**Download URL Pattern:**
```
https://github.com/ITherso/venom/releases/download/v0.9.0-alpha/venom-0.9.0-alpha-{os}-{arch}
```

**Examples:**
```bash
# macOS arm64
curl -L https://github.com/ITherso/venom/releases/download/v0.9.0-alpha/venom-0.9.0-alpha-aarch64-apple-darwin -o venom
chmod +x venom

# Linux x86_64
curl -L https://github.com/ITherso/venom/releases/download/v0.9.0-alpha/venom-0.9.0-alpha-x86_64-unknown-linux-gnu -o venom
chmod +x venom

# Windows x86_64
Invoke-WebRequest -Uri "https://github.com/ITherso/venom/releases/download/v0.9.0-alpha/venom-0.9.0-alpha-x86_64-pc-windows-msvc.exe" -OutFile "venom.exe"
```

### Verification

**Verify SHA256 checksums:**
```bash
# Download checksums
curl -L https://github.com/ITherso/venom/releases/download/v0.9.0-alpha/SHA256SUMS -o SHA256SUMS

# Verify (macOS/Linux)
shasum -a 256 -c SHA256SUMS

# Verify (Windows PowerShell)
(Get-FileHash -Path venom.exe -Algorithm SHA256).Hash -eq (Get-Content SHA256SUMS)
```

**Verify GPG signature:**
```bash
# Download signature
curl -L https://github.com/ITherso/venom/releases/download/v0.9.0-alpha/venom.asc -o venom.asc

# Import public key
gpg --import https://keybase.io/itherso/pgp_keys.asc

# Verify
gpg --verify venom.asc venom
```

## Cloud Marketplace

### AWS

**AMI Details:**
- Region: Global (available in all regions)
- Architecture: x86_64
- Root volume: 30GB (gp3)
- Security group: HTTP/HTTPS pre-configured

**Launch:**
```bash
# Find AMI
aws ec2 describe-images --owners self --filters "Name=name,Values=venom-*"

# Launch instance
aws ec2 run-instances \
  --image-id ami-xxxxxxxxx \
  --instance-type t3.medium \
  --key-name your-key \
  --security-groups venom-sg
```

### Azure

**VM Image:**
- Publisher: ITherso
- Offer: venom
- SKU: 1-0-0
- Size: Standard_B2s (recommended)

**Deploy:**
```bash
az vm create \
  --resource-group myResourceGroup \
  --name venom-vm \
  --image UbuntuLTS \
  --admin-username azureuser \
  --generate-ssh-keys
```

### GCP

**Custom Image:**
- Image family: venom
- Architecture: x86_64
- Boot disk: 30GB

**Deploy:**
```bash
gcloud compute instances create venom-instance \
  --image-family=venom \
  --image-project=itherso-venom \
  --machine-type=n1-standard-2 \
  --zone=us-central1-a
```

## Build from Source

### Prerequisites

- Rust 1.70+
- PostgreSQL 12+ (optional)
- Redis 6+ (optional)
- Node.js 16+ (for frontend)

### Build Steps

```bash
# Clone repository
git clone https://github.com/ITherso/venom.git
cd venom

# Build backend
cargo build --release

# Build frontend
cd web
npm install
npm run build
cd ..

# Binary location
./target/release/venom
```

### Custom Configuration

```bash
# Build with specific features
cargo build --release --features "postgres,redis"

# Build for specific target
cargo build --release --target x86_64-unknown-linux-musl

# Optimized build
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

## Installation Verification

### Verify Installation

```bash
# Check version
venom --version

# Check installation path
which venom

# Run help
venom --help

# Test connectivity
curl http://localhost:3000
```

### Troubleshooting

**Command not found:**
```bash
# Check PATH
echo $PATH

# Add to PATH permanently
export PATH="$PATH:~/.local/bin"
echo 'export PATH="$PATH:~/.local/bin"' >> ~/.bashrc
```

**Permission denied:**
```bash
# Fix permissions
chmod +x /path/to/venom
```

**Port already in use:**
```bash
# Check what's using port 8080
lsof -i :8080

# Use different port
venom --proxy-port 9090
```

## Updates & Upgrades

### Auto-update

VENOM includes automatic update checking (can be disabled):

```bash
# Disable auto-updates
export VENOM_AUTO_UPDATE=false

# Force check for updates
venom --check-updates
```

### Manual Upgrade

**Via package manager:**
```bash
# macOS
brew upgrade venom

# Ubuntu/Debian
sudo apt-get upgrade venom

# Arch
sudo pacman -S venom

# Chocolatey
choco upgrade venom
```

**Via Cargo:**
```bash
cargo install --force venom
```

**Docker:**
```bash
docker pull ghcr.io/itherso/venom:latest
```

## Uninstallation

### Remove via Package Manager

```bash
# macOS
brew uninstall venom

# Ubuntu/Debian
sudo apt-get remove venom

# Arch
sudo pacman -R venom

# Chocolatey
choco uninstall venom

# Cargo
cargo uninstall venom
```

### Remove Docker Image

```bash
docker rmi ghcr.io/itherso/venom:latest
```

## Support & Issues

- **GitHub Issues:** https://github.com/ITherso/venom/issues
- **Discussions:** https://github.com/ITherso/venom/discussions
- **Security:** security@venom.dev
