# Distribution and installation

Venom `0.9.0-alpha` is distributed as source and as prerelease archives attached to GitHub Releases. It is not published through a supported package-manager repository, container registry, cloud marketplace, or orchestrated deployment channel.

> Venom is not production-ready. Verify release artifacts, read the [runtime map](internals/runtime-map.md), and use the binary only against systems you own or are explicitly authorized to test.

## Build from source

Requirements: Rust 1.88 or newer and Git.

```bash
git clone https://github.com/ITherso/venom.git
cd venom
cargo build --locked --release -p venom-cli
./target/release/venom --help
```

On Windows, the binary is `target\release\venom.exe`.

PostgreSQL, Redis, Node.js, a dashboard, and an API service are not required by the CLI scan commands.

## GitHub prerelease archives

The [`v0.9.0-alpha` prerelease](https://github.com/ITherso/venom/releases/tag/v0.9.0-alpha) publishes these archives:

| Target | Archive |
| --- | --- |
| Linux x86_64 GNU | `venom-v0.9.0-alpha-x86_64-unknown-linux-gnu.tar.gz` |
| macOS x86_64 | `venom-v0.9.0-alpha-x86_64-apple-darwin.tar.gz` |
| macOS Apple Silicon | `venom-v0.9.0-alpha-aarch64-apple-darwin.tar.gz` |
| Windows x86_64 MSVC | `venom-v0.9.0-alpha-x86_64-pc-windows-msvc.zip` |

The release also includes `SHA256SUMS`. Download the checksum file and the selected archive into the same directory, then verify before extraction:

```bash
sha256sum --check --ignore-missing SHA256SUMS
```

On macOS, select the downloaded archive's line before checking (replace the archive name as needed):

```bash
grep 'venom-v0.9.0-alpha-aarch64-apple-darwin.tar.gz' SHA256SUMS | shasum -a 256 -c -
```

On Windows, compare `Get-FileHash -Algorithm SHA256 <archive>` with the corresponding line in `SHA256SUMS`.

The release does not publish a GPG signature. GitHub Actions generates build-provenance attestations for tag builds; checksums and attestations are evidence about the artifact build, not a production-readiness claim.

## Local container build

The repository Dockerfile is built in CI and can package the current CLI locally:

```bash
docker build -t venom:local .
docker run --rm venom:local --help
```

The image's default command is `venom --help`; it does not open a listener or contact a target. Pass an explicit deterministic `scan` command and an authorized reachable origin when using the image for an assessment. The non-default API and proxy adapters are not compiled into this image.

Repository workflows do not publish a supported image to Docker Hub or GHCR, and no `latest`, `slim`, or `full` image contract is promised.

## Unsupported channels

The following installation/deployment claims are **not** supported for `0.9.0-alpha`:

- Homebrew, Apt/PPA, Pacman/AUR, Snap, Chocolatey, Scoop, or crates.io packages;
- `get.venom.dev` quick-install scripts;
- Docker Hub or GitHub Container Registry images;
- Kubernetes, Helm, Terraform, Docker Compose, or a PostgreSQL/Redis service stack;
- AWS, Azure, or GCP marketplace images;
- automatic update checks or signed release binaries.

The repository-root `install.sh` and `docker-compose.yml` are historical experimental artifacts. They contain unverified package/container assumptions and are not supported installation paths. Do not use them as release instructions.

The non-deployable [deployment blueprint](experimental/deployment-blueprint.md) records prerequisites that must exist before orchestrated manifests can become executable product artifacts.

## Verify the installed binary

```bash
venom --version
venom --help
venom scan --help
```

The supported CLI truth is documented in [Getting Started](GETTING_STARTED.md). `venom scan` is the bounded deterministic Preview, while `decision-scan` is its deprecated compatibility alias. The direct-I/O `legacy-scan`, unsupported `api`, and experimental `proxy` adapters are absent from default builds and require explicit Cargo features.

## Reporting problems

- [GitHub issues](https://github.com/ITherso/venom/issues)
- [GitHub discussions](https://github.com/ITherso/venom/discussions)
- [Security policy](https://github.com/ITherso/venom/blob/main/SECURITY.md)
