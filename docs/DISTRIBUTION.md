# Distribution and installation

The unreleased `0.10.0-alpha.2` development source line is currently available from the
repository only. It has no matching prebuilt release artifact, package-manager
repository, container registry, cloud marketplace, or orchestrated deployment
channel.

> Termivar is not production-ready. Review and pin the source commit, read the
> [runtime map](internals/runtime-map.md), and use the resulting binary only
> against systems you own or are explicitly authorized to test.

## Build from source

Requirements: Rust 1.88 or newer and Git.

```bash
git clone https://github.com/ITherso/termivar.git termivar
cd termivar
REVIEWED_COMMIT="REPLACE_WITH_THE_REVIEWED_FULL_COMMIT_SHA"
test "$REVIEWED_COMMIT" != "REPLACE_WITH_THE_REVIEWED_FULL_COMMIT_SHA"
git checkout --detach "$REVIEWED_COMMIT"
test "$(git rev-parse HEAD)" = "$REVIEWED_COMMIT"
cargo build --locked --release -p termivar-cli
./target/release/termivar --help
```

On Windows, the binary is `target\release\termivar.exe`.

PostgreSQL, Redis, Node.js, a dashboard, and an API service are not required by the CLI scan commands.

## Release status

`v0.10.0-alpha.1` is the latest published experimental prerelease. Current
`main` has advanced to the unreleased `0.10.0-alpha.2` development line, so no
published archive represents later source behavior. The historical
`v0.9.0-alpha` release predates the deterministic-default and legacy-authority
remediation and is not a supported installation path for the behavior
documented here.

Future tags must use the archive, checksum, and provenance contract in
[Release Process](RELEASE.md). For unreleased behavior, build a reviewed,
pinned commit from source rather than substituting an older archive.

## Local container build

The repository Dockerfile is built in CI and can package the current CLI locally:

```bash
docker build -t termivar:local .
docker run --rm termivar:local --help
```

The image's default command is `termivar --help`; it does not open a listener or contact a target. Pass an explicit deterministic `scan` command and an authorized reachable origin when using the image for an assessment. The non-default API and proxy adapters are not compiled into this image.

Repository workflows do not publish a supported image to Docker Hub or GHCR,
and no `latest`, `slim`, or `full` image contract is promised. A maintainer may
manually build and optionally publish a commit-scoped development image; that
manual artifact is not an installation channel or a release image.

## Unsupported channels

The following installation/deployment claims are **not** supported for this source state:

- Homebrew, Apt/PPA, Pacman/AUR, Snap, Chocolatey, Scoop, or crates.io packages;
- quick-install scripts from a vanity domain;
- Docker Hub or GitHub Container Registry images;
- Kubernetes, Helm, Terraform, Docker Compose, or a PostgreSQL/Redis service stack;
- AWS, Azure, or GCP marketplace images;
- automatic update checks or signed release binaries.

The historical root `docker-compose.yml` was removed. It coupled the CLI to
unused PostgreSQL/Redis services, default credentials, disabled security, and a
listener the default image did not provide. The architecture gate rejects a
replacement root Compose manifest while deployment status remains unsupported.
There is no supported repository installer until a remediated release exists.

The non-deployable [deployment blueprint](experimental/deployment-blueprint.md) records prerequisites that must exist before orchestrated manifests can become executable product artifacts.

## Verify the source-built binary

```bash
termivar --version
termivar --help
termivar scan --help
```

The supported CLI truth is documented in [Getting Started](GETTING_STARTED.md).
`termivar scan` is the bounded deterministic Preview, while `decision-scan` is its
deprecated compatibility alias. The mixed-authority `legacy-scan` (whose
complete run remains `Unmetered`), Preview local-file `artifact`, unsupported
`api`, and experimental `proxy` adapters are absent from default builds and
require explicit Cargo features. The artifact adapter reads only one explicitly
selected regular file and reports signature observations; it is not a machine
scanner, malware verifier, or distribution channel.

## Reporting problems

- [GitHub issues](https://github.com/ITherso/termivar/issues)
- [GitHub discussions](https://github.com/ITherso/termivar/discussions)
- [Security policy](https://github.com/ITherso/termivar/blob/main/SECURITY.md)
