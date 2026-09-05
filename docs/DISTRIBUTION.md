# Distribution and installation

Choose a binary deliberately. Neither line is production-ready or independently
audited; the published prerelease does not acquire later source fixes.

| Choice | Exact identity | Build features |
| --- | --- | --- |
| Published prerelease | [v0.10.0-alpha.1](https://github.com/ITherso/termivar/releases/tag/v0.10.0-alpha.1), release ID `382219595`, tag commit `2212b2590c6193a18915dcd33ad2bb31e1a9ef7b` | Existing `release-bundle` |
| Reviewed development source | `0.10.0-alpha.2` at `a29ba40c8cfdc7d0385431ea4d9e374e213ca4e0` | Default CLI build, or explicit `release-bundle` |

The CLI's default feature list is empty; its scanner dependency enables
`scanning` and `reporting`. The existing release bundle additionally compiles
`artifact-adapter`, `normalization-resilience`, `graphql-review`,
`openapi-review`, `rest-review`, and `authorization-review`. Compiling these
features does not opt into their runtime actions. The bundle excludes OAST,
the legacy runner, the unsupported API listener, and the experimental proxy.

The alpha.1 archives predate PRs #109–#111. Do not use the older prerelease for
credentialed or production evaluation. The walkthrough is credential-free and
loopback-only. See the [maintenance record](audits/native-oast-corrective-maintenance.md)
for the later fixes and unresolved F3; no OAST setup is part of this guide.

## Before either path

The archived binary needs no Rust toolchain. The walkthrough and archive
inspection use Python **3.12.4 or newer**, standard library only. Windows needs
that minimum for the helper's
[private-directory creation](https://docs.python.org/3.12/library/os.html#os.mkdir).
Source compilation also needs Git, Rust 1.88 or newer, and the platform's linker.

Use a reviewed checkout containing this guide, `scripts/first_use.py`, and
`scripts/verify_release_archive.py` as the **tools checkout**. Git is needed to
obtain that checkout; the scripts are not inside the published binary archive.
If you do not already have one, start in a private, user-owned parent directory
and clone into a new directory (the same commands work in PowerShell):

```text
git clone https://github.com/ITherso/termivar.git termivar-first-use-tools
cd termivar-first-use-tools
git rev-parse HEAD
```

Run the remaining commands from that checkout's root. Inspect the scripts and
record the full revision printed above; it identifies the tools you actually
obtained, not the pinned source binary or the published release.
If either script is absent, stop: the alpha.1 tag and the pinned development
revision below predate these walkthrough tools. Do not switch this tools
checkout to the older source revision; use the separate source tree below.

No step needs administrator privileges, global PATH changes, execution-policy
changes, Gatekeeper bypass, or disabled antivirus/App Control. If host security
blocks a binary, leave it blocked and report the unexecuted step.

## Try the published prerelease

Download only your matching archive and the exact release's
[SHA256SUMS](https://github.com/ITherso/termivar/releases/download/v0.10.0-alpha.1/SHA256SUMS).

| Platform | Archive |
| --- | --- |
| Linux x86_64 (GNU) | [termivar-v0.10.0-alpha.1-x86_64-unknown-linux-gnu.tar.gz](https://github.com/ITherso/termivar/releases/download/v0.10.0-alpha.1/termivar-v0.10.0-alpha.1-x86_64-unknown-linux-gnu.tar.gz) |
| macOS Apple Silicon | [termivar-v0.10.0-alpha.1-aarch64-apple-darwin.tar.gz](https://github.com/ITherso/termivar/releases/download/v0.10.0-alpha.1/termivar-v0.10.0-alpha.1-aarch64-apple-darwin.tar.gz) |
| macOS Intel | [termivar-v0.10.0-alpha.1-x86_64-apple-darwin.tar.gz](https://github.com/ITherso/termivar/releases/download/v0.10.0-alpha.1/termivar-v0.10.0-alpha.1-x86_64-apple-darwin.tar.gz) |
| Windows x86_64 (MSVC) | [termivar-v0.10.0-alpha.1-x86_64-pc-windows-msvc.zip](https://github.com/ITherso/termivar/releases/download/v0.10.0-alpha.1/termivar-v0.10.0-alpha.1-x86_64-pc-windows-msvc.zip) |

The helper selects the **single exact filename** in the checksum manifest,
rejects missing, duplicate, or malformed entries, and compares the archive
digest. You do not need the other three archives. It then inspects the archive
and refuses unexpected names, absolute/traversing paths, links, and an
unexpected executable. Extraction re-verifies and uses a fresh private
destination whose parent already exists and is trusted. It never overwrites,
downloads, installs, or executes anything.

Checksum agreement checks bytes against the manifest, not independent safety
or platform code signing. Build provenance is separate: see the
[release contract](RELEASE.md) and GitHub's
[artifact-attestation verification guidance](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations#verifying-an-artifact-attestation-for-binaries).
Do not silently substitute another archive or a source build after a failure.

### Linux and macOS

First select exactly one filename.

Linux x86_64:

```bash
ASSET="termivar-v0.10.0-alpha.1-x86_64-unknown-linux-gnu.tar.gz"
```

macOS Apple Silicon:

```bash
ASSET="termivar-v0.10.0-alpha.1-aarch64-apple-darwin.tar.gz"
```

macOS Intel:

```bash
ASSET="termivar-v0.10.0-alpha.1-x86_64-apple-darwin.tar.gz"
```

Then download and inspect. `curl` is an explicit acquisition prerequisite.
The download directory must not already exist.

```bash
set -eu
RELEASE_URL="https://github.com/ITherso/termivar/releases/download/v0.10.0-alpha.1"
mkdir -m 700 first-use-downloads
curl --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
  --output "first-use-downloads/$ASSET" "$RELEASE_URL/$ASSET"
curl --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
  --output first-use-downloads/SHA256SUMS "$RELEASE_URL/SHA256SUMS"
python3 scripts/verify_release_archive.py \
  --archive "first-use-downloads/$ASSET" \
  --checksums first-use-downloads/SHA256SUMS
```

Review the inspection output before extracting to the new directory:

```bash
set -eu
python3 scripts/verify_release_archive.py \
  --archive "first-use-downloads/$ASSET" \
  --checksums first-use-downloads/SHA256SUMS \
  --extract-to termivar-alpha1
./termivar-alpha1/termivar --version
./termivar-alpha1/termivar --help
./termivar-alpha1/termivar scan --help
```

Expect version `0.10.0-alpha.1`. Continue with the
[released-binary walkthrough](GETTING_STARTED.md#run-the-local-walkthrough).

### Windows PowerShell

The download and extraction directories must not already exist. Use an
installed Python 3.12.4+ interpreter as `python`.

```powershell
$ErrorActionPreference = "Stop"
$asset = "termivar-v0.10.0-alpha.1-x86_64-pc-windows-msvc.zip"
$releaseUrl = "https://github.com/ITherso/termivar/releases/download/v0.10.0-alpha.1"
New-Item -ItemType Directory -Path first-use-downloads | Out-Null
Invoke-WebRequest -Uri "$releaseUrl/$asset" -OutFile "first-use-downloads/$asset"
Invoke-WebRequest -Uri "$releaseUrl/SHA256SUMS" -OutFile first-use-downloads/SHA256SUMS
python scripts/verify_release_archive.py --archive "first-use-downloads/$asset" --checksums first-use-downloads/SHA256SUMS
if ($LASTEXITCODE -ne 0) { throw "Archive inspection failed" }
```

Review the inspection output before the next commands:

```powershell
python scripts/verify_release_archive.py --archive "first-use-downloads/$asset" --checksums first-use-downloads/SHA256SUMS --extract-to termivar-alpha1
if ($LASTEXITCODE -ne 0) { throw "Verified extraction failed" }
.\termivar-alpha1\termivar.exe --version
.\termivar-alpha1\termivar.exe --help
.\termivar-alpha1\termivar.exe scan --help
```

Expect version `0.10.0-alpha.1`. Continue with the
[released-binary walkthrough](GETTING_STARTED.md#run-the-local-walkthrough).
Published-platform acceptance is recorded per actual native execution in the
[sample provenance](examples/first-use/README.md); downloadable does not mean
every archive was executed for this walkthrough.

## Build from source

Keep the walkthrough scripts in the tools checkout. Clone a **separate**
source tree at the concrete reviewed revision below. These commands build
package `termivar-cli`, whose executable is `termivar`.

Linux/macOS:

```bash
set -eu
SOURCE_COMMIT="a29ba40c8cfdc7d0385431ea4d9e374e213ca4e0"
git clone https://github.com/ITherso/termivar.git ../termivar-source-a29ba40
git -C ../termivar-source-a29ba40 checkout --detach "$SOURCE_COMMIT"
test "$(git -C ../termivar-source-a29ba40 rev-parse HEAD)" = "$SOURCE_COMMIT"
cargo build --locked --release -p termivar-cli \
  --manifest-path ../termivar-source-a29ba40/Cargo.toml \
  --target-dir ../termivar-source-a29ba40/target
../termivar-source-a29ba40/target/release/termivar --version
```

Windows PowerShell:

```powershell
$ErrorActionPreference = "Stop"
$sourceCommit = "a29ba40c8cfdc7d0385431ea4d9e374e213ca4e0"
$sourceDir = "..\termivar-source-a29ba40"
if (Test-Path -LiteralPath $sourceDir) { throw "Choose a fresh source directory" }
git clone https://github.com/ITherso/termivar.git $sourceDir
if ($LASTEXITCODE -ne 0) { throw "Source clone failed" }
git -C $sourceDir checkout --detach $sourceCommit
if ($LASTEXITCODE -ne 0) { throw "Source checkout failed" }
if ((git -C $sourceDir rev-parse HEAD) -ne $sourceCommit) { throw "Source identity mismatch" }
cargo build --locked --release -p termivar-cli --manifest-path "$sourceDir/Cargo.toml" --target-dir "$sourceDir/target"
if ($LASTEXITCODE -ne 0) { throw "Source build failed" }
& "$sourceDir/target/release/termivar.exe" --version
```

Expect `0.10.0-alpha.2`. A deliberately chosen alternative must also be a
reviewed full commit: record it, inspect its manifest/features, build that exact
tree, and pass its real ref/version to the runner. A commit pin is not an audit.

To compare the **same source revision** with the existing release bundle,
build into a different output directory so the default binary is preserved:

```bash
cargo build --locked --release -p termivar-cli \
  --manifest-path ../termivar-source-a29ba40/Cargo.toml \
  --features release-bundle \
  --target-dir ../termivar-source-a29ba40/target/release-bundle
```

The resulting path is
`../termivar-source-a29ba40/target/release-bundle/release/termivar`
(`termivar.exe` on Windows). PowerShell accepts the same command on one line.
Label that source binary `release-bundle`, not a published-release binary.
No optional runtime review flag is needed for the local example.

## Verify the source-built binary

From the tools checkout, inspect the default source binary:

```bash
../termivar-source-a29ba40/target/release/termivar --help
../termivar-source-a29ba40/target/release/termivar scan --help
```

On Windows, use `..\termivar-source-a29ba40\target\release\termivar.exe`.
Then run the [source-binary walkthrough](GETTING_STARTED.md#development-source-binary).
The runner checks the actual version and records the executable hash; ref and
feature labels are explicit caller declarations, not facts inferred from help.

## Release status and unsupported channels

The development line has no matching prebuilt release. The historical
`v0.9.0-alpha` archives predate the deterministic-default remediation and are
not an installation path for this guide. Future releases use the existing
[release process](RELEASE.md); this walkthrough changes no release or tag.

There is no supported Homebrew/Apt/AUR/Snap/Chocolatey/Scoop/crates.io package,
repository installer, automatic updater, signed-platform binary channel,
published Docker Hub/GHCR image, or cloud-marketplace deployment.
Kubernetes, Helm, Terraform, Compose, and a PostgreSQL/Redis service stack are
not supported installation paths. The historical root Compose manifest remains
removed; the [deployment blueprint](experimental/deployment-blueprint.md) is
non-deployable reference material.

### Local container build

The existing Dockerfile can package the CLI locally; it is not used by this
native walkthrough or published to a registry by repository workflows.

```bash
docker build -t termivar:local .
docker run --rm termivar:local --help
```

Its default command is help, not a listener. The optional API and proxy adapters
are not compiled into that image. See the [runtime map](internals/runtime-map.md)
before treating any compiled module as an executable product.

## Reporting problems

Attach the actual version, OS/architecture, source or release ref, exit code,
and redacted diagnostics. Never include credentials or private machine paths.

- [GitHub issues](https://github.com/ITherso/termivar/issues)
- [GitHub discussions](https://github.com/ITherso/termivar/discussions)
- [Security policy](https://github.com/ITherso/termivar/blob/main/SECURITY.md)
