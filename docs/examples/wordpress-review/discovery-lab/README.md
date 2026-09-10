# Disposable WordPress metadata-discovery lab

This acceptance lab is test infrastructure, not an assessment capture and not
a vulnerable WordPress image. It gives CI an independently declared ground
truth for the explicitly selected `--wordpress-discovery` path.

The controller is
[`scripts/wordpress_discovery_lab_acceptance.py`](https://github.com/ITherso/termivar/blob/main/scripts/wordpress_discovery_lab_acceptance.py).
It uses the task-owned files under
[`scripts/fixtures/wordpress-discovery-lab`](https://github.com/ITherso/termivar/tree/main/scripts/fixtures/wordpress-discovery-lab)
and checks the declarations in [`ground-truth.json`](ground-truth.json) against
WP-CLI from inside the disposable lab before Termivar runs. Termivar itself
never invokes WP-CLI and receives neither these declarations nor any lab
credential.

## Pinned stack

The real lab requires a native Linux x86-64 Docker Engine because its bounded
host relay connects directly to the container's private internal-bridge address.
Docker Desktop hosts are rejected before Docker access rather than receiving a
misleading timeout; static controller tests still run on other hosts. The CI job
uses architecture-specific manifest digests. The source tags and OCI index
digests below were resolved through the Docker Registry V2 API on 2026-09-10;
the controller never resolves a moving tag at runtime.

| Role | Source tag | OCI index | Pinned Linux/amd64 manifest |
| --- | --- | --- | --- |
| WordPress + Apache | `wordpress:7.1-php8.3-apache` | `sha256:5a93c470ae8220fddf71f6ebe3bc94e615ddc2ae4d9810f795b830fb11c41a17` | `wordpress@sha256:49801e46d08eb27ea68ed62e205bb35b1bb2dc962251bf2292a7d374f9637cee` |
| WP-CLI ground truth | `wordpress:cli-2.12.0-php8.3` | `sha256:2b5e9d4d3e51909dca1aaa4732e9f5e5bf0377c2114dbd8ff39f060bff202586` | `wordpress@sha256:51ff6b7643d9b4c29d74d83b2c3fe12e706812e7add075f189535f498dd5201d` |
| Database | `mariadb:11.8.9` | `sha256:2d2f4095530294735a857cfe22bb101e19b0849b416911c796ec4aa81b164a62` | `mariadb@sha256:a75328dabed542a3b704efe54086071cb3f99e6a640cc8a18d7273bc4de2e5e7` |

The controller pulls those three images first. It then builds the tiny derived
fixture with `--network=none`, creates a Docker `--internal` bridge, gives the
database no host port, and attaches WordPress only to that internal bridge. A
bounded test-only TCP relay binds a random `127.0.0.1` port on the host and
forwards raw bytes to Apache inside that bridge; the container itself publishes
no port. The WordPress container runs as `www-data` and Apache listens on
unprivileged container port 8080. WordPress cron and automatic update traffic
are disabled and the application is configured to block external HTTP. No host
network, privileged container, Docker-socket mount, production volume, or public
target is used. Task-owned containers, volumes, the bridge, relay, and derived
fixture image are removed after the run; pulled upstream layers may remain in
the runner's ordinary Docker cache.

The derived image contains only original GPL-2.0-or-later test code:

- child theme `termivar-child` at `1.4.0`, with one task-owned `includes_url()`
  image reference that follows the configured core base and supplies a
  deterministic identity-only core signal even when the generator is suppressed;
- parent theme `termivar-parent` at `3.2.1`, referenced only by the child's
  `Template` header;
- active plugin `termivar-metadata-lab` at `2.3.4`, whose readme deliberately
  says `Stable tag: 9.9.9`;
- inactive `termivar-hidden-lab` at `4.5.6`, with no public root-page reference;
- a harmless switch that removes the public generator for one scenario.

The active plugin also registers `termivar-lab/v1`. That value is an API
namespace version, not a plugin release version.

## Acceptance scenarios

The real-CMS job preserves the original seven root-layout scans: an ordinary web
review, the transport-free WordPress review, and explicit discovery, followed by
the review/discovery pair with the generator suppressed and with plain
permalinks. The pinned current WordPress core advertises the plain REST root as
`/index.php?rest_route=/`; the older handbook illustration without `index.php`
is not substituted for the current-core oracle.

The same disposable installation is then moved through three controller-verified
deployment layouts without changing the image set or giving Termivar server
access:

- a complete application at `/blog/`, exercised with pretty and plain REST
  advertisements;
- a site whose public home is `/` while WordPress core and conventional content
  are under `/cms/`;
- that root-home deployment with themes moved to `/site-content/themes/` and
  plugins moved separately to `/modules/`. This last case is first scanned with
  no declaration, then with a strict `security.wordpress-layout/v1` declaration
  containing role roots only.

During the `/blog/` cases, the selected page also contains a task-owned
`/shop/wp-content/themes/termivar-child/` decoy with the same slug and a distinct
`88.8.8` stylesheet declaration. The controller requires it to remain a sibling
association: Termivar must not derive or fetch that sibling stylesheet as
WordPress metadata for `/blog/`.

For every fully resolved configuration the review and discovery traces are
compared. The allowed delta is exactly four anonymous same-origin GETs at the
literal independently declared bases: the advertised REST index, child
stylesheet, depth-one parent stylesheet, and active plugin readme. With the
custom deployment but no layout declaration, only the advertised REST index is
eligible; the declaration then enables exactly the three observed component
metadata requests. No REST route, plugin PHP entrypoint, inactive plugin,
foreign/sibling stylesheet, or additional parent is accepted as an attributable
request.

After the lab is fully stopped, the same development executable verifies every
bundle and self-compares every report. It also compares review-only with
discovery, custom no-layout with declared-layout results, and the known-different
`/blog/` and `/` applications. The custom comparison must expose methodology and
coverage changes without calling them remediation; the cross-application
WordPress entity comparison must be `not_compared` with
`application_scope_mismatch`. The CI artifact retains only a bounded
JSON/Markdown summary with request paths, opaque references, hashes, counts, and
safe ground truth; it does not retain credentials, declaration paths, or full
assessment documents.

The summary reports observable component-identity recall with an explicit
denominator, version accuracy by evidence source class, false identity matches,
and expected abstentions. The inactive plugin without a public reference is
deliberately excluded from the recall denominator and counted as an expected
abstention; the readme Stable tag is another expected abstention from installed-
version evidence. Unexpected component rows or a wrong source class fail the
job instead of being hidden by aggregate counts.

Each scan runs as a fresh process. On this Linux job the controller records GNU
time's maximum-resident-set-size high-water mark in KiB, elapsed wall time,
discovery response bytes, and the exact request delta for each off/on pair.
Elapsed time includes loopback HTTP activity and is not a parser benchmark; the
OS high-water mark is neither Rust heap usage nor an exact discovery-only
allocation. A host without the approved metric is labelled `not_measured` rather
than receiving an inferred number.

Static fixture/controller tests run on hosts without Docker. They are not a
substitute for the Ubuntu real-CMS job.

## Meaning and provenance

The WordPress image is the Docker Official Image maintained by the Docker
community; it is not presented as a WordPress-project build attestation. The
controller independently records Docker image IDs and the executable/report
hashes it actually used. A digest identifies bytes but does not authenticate a
remote installation.

WordPress is GPLv2-or-later, WP-CLI is MIT, and MariaDB Community Server is
GPLv2. The fixture code is GPL-2.0-or-later. No container image is distributed
as a Termivar product artifact.

Primary references:

- [WordPress REST discovery](https://developer.wordpress.org/rest-api/using-the-rest-api/discovery/)
- [`get_rest_url()` current source](https://developer.wordpress.org/reference/functions/get_rest_url/)
- [Theme main stylesheet headers](https://developer.wordpress.org/themes/core-concepts/main-stylesheet/)
- [`get_file_data()` header behavior](https://developer.wordpress.org/reference/functions/get_file_data/)
- [Plugin readme and Stable tag](https://developer.wordpress.org/plugins/wordpress-org/how-your-readme-txt-works/)
- [Generator metadata](https://developer.wordpress.org/reference/functions/get_the_generator/)
- [WP-CLI Docker installation](https://make.wordpress.org/cli/handbook/guides/installing/#installing-via-docker)
- [Docker internal-network behavior](https://docs.docker.com/reference/cli/docker/network/create/#network-internal-mode---internal)
- [Docker Official WordPress image source](https://github.com/docker-library/wordpress)
- [WordPress license](https://wordpress.org/about/license/)
- [WP-CLI license](https://github.com/wp-cli/wp-cli/blob/main/LICENSE)
- [MariaDB licensing FAQ](https://mariadb.com/docs/general-resources/community/community/faq/licensing-questions/licensing-faq)
