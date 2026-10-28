# Supplied-session authenticated assessment

The non-default `supplied-session-review` feature adds one deliberately narrow
authenticated collection path to an explicit `web-review` assessment. It is a
development Preview, is not compiled into the curated `release-bundle`, and
does nothing unless the operator supplies a policy and its matching explicit
acquisition selection. V1–V6 use an out-of-band credential source; V7 instead
selects a private authorization-URI handoff and creates its own transaction.

The V1 policy accepts one complete `Authorization` header value. The V2 policy
accepts one small scanner-owned cookie jar from an explicit local file. The V3
policy accepts one username/password pair from an explicit local file and uses
it only for one bounded form-login transition: one anonymous `GET` of the exact
declared login page, followed by at most one explicit
`application/x-www-form-urlencoded` `POST` to that same URL. V3 does not discover
forms, guess credentials, retry an ambiguous submission, bypass MFA/CAPTCHA, or
perform OAuth. V1 and V2 still send no body or non-`GET` method. None of the
three modes loads a browser profile, automatically renews a session, or enables
an existing active vulnerability family under the selected credential.
Application-defined `GET` handling and the explicitly authorized V3 login
`POST` can have server-side effects, so the operator must authorize the whole
selected sequence. A principal alias is an operator assertion, not
authenticated identity.

V4 adds one separately selected **scheduled cookie renewal**, not login discovery
or an automatic retry after session loss. It starts with a supplied cookie jar,
reuses the existing `--session-policy` / `--session-cookie-file` command below,
and permits one bodyless same-application POST between healthy resource windows.
Only exact declared host-only, HttpOnly, nonpersistent Strict/Lax cookies are
accepted. The replacement advances the credential epoch immediately, then an
independent health GET must succeed before another resource is collected. A
failed renewal or new-epoch health check never restores or retries the old jar.

## Policy V4: one scheduled renewal

Use the V2 policy fields and cookie TSV shape with these explicit differences:

```toml
schema = "security.supplied-session-policy/v4"
renewal_path = "/app/renew"
renewal_method = "post"
renewal_after_resource_count = 1
max_renewal_attempts = 1
# With two resources: startup + two resource/health pairs + renewal + health.
max_session_requests = 7
```

This is an excerpt, not a complete policy. Resources must number two or three;
the boundary must follow at least one and precede the final resource. The exact
request allowance is `3 + 2 * resource_count`, within the unchanged nine-request
ceiling. There are at most five health checkpoints including renewal health.
All selected cookies must cover health, resources and the renewal path, remain
host-only and nonpersistent, and preserve the exact configured security
attributes. Domain, Max-Age/Expires, extensions, undeclared cookies, missing or
duplicated selected cookies fail closed at renewal. No browser cookie jar is used.
The explicitly authorized POST may have application-defined side effects.

`security.supplied-session-audit/v4` records value-free renewal outcome, attempt,
bytes, applied-cookie count, epochs and the immediate health receipt. Epoch
identifies this run's credential context, not authenticated identity. Earlier
resources remain qualified only by their original same-epoch health evidence.
The new policy is initially rejected by the WordPress and WebSocket session
consumers before secret/output acquisition; v1–v3 behavior is unchanged. It
remains non-default, outside `release-bundle` and unpublished.

## Policy V5: import one external public-code transaction

V5 is a deliberately narrower acquisition step, **not an interactive OAuth/OIDC
login client**. The operator has already obtained an authorization code using
a public client and S256. Termivar reads that explicitly supplied transaction
once, redeems it at one policy-authorized token endpoint, then uses the existing
Bearer startup/resource/checkpoint sequence. The IdP child has a distinct exact
endpoint permit and connection pool, but shares the assessment's parent request,
byte, cancellation and deadline accounting. A target permit does not authorize
an IdP endpoint, and token claims cannot create either permit.

An illustrative operator invocation, after independently preparing the policy
and private transaction file, is:

```bash
termivar scan https://app.example.test/app/ \
  --profile web-review \
  --session-policy ./oauth-session-policy.toml \
  --session-oauth-code-file ./oauth-transaction.secret.tsv \
  --report-dir ./assessment-oauth-session
```

This is not a claim that the example host was contacted. The actual process
tests use owned numeric-loopback fixtures. The following complete non-secret
policy illustrates the HTTPS profile:

```toml
schema = "security.supplied-session-policy/v5"
principal_alias = "operator-declared-reader"
credential_mechanism = "authorization_header"
credential_acquisition = "imported_oauth_code_pkce"
health_path = "/app/health"
health_json_field = "authenticated"
resources = ["/app/private/one", "/app/private/two"]
max_session_requests = 6
max_total_response_bytes = 65536
max_response_body_bytes = 8192
max_wall_time_ms = 10000

[oauth_code]
profile = "external-public-code-s256-bearer/v1"
transport_profile = "verified-https/v1"
issuer = "https://idp.example.test/realm"
token_endpoint = "https://idp.example.test/realm/token"
client_id = "explicit-public-client"
redirect_uri = "https://app.example.test/callback"
scopes = ["canary-read"]
max_token_response_bytes = 8192
```

Only a public-client `authorization_code` exchange is supported. There is no
client-secret, ID-token, refresh, device, implicit or password-grant path. The
issuer/token origin must match and the token endpoint must be under the declared
issuer path by segments; this is operator-supplied configuration, not discovery
or issuer authentication. The redirect URI is an equality binding, never a
callback that Termivar opens or follows. URLs are strict canonical, query-free,
fragment-free ASCII HTTPS references. The separately selected
`owned-numeric-loopback-http/v1` profile permits only numeric-loopback HTTP test
origins, not hostname `localhost`, real cleartext credentials, or accept-any TLS.

The private UTF-8 TSV contains exactly eight unique rows, with these literal
field names: `authorization_code`, `code_verifier`, `code_challenge`, `issuer`,
`client_id`, `redirect_uri`, `scope`, `received_unix_seconds`. Values are not
trimmed; LF and CRLF delimit rows. Do not place the actual code, verifier, token,
or session cookie in a command, URL, issue or report. Use a fresh protected
regular file. The 16 KiB input bound, existing no-follow/regular-file acquisition
and trusted-parent/quiescent-file assumptions apply; this is not an immutable
filesystem snapshot or ancestor-containment guarantee.

The imported issuer/client/redirect/scope must equal the policy. The local S256
challenge must equal SHA-256 of the imported 43–128 byte verifier. Its asserted
receipt time must be at most 60 seconds old, allowing at most five seconds of
future skew; freshness is checked again immediately before dispatch. These are
checks on supplied assertions: they do not prove a trusted clock, secure
front-channel/state/nonce handling, that Termivar initiated authorization, or
that the provider enforced PKCE. The code is attempted once per assessment,
including after an ambiguous transport failure. Cross-run replay is left to the
provider; no persistent secret-derived equality cache is created.

The body contains only `grant_type`, `client_id`, `redirect_uri`, `code` and
`code_verifier`. There is no cookie, Authorization header, ambient proxy,
redirect, retry, token endpoint guessing or implicit provider metadata fetch.
Complete status-200 uncoded JSON is required. The child token-body limit is at
most 32 KiB and must also fit the smaller common per-body and total limits.
Duplicate JSON keys, unsupported token types/ID tokens, malformed or truncated
responses cannot establish a credential. Bounded unknown extension values are
inert, not network or execution instructions.

This V1 acquisition profile deliberately requires an explicit exact `scope`
echo and an integer `expires_in` of 1–3,600 seconds. RFC 6749 allows the scope
field to be omitted when unchanged; such a response is unsupported by this
narrower profile, not necessarily an invalid OAuth server. `openid` and
`offline_access` scopes are unsupported. Only a Bearer access token fitting the
existing 8 KiB Authorization bound is admitted; a refresh token is discarded,
with its presence recorded only after successful parsing. Bearer syntax alone
does not prove that every possible hidden sender constraint is absent. The
token is opaque: it is not decoded, signature-verified, promoted to an identity,
or used to select a URL. Its declared lifetime narrows the use deadline; it is
not an observed server expiration decision.

For `N` resources, V5 requires the exact allowance `2 + 2 * N`: one token POST,
one startup health GET, and a resource/health GET pair per resource. At most
three resources fit within the unchanged nine-request session ceiling (eight
requests at three resources). Smaller parent bounds win; the IdP has no fresh
allowance. Failed/partial transport bytes stay charged, including the existing
last-delivered-chunk overrun semantics. Request admission, completed response,
parsed credential and committed credential are distinct audit counters.

Only the private context-bound, read-back committed acquisition receipt can
authorize subsequent Bearer work. Token acquisition alone does not establish
target session health. The existing explicit JSON health predicate remains
mandatory; a valid token for the wrong canary principal can still fail it.
Cancellation, exhaustion, an unusable exchange or unhealthy startup never
silently falls back to anonymous authenticated coverage. Ordinary anonymous
assessment processing remains separately anonymous and unchanged.

`security.supplied-session-audit/v5` saves value-free acquisition facts beside
the existing checkpoint/resource audit. It explicitly marks external context
as operator-declared and authorization initiation, browser callback, state/nonce,
OIDC identity and token-signature validation as not performed. Unevaluated scope,
refresh and lifetime facts are null rather than assertions of absence. It saves
neither raw transaction/token/response bytes nor their public unkeyed digests.
Guarded application buffers do not promise zero sensitive copies in HTTP/Python
libraries, the OS or allocator history. JSON retains the full audit, HTML and
Markdown explain its conditional meaning, and item-oriented CSV is not a full
acquisition transcript. Strict feature-independent readers preserve historical
v1–v4 documents; Compare treats IdP/policy/principal changes as context changes,
not vulnerability introduction or remediation. Verify checks bundle integrity
and the saved contract, not provider or identity truth.

V5 is initially refused by WordPress and WebSocket session consumers before
secret acquisition; their earlier explicitly supported combinations do not
change. It stays non-default, outside the seven-member curated bundle and
published alpha.2. Full interactive authorization, OIDC, provider metadata/JWKS,
renewal and external-service qualification remain separate work.

The owned Keycloak helper uses a pinned isolated provider and **admin-prepared
SSO fixture**, then a real public-code/S256/form-post authorization transaction.
It is not qualification of ordinary interactive login, MFA or consent. A separate
resource-client introspection oracle distinguishes the two canaries. Controller
and resource-server traffic is not charged or described as scanner traffic.
Only this test controller explicitly returns the provider's retained `Secure`
SSO cookies over HTTP to its exact owned numeric-loopback relay origin, port
and authorization path. Other destinations remain refused. This fixture-only
exception does not relax the product cookie policy or qualify browser behavior.
`--validate-only` checks fixture contracts and never establishes IdP execution:

```bash
python scripts/oauth_code_lab_acceptance.py --validate-only
python scripts/oauth_code_lab_acceptance.py \
  --binary ./target/oauth-lab/release/termivar \
  --output-dir ./new-private-safe-evidence \
  --source-ref <exact-source-sha> --expect-version 0.10.0-alpha.3
```

The executable must already be built with `supplied-session-review`; actual lab
execution requires Linux Docker. Only its bounded safe JSON evidence is an
upload candidate, never temporary transaction files, provider logs or reports.
The current helper runs six imported-code scenarios and three scheduled-refresh
scenarios. It removes its owned fixture before all nine Verify/self-Compare
pairs and four controlled comparisons. The controller's old-refresh-token
refusal controls are separate from scanner traffic and do not upgrade the
product's server-replay assurance. Static tests and native synthetic CLI tests
are distinct from a completed real-provider lab.

Primary protocol references: [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749),
[RFC 7636](https://www.rfc-editor.org/rfc/rfc7636) and
[RFC 9700](https://www.rfc-editor.org/rfc/rfc9700). These are development
references, never scan-time fetch destinations.

## Policy V6: one scheduled opaque-Bearer refresh

V6 uses the same explicit policy and imported transaction file as V5, but selects
one additional **scheduled** token-endpoint exchange after the first resource
and its healthy checkpoint. It is not automatic recovery after session loss,
interactive authorization, OIDC, or a new credential authority. V5 still
discards refresh material and never refreshes.

Use the complete V5 policy above with exactly these differences (this is an
excerpt, not another complete policy):

```toml
schema = "security.supplied-session-policy/v6"
resources = ["/app/private/one", "/app/private/two"]
max_session_requests = 8

[oauth_refresh]
profile = "scheduled-public-bearer-refresh/v1"
after_resource_count = 1
max_attempts = 1
```

There must be exactly two selected resources and the exact eight-request child
allowance. Existing smaller parent, body, byte and time bounds still win. The
fixed successful schedule is:

| Order | Operation | Credential context |
| --- | --- | --- |
| 1 | Imported-code token POST | IdP-only code/S256 form |
| 2 | Startup health GET | Access credential, epoch 1 |
| 3–4 | First resource GET and health GET | Epoch 1 |
| 5 | One refresh-token POST | IdP-only refresh form |
| 6 | Immediate renewal health GET | Replacement access credential, epoch 2 |
| 7–8 | Second resource GET and terminal health GET | Epoch 2 |

The two IdP phases share one private broker pool and the same parent accounting,
deadline and cancellation. Neither endpoint permit grants authority over the
other origin. The refresh form contains only `grant_type`, `client_id`,
`refresh_token` and the exact selected `scope`; it carries no target credential,
cookie, client secret or redirect URI. Refresh material is bounded printable
ASCII, is not trimmed, and uses form encoding rather than header syntax. The
form is limited independently to 16 KiB before allocation. The old refresh value
is discarded after the one attempt even on ambiguous failure. No retry, old-token
fallback or second refresh is permitted; the unused replacement refresh value
is also discarded.

Only the existing committed code receipt plus the exact committed first resource
and healthy boundary can authorize this phase. A separate read-back committed
renewal receipt is required for epoch 2; the old code receipt alone cannot
qualify it. Renewed health must pass before another protected resource. Earlier
resources retain their original acquisition epoch, including after later loss.

Both token responses require complete uncoded bounded JSON, an exact scope echo,
opaque Bearer material and a refresh value. V6 refuses `id_token` or top-level
`cnf`; unsupported hidden sender constraints remain unknown. The replacement
refresh value must differ locally. That inequality **does not prove** the server
revoked the old value, detects replay, authenticated an identity or implements
all OAuth security requirements. No token is decoded or signature-verified.
The provider-declared access lifetime may be replaced, but never extends or
resets the immutable assessment/policy wall deadline.

`security.supplied-session-audit/v6` retains value-free acquisition, scheduled
renewal, epochs, counters and the separately labelled renewal health checkpoint.
Three common checkpoints plus that nested health are four actual GETs, not a
duplicate terminal checkpoint. Null unevaluated facts remain distinct from
negative observations. JSON/CSV preserve the full typed audit; HTML/Markdown
display both epochs and the conditional rotation meaning. Strict offline
readers retain historical v1–v5 contracts. Compare separates methodology,
declared context/epoch and coverage changes from vulnerability or remediation.

An illustrative command uses the same flags, with the V6 policy selected:

```bash
termivar scan https://app.example.test/app/ \
  --profile web-review \
  --session-policy ./oauth-renewal-policy.toml \
  --session-oauth-code-file ./oauth-transaction.secret.tsv \
  --report-dir ./assessment-oauth-renewal
```

The example host is not a test destination. Native process tests use owned
numeric-loopback synthetic application/IdP responses; real-provider acceptance
uses the separately pinned disposable Keycloak controller. Neither supplies
ordinary browser login, consent, MFA or general production-IdP qualification.
V6 WordPress/WebSocket composition is refused before secret/output acquisition.
The feature remains non-default, outside the curated bundle and unpublished.

## Build and invoke

Build an isolated candidate with the feature selected explicitly:

```bash
cargo build --locked -p termivar-cli \
  --no-default-features --features supplied-session-review
```

For an authorized HTTPS application:

```bash
termivar scan https://app.example.test/app/ \
  --profile web-review \
  --session-policy ./session-policy.toml \
  --session-auth-file ./authorization.secret \
  --report-dir ./assessment-session
```

`--session-auth-env` and `--session-auth-stdin` are alternatives to the regular
file for a V1 policy. A V2 policy instead requires exactly one
`--session-cookie-file`:

```bash
termivar scan https://app.example.test/app/ \
  --profile web-review \
  --session-policy ./cookie-session-policy.toml \
  --session-cookie-file ./cookies.secret.tsv \
  --report-dir ./assessment-cookie-session
```

A V3 policy instead requires exactly one `--session-login-file`:

```bash
termivar scan https://app.example.test/app/ \
  --profile web-review \
  --session-policy ./form-login-policy.toml \
  --session-login-file ./form-login.secret.tsv \
  --report-dir ./assessment-form-login
```

The policy and credential acquisition mechanism must agree, and exactly one
credential source is required. V1/V2/V3/V4/V5/V6 source mismatches and V3/V4/V5/V6 combined with
`--wordpress-supplied-session` are rejected after policy validation but before
output reservation or secret-file acquisition. There is no raw credential
argument, cookie environment source, browser import, or cookie stdin source.
HTTP is refused except for numeric-loopback development fixtures; `Secure`
cookies still require HTTPS, including on loopback.

For V1, the secret source contains the complete bounded header value, for
example a scheme and its credentials. Its bytes must not contain control
characters. The value is never a target, a scope grant, a principal identifier,
or a report field. V2 instead uses the ID-bound cookie rows described below.
V3's bounded TSV contains exactly one `username<TAB>value` and one
`password<TAB>value` row. It has no field-name freedom and neither value is
placed in argv, diagnostics, evidence or reports. The file is limited to 8 KiB,
the username to 256 UTF-8 bytes and the password to 4 KiB.

## Policy V1

The strict bounded policy is TOML. This example selects two query-free,
root-relative resources beneath the already selected application:

```toml
schema = "security.supplied-session-policy/v1"
principal_alias = "fixture-reader"
credential_mechanism = "authorization_header"
health_path = "/app/health"
health_json_field = "authenticated"
resources = ["/app/private", "/app/private-2"]
max_session_requests = 5
max_total_response_bytes = 131072
max_response_body_bytes = 32768
max_wall_time_ms = 5000
```

The selected target supplies the immutable scheme, host, effective port and
application directory. V1 accepts one to four resource paths. Paths and the
health endpoint must remain inside that application, be query- and
fragment-free, and pass the raw-reference safety checks. Login, logout, action,
download and administration-style paths are rejected by V1. This bounded
denylist narrows accidental selection; it does not prove that an admitted `GET`
is side-effect-free. A discovered link cannot extend the policy.

The policy may allow at most nine supplied-session requests. It must budget one
startup health check plus one resource request and one following health check
for every selected resource. Per-body, total-response and wall-time limits are
narrowing ceilings; the assessment's smaller parent limits, cancellation and
deadline always win.

The health response must be a complete successful JSON representation whose
named top-level field is exactly the Boolean `true`. A `200` login page, a
truthy string, missing field, duplicate JSON key, truncated body, redirect or
transport error does not establish healthy session context.

## Policy V2 and supplied cookie file

V2 keeps the same application, resource, health and request limits, and adds
strict non-secret metadata for one to eight cookies. This HTTPS example declares
two same-name cookies with different paths:

```toml
schema = "security.supplied-session-policy/v2"
principal_alias = "fixture-reader"
credential_mechanism = "cookie_jar"
cookie_update_policy = "stop_on_selected_cookie"
health_path = "/app/health"
health_json_field = "authenticated"
resources = ["/app/private", "/app/private-2"]
max_session_requests = 5
max_total_response_bytes = 131072
max_response_body_bytes = 32768
max_wall_time_ms = 5000

[[cookies]]
id = "broad-session"
name = "session"
domain = "app.example.test"
host_only = true
path = "/app/"
secure = true
http_only = true
same_site = "lax"

[[cookies]]
id = "narrow-session"
name = "session"
domain = "app.example.test"
host_only = true
path = "/app/private"
secure = true
http_only = true
same_site = "strict"
expires_unix_seconds = 4102444800
```

The secret file contains exactly one `id<TAB>value` row for every declared
cookie. IDs bind values to reviewed metadata and are not sent; values are
composed into `Cookie` only for an exact admitted request. The file is limited
to 16 KiB, each value to 4 KiB, and the composed header to 8 KiB. Duplicate,
unknown, missing, expired, malformed, or initially non-covering rows fail before
network execution. Applicable same-name cookies are emitted in longer-path-first
order. If any selected persistent cookie expires during execution, the fixed
epoch fails closed before another credentialed request; the runtime does not
silently continue with a smaller cookie set.

V2 validates host-only/domain, path, `Secure`, expiry, `HttpOnly` and `SameSite`
metadata. Protocol applicability is intersected with the policy's narrower exact
application authority; a Domain declaration never grants another target host.
`HttpOnly` and `SameSite` are preserved facts, not a claim that this non-browser
client reproduces browser script or CSRF behavior.

## Policy V3 and bounded form login

V3 keeps the same exact application, health predicate, response-byte and
wall-time authority, but establishes the cookie jar through one explicit login
transition. This two-resource example uses seven requests: login-page `GET`,
login `POST`, startup health, and one resource/health pair per resource.

```toml
schema = "security.supplied-session-policy/v3"
principal_alias = "fixture-reader"
credential_mechanism = "cookie_jar"
credential_acquisition = "bounded_form_login"
cookie_update_policy = "stop_on_selected_cookie"
login_path = "/app/login"
login_method = "post"
login_encoding = "application/x-www-form-urlencoded"
username_field = "username"
password_field = "password"
csrf_field = "csrf_token"
max_login_attempts = 1
health_path = "/app/health"
health_json_field = "authenticated"
resources = ["/app/private", "/app/private-2"]
max_session_requests = 7
max_total_response_bytes = 131072
max_response_body_bytes = 32768
max_wall_time_ms = 5000

[[cookies]]
id = "generated-session"
name = "session"
domain = "app.example.test"
host_only = true
path = "/app/"
secure = true
http_only = true
same_site = "lax"
```

V3 admits one to three resources. Its exact request count is
`3 + (2 * resource_count)` and remains within the unchanged nine-request hard
ceiling. It begins without a cookie. The login page is one anonymous, complete,
untruncated status-200 UTF-8 `text/html` representation of at most 64 KiB and
2,048 DOM nodes. Exactly one eligible form must have no `action` or an action
exactly equal to the configured login path, an explicit `POST` method, and no
`enctype` or exactly `application/x-www-form-urlencoded`. It must contain
exactly the configured enabled username input (default/text), password input
(`type=password`) and hidden CSRF input. The CSRF value is required, bounded to
2,048 UTF-8 bytes, guarded in memory and never serialized. Missing, duplicate,
disabled, wrong-type, malformed, partial or over-limit input authorizes no
submission. Returning this operator-selected field is login plumbing, not a
test or claim that the application resists CSRF.

The form body contains only the three configured fields and values. The same
exact login URL receives at most one POST. Redirect following and retry are
disabled; a timeout or other ambiguous outcome is not resubmitted. There is no
pre-session cookie, Authorization value, ambient cookie store, credential
guessing, login-path discovery or fallback form selection.

Only response cookies matching the policy's declared host-only application
cookie metadata may establish the scanner-owned jar. V3 accepts session cookies
only: the exact application host, an applicable safe path, `Secure` matching
the selected scheme, `HttpOnly`, `SameSite=Strict|Lax`, and no expiry. The
operator's application scope remains narrower than cookie protocol scope. A
cookie response, successful status or familiar page text does not establish
login success. After the form transition, the existing complete JSON startup
health predicate is the sole success oracle. Only then does the lifecycle move
from pre-authentication epoch zero to authenticated epoch one and begin resource
collection.

## Execution and evidence

The runtime creates a context-isolated, redirect-disabled, no-proxy child of the
existing assessment broker. It sends only the configured V1 authorization value,
request-applicable V2 cookie pairs, or the V3 jar established by the single
bounded login transition to the exact selected application and never forwards
them across a redirect. It does not enable reqwest's automatic cookie store.
V1/V2 start with the supplied credential at epoch one. V3 records its anonymous
login-page GET and explicit login POST separately, starts at epoch zero without
a cookie, and can reach epoch one only after a valid cookie transition and the
independent startup JSON health check. Each dispatched resource is followed by
a deterministic health checkpoint before it can become committed authenticated
coverage; loss stops later supplied-session work. There is no silent anonymous
retry, POST retry or automatic refresh.

Every V2 response and every V3 response after initial session establishment is
checked for bounded `Set-Cookie` fields before its body can be committed. An
update to a selected cookie stops later supplied-session work with
`credential_update_required`; malformed, over-limit or otherwise unusable update
metadata stops with `credential_update_unusable`. An unselected response cookie
is counted but not applied. Outside the initial V3 login response, response
updates remain unapplied and automatic renewal remains absent. V1/V2 keep epoch
one; successful V3 establishment changes only epoch zero to epoch one.

Each complete `200` resource response remains a body-free staged observation
until its immediately following health checkpoint is both healthy and committed.
Only then does it count as authenticated `committed` coverage. If that checkpoint
is unhealthy or unavailable, the response remains `health_unqualified`, counts
as dispatched activity, and does not count as authenticated coverage.

The central report adds `security.supplied-session-audit/v1` for V1,
`security.supplied-session-audit/v2` for V2, or
`security.supplied-session-audit/v3` for V3. It records opaque
policy, application, principal and resource references; the operator-declared
assurance; checkpoint and resource outcomes; and reconciled request/byte counts.
V2 additionally records only non-secret cookie-policy aggregates and value-free
selected/unselected/unusable update counts; it never records cookie names,
values, domains, paths, source file locations or response fields.
V3 additionally records a login reference, bounded page/CSRF/submission/cookie
outcomes, attempt and acquired-cookie counts, response-byte accounting, the
zero-to-one epoch transition when established, and that no pre-session cookie
was applied. It never records the username, password, CSRF value, form body,
cookie values, field names, raw login URL or secret-file path.
The configured response-byte limit and an exact exceeded flag are separate from
the unclamped transport count because the broker charges a final delivered chunk
even when only the bounded prefix is retained.
It never records the Authorization value, response body, readable resource URL,
or an unkeyed credential digest. Evidence committed before a later loss remains
qualified by its recorded checkpoints. Startup and boundary checks do not prove
continuous authentication between them.

This slice produces an audit, not a vulnerability item. Exploit execution and
impact validation remain `not_performed`. An empty or interrupted authenticated
coverage window is not proof that the application denied access or is secure.
Offline Verify checks bundle integrity; Compare describes audit/context and
coverage changes without treating logout or a different principal as
remediation. A changed credential-acquisition mode or login lifecycle is likewise
a context/methodology change, not proof that target access was added, removed or
fixed.

### Explicit WordPress consumer

When the executable is compiled with both `supplied-session-review` and
`wordpress-review`, an operator can additionally select:

```text
--profile web-review --wordpress-review --wordpress-discovery \
  --wordpress-supplied-session
```

The usual V1 or V2 supplied-session policy and exactly one matching credential
source remain mandatory. V3 is rejected before its login secret is opened; its
WordPress consumer is intentionally deferred to S02. The current composition
interprets only complete selected resource
HTML whose immediately following health checkpoint and S01 resource evidence
were committed. It binds the observation to the policy, application, principal,
credential mechanism and fixed epoch. A login response, incompatible application,
unsupported representation, truncated body, health loss or uncommitted evidence
cannot nominate WordPress metadata.

Eligible component hints may nominate only the existing public WordPress
metadata requests. Those requests remain anonymous, same-origin and broker-owned
inside the existing shared WordPress allowance; no Cookie or Authorization value
is forwarded. Authenticated-page JS/CSS does not nominate fingerprint acquisition
in this initial integration. The authenticated page ledger is separate from the
anonymous observed-page collection, and a different principal or epoch is a
context change rather than evidence of installation change or remediation.

### Explicit WebSocket consumer

When the executable is compiled with both `supplied-session-review` and
`websocket-review`, the V1 Authorization-header session may be consumed by the
bounded WebSocket review only when the operator additionally selects
`--websocket-supplied-session`. The combined invocation requires exactly one
selected protected resource:

```text
termivar scan http://127.0.0.1:<owned-fixture-port>/app/ \
  --profile web-review \
  --session-policy session-policy.toml \
  --session-auth-file authorization.secret \
  --websocket-review-policy websocket-policy.json \
  --websocket-supplied-session \
  --report-dir assessment
```

The fixed schedule is startup health, protected-resource staging, one
credentialed WebSocket handshake and bounded exchange, then terminal health.
Both health checkpoints are required before either the staged resource or the
WebSocket result is qualified for the declared application, principal and epoch.
Startup loss prevents the WebSocket dispatch. Terminal loss preserves only the
value-free wire result and leaves the context unqualified; it does not publish
the protected resource as committed evidence.

V2 cookie and V3 form-login policies are intentionally unsupported by this
consumer and are rejected before credential or output acquisition. The same
session cannot be selected simultaneously by the WordPress and WebSocket
consumers. Without the explicit integration flag, WebSocket review remains its
existing anonymous isolated connection and receives neither the Authorization
value nor supplied-session context. The WebSocket connection shares the parent
deadline and accounting; it does not create a fresh session-request allowance.
Health checkpoints qualify only the bounded declared context window and do not
establish continuous authentication.

## Policy V7: client-initiated public-client authorization

V7 generates independent 32-byte OS-random PKCE verifier, state and opaque
transaction reference. It supports only S256, the explicitly configured issuer
and authorization/token endpoints, and one previously registered IPv4 callback
`http://127.0.0.1:<fixed-unprivileged-port>/termivar/oauth/callback`. It does not
register a client, open a browser, discover endpoints or read a browser profile.
The operator completes any login, MFA and consent in their own user agent.
No OIDC nonce, identity or token-signature validation is performed.

With an owned application and an already configured public client, the CLI is:

```text
termivar scan https://application.example/app/ --profile web-review \
  --session-policy initiated-policy.toml \
  --session-oauth-authorization-output private-authorization.txt \
  --report-dir assessment
```

The policy is a complete strict V7 document, not an imported code transaction:

```toml
schema = "security.supplied-session-policy/v7"
principal_alias = "operator-declared-user"
credential_mechanism = "authorization_header"
credential_acquisition = "client_initiated_oauth_pkce"
health_path = "/app/health"
health_json_field = "authenticated"
resources = ["/app/read-only-one", "/app/read-only-two"]
max_session_requests = 6
max_total_response_bytes = 65536
max_response_body_bytes = 8192
max_wall_time_ms = 10000
[oauth_code]
profile = "client-initiated-public-code-s256-bearer/v1"
transport_profile = "verified-https/v1"
issuer = "https://identity.example/issuer"
token_endpoint = "https://identity.example/issuer/token"
client_id = "previously-registered-public-client"
redirect_uri = "http://127.0.0.1:43123/termivar/oauth/callback"
scopes = ["read-only"]
max_token_response_bytes = 8192
[oauth_authorization]
profile = "loopback-form-post-state/v1"
authorization_endpoint = "https://identity.example/issuer/authorize"
max_wait_ms = 30000
```

This example is not a supplied endpoint permit or a claim that an external
provider was tested. The health endpoint must implement the operator's protected
JSON predicate; status 200 alone does not qualify it. Real issuer/token/target
connections require normal verified HTTPS. The cleartext exception above is
only the numeric-loopback response receiver. The separately selected
`owned-numeric-loopback-http/v1` issuer profile remains an owned-test exception,
not RFC 9207 HTTPS conformance. `openid` is not supported by this token profile.

The output is create-only, outside the report bundle, in a trusted private local
directory. It contains one authorization URI plus a newline; it contains state
and challenge, never the verifier. The file is usable only while the command
waits. Unix creation is mode 0600; Windows inherits the directory ACL. No claim
is made that ancestor checks form an atomic snapshot or that an arbitrary host
library writer is interruptible. Only the still-owned file is removed; a
replacement or unverifiable residual is retained with a static warning.

The listener is bound before handoff, receives at most one connection and closes
before token acquisition/report composition. Only an exact Host/path, bounded
complete `application/x-www-form-urlencoded` POST can qualify. A present Origin
must match; a missing Origin is not itself a protocol error. Duplicate known
form parameters, wrong/missing state or issuer, ambiguous framing, credential
headers, oversized/partial input and stale responses fail closed without another
accept or token retry. Unknown bounded form extensions are ignored and counted.
Provider errors retain only a closed class, never descriptions or redirects.

There is one parent runtime and immutable deadline. Authorization wait is at
most 30 seconds under that parent; after a qualified callback the existing
session window remains at most ten seconds and the smaller remaining parent
time wins. One callback reception reservation consumes a parent logical attempt,
even if no connection arrives. Raw received framing/form bytes are charged to
parent response accounting, not outgoing token request-body accounting. A fixed
inert reply has a separate actual-write counter, not a peer-receipt assertion.
The session's `2 + 2 * resource_count` outgoing requests remain separately
reported; at most three resources plus the callback reservation fit the existing
nine-admission ceiling. No WordPress/WebSocket composition or refresh is selected
by V7. Generic anonymous subject processing is not suppressed.

Only exact committed callback evidence authorizes the existing once-only IdP
token POST. Every subsequent health/resource credential use revalidates the
callback → token evidence chain in the same knowledge authority. Saved reports
and imported V5/V6 TSV files cannot mint that authority. Matching state/issuer
and a redeemed opaque Bearer credential do not authenticate a browser, principal,
token signature or remote PKCE enforcement. Session health still qualifies only
its checkpoints and bounded coverage window.

V7 saves separate `oauth_authorization` and `oauth_token_exchange` audit sections;
it does not relabel the historical external-transaction `oauth_code` audit.
Codes, verifier, state, raw forms, URI/query and local paths are not report data.
Verify remains an integrity check. Compare distinguishes policy/methodology,
coverage and accounting; per-run proof references and elapsed time do not become
stable principal identity or target-change evidence.

## Secret boundary

Policy validation happens before the selected secret source is read. File input
uses the shared regular-file, final-component no-follow and bounded-read
contract; trusted parents and mutable-file limitations still apply. Owned CLI
intake bytes are guarded through constructor handoff, but this is not a claim
that operating-system environment storage, allocator history, process dumps,
HTTP-library buffers or every downstream copy is erased. See
[Credential-input guarantees and limits](credential-input.md).

## Protocol references

The boundaries follow the current [OWASP Authentication Cheat
Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html),
[OWASP CSRF Prevention Cheat
Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html),
and [OWASP Session Management Cheat
Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
for TLS-protected login, an explicit anti-CSRF input and scoped session handling,
and [RFC
9110](https://www.rfc-editor.org/rfc/rfc9110.html) for HTTP semantics. V2 applies
the domain/path/Secure and ordering rules used from [RFC
6265](https://www.rfc-editor.org/rfc/rfc6265.html) only inside the operator's
narrower application authority; V3 narrows this further to declared host-only
session cookies. These references define protocol expectations, not proof that
an observed principal or session is authentic.

V7's public-client transaction uses [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636)
S256, [RFC 9207](https://www.rfc-editor.org/rfc/rfc9207) issuer comparison and the
[OAuth form-post response mode](https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html).
Its fixed numeric-loopback callback is a deliberately narrower profile than
general [RFC 8252](https://www.rfc-editor.org/rfc/rfc8252) native-client support;
it supports neither dynamic redirect rewriting nor a browser launch mechanism.
The [OAuth security BCP](https://www.rfc-editor.org/rfc/rfc9700) informs these
boundaries without establishing general provider or OIDC compatibility.
