# Plugin trait fixtures

These fixtures exercise Termivar's source-level `Plugin` boundary. They are not
detectors, scanners, payload libraries, or vulnerability claims.

Each fixture records at most one fixed, inert INFO marker observation when a
local host invokes it:

| Fixture type | Exact marker |
| --- | --- |
| `SqlMarkerFixture` | `venom-fixture:sql` |
| `XssMarkerFixture` | `venom-fixture:xss` |
| `LfiMarkerFixture` | `venom-fixture:lfi` |
| `XxeMarkerFixture` | `venom-fixture:xxe` |
| `SsrfMarkerFixture` | `venom-fixture:ssrf` |
| `SstiMarkerFixture` | `venom-fixture:ssti` |

The fixtures perform no network I/O and match only the complete input shown in
the table. The host-owned context applies subject, correlation, redaction, and
evidence limits. Successful execution means only that the trait call completed.
Recorded observations still require host reasoning and verification and never
become findings automatically.
