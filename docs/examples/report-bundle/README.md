# Single-run report-bundle example

This directory records one real local execution of the development
`termivar 0.10.0-alpha.2` binary built from source revision
`e747db4153eb52e06664bcec9dcb3411daef6fe6` on Windows. The fixed
repository-owned numeric-loopback fixture was already running inside the
helper; no public target, credential, callback, or OAST provider was used.

Generation command, run from the repository root:

```powershell
python scripts/report_bundle_example.py `
  --binary target/debug/termivar.exe `
  --output docs/examples/report-bundle/assessment-001
```

The binary identified itself as `termivar 0.10.0-alpha.2` and had SHA-256
`c6c27b8d6bfc6aedb0c89058b7557650905c254a124dad13edee5f82918510f6`.
The fixture contract SHA-256 was
`85406051314bd6316af1542848cb56eb97969bf2f7f269b4959f3eb00bcff4e3`.

The helper observed one scan invocation and exactly three assessment requests
after the fixture-readiness request. It then invoked the existing offline
Report Compare command against `assessment.json` twice. Comparison added zero
fixture requests and produced four unchanged items, with zero changed or
one-sided items.

The committed bundle contains exactly:

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `assessment.html` | 8000 | `a43070ee91860782a1eb47cd081b5fe628423a847bcc172e1a039cb6055cf1c1` |
| `assessment.json` | 3907 | `c3104e05c372eab172f2247ae748d867b5e5e01d2adf4daa40d21e5515267ab9` |
| `manifest.json` | 711 | `c77ce74508e8efaff7ebf1b0203331b4295d468c726e4acd7bad709eb85813df` |

`manifest.json` hashes the exact HTML and JSON payload bytes, not itself. Its
digests are integrity metadata, not authentication, source attestation, scope
proof, or a remediation claim. The fixture is an execution-contract example,
not a security-effectiveness test.

This feature exists on development source only. The published
`v0.10.0-alpha.1` archives do not contain `--report-dir`.
