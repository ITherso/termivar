# Fuzzing

The `fuzz/` package contains cargo-fuzz targets for HTTP, JSON, YAML, XML, and generic parser inputs.

## Setup

```bash
cargo install cargo-fuzz
cargo fuzz list
cargo fuzz run http_parser
```

Run fuzzing on a dedicated machine or bounded CI job. Start with a small, non-sensitive seed corpus. Crashes must preserve the minimized input and exact commit SHA.

## Targets

| Target | Parser |
| --- | --- |
| `http_parser` | `httparse` request parser |
| `json_parser` | `serde_json` value parser |
| `yaml_parser` | `serde_yaml` value parser |
| `xml_parser` | `quick-xml` event reader |
| `text_parser` | URL and UTF-8 parsing boundary |

Fuzz harnesses should have no network, filesystem, clock, or random dependencies. A parser rejection is not a crash; panics, hangs, excessive allocation, and sanitizer findings require triage.
