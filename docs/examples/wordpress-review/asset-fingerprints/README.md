# Synthetic WordPress asset-fingerprint catalogue

This directory contains an original, task-owned finite reference matrix for
development and acceptance. It is synthetic; it was not downloaded from a
WordPress installation, plugin vendor, or vulnerability feed.

The strict product input is [`catalogue.synthetic.json`](catalogue.synthetic.json).
[`catalogue-source.synthetic.json`](catalogue-source.synthetic.json) is a
development-only preparation declaration. Each `local_file` names one explicit
regular file below this directory. The preparation helper does not crawl for
other releases or files and removes every local filename from the product
catalogue:

```bash
python scripts/prepare_wordpress_fingerprint_catalog.py \
  --source docs/examples/wordpress-review/asset-fingerprints/catalogue-source.synthetic.json \
  --output /tmp/termivar-fingerprint-catalogue.json
```

The output path must be new. The helper performs no network request and refuses
links, unsafe relative paths, unsupported extensions, duplicate JSON keys,
unknown fields, and bounded-input violations.

## Independent byte matrix

The literal SHA-256 values below were fixed from the source bytes independently
of Termivar's catalogue matcher. The JS shared by A/B and the CSS shared by B/C
make their intersection identify release B among these three listed releases.
The common stylesheet is intentionally nondiscriminating.

| Bytes | Length | SHA-256 | Listed releases |
| --- | ---: | --- | --- |
| `fingerprint.js` shared form | 49 | `0a0760b281d010ed4d70610e4f2f460a33846088b373ec10fd47d0d5ccb4bf26` | A, B |
| `fingerprint.js` C form | 50 | `4f770e9b2646e3b0d0b0ac777c7f76ad3893f1477d1a9e00c3cfbfb443b5f4a2` | C |
| `fingerprint.css` A form | 37 | `9ae3210e7954adbb2ed976b34b4605495de9a8406634bedd92bc14a3d317fdae` | A |
| `fingerprint.css` shared form | 37 | `c8b61302a47ea3208b743c287349570d3580756b3fafc73ac14a5eada9557b90` | B, C |
| `common.css` | 32 | `e4b20a225f36b6cecb22bd9c1e89b256f33ed39ad9e34bf2044462bba21bf17f` | A, B, C |

The reviewed expectations are:

- A JS plus A CSS is jointly compatible only with listed release A.
- shared A/B JS plus shared B/C CSS is jointly compatible only with listed
  release B.
- C JS plus shared B/C CSS is jointly compatible only with listed release C.
- shared A/B JS alone leaves A and B provisional; `common.css` alone leaves all
  three listed releases nondiscriminated.
- C JS mixed with A CSS has no consistent listed release.
- if a listed release omits a reference row, that comparison is unknown rather
  than a mismatch.

These are statements only about the finite catalogue and the exact observed
bytes. An unlisted release or custom build can share the same assets. Even the
two-file B intersection is therefore a `single_catalogue_candidate`, not an
authenticated installed version, whole-package verification, patch state, or
vulnerability conclusion. Asset content and the `ver` query used by later test
fixtures deliberately carry no release label.

The files and catalogue notice are provided under the repository's MIT license.
Their digests identify bytes; they are not signatures or publisher
authentication.
