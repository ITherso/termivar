# Deviation records

The opt-in `detection` feature exposes an Experimental, host-owned data/helper
surface. It does not establish a baseline, score a response, assign confidence
or severity, classify a vulnerability, or create a finding.

`ResponseDeviation` carries four caller-computed normalized dimensions: timing,
response size, text marker, and status code. Its validation rejects non-finite
or out-of-range values, and its dominant-dimension helper is a deterministic
description of those supplied values only.

`ErrorKeywordMatcher` is a literal/regular-expression text utility. A match is
not evidence of a vulnerability or even an application error. Hosts remain
responsible for authorization, input normalization, evidence provenance,
controlled repetition, and any downstream review policy.

The same feature also exposes validated signal-definition and caller-scored
technique catalogs. Those catalogs store records; Termivar does not apply a
transformation or automatically inspect a response against a definition.
