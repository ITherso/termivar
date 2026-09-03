//! Bounded overlap-preserving byte-slice and streaming signature scans.

use crate::report::ArtifactScanReportParts;
use crate::{
    ArtifactCatalog, ArtifactContentIdentity, ArtifactDigest, ArtifactError,
    ArtifactMatchObservation, ArtifactScanCompletion, ArtifactScanReport, ConsumedPrefixDigest,
};
use sha2::{Digest, Sha256};
use std::io::{ErrorKind, Read};

/// Stable semantics of V1 exact/wildcard artifact matching.
pub const ARTIFACT_SCAN_ALGORITHM_VERSION: &str = "venom.artifact-signature-scan/v1";
/// Absolute hard ceiling for bytes consumed by one scan.
pub const MAX_INPUT_BYTES: u64 = 512 * 1024 * 1024;
/// Absolute hard ceiling for observations retained by one scan.
pub const MAX_MATCHES_PER_SCAN: usize = 30_000;
/// Absolute hard ceiling for the fixed streaming read buffer.
pub const MAX_READER_CHUNK_BYTES: usize = 1024 * 1024;
/// Absolute hard ceiling for matcher offset probes and candidate verifications.
pub const MAX_MATCH_WORK_UNITS: usize = 1_700_000_000;
/// Conservative default input ceiling (64 MiB).
pub const DEFAULT_INPUT_BYTES: u64 = 64 * 1024 * 1024;
/// Conservative default observation ceiling.
pub const DEFAULT_MATCHES_PER_SCAN: usize = 10_000;
/// Conservative default reader chunk (64 KiB).
pub const DEFAULT_READER_CHUNK_BYTES: usize = 64 * 1024;
/// Conservative default matcher-work ceiling.
pub const DEFAULT_MATCH_WORK_UNITS: usize = 250_000_000;
const MAX_CONSECUTIVE_INTERRUPTS: usize = 16;

const _: () = assert!(DEFAULT_MATCH_WORK_UNITS as u64 >= 3 * DEFAULT_INPUT_BYTES);
const _: () = assert!(MAX_MATCH_WORK_UNITS as u64 >= 3 * MAX_INPUT_BYTES);

/// Checked host-narrowable limits for one scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArtifactScanLimits {
    max_input_bytes: u64,
    max_matches: usize,
    reader_chunk_bytes: usize,
    max_match_work_units: usize,
}

impl ArtifactScanLimits {
    /// Creates finite limits which cannot exceed compiled hard ceilings.
    pub fn new(
        max_input_bytes: u64,
        max_matches: usize,
        reader_chunk_bytes: usize,
    ) -> Result<Self, ArtifactError> {
        validate_limit(max_input_bytes, MAX_INPUT_BYTES, "input bytes")?;
        validate_limit(
            u64::try_from(max_matches)
                .map_err(|_| ArtifactError::InvalidScanLimit { field: "matches" })?,
            MAX_MATCHES_PER_SCAN as u64,
            "matches",
        )?;
        validate_limit(
            u64::try_from(reader_chunk_bytes).map_err(|_| ArtifactError::InvalidScanLimit {
                field: "reader chunk bytes",
            })?,
            MAX_READER_CHUNK_BYTES as u64,
            "reader chunk bytes",
        )?;
        Ok(Self {
            max_input_bytes,
            max_matches,
            reader_chunk_bytes,
            max_match_work_units: DEFAULT_MATCH_WORK_UNITS,
        })
    }

    /// Narrows the finite matcher-work ceiling.
    pub fn with_max_match_work_units(mut self, maximum: usize) -> Result<Self, ArtifactError> {
        validate_limit(
            u64::try_from(maximum).map_err(|_| ArtifactError::InvalidScanLimit {
                field: "match work units",
            })?,
            MAX_MATCH_WORK_UNITS as u64,
            "match work units",
        )?;
        self.max_match_work_units = maximum;
        Ok(self)
    }

    pub fn max_input_bytes(self) -> u64 {
        self.max_input_bytes
    }

    pub fn max_matches(self) -> usize {
        self.max_matches
    }

    pub fn reader_chunk_bytes(self) -> usize {
        self.reader_chunk_bytes
    }

    pub fn max_match_work_units(self) -> usize {
        self.max_match_work_units
    }
}

impl Default for ArtifactScanLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: DEFAULT_INPUT_BYTES,
            max_matches: DEFAULT_MATCHES_PER_SCAN,
            reader_chunk_bytes: DEFAULT_READER_CHUNK_BYTES,
            max_match_work_units: DEFAULT_MATCH_WORK_UNITS,
        }
    }
}

fn validate_limit(value: u64, maximum: u64, field: &'static str) -> Result<(), ArtifactError> {
    if value == 0 || value > maximum {
        return Err(ArtifactError::InvalidScanLimit { field });
    }
    Ok(())
}

/// Read-only scanner bound to one sealed catalog and one checked limit set.
#[derive(Debug)]
pub struct ArtifactScanner<'catalog> {
    catalog: &'catalog ArtifactCatalog,
    limits: ArtifactScanLimits,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScanStop {
    MatchLimit,
    MatchWorkLimit,
}

#[derive(Default)]
struct ScanProgress {
    observations: Vec<ArtifactMatchObservation>,
    match_work_units: usize,
    match_start_positions_checked: u64,
}

impl<'catalog> ArtifactScanner<'catalog> {
    /// Creates a scanner. Catalog membership never grants path or I/O authority.
    pub fn new(
        catalog: &'catalog ArtifactCatalog,
        limits: ArtifactScanLimits,
    ) -> Result<Self, ArtifactError> {
        if catalog.maximum_pattern_length() > crate::MAX_PATTERN_BYTES {
            return Err(ArtifactError::LimitExceeded {
                field: "catalog pattern bytes",
                limit: crate::MAX_PATTERN_BYTES,
            });
        }
        Ok(Self { catalog, limits })
    }

    pub fn limits(&self) -> ArtifactScanLimits {
        self.limits
    }

    /// Scans only the bounded prefix authorized by the checked limits.
    pub fn scan_bytes(&self, input: &[u8]) -> Result<ArtifactScanReport, ArtifactError> {
        let input_limit = usize::try_from(self.limits.max_input_bytes)
            .unwrap_or(usize::MAX)
            .min(input.len());
        let bounded = &input[..input_limit];
        let mut progress = ScanProgress::default();
        let stop = self.scan_starts(bounded, 0, 0..bounded.len(), &mut progress)?;
        let completion = if let Some(stop) = stop {
            completion_for_stop(stop)
        } else if input.len() > bounded.len() {
            ArtifactScanCompletion::InputLimitReached
        } else {
            ArtifactScanCompletion::Complete
        };
        let digest = Sha256::digest(bounded);
        self.build_report(
            completion,
            bounded.len() as u64,
            hex::encode(digest),
            progress,
        )
    }

    /// Scans a caller-owned reader with a fixed chunk and bounded overlap carry.
    ///
    /// Repeated interrupted reads are bounded. Other reader failures become a
    /// typed incomplete report and never expose the reader's raw error text.
    pub fn scan_reader<R: Read>(&self, mut reader: R) -> Result<ArtifactScanReport, ArtifactError> {
        let mut chunk = vec![0u8; self.limits.reader_chunk_bytes];
        let mut window = Vec::with_capacity(
            self.limits
                .reader_chunk_bytes
                .checked_add(self.catalog.maximum_pattern_length().saturating_sub(1))
                .ok_or(ArtifactError::OffsetOverflow)?,
        );
        let mut window_start = 0u64;
        let mut bytes_read = 0u64;
        let mut hasher = Sha256::new();
        let mut progress = ScanProgress::default();
        let mut consecutive_interrupts = 0usize;

        loop {
            let remaining = self.limits.max_input_bytes.saturating_sub(bytes_read);
            if remaining == 0 {
                let stop =
                    self.scan_starts(&window, window_start, 0..window.len(), &mut progress)?;
                return self.build_report(
                    stop.map(completion_for_stop)
                        .unwrap_or(ArtifactScanCompletion::InputLimitReached),
                    bytes_read,
                    hex::encode(hasher.finalize()),
                    progress,
                );
            }
            let requested = usize::try_from(remaining)
                .unwrap_or(usize::MAX)
                .min(chunk.len());
            let read = match reader.read(&mut chunk[..requested]) {
                Ok(read) => {
                    consecutive_interrupts = 0;
                    read
                },
                Err(error) if error.kind() == ErrorKind::Interrupted => {
                    consecutive_interrupts = consecutive_interrupts.saturating_add(1);
                    if consecutive_interrupts <= MAX_CONSECUTIVE_INTERRUPTS {
                        continue;
                    }
                    let _ =
                        self.scan_starts(&window, window_start, 0..window.len(), &mut progress)?;
                    return self.build_report(
                        ArtifactScanCompletion::ReaderFailed,
                        bytes_read,
                        hex::encode(hasher.finalize()),
                        progress,
                    );
                },
                Err(_) => {
                    let _ =
                        self.scan_starts(&window, window_start, 0..window.len(), &mut progress)?;
                    return self.build_report(
                        ArtifactScanCompletion::ReaderFailed,
                        bytes_read,
                        hex::encode(hasher.finalize()),
                        progress,
                    );
                },
            };
            if read == 0 {
                let stop =
                    self.scan_starts(&window, window_start, 0..window.len(), &mut progress)?;
                return self.build_report(
                    stop.map(completion_for_stop)
                        .unwrap_or(ArtifactScanCompletion::Complete),
                    bytes_read,
                    hex::encode(hasher.finalize()),
                    progress,
                );
            }
            if read > requested {
                let _ = self.scan_starts(&window, window_start, 0..window.len(), &mut progress)?;
                return self.build_report(
                    ArtifactScanCompletion::ReaderFailed,
                    bytes_read,
                    hex::encode(hasher.finalize()),
                    progress,
                );
            }

            let read_u64 = u64::try_from(read).map_err(|_| ArtifactError::OffsetOverflow)?;
            bytes_read = bytes_read
                .checked_add(read_u64)
                .ok_or(ArtifactError::OffsetOverflow)?;
            hasher.update(&chunk[..read]);
            window.extend_from_slice(&chunk[..read]);

            let retained = self.catalog.maximum_pattern_length().saturating_sub(1);
            let scanable_starts = window.len().saturating_sub(retained);
            if let Some(stop) =
                self.scan_starts(&window, window_start, 0..scanable_starts, &mut progress)?
            {
                return self.build_report(
                    completion_for_stop(stop),
                    bytes_read,
                    hex::encode(hasher.finalize()),
                    progress,
                );
            }
            if scanable_starts > 0 {
                retain_unchecked_carry(&mut window, scanable_starts, retained)?;
                window_start = window_start
                    .checked_add(
                        u64::try_from(scanable_starts)
                            .map_err(|_| ArtifactError::OffsetOverflow)?,
                    )
                    .ok_or(ArtifactError::OffsetOverflow)?;
                debug_assert_eq!(progress.match_start_positions_checked, window_start);
            }
        }
    }

    fn scan_starts(
        &self,
        input: &[u8],
        absolute_base: u64,
        starts: std::ops::Range<usize>,
        progress: &mut ScanProgress,
    ) -> Result<Option<ScanStop>, ArtifactError> {
        for start in starts {
            for (anchor_offset, by_byte) in self.catalog.anchor_groups() {
                if !self.charge_match_work(progress) {
                    return Ok(Some(ScanStop::MatchWorkLimit));
                }
                let Some(anchor_index) = start.checked_add(*anchor_offset) else {
                    return Err(ArtifactError::OffsetOverflow);
                };
                let Some(anchor_byte) = input.get(anchor_index) else {
                    continue;
                };
                let Some(candidates) = by_byte.get(anchor_byte) else {
                    continue;
                };
                for candidate in candidates {
                    if !self.charge_match_work(progress) {
                        return Ok(Some(ScanStop::MatchWorkLimit));
                    }
                    let signature = self.catalog.signature(*candidate);
                    if !signature.pattern().matches_at(input, start) {
                        continue;
                    }
                    if progress.observations.len() >= self.limits.max_matches {
                        return Ok(Some(ScanStop::MatchLimit));
                    }
                    let absolute_start = absolute_base
                        .checked_add(
                            u64::try_from(start).map_err(|_| ArtifactError::OffsetOverflow)?,
                        )
                        .ok_or(ArtifactError::OffsetOverflow)?;
                    progress.observations.push(ArtifactMatchObservation::new(
                        signature.signature_ref().clone(),
                        absolute_start,
                        signature.pattern().len(),
                        signature.observation_class(),
                    )?);
                }
            }
            progress.match_start_positions_checked = absolute_base
                .checked_add(u64::try_from(start).map_err(|_| ArtifactError::OffsetOverflow)?)
                .and_then(|absolute_start| absolute_start.checked_add(1))
                .ok_or(ArtifactError::OffsetOverflow)?;
        }
        Ok(None)
    }

    fn charge_match_work(&self, progress: &mut ScanProgress) -> bool {
        if progress.match_work_units >= self.limits.max_match_work_units {
            return false;
        }
        progress.match_work_units += 1;
        true
    }

    fn build_report(
        &self,
        completion: ArtifactScanCompletion,
        bytes_consumed: u64,
        digest_hex: String,
        progress: ScanProgress,
    ) -> Result<ArtifactScanReport, ArtifactError> {
        let content_identity = if completion.is_complete() {
            ArtifactContentIdentity::Artifact {
                digest: ArtifactDigest::from_hex(&digest_hex),
            }
        } else {
            ArtifactContentIdentity::ConsumedPrefix {
                digest: ConsumedPrefixDigest::from_hex(&digest_hex),
                bytes_consumed,
            }
        };
        ArtifactScanReport::new(ArtifactScanReportParts {
            algorithm_version: ARTIFACT_SCAN_ALGORITHM_VERSION,
            catalog_digest: self.catalog.digest().clone(),
            content_identity,
            completion,
            bytes_consumed,
            match_start_positions_checked: progress.match_start_positions_checked,
            signatures_considered: self.catalog.len(),
            matches: progress.observations,
            match_work_units: progress.match_work_units,
        })
    }
}

fn retain_unchecked_carry(
    window: &mut Vec<u8>,
    completed_starts: usize,
    maximum_carry: usize,
) -> Result<(), ArtifactError> {
    if completed_starts > window.len() {
        return Err(ArtifactError::InvalidScanReport {
            field: "completed streaming starts",
        });
    }
    window.drain(..completed_starts);
    if window.len() > maximum_carry {
        return Err(ArtifactError::InvalidScanReport {
            field: "stream carry bytes",
        });
    }
    Ok(())
}

fn completion_for_stop(stop: ScanStop) -> ArtifactScanCompletion {
    match stop {
        ScanStop::MatchLimit => ArtifactScanCompletion::MatchLimitReached,
        ScanStop::MatchWorkLimit => ArtifactScanCompletion::MatchWorkLimitReached,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ArtifactCatalog, ArtifactPattern, ArtifactSignaturePack};
    use std::collections::BTreeSet;
    use std::fmt::Write;
    use std::io::{self, Cursor};

    const PACK: &str = r#"schema = "venom.artifact-signatures/v1"
pack_id = "lab"
pack_revision = 1
title = "Lab patterns"
summary = "Harmless matcher fixtures"

[[signatures]]
id = "overlap"
revision = 1
label = "Overlapping A pair"
observation_class = "test-canary"
pattern = "41 41"
tags = ["lab"]

[[signatures]]
id = "wild"
revision = 1
label = "Wildcard marker"
observation_class = "user-defined-marker"
pattern = "42 ?? 44"
tags = ["lab"]

[[signatures]]
id = "same-start"
revision = 1
label = "Second same-start marker"
observation_class = "embedded-format-marker"
pattern = "41 ?? 41"
tags = ["lab"]
"#;

    fn catalog() -> ArtifactCatalog {
        let pack = ArtifactSignaturePack::parse_toml(PACK.as_bytes()).expect("pack");
        let mut builder = ArtifactCatalog::builder();
        builder.register(pack).expect("register");
        builder.seal().expect("seal")
    }

    fn scanner(limits: ArtifactScanLimits) -> ArtifactScanner<'static> {
        ArtifactScanner::new(Box::leak(Box::new(catalog())), limits).expect("scanner")
    }

    fn catalog_from_source(source: &str) -> ArtifactCatalog {
        let pack = ArtifactSignaturePack::parse_toml(source.as_bytes()).expect("pack");
        let mut builder = ArtifactCatalog::builder();
        builder.register(pack).expect("register");
        builder.seal().expect("seal")
    }

    #[test]
    fn limits_are_checked_at_zero_boundary_and_hard_maximum() {
        assert!(ArtifactScanLimits::new(1, 1, 1).is_ok());
        assert!(ArtifactScanLimits::new(
            MAX_INPUT_BYTES,
            MAX_MATCHES_PER_SCAN,
            MAX_READER_CHUNK_BYTES
        )
        .is_ok());
        for result in [
            ArtifactScanLimits::new(0, 1, 1),
            ArtifactScanLimits::new(1, 0, 1),
            ArtifactScanLimits::new(1, 1, 0),
            ArtifactScanLimits::new(MAX_INPUT_BYTES + 1, 1, 1),
            ArtifactScanLimits::new(1, MAX_MATCHES_PER_SCAN + 1, 1),
            ArtifactScanLimits::new(1, 1, MAX_READER_CHUNK_BYTES + 1),
        ] {
            assert!(matches!(
                result,
                Err(ArtifactError::InvalidScanLimit { .. })
            ));
        }
        let defaults = ArtifactScanLimits::default();
        assert_eq!(defaults.max_input_bytes(), DEFAULT_INPUT_BYTES);
        assert_eq!(defaults.max_matches(), DEFAULT_MATCHES_PER_SCAN);
        assert_eq!(defaults.reader_chunk_bytes(), DEFAULT_READER_CHUNK_BYTES);
        assert_eq!(defaults.max_match_work_units(), DEFAULT_MATCH_WORK_UNITS);
        assert!(DEFAULT_MATCH_WORK_UNITS >= 3 * DEFAULT_INPUT_BYTES as usize);
        assert!(MAX_MATCH_WORK_UNITS >= 3 * MAX_INPUT_BYTES as usize);
        assert_eq!(
            ArtifactScanLimits::new(1, 1, 1)
                .expect("limits")
                .with_max_match_work_units(MAX_MATCH_WORK_UNITS)
                .expect("hard work limit")
                .max_match_work_units(),
            MAX_MATCH_WORK_UNITS
        );
        for maximum in [0, MAX_MATCH_WORK_UNITS + 1] {
            assert!(matches!(
                ArtifactScanLimits::new(1, 1, 1)
                    .expect("limits")
                    .with_max_match_work_units(maximum),
                Err(ArtifactError::InvalidScanLimit {
                    field: "match work units"
                })
            ));
        }
    }

    #[test]
    fn byte_scan_preserves_overlaps_multiple_patterns_and_order() {
        let report = scanner(ArtifactScanLimits::new(1024, 32, 8).expect("limits"))
            .scan_bytes(b"AAA BxD")
            .expect("scan");
        assert_eq!(report.completion(), ArtifactScanCompletion::Complete);
        let observed = report
            .matches()
            .map(|entry| {
                (
                    entry.absolute_offset(),
                    entry.signature().signature_id().as_str(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            observed,
            [
                (0, "overlap"),
                (0, "same-start"),
                (1, "overlap"),
                (4, "wild")
            ]
        );
        assert_eq!(report.bytes_consumed(), 7);
        assert_eq!(report.match_start_positions_checked(), 7);
        assert_eq!(report.signatures_considered(), 3);
        assert_eq!(report.match_work_units(), 14);
    }

    #[test]
    fn byte_scan_handles_empty_no_match_final_offset_and_long_pattern() {
        let scanner = scanner(ArtifactScanLimits::new(1024, 32, 8).expect("limits"));
        assert_eq!(scanner.scan_bytes(b"").expect("empty").match_count(), 0);
        assert_eq!(scanner.scan_bytes(b"xyz").expect("none").match_count(), 0);
        let final_match = scanner.scan_bytes(b"xxAA").expect("final");
        assert_eq!(
            final_match
                .matches()
                .next()
                .expect("match")
                .absolute_offset(),
            2
        );
        assert_eq!(scanner.scan_bytes(b"A").expect("short").match_count(), 0);
    }

    #[test]
    fn input_and_match_limits_are_typed_prefix_results() {
        let input_limited = scanner(ArtifactScanLimits::new(2, 32, 2).expect("limits"))
            .scan_bytes(b"AAA")
            .expect("scan");
        assert_eq!(
            input_limited.completion(),
            ArtifactScanCompletion::InputLimitReached
        );
        assert_eq!(input_limited.bytes_consumed(), 2);
        assert_eq!(input_limited.match_start_positions_checked(), 2);
        assert!(!input_limited.content_identity().is_complete_artifact());

        let match_limited = scanner(ArtifactScanLimits::new(32, 1, 2).expect("limits"))
            .scan_bytes(b"AAA")
            .expect("scan");
        assert_eq!(
            match_limited.completion(),
            ArtifactScanCompletion::MatchLimitReached
        );
        assert_eq!(match_limited.match_count(), 1);
        assert_eq!(match_limited.bytes_consumed(), 3);
        assert_eq!(match_limited.match_start_positions_checked(), 0);
        assert!(match_limited
            .content_identity()
            .digest()
            .starts_with("consumed-prefix-sha256:"));
    }

    #[test]
    fn exact_match_work_budget_completes_and_one_fewer_unit_stops() {
        let data = b"AAA BxD";
        let exact_limits = ArtifactScanLimits::new(1024, 32, 8)
            .expect("limits")
            .with_max_match_work_units(14)
            .expect("work limit");
        let exact_bytes = scanner(exact_limits).scan_bytes(data).expect("bytes");
        let exact_stream = scanner(exact_limits)
            .scan_reader(Cursor::new(data))
            .expect("stream");
        assert_eq!(exact_bytes, exact_stream);
        assert_eq!(exact_bytes.completion(), ArtifactScanCompletion::Complete);
        assert_eq!(exact_bytes.match_work_units(), 14);
        assert_eq!(exact_bytes.match_start_positions_checked(), 7);

        let one_fewer_limits = ArtifactScanLimits::new(1024, 32, 8)
            .expect("limits")
            .with_max_match_work_units(13)
            .expect("work limit");
        let stopped_bytes = scanner(one_fewer_limits).scan_bytes(data).expect("bytes");
        let stopped_stream = scanner(one_fewer_limits)
            .scan_reader(Cursor::new(data))
            .expect("stream");
        assert_eq!(stopped_bytes, stopped_stream);
        assert_eq!(
            stopped_bytes.completion(),
            ArtifactScanCompletion::MatchWorkLimitReached
        );
        assert_eq!(stopped_bytes.match_work_units(), 13);
        assert_eq!(stopped_bytes.bytes_consumed(), 7);
        assert_eq!(stopped_bytes.match_start_positions_checked(), 6);
    }

    #[test]
    fn complete_digest_is_stable_and_input_sensitive() {
        let scanner = scanner(ArtifactScanLimits::new(1024, 32, 8).expect("limits"));
        let first = scanner.scan_bytes(b"AAAA").expect("first");
        let repeated = scanner.scan_bytes(b"AAAA").expect("repeat");
        let changed = scanner.scan_bytes(b"AAAB").expect("changed");
        assert_eq!(first.content_identity(), repeated.content_identity());
        assert_ne!(first.content_identity(), changed.content_identity());
        assert!(first
            .content_identity()
            .digest()
            .starts_with("artifact-sha256:"));
    }

    #[test]
    fn all_complete_chunk_sizes_equal_byte_scan() {
        let data = b"zAAA BxD AA";
        let expected = scanner(ArtifactScanLimits::new(1024, 32, 8).expect("limits"))
            .scan_bytes(data)
            .expect("bytes");
        for chunk in 1..=8 {
            let report = scanner(ArtifactScanLimits::new(1024, 32, chunk).expect("limits"))
                .scan_reader(Cursor::new(data))
                .expect("reader");
            assert_eq!(report, expected, "chunk={chunk}");
        }
    }

    #[test]
    fn streaming_retains_cross_boundary_overlaps_without_duplicates() {
        let report = scanner(ArtifactScanLimits::new(1024, 32, 1).expect("limits"))
            .scan_reader(Cursor::new(b"AAAA"))
            .expect("scan");
        let overlaps = report
            .matches()
            .filter(|entry| entry.signature().signature_id().as_str() == "overlap")
            .map(ArtifactMatchObservation::absolute_offset)
            .collect::<Vec<_>>();
        assert_eq!(overlaps, [0, 1, 2]);
    }

    struct ShortReader {
        bytes: Vec<u8>,
        offset: usize,
    }

    impl Read for ShortReader {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            if self.offset == self.bytes.len() {
                return Ok(0);
            }
            output[0] = self.bytes[self.offset];
            self.offset += 1;
            Ok(1)
        }
    }

    struct InterruptedOnce<R> {
        inner: R,
        interrupted: bool,
    }

    impl<R: Read> Read for InterruptedOnce<R> {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            if !self.interrupted {
                self.interrupted = true;
                return Err(io::Error::from(ErrorKind::Interrupted));
            }
            self.inner.read(output)
        }
    }

    #[test]
    fn short_and_interrupted_reads_preserve_complete_results() {
        let scanner = scanner(ArtifactScanLimits::new(1024, 32, 8).expect("limits"));
        let expected = scanner.scan_bytes(b"zAAA BxD").expect("bytes");
        let short = scanner
            .scan_reader(ShortReader {
                bytes: b"zAAA BxD".to_vec(),
                offset: 0,
            })
            .expect("short");
        let interrupted = scanner
            .scan_reader(InterruptedOnce {
                inner: Cursor::new(b"zAAA BxD"),
                interrupted: false,
            })
            .expect("interrupted");
        assert_eq!(short, expected);
        assert_eq!(interrupted, expected);
    }

    struct FailingReader {
        delivered: bool,
    }

    impl Read for FailingReader {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            if self.delivered {
                return Err(io::Error::other("VENOM-READER-SECRET-MUST-NOT-LEAK"));
            }
            self.delivered = true;
            output[..2].copy_from_slice(b"AA");
            Ok(2)
        }
    }

    #[test]
    fn reader_failure_is_typed_redacted_and_retains_partial_observations() {
        let report = scanner(ArtifactScanLimits::new(1024, 32, 8).expect("limits"))
            .scan_reader(FailingReader { delivered: false })
            .expect("typed report");
        assert_eq!(report.completion(), ArtifactScanCompletion::ReaderFailed);
        assert_eq!(report.match_count(), 1);
        assert!(report
            .content_identity()
            .digest()
            .starts_with("consumed-prefix-sha256:"));
        assert!(!format!("{report:?}").contains("VENOM-READER-SECRET"));
        assert!(!report
            .to_json()
            .expect("json")
            .contains("VENOM-READER-SECRET"));
    }

    #[test]
    fn streaming_input_and_match_limits_are_typed() {
        let input_limited = scanner(ArtifactScanLimits::new(2, 32, 1).expect("limits"))
            .scan_reader(Cursor::new(b"AAA"))
            .expect("input");
        assert_eq!(
            input_limited.completion(),
            ArtifactScanCompletion::InputLimitReached
        );
        let match_limited = scanner(ArtifactScanLimits::new(1024, 1, 1).expect("limits"))
            .scan_reader(Cursor::new(b"AAA"))
            .expect("match");
        assert_eq!(
            match_limited.completion(),
            ArtifactScanCompletion::MatchLimitReached
        );
        assert_eq!(match_limited.bytes_consumed(), 3);
        assert_eq!(match_limited.match_start_positions_checked(), 0);
    }

    #[test]
    fn checked_absolute_offset_overflow_fails_closed() {
        let scanner = scanner(ArtifactScanLimits::new(1024, 32, 8).expect("limits"));
        let mut progress = ScanProgress::default();
        assert_eq!(
            scanner.scan_starts(b"AAA", u64::MAX, 1..2, &mut progress),
            Err(ArtifactError::OffsetOverflow)
        );
    }

    struct AlwaysInterrupted;

    impl Read for AlwaysInterrupted {
        fn read(&mut self, _output: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::from(ErrorKind::Interrupted))
        }
    }

    #[test]
    fn repeated_interrupts_are_bounded_and_fail_closed() {
        let report = scanner(ArtifactScanLimits::new(1024, 32, 8).expect("limits"))
            .scan_reader(AlwaysInterrupted)
            .expect("typed report");
        assert_eq!(report.completion(), ArtifactScanCompletion::ReaderFailed);
        assert_eq!(report.bytes_consumed(), 0);
        assert_eq!(report.match_start_positions_checked(), 0);
        assert_eq!(report.match_count(), 0);
    }

    struct InvalidReadCount;

    impl Read for InvalidReadCount {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            Ok(output.len().saturating_add(1))
        }
    }

    #[test]
    fn invalid_reader_count_cannot_panic_or_expand_input_authority() {
        let report = scanner(ArtifactScanLimits::new(1024, 32, 8).expect("limits"))
            .scan_reader(InvalidReadCount)
            .expect("typed report");
        assert_eq!(report.completion(), ArtifactScanCompletion::ReaderFailed);
        assert_eq!(report.bytes_consumed(), 0);
        assert_eq!(report.match_start_positions_checked(), 0);
        assert_eq!(report.match_count(), 0);
    }

    #[test]
    fn deterministic_pattern_data_matrix_preserves_scan_invariants() {
        let mut source = String::from(
            r#"schema = "venom.artifact-signatures/v1"
pack_id = "property-matrix"
pack_revision = 1
title = "Property matrix"
summary = "Bounded deterministic parser and scanner matrix"
"#,
        );
        let mut data = vec![0u8; 512];
        let mut state = 0x4d59_5df4_d0f3_3173u64;
        for byte in &mut data {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            *byte = (state >> 32) as u8;
        }
        for index in 0..32usize {
            let first = 0x20u8 + index as u8;
            let middle = 0x60u8 + index as u8;
            let last = 0xa0u8 + index as u8;
            let pattern = if index % 2 == 0 {
                format!("{first:02x}   ? {last:02x}")
            } else {
                format!("{first:02x} {middle:02x}   {last:02x}")
            };
            writeln!(
                source,
                r#"
[[signatures]]
id = "matrix-{index:02}"
revision = 1
label = "Matrix marker {index}"
observation_class = "test-canary"
pattern = "{pattern}"
tags = ["property"]"#
            )
            .expect("string write");
            let offset = index * 13;
            data[offset] = first;
            if index % 2 == 1 {
                data[offset + 1] = middle;
            }
            data[offset + 2] = last;
        }

        let pack = ArtifactSignaturePack::parse_toml(source.as_bytes()).expect("pack");
        for signature in pack.signatures() {
            let canonical = signature.pattern().canonical();
            assert_eq!(
                ArtifactPattern::parse(canonical)
                    .expect("canonical round trip")
                    .canonical(),
                canonical
            );
        }
        let mut builder = ArtifactCatalog::builder();
        builder.register(pack).expect("register");
        let catalog = builder.seal().expect("seal");
        let byte_scanner = ArtifactScanner::new(
            &catalog,
            ArtifactScanLimits::new(1024, 256, 64).expect("limits"),
        )
        .expect("scanner");
        let bytes = byte_scanner.scan_bytes(&data).expect("byte scan");
        assert_eq!(bytes.completion(), ArtifactScanCompletion::Complete);

        let tuples = bytes
            .matches()
            .map(|observation| {
                (
                    observation.absolute_offset(),
                    observation.signature().clone(),
                    observation.pattern_length(),
                )
            })
            .collect::<Vec<_>>();
        assert!(tuples.windows(2).all(|window| window[0] < window[1]));
        assert_eq!(
            tuples.iter().cloned().collect::<BTreeSet<_>>().len(),
            tuples.len()
        );
        assert!(tuples.iter().all(|(offset, _, length)| {
            offset
                .checked_add(u64::from(*length))
                .is_some_and(|end| end <= data.len() as u64)
        }));

        for chunk in 1..=32 {
            let stream_scanner = ArtifactScanner::new(
                &catalog,
                ArtifactScanLimits::new(1024, 256, chunk).expect("limits"),
            )
            .expect("scanner");
            let streamed = stream_scanner
                .scan_reader(Cursor::new(&data))
                .expect("stream scan");
            assert_eq!(streamed, bytes, "chunk={chunk}");
        }
    }

    #[test]
    fn one_byte_chunks_preserve_maximum_leading_wildcard_carry() {
        let pattern = format!(
            "{} 41 42",
            std::iter::repeat_n("??", crate::MAX_PATTERN_BYTES - 2)
                .collect::<Vec<_>>()
                .join(" ")
        );
        let source = format!(
            r#"schema = "venom.artifact-signatures/v1"
pack_id = "max-carry"
pack_revision = 1
title = "Maximum carry"
summary = "Maximum bounded leading wildcard carry"
[[signatures]]
id = "leading-wildcard"
revision = 1
label = "Leading wildcard marker"
observation_class = "test-canary"
pattern = "{pattern}"
tags = ["carry"]
"#
        );
        let catalog = catalog_from_source(&source);
        let mut data = vec![0u8; crate::MAX_PATTERN_BYTES];
        data[crate::MAX_PATTERN_BYTES - 2..].copy_from_slice(b"AB");
        let byte_scanner = ArtifactScanner::new(
            &catalog,
            ArtifactScanLimits::new(1024, 8, 64).expect("limits"),
        )
        .expect("scanner");
        let stream_scanner = ArtifactScanner::new(
            &catalog,
            ArtifactScanLimits::new(1024, 8, 1).expect("limits"),
        )
        .expect("scanner");
        let bytes = byte_scanner.scan_bytes(&data).expect("bytes");
        let streamed = stream_scanner
            .scan_reader(Cursor::new(&data))
            .expect("stream");
        assert_eq!(streamed, bytes);
        assert_eq!(bytes.match_count(), 1);
        assert_eq!(bytes.matches().next().expect("match").absolute_offset(), 0);
        assert_eq!(bytes.match_work_units(), crate::MAX_PATTERN_BYTES + 1);
    }

    #[test]
    fn streaming_carry_is_explicitly_bounded_to_maximum_pattern_minus_one() {
        let maximum_carry = crate::MAX_PATTERN_BYTES - 1;
        let mut maximum_window = vec![0u8; crate::MAX_PATTERN_BYTES * 2 - 1];
        retain_unchecked_carry(&mut maximum_window, crate::MAX_PATTERN_BYTES, maximum_carry)
            .expect("bounded carry");
        assert_eq!(maximum_window.len(), maximum_carry);

        let mut oversized_carry = vec![0u8; crate::MAX_PATTERN_BYTES * 2 - 1];
        assert_eq!(
            retain_unchecked_carry(
                &mut oversized_carry,
                crate::MAX_PATTERN_BYTES - 1,
                maximum_carry,
            ),
            Err(ArtifactError::InvalidScanReport {
                field: "stream carry bytes"
            })
        );
    }

    fn many_offset_catalog() -> ArtifactCatalog {
        let mut source = String::from(
            r#"schema = "venom.artifact-signatures/v1"
pack_id = "many-offsets"
pack_revision = 1
title = "Many offsets"
summary = "Adversarial bounded anchor-offset fixture"
"#,
        );
        for offset in 0..64usize {
            let prefix = std::iter::repeat_n("??", offset)
                .collect::<Vec<_>>()
                .join(" ");
            let pattern = if prefix.is_empty() {
                format!("41 {:02X}", 0x80 + offset)
            } else {
                format!("{prefix} 41 {:02X}", 0x80 + offset)
            };
            writeln!(
                source,
                r#"
[[signatures]]
id = "offset-{offset:02}"
revision = 1
label = "Offset marker {offset}"
observation_class = "test-canary"
pattern = "{pattern}"
tags = ["work"]"#
            )
            .expect("write");
        }
        catalog_from_source(&source)
    }

    #[test]
    fn adversarial_many_offsets_stop_at_exact_match_work_budget() {
        let catalog = many_offset_catalog();
        let data = vec![0x41; 128];
        let limits = ArtifactScanLimits::new(1024, 32, 128)
            .expect("limits")
            .with_max_match_work_units(100)
            .expect("work limit");
        let byte_report = ArtifactScanner::new(&catalog, limits)
            .expect("scanner")
            .scan_bytes(&data)
            .expect("bytes");
        let stream_report = ArtifactScanner::new(&catalog, limits)
            .expect("scanner")
            .scan_reader(Cursor::new(&data))
            .expect("stream");
        assert_eq!(byte_report, stream_report);
        assert_eq!(
            byte_report.completion(),
            ArtifactScanCompletion::MatchWorkLimitReached
        );
        assert_eq!(byte_report.match_work_units(), 100);
        assert_eq!(byte_report.match_count(), 0);

        let tiny_chunks = ArtifactScanner::new(
            &catalog,
            ArtifactScanLimits::new(1024, 32, 1)
                .expect("limits")
                .with_max_match_work_units(100)
                .expect("work limit"),
        )
        .expect("scanner")
        .scan_reader(Cursor::new(&data))
        .expect("tiny stream");
        assert_eq!(
            tiny_chunks.completion(),
            ArtifactScanCompletion::MatchWorkLimitReached
        );
        assert_eq!(tiny_chunks.match_work_units(), 100);
        assert_eq!(
            tiny_chunks.matches().collect::<Vec<_>>(),
            byte_report.matches().collect::<Vec<_>>()
        );
    }

    #[test]
    fn multi_mebibyte_shared_anchor_catalog_completes_with_default_work_budget() {
        let source = r#"schema = "venom.artifact-signatures/v1"
pack_id = "work-completion"
pack_revision = 1
title = "Work completion"
summary = "Controlled multi mebibyte completion fixture"
[[signatures]]
id = "shared-anchor-zero"
revision = 1
label = "Shared anchor zero marker"
observation_class = "test-canary"
pattern = "56 00"
tags = ["work"]
[[signatures]]
id = "shared-anchor-one"
revision = 1
label = "Shared anchor one marker"
observation_class = "test-canary"
pattern = "56 01"
tags = ["work"]
"#;
        let catalog = catalog_from_source(source);
        let data = vec![0x56u8; 2 * 1024 * 1024];
        let report = ArtifactScanner::new(&catalog, ArtifactScanLimits::default())
            .expect("scanner")
            .scan_reader(Cursor::new(&data))
            .expect("scan");
        assert_eq!(report.completion(), ArtifactScanCompletion::Complete);
        assert_eq!(report.match_count(), 0);
        assert_eq!(report.bytes_consumed(), data.len() as u64);
        assert_eq!(report.match_start_positions_checked(), data.len() as u64);
        assert_eq!(report.match_work_units(), data.len() * 3);
        assert!(report.match_work_units() < DEFAULT_MATCH_WORK_UNITS);
    }
}
