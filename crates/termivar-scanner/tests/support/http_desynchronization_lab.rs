//! Test-only support module for bounded HTTP/1 parser-boundary comparisons.
//!
//! This module deliberately has no product, CLI, report, or live-target entry
//! point. It sends four fixed, harmless byte sequences through single-use
//! numeric-loopback sockets and records only typed boundary summaries.

use std::time::Duration;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinHandle,
    time::timeout,
};
use tokio_util::sync::CancellationToken;

use crate::{
    runtime_budget::RequestAccountingBroker, DecisionExecutionStage, RuntimeBudget,
    RuntimeBudgetDimension, TransportDispatchOutcome,
};

const MAX_CASE_REQUEST_BYTES: usize = 2 * 1024;
const MAX_MATRIX_REQUEST_BYTES: usize = 8 * 1024;
const CASE_TIMEOUT: Duration = Duration::from_secs(1);
const MATRIX_TIMEOUT: Duration = Duration::from_secs(5);
const INCOMPLETE_READ_TIMEOUT: Duration = Duration::from_millis(50);
const MATRIX_CASE_LIMIT: u32 = 4;

const CLEAN_REQUEST: &[u8; 63] =
    b"POST /cleanx HTTP/1.1\r\nHost: loopback\r\nContent-Length: 3\r\n\r\nabc";
const CONTENT_LENGTH_THEN_TRANSFER_ENCODING_REQUEST: &[u8; 101] = b"POST /matrix HTTP/1.1\r\nHost: loopback\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n";
const TRANSFER_ENCODING_THEN_CONTENT_LENGTH_REQUEST: &[u8; 102] = b"POST /matrix HTTP/1.1\r\nHost: loopback\r\nTransfer-Encoding: chunked\r\nContent-Length: 13\r\n\r\n0\r\n\r\npadding!";
const INCOMPLETE_REQUEST: &[u8; 62] =
    b"POST /cleanx HTTP/1.1\r\nHost: loopback\r\nContent-Length: 4\r\n\r\nab";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LabCaseId {
    Clean,
    ContentLengthThenTransferEncoding,
    TransferEncodingThenContentLength,
    Incomplete,
}

impl LabCaseId {
    const fn action_id(self) -> &'static str {
        match self {
            Self::Clean => "lab.http-desynchronization.clean",
            Self::ContentLengthThenTransferEncoding => {
                "lab.http-desynchronization.content-length-then-transfer-encoding"
            },
            Self::TransferEncodingThenContentLength => {
                "lab.http-desynchronization.transfer-encoding-then-content-length"
            },
            Self::Incomplete => "lab.http-desynchronization.incomplete",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ParserProfile {
    ContentLength,
    Chunked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ParserProgress {
    Complete { boundary: usize },
    Incomplete { needed: usize },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LabConclusion {
    Agreement,
    ParserBoundaryDisagreement,
    InconclusiveTimeout,
}

impl LabConclusion {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Agreement => "agreement",
            Self::ParserBoundaryDisagreement => "parser_boundary_disagreement",
            Self::InconclusiveTimeout => "inconclusive_timeout",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LabCaseSpec {
    id: LabCaseId,
    request: &'static [u8],
    front_parser: ParserProfile,
    back_parser: Option<ParserProfile>,
    expected_header_end: usize,
    expected_front_boundary: Option<usize>,
    expected_back_boundary: Option<usize>,
    expected_needed: Option<usize>,
    expected_conclusion: LabConclusion,
}

const LAB_CASES: [LabCaseSpec; MATRIX_CASE_LIMIT as usize] = [
    LabCaseSpec {
        id: LabCaseId::Clean,
        request: CLEAN_REQUEST,
        front_parser: ParserProfile::ContentLength,
        back_parser: Some(ParserProfile::ContentLength),
        expected_header_end: 60,
        expected_front_boundary: Some(63),
        expected_back_boundary: Some(63),
        expected_needed: None,
        expected_conclusion: LabConclusion::Agreement,
    },
    LabCaseSpec {
        id: LabCaseId::ContentLengthThenTransferEncoding,
        request: CONTENT_LENGTH_THEN_TRANSFER_ENCODING_REQUEST,
        front_parser: ParserProfile::ContentLength,
        back_parser: Some(ParserProfile::Chunked),
        expected_header_end: 88,
        expected_front_boundary: Some(91),
        expected_back_boundary: Some(101),
        expected_needed: None,
        expected_conclusion: LabConclusion::ParserBoundaryDisagreement,
    },
    LabCaseSpec {
        id: LabCaseId::TransferEncodingThenContentLength,
        request: TRANSFER_ENCODING_THEN_CONTENT_LENGTH_REQUEST,
        front_parser: ParserProfile::Chunked,
        back_parser: Some(ParserProfile::ContentLength),
        expected_header_end: 89,
        expected_front_boundary: Some(94),
        expected_back_boundary: Some(102),
        expected_needed: None,
        expected_conclusion: LabConclusion::ParserBoundaryDisagreement,
    },
    LabCaseSpec {
        id: LabCaseId::Incomplete,
        request: INCOMPLETE_REQUEST,
        front_parser: ParserProfile::ContentLength,
        back_parser: None,
        expected_header_end: 60,
        expected_front_boundary: None,
        expected_back_boundary: None,
        expected_needed: Some(64),
        expected_conclusion: LabConclusion::InconclusiveTimeout,
    },
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LabCaseSummary {
    id: LabCaseId,
    front_request_bytes: usize,
    back_request_bytes: usize,
    header_end: usize,
    front_parser: ParserProfile,
    back_parser: Option<ParserProfile>,
    front_boundary: Option<usize>,
    back_boundary: Option<usize>,
    needed_bytes: Option<usize>,
    conclusion: LabConclusion,
    dispatch_outcome: TransportDispatchOutcome,
    front_connections: usize,
    back_connections: usize,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct NetworkTotals {
    front_bind_attempts: usize,
    back_bind_attempts: usize,
    front_connections: usize,
    back_connections: usize,
    front_request_bytes: usize,
    back_request_bytes: usize,
    in_flight_cases: usize,
    peak_in_flight_cases: usize,
}

impl NetworkTotals {
    fn begin_case(&mut self) -> Result<(), LabError> {
        if self.in_flight_cases != 0 {
            return Err(LabError::ConcurrentCase);
        }
        self.in_flight_cases = self.in_flight_cases.saturating_add(1);
        self.peak_in_flight_cases = self.peak_in_flight_cases.max(self.in_flight_cases);
        Ok(())
    }

    fn finish_case(&mut self) {
        assert_eq!(
            self.in_flight_cases, 1,
            "a laboratory case must finish exactly once"
        );
        self.in_flight_cases = 0;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LabError {
    CancelledBeforeDispatch,
    CancelledDuringDispatch,
    Budget(RuntimeBudgetDimension),
    CaseTooLarge,
    MatrixTooLarge,
    ConcurrentCase,
    BindFailed,
    ConnectFailed,
    IoFailed,
    NonLoopbackPeer,
    ParserRejected,
    UnexpectedParserState,
    CaseDeadline,
    TaskFailed,
}

impl LabError {
    const fn budget_dimension(self) -> Option<RuntimeBudgetDimension> {
        match self {
            Self::Budget(dimension) => Some(dimension),
            _ => None,
        }
    }
}

struct ClientTaskGuard {
    handle: Option<JoinHandle<Result<(), LabError>>>,
}

impl ClientTaskGuard {
    fn new(handle: JoinHandle<Result<(), LabError>>) -> Self {
        Self {
            handle: Some(handle),
        }
    }

    async fn join(mut self) -> Result<(), LabError> {
        let result = self
            .handle
            .as_mut()
            .ok_or(LabError::TaskFailed)?
            .await
            .map_err(|_| LabError::TaskFailed)?;
        let _ = self.handle.take();
        result
    }
}

impl Drop for ClientTaskGuard {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

fn validate_case_bounds(request_bytes: usize, matrix_bytes: usize) -> Result<(), LabError> {
    if request_bytes > MAX_CASE_REQUEST_BYTES {
        return Err(LabError::CaseTooLarge);
    }
    if matrix_bytes > MAX_MATRIX_REQUEST_BYTES {
        return Err(LabError::MatrixTooLarge);
    }
    Ok(())
}

fn bounded_parser_boundary(boundary: usize) -> Result<usize, LabError> {
    if boundary > MAX_CASE_REQUEST_BYTES {
        Err(LabError::CaseTooLarge)
    } else {
        Ok(boundary)
    }
}

fn find_sequence(haystack: &[u8], needle: &[u8], start: usize) -> Option<usize> {
    haystack
        .get(start..)?
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|offset| start.saturating_add(offset))
}

fn http_request_line_marker_count(request: &[u8]) -> usize {
    request
        .windows(b" HTTP/".len())
        .filter(|window| *window == b" HTTP/")
        .count()
}

fn header_end(request: &[u8]) -> Result<usize, LabError> {
    find_sequence(request, b"\r\n\r\n", 0)
        .and_then(|offset| offset.checked_add(4))
        .ok_or(LabError::ParserRejected)
}

fn exact_header_value<'a>(
    request: &'a [u8],
    header_end: usize,
    prefix: &str,
) -> Result<&'a str, LabError> {
    let header = std::str::from_utf8(request.get(..header_end).ok_or(LabError::ParserRejected)?)
        .map_err(|_| LabError::ParserRejected)?;
    let mut matching = header
        .split("\r\n")
        .skip(1)
        .filter_map(|line| line.strip_prefix(prefix));
    let value = matching.next().ok_or(LabError::ParserRejected)?;
    if matching.next().is_some() || value.is_empty() {
        return Err(LabError::ParserRejected);
    }
    Ok(value)
}

fn parse_content_length(request: &[u8]) -> Result<ParserProgress, LabError> {
    let header_end = header_end(request)?;
    let length = exact_header_value(request, header_end, "Content-Length: ")?
        .parse::<usize>()
        .map_err(|_| LabError::ParserRejected)?;
    let needed = bounded_parser_boundary(
        header_end
            .checked_add(length)
            .ok_or(LabError::ParserRejected)?,
    )?;
    if request.len() < needed {
        Ok(ParserProgress::Incomplete { needed })
    } else {
        Ok(ParserProgress::Complete { boundary: needed })
    }
}

fn parse_chunked(request: &[u8]) -> Result<ParserProgress, LabError> {
    let header_end = header_end(request)?;
    if exact_header_value(request, header_end, "Transfer-Encoding: ")? != "chunked" {
        return Err(LabError::ParserRejected);
    }

    let mut cursor = header_end;
    loop {
        let Some(size_line_end) = find_sequence(request, b"\r\n", cursor) else {
            let needed = bounded_parser_boundary(
                request
                    .len()
                    .checked_add(2)
                    .ok_or(LabError::ParserRejected)?,
            )?;
            return Ok(ParserProgress::Incomplete { needed });
        };
        let size_text = std::str::from_utf8(
            request
                .get(cursor..size_line_end)
                .ok_or(LabError::ParserRejected)?,
        )
        .map_err(|_| LabError::ParserRejected)?;
        if size_text.is_empty() || size_text.contains(';') {
            return Err(LabError::ParserRejected);
        }
        let size = usize::from_str_radix(size_text, 16).map_err(|_| LabError::ParserRejected)?;
        cursor = size_line_end
            .checked_add(2)
            .ok_or(LabError::ParserRejected)?;

        if size == 0 {
            let needed =
                bounded_parser_boundary(cursor.checked_add(2).ok_or(LabError::ParserRejected)?)?;
            if request.len() < needed {
                return Ok(ParserProgress::Incomplete { needed });
            }
            if request.get(cursor..needed) != Some(&b"\r\n"[..]) {
                return Err(LabError::ParserRejected);
            }
            return Ok(ParserProgress::Complete { boundary: needed });
        }

        let data_end = cursor.checked_add(size).ok_or(LabError::ParserRejected)?;
        let needed =
            bounded_parser_boundary(data_end.checked_add(2).ok_or(LabError::ParserRejected)?)?;
        if request.len() < needed {
            return Ok(ParserProgress::Incomplete { needed });
        }
        if request.get(data_end..needed) != Some(&b"\r\n"[..]) {
            return Err(LabError::ParserRejected);
        }
        cursor = needed;
    }
}

fn parse_with(profile: ParserProfile, request: &[u8]) -> Result<ParserProgress, LabError> {
    match profile {
        ParserProfile::ContentLength => parse_content_length(request),
        ParserProfile::Chunked => parse_chunked(request),
    }
}

async fn bind_loopback_listener() -> Result<TcpListener, LabError> {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|_| LabError::BindFailed)?;
    if !listener
        .local_addr()
        .map_err(|_| LabError::BindFailed)?
        .ip()
        .is_loopback()
    {
        return Err(LabError::NonLoopbackPeer);
    }
    Ok(listener)
}

async fn execute_network_case(
    spec: LabCaseSpec,
    totals: &mut NetworkTotals,
) -> Result<LabCaseSummary, LabError> {
    let front_connections_before = totals.front_connections;
    let back_connections_before = totals.back_connections;
    totals.front_bind_attempts = totals.front_bind_attempts.saturating_add(1);
    let front_listener = bind_loopback_listener().await?;
    let front_address = front_listener
        .local_addr()
        .map_err(|_| LabError::BindFailed)?;
    let back_listener = if spec.back_parser.is_some() {
        totals.back_bind_attempts = totals.back_bind_attempts.saturating_add(1);
        Some(bind_loopback_listener().await?)
    } else {
        None
    };
    let back_address = back_listener
        .as_ref()
        .map(|listener| listener.local_addr())
        .transpose()
        .map_err(|_| LabError::BindFailed)?;

    let (release_client, hold_client) = oneshot::channel::<()>();
    let client_request = spec.request;
    let client_task = ClientTaskGuard::new(tokio::spawn(async move {
        let mut client = TcpStream::connect(front_address)
            .await
            .map_err(|_| LabError::ConnectFailed)?;
        if !client
            .peer_addr()
            .map_err(|_| LabError::ConnectFailed)?
            .ip()
            .is_loopback()
        {
            return Err(LabError::NonLoopbackPeer);
        }
        client
            .write_all(client_request)
            .await
            .map_err(|_| LabError::IoFailed)?;
        let _ = hold_client.await;
        Ok(())
    }));

    let result = async {
        let (mut front, front_peer) = front_listener
            .accept()
            .await
            .map_err(|_| LabError::IoFailed)?;
        if !front_peer.ip().is_loopback() {
            return Err(LabError::NonLoopbackPeer);
        }
        totals.front_connections = totals.front_connections.saturating_add(1);

        let mut received = vec![0_u8; spec.request.len()];
        front
            .read_exact(&mut received)
            .await
            .map_err(|_| LabError::IoFailed)?;
        if received != spec.request {
            return Err(LabError::IoFailed);
        }
        totals.front_request_bytes = totals
            .front_request_bytes
            .checked_add(received.len())
            .ok_or(LabError::MatrixTooLarge)?;

        let front_progress = parse_with(spec.front_parser, &received)?;
        match (front_progress, back_listener, back_address) {
            (
                ParserProgress::Complete {
                    boundary: front_boundary,
                },
                Some(back_listener),
                Some(back_address),
            ) => {
                let mut forward = TcpStream::connect(back_address)
                    .await
                    .map_err(|_| LabError::ConnectFailed)?;
                if !forward
                    .peer_addr()
                    .map_err(|_| LabError::ConnectFailed)?
                    .ip()
                    .is_loopback()
                {
                    return Err(LabError::NonLoopbackPeer);
                }
                forward
                    .write_all(&received)
                    .await
                    .map_err(|_| LabError::IoFailed)?;

                let (mut back, back_peer) = back_listener
                    .accept()
                    .await
                    .map_err(|_| LabError::IoFailed)?;
                if !back_peer.ip().is_loopback() {
                    return Err(LabError::NonLoopbackPeer);
                }
                totals.back_connections = totals.back_connections.saturating_add(1);
                let mut forwarded = vec![0_u8; spec.request.len()];
                back.read_exact(&mut forwarded)
                    .await
                    .map_err(|_| LabError::IoFailed)?;
                if forwarded != spec.request {
                    return Err(LabError::IoFailed);
                }
                totals.back_request_bytes = totals
                    .back_request_bytes
                    .checked_add(forwarded.len())
                    .ok_or(LabError::MatrixTooLarge)?;
                let back_parser = spec.back_parser.ok_or(LabError::UnexpectedParserState)?;
                let ParserProgress::Complete {
                    boundary: back_boundary,
                } = parse_with(back_parser, &forwarded)?
                else {
                    return Err(LabError::UnexpectedParserState);
                };
                let conclusion = if front_boundary == back_boundary {
                    LabConclusion::Agreement
                } else {
                    LabConclusion::ParserBoundaryDisagreement
                };
                Ok(LabCaseSummary {
                    id: spec.id,
                    front_request_bytes: received.len(),
                    back_request_bytes: forwarded.len(),
                    header_end: header_end(&received)?,
                    front_parser: spec.front_parser,
                    back_parser: spec.back_parser,
                    front_boundary: Some(front_boundary),
                    back_boundary: Some(back_boundary),
                    needed_bytes: None,
                    conclusion,
                    dispatch_outcome: TransportDispatchOutcome::Completed,
                    front_connections: totals
                        .front_connections
                        .saturating_sub(front_connections_before),
                    back_connections: totals
                        .back_connections
                        .saturating_sub(back_connections_before),
                })
            },
            (ParserProgress::Incomplete { needed }, None, None) => {
                let missing = needed
                    .checked_sub(received.len())
                    .filter(|missing| *missing > 0)
                    .ok_or(LabError::UnexpectedParserState)?;
                let mut remainder = vec![0_u8; missing];
                match timeout(INCOMPLETE_READ_TIMEOUT, front.read_exact(&mut remainder)).await {
                    Err(_) => Ok(LabCaseSummary {
                        id: spec.id,
                        front_request_bytes: received.len(),
                        back_request_bytes: 0,
                        header_end: header_end(&received)?,
                        front_parser: spec.front_parser,
                        back_parser: None,
                        front_boundary: None,
                        back_boundary: None,
                        needed_bytes: Some(needed),
                        conclusion: LabConclusion::InconclusiveTimeout,
                        dispatch_outcome: TransportDispatchOutcome::RequestTimeout,
                        front_connections: totals
                            .front_connections
                            .saturating_sub(front_connections_before),
                        back_connections: totals
                            .back_connections
                            .saturating_sub(back_connections_before),
                    }),
                    Ok(_) => Err(LabError::UnexpectedParserState),
                }
            },
            _ => Err(LabError::UnexpectedParserState),
        }
    }
    .await;

    let _ = release_client.send(());
    client_task.join().await?;
    result
}

async fn execute_case(
    spec: LabCaseSpec,
    broker: &RequestAccountingBroker,
    cancellation: &CancellationToken,
    matrix_bytes: usize,
    totals: &mut NetworkTotals,
) -> Result<LabCaseSummary, LabError> {
    if cancellation.is_cancelled() {
        return Err(LabError::CancelledBeforeDispatch);
    }
    validate_case_bounds(spec.request.len(), matrix_bytes)?;

    let mut lease = broker
        .try_begin_with_request_body_bytes(
            spec.id.action_id(),
            DecisionExecutionStage::Active,
            None,
            u64::try_from(spec.request.len()).map_err(|_| LabError::CaseTooLarge)?,
        )
        .map_err(|error| LabError::Budget(error.dimension()))?;

    totals.begin_case()?;
    let result = tokio::select! {
        biased;
        _ = cancellation.cancelled() => None,
        result = timeout(CASE_TIMEOUT, execute_network_case(spec, totals)) => Some(result),
    };
    totals.finish_case();
    let Some(result) = result else {
        lease.finish(TransportDispatchOutcome::Cancelled);
        return Err(LabError::CancelledDuringDispatch);
    };
    let summary = match result {
        Ok(Ok(summary)) => {
            lease.finish(summary.dispatch_outcome);
            summary
        },
        Ok(Err(error)) => {
            lease.finish(TransportDispatchOutcome::TransportFailure);
            return Err(error);
        },
        Err(_) => {
            lease.finish(TransportDispatchOutcome::RequestTimeout);
            return Err(LabError::CaseDeadline);
        },
    };
    drop(lease);
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };

    struct DropSignal(Arc<AtomicBool>);

    impl Drop for DropSignal {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    fn matrix_budget() -> RuntimeBudget {
        RuntimeBudget::default()
            .with_max_total_requests(MATRIX_CASE_LIMIT)
            .with_max_wall_time(MATRIX_TIMEOUT)
            .with_max_response_bytes(1)
            .with_max_request_body_bytes(
                u64::try_from(MAX_MATRIX_REQUEST_BYTES).expect("matrix limit fits u64"),
            )
            .with_max_active_verifications(
                u16::try_from(MATRIX_CASE_LIMIT).expect("case limit fits u16"),
            )
    }

    fn assert_summary_matches_literal_oracle(summary: LabCaseSummary, spec: LabCaseSpec) {
        assert_eq!(summary.id, spec.id);
        assert_eq!(http_request_line_marker_count(spec.request), 1);
        assert_eq!(summary.front_request_bytes, spec.request.len());
        assert_eq!(
            summary.back_request_bytes,
            spec.back_parser.map_or(0, |_| spec.request.len())
        );
        assert_eq!(summary.header_end, spec.expected_header_end);
        assert_eq!(summary.front_parser, spec.front_parser);
        assert_eq!(summary.back_parser, spec.back_parser);
        assert_eq!(summary.front_boundary, spec.expected_front_boundary);
        assert_eq!(summary.back_boundary, spec.expected_back_boundary);
        assert_eq!(summary.needed_bytes, spec.expected_needed);
        assert_eq!(summary.conclusion, spec.expected_conclusion);
        assert_eq!(
            summary.conclusion.as_str(),
            spec.expected_conclusion.as_str()
        );
        assert_eq!(summary.front_connections, 1);
        assert_eq!(
            summary.back_connections,
            usize::from(spec.back_parser.is_some())
        );
    }

    #[tokio::test]
    async fn owned_loopback_matrix_is_bounded_and_reports_only_parser_boundaries() {
        let broker = RequestAccountingBroker::new(matrix_budget());
        let cancellation = CancellationToken::new();
        let mut totals = NetworkTotals::default();
        let matrix_bytes = LAB_CASES
            .iter()
            .map(|spec| spec.request.len())
            .sum::<usize>();
        assert_eq!(matrix_bytes, 328);

        let summaries = timeout(MATRIX_TIMEOUT, async {
            let mut summaries = Vec::with_capacity(LAB_CASES.len());
            for spec in LAB_CASES {
                summaries.push(
                    execute_case(spec, &broker, &cancellation, matrix_bytes, &mut totals)
                        .await
                        .expect("fixed owned loopback case must complete"),
                );
            }
            summaries
        })
        .await
        .expect("matrix stays within its total deadline");

        assert_eq!(summaries.len(), LAB_CASES.len());
        for (summary, spec) in summaries.iter().copied().zip(LAB_CASES) {
            assert_summary_matches_literal_oracle(summary, spec);
        }
        assert_eq!(
            summaries[0].dispatch_outcome,
            TransportDispatchOutcome::Completed
        );
        assert_eq!(
            summaries[1].dispatch_outcome,
            TransportDispatchOutcome::Completed
        );
        assert_eq!(
            summaries[2].dispatch_outcome,
            TransportDispatchOutcome::Completed
        );
        assert_eq!(
            summaries[3].dispatch_outcome,
            TransportDispatchOutcome::RequestTimeout
        );

        assert_eq!(totals.front_bind_attempts, 4);
        assert_eq!(totals.back_bind_attempts, 3);
        assert_eq!(totals.front_connections, 4);
        assert_eq!(totals.back_connections, 3);
        assert_eq!(totals.front_request_bytes, 328);
        assert_eq!(totals.back_request_bytes, 266);
        assert_eq!(totals.in_flight_cases, 0);
        assert_eq!(totals.peak_in_flight_cases, 1);

        let snapshot = broker.snapshot();
        assert_eq!(snapshot.total_requests(), 4);
        assert_eq!(snapshot.active_verifications(), 4);
        assert_eq!(snapshot.passive_requests(), 0);
        assert_eq!(snapshot.request_body_bytes(), 328);
        assert_eq!(snapshot.response_bytes(), 0);
        assert_eq!(broker.budget().max_response_bytes(), 1);
        assert_eq!(broker.budget().max_wall_time(), MATRIX_TIMEOUT);

        let audit = broker.dispatch_audit();
        assert_eq!(audit.omitted_receipt_count(), 0);
        assert_eq!(audit.receipts().len(), 4);
        let expected_outcomes = [
            TransportDispatchOutcome::Completed,
            TransportDispatchOutcome::Completed,
            TransportDispatchOutcome::Completed,
            TransportDispatchOutcome::RequestTimeout,
        ];
        for ((receipt, spec), expected_outcome) in audit
            .receipts()
            .iter()
            .zip(LAB_CASES)
            .zip(expected_outcomes)
        {
            assert_eq!(receipt.action_id(), spec.id.action_id());
            assert_eq!(receipt.stage(), DecisionExecutionStage::Active);
            assert_eq!(receipt.origin(), None);
            assert_eq!(
                receipt.request_body_bytes(),
                u64::try_from(spec.request.len()).unwrap()
            );
            assert_eq!(receipt.response_bytes(), 0);
            assert_eq!(receipt.outcome(), expected_outcome);
        }

        let totals_before_refusal = totals;
        let snapshot_before_refusal = broker.snapshot();
        let refusal = execute_case(
            LAB_CASES[0],
            &broker,
            &cancellation,
            matrix_bytes,
            &mut totals,
        )
        .await
        .unwrap_err();
        assert_eq!(
            refusal.budget_dimension(),
            Some(RuntimeBudgetDimension::TotalRequests)
        );
        assert_eq!(totals, totals_before_refusal);
        assert_eq!(broker.snapshot(), snapshot_before_refusal);
        assert_eq!(broker.dispatch_audit().receipts().len(), 4);
    }

    #[tokio::test]
    async fn cancellation_prevents_accounting_and_loopback_setup() {
        let broker = RequestAccountingBroker::new(matrix_budget());
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let mut totals = NetworkTotals::default();

        let error = execute_case(LAB_CASES[0], &broker, &cancellation, 328, &mut totals)
            .await
            .unwrap_err();

        assert_eq!(error, LabError::CancelledBeforeDispatch);
        assert_eq!(broker.snapshot(), Default::default());
        assert!(broker.dispatch_audit().is_empty());
        assert_eq!(totals, NetworkTotals::default());
    }

    #[tokio::test]
    async fn cancellation_during_dispatch_finishes_accounting_and_closes_transport() {
        let broker = RequestAccountingBroker::new(matrix_budget());
        let cancellation = CancellationToken::new();
        let cancellation_trigger = cancellation.clone();
        let trigger_task = tokio::spawn(async move {
            tokio::task::yield_now().await;
            cancellation_trigger.cancel();
        });
        let mut totals = NetworkTotals::default();
        let error = execute_case(LAB_CASES[3], &broker, &cancellation, 328, &mut totals)
            .await
            .unwrap_err();
        trigger_task.await.expect("cancellation trigger must join");

        assert_eq!(error, LabError::CancelledDuringDispatch);
        assert_eq!(totals.in_flight_cases, 0);
        let audit = broker.dispatch_audit();
        assert_eq!(audit.receipts().len(), 1);
        assert_eq!(
            audit.receipts()[0].outcome(),
            TransportDispatchOutcome::Cancelled
        );
        let snapshot = broker.snapshot();
        assert_eq!(snapshot.total_requests(), 1);
        assert_eq!(snapshot.active_verifications(), 1);
        assert_eq!(snapshot.request_body_bytes(), 62);
        assert_eq!(snapshot.response_bytes(), 0);
    }

    #[tokio::test]
    async fn cancelled_join_aborts_the_owned_client_task() {
        let dropped = Arc::new(AtomicBool::new(false));
        let task_dropped = Arc::clone(&dropped);
        let (started, started_rx) = oneshot::channel();
        let guard = ClientTaskGuard::new(tokio::spawn(async move {
            let _drop_signal = DropSignal(task_dropped);
            let _ = started.send(());
            std::future::pending::<()>().await;
            Ok(())
        }));
        started_rx.await.expect("owned client task must start");

        assert!(timeout(Duration::from_millis(10), guard.join())
            .await
            .is_err());
        timeout(Duration::from_secs(1), async {
            while !dropped.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("aborted client task must release its owned future");
    }

    #[test]
    fn fixed_request_bytes_have_independent_literal_boundaries() {
        let expected = [
            (63, 60, Some(63), Some(63), None),
            (101, 88, Some(91), Some(101), None),
            (102, 89, Some(94), Some(102), None),
            (62, 60, None, None, Some(64)),
        ];

        for (spec, (length, header, front, back, needed)) in LAB_CASES.into_iter().zip(expected) {
            assert_eq!(http_request_line_marker_count(spec.request), 1);
            assert_eq!(spec.request.len(), length);
            assert_eq!(header_end(spec.request).unwrap(), header);
            assert_eq!(spec.expected_header_end, header);
            assert_eq!(spec.expected_front_boundary, front);
            assert_eq!(spec.expected_back_boundary, back);
            assert_eq!(spec.expected_needed, needed);
            assert_eq!(
                parse_with(spec.front_parser, spec.request).unwrap(),
                match (front, needed) {
                    (Some(boundary), None) => ParserProgress::Complete { boundary },
                    (None, Some(needed)) => ParserProgress::Incomplete { needed },
                    _ => panic!("literal oracle must select exactly one front state"),
                }
            );
            if let (Some(profile), Some(boundary)) = (spec.back_parser, back) {
                assert_eq!(
                    parse_with(profile, spec.request).unwrap(),
                    ParserProgress::Complete { boundary }
                );
            }
        }
        assert_eq!(
            http_request_line_marker_count(
                b"GET /first HTTP/1.1\r\nHost: loopback\r\n\r\nGET /second HTTP/1.1\r\n\r\n"
            ),
            2
        );
    }

    #[test]
    fn size_guards_and_parser_controls_fail_closed() {
        let mut totals = NetworkTotals::default();
        assert_eq!(totals.begin_case(), Ok(()));
        assert_eq!(totals.begin_case(), Err(LabError::ConcurrentCase));
        totals.finish_case();
        assert_eq!(totals.in_flight_cases, 0);

        assert_eq!(
            validate_case_bounds(MAX_CASE_REQUEST_BYTES + 1, 0),
            Err(LabError::CaseTooLarge)
        );
        assert_eq!(
            validate_case_bounds(1, MAX_MATRIX_REQUEST_BYTES + 1),
            Err(LabError::MatrixTooLarge)
        );
        assert_eq!(
            parse_content_length(b"POST / HTTP/1.1\r\nHost: loopback\r\n\r\n"),
            Err(LabError::ParserRejected)
        );
        assert_eq!(
            parse_content_length(
                b"POST / HTTP/1.1\r\nHost: loopback\r\nContent-Length: 65536\r\n\r\n"
            ),
            Err(LabError::CaseTooLarge)
        );
        assert_eq!(
            parse_chunked(
                b"POST / HTTP/1.1\r\nHost: loopback\r\nTransfer-Encoding: gzip\r\n\r\n0\r\n\r\n"
            ),
            Err(LabError::ParserRejected)
        );
        assert_eq!(
            parse_chunked(b"POST / HTTP/1.1\r\nHost: loopback\r\nTransfer-Encoding: chunked\r\n\r\n1;x=y\r\na\r\n0\r\n\r\n"),
            Err(LabError::ParserRejected)
        );
        assert_eq!(
            parse_chunked(
                b"POST / HTTP/1.1\r\nHost: loopback\r\nTransfer-Encoding: chunked\r\n\r\n10000\r\n"
            ),
            Err(LabError::CaseTooLarge)
        );
    }
}
