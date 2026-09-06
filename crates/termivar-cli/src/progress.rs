//! Bounded, best-effort stderr presentation for opted-in web assessments.
//!
//! Scanner execution only exposes safe numeric snapshots. This module owns all
//! formatting and terminal I/O, and its single fixed-size mailbox deliberately
//! cannot exert backpressure on assessment work.

use std::{
    collections::VecDeque,
    fmt,
    io::{self, Write},
    sync::{mpsc, Arc, Condvar, Mutex, MutexGuard},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use termivar_scanner::web_runtime::{
    WebAssessmentProgressObserver, WebAssessmentProgressSnapshot, WebAssessmentUsage,
};

const PREFIX: &str = "[progress]";
const MAX_LINE_BYTES: usize = 512;
const MAX_TOTAL_BYTES: usize = 64 * 1024;
const TERMINAL_RESERVE_BYTES: usize = MAX_LINE_BYTES;
const MAX_TRANSITIONS: usize = 8;
const TRANSITION_RESERVE_BYTES: usize = MAX_TRANSITIONS * MAX_LINE_BYTES;
const SNAPSHOT_BUDGET_BYTES: usize =
    MAX_TOTAL_BYTES - TRANSITION_RESERVE_BYTES - TERMINAL_RESERVE_BYTES;
const SHUTDOWN_WAIT: Duration = Duration::from_millis(250);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProgressStage {
    AssessmentRunning,
    ComposingReport,
    RenderingReport,
    WritingStdout,
    PublishingReport,
    Completed,
    Incomplete,
    Failed,
}

impl ProgressStage {
    const fn label(self) -> &'static str {
        match self {
            Self::AssessmentRunning => "assessment_running",
            Self::ComposingReport => "composing_report",
            Self::RenderingReport => "rendering_report",
            Self::WritingStdout => "writing_stdout",
            Self::PublishingReport => "publishing_report",
            Self::Completed => "completed",
            Self::Incomplete => "incomplete",
            Self::Failed => "failed",
        }
    }

    const fn terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Incomplete | Self::Failed)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct ProgressCounts {
    accounted_requests: Option<u32>,
    active_verifications: Option<u16>,
    subjects_started: Option<usize>,
    subjects_processed: Option<usize>,
}

impl From<WebAssessmentProgressSnapshot> for ProgressCounts {
    fn from(snapshot: WebAssessmentProgressSnapshot) -> Self {
        Self {
            accounted_requests: Some(snapshot.requests_accounted()),
            active_verifications: Some(snapshot.active_verifications_accounted()),
            subjects_started: Some(snapshot.executed_subjects()),
            subjects_processed: Some(snapshot.subjects_processed()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BundleCommitState {
    NotCommitted,
    Committed,
}

impl BundleCommitState {
    const fn label(self) -> &'static str {
        match self {
            Self::NotCommitted => "not_committed",
            Self::Committed => "committed",
        }
    }
}

/// One opted-in progress lifecycle. Construction starts exactly one writer;
/// the ordinary scan path never creates this type.
pub(crate) struct ProgressSession {
    observer: WebAssessmentProgressObserver,
    started_at: Instant,
    counts: ProgressCounts,
    output: Option<ProgressOutput>,
    final_usage: bool,
    terminal: bool,
}

impl ProgressSession {
    pub(crate) fn start(observer: WebAssessmentProgressObserver) -> Self {
        let counts = observer.latest().map(Into::into).unwrap_or_default();
        let mut session = Self {
            observer,
            started_at: Instant::now(),
            counts,
            output: ProgressOutput::stderr(),
            final_usage: false,
            terminal: false,
        };
        session.transition(ProgressStage::AssessmentRunning);
        session
    }

    pub(crate) fn periodic_snapshot(&mut self) {
        if self.terminal {
            return;
        }
        self.refresh();
        let line = render_line(
            ProgressStage::AssessmentRunning,
            self.started_at.elapsed(),
            self.counts,
            None,
        );
        if let Some(output) = &self.output {
            output.snapshot(line);
        }
    }

    pub(crate) fn observe_final_usage(&mut self, usage: WebAssessmentUsage) {
        self.refresh();
        self.counts.accounted_requests = Some(usage.total_requests());
        self.counts.active_verifications = Some(usage.active_verifications());
        self.counts.subjects_started = Some(usage.executed_subjects());
        self.counts.subjects_processed = self
            .counts
            .subjects_processed
            .map(|processed| processed.min(usage.executed_subjects()));
        self.final_usage = true;
    }

    pub(crate) fn transition(&mut self, stage: ProgressStage) {
        if self.terminal || stage.terminal() {
            return;
        }
        self.refresh();
        let line = render_line(stage, self.started_at.elapsed(), self.counts, None);
        if let Some(output) = &self.output {
            output.transition(line);
        }
    }

    pub(crate) fn finish(
        &mut self,
        stage: ProgressStage,
        bundle_commit: Option<BundleCommitState>,
    ) {
        if self.terminal || !stage.terminal() {
            return;
        }
        self.refresh();
        self.terminal = true;
        let line = render_line(stage, self.started_at.elapsed(), self.counts, bundle_commit);
        if let Some(mut output) = self.output.take() {
            output.terminal(line);
        }
    }

    fn refresh(&mut self) {
        if self.final_usage {
            return;
        }
        if let Some(snapshot) = self.observer.latest() {
            self.counts = snapshot.into();
        }
    }
}

impl fmt::Debug for ProgressSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProgressSession")
            .field("terminal", &self.terminal)
            .finish_non_exhaustive()
    }
}

impl Drop for ProgressSession {
    fn drop(&mut self) {
        if let Some(mut output) = self.output.take() {
            output.stop_without_terminal();
        }
    }
}

fn render_line(
    stage: ProgressStage,
    elapsed: Duration,
    counts: ProgressCounts,
    bundle_commit: Option<BundleCommitState>,
) -> Vec<u8> {
    let elapsed_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
    let publication = bundle_commit.map_or_else(String::new, |state| {
        format!(" bundle_commit={}", state.label())
    });
    let accounted_requests = display_count(counts.accounted_requests);
    let active_verifications = display_count(counts.active_verifications);
    let subjects_started = display_count(counts.subjects_started);
    let subjects_processed = display_count(counts.subjects_processed);
    let line = format!(
        "{PREFIX} state={} elapsed_ms={elapsed_ms} accounted_requests={accounted_requests} accounted_active_verifications={active_verifications} subjects_started={subjects_started} subjects_processed={subjects_processed} counts=last_observed{publication}\n",
        stage.label(),
    );
    debug_assert!(line.is_ascii());
    debug_assert!(line.len() <= MAX_LINE_BYTES);
    line.into_bytes()
}

fn display_count<T: fmt::Display>(count: Option<T>) -> String {
    count.map_or_else(|| "unknown".to_owned(), |count| count.to_string())
}

struct ProgressOutput {
    shared: Arc<Mailbox>,
    done: Option<mpsc::Receiver<()>>,
    worker: Option<JoinHandle<()>>,
    closed: bool,
}

impl ProgressOutput {
    fn stderr() -> Option<Self> {
        Self::spawn_with(move |shared, done| {
            let stderr = io::stderr();
            run_writer(stderr, shared, done);
        })
    }

    fn spawn_with(
        writer: impl FnOnce(Arc<Mailbox>, mpsc::Sender<()>) + Send + 'static,
    ) -> Option<Self> {
        let shared = Arc::new(Mailbox::default());
        let (done_tx, done_rx) = mpsc::channel();
        let worker_shared = Arc::clone(&shared);
        let worker = thread::Builder::new()
            .name("termivar-progress".to_owned())
            .spawn(move || writer(worker_shared, done_tx))
            .ok()?;
        Some(Self {
            shared,
            done: Some(done_rx),
            worker: Some(worker),
            closed: false,
        })
    }

    #[cfg(test)]
    fn with_writer(writer: impl Write + Send + 'static) -> Option<Self> {
        Self::spawn_with(move |shared, done| run_writer(writer, shared, done))
    }

    fn transition(&self, line: Vec<u8>) {
        self.shared.push_transition(line);
    }

    fn snapshot(&self, line: Vec<u8>) {
        self.shared.replace_snapshot(line);
    }

    fn terminal(&mut self, line: Vec<u8>) {
        self.shared.push_terminal(line);
        self.close(true);
    }

    fn stop_without_terminal(&mut self) {
        self.close(false);
    }

    fn close(&mut self, drain: bool) {
        if self.closed {
            return;
        }
        self.closed = true;
        self.shared.close(drain);
        let finished = self
            .done
            .take()
            .is_some_and(|done| done.recv_timeout(SHUTDOWN_WAIT).is_ok());
        if finished {
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
        } else {
            // Dropping a JoinHandle detaches it. A permanently blocked OS stderr
            // write can therefore retain this one worker until process exit.
            self.worker.take();
        }
    }
}

impl Drop for ProgressOutput {
    fn drop(&mut self) {
        self.close(false);
    }
}

#[derive(Default)]
struct Mailbox {
    state: Mutex<MailboxState>,
    ready: Condvar,
}

#[derive(Default)]
struct MailboxState {
    transitions: VecDeque<Vec<u8>>,
    snapshot: Option<Vec<u8>>,
    terminal: Option<Vec<u8>>,
    accepted_transition_bytes: usize,
    accepted_snapshot_bytes: usize,
    closing: bool,
    disabled: bool,
    terminal_enqueued: bool,
}

impl Mailbox {
    fn push_transition(&self, line: Vec<u8>) {
        if !valid_line(&line) {
            return;
        }
        let mut state = self.lock();
        if state.disabled
            || state.closing
            || state.terminal_enqueued
            || state.transitions.len() >= MAX_TRANSITIONS
            || state
                .accepted_transition_bytes
                .checked_add(line.len())
                .is_none_or(|total| total > TRANSITION_RESERVE_BYTES)
        {
            return;
        }
        if let Some(stale) = state.snapshot.take() {
            state.accepted_snapshot_bytes =
                state.accepted_snapshot_bytes.saturating_sub(stale.len());
        }
        state.accepted_transition_bytes += line.len();
        state.transitions.push_back(line);
        self.ready.notify_one();
    }

    fn replace_snapshot(&self, line: Vec<u8>) {
        if !valid_line(&line) {
            return;
        }
        let mut state = self.lock();
        let queued_bytes = state.snapshot.as_ref().map_or(0, Vec::len);
        let accepted_without_queued = state.accepted_snapshot_bytes.saturating_sub(queued_bytes);
        if state.disabled
            || state.closing
            || state.terminal_enqueued
            || accepted_without_queued
                .checked_add(line.len())
                .is_none_or(|total| total > SNAPSHOT_BUDGET_BYTES)
        {
            return;
        }
        state.accepted_snapshot_bytes = accepted_without_queued + line.len();
        state.snapshot = Some(line);
        self.ready.notify_one();
    }

    fn push_terminal(&self, line: Vec<u8>) {
        if !valid_line(&line) {
            return;
        }
        let mut state = self.lock();
        if state.disabled || state.terminal_enqueued || line.len() > TERMINAL_RESERVE_BYTES {
            return;
        }
        state.snapshot = None;
        state.terminal = Some(line);
        state.terminal_enqueued = true;
        state.closing = true;
        self.ready.notify_one();
    }

    fn close(&self, drain: bool) {
        let mut state = self.lock();
        state.closing = true;
        if !drain {
            state.transitions.clear();
            state.snapshot = None;
            state.terminal = None;
        }
        self.ready.notify_one();
    }

    fn disable(&self) {
        let mut state = self.lock();
        state.disabled = true;
        state.closing = true;
        state.transitions.clear();
        state.snapshot = None;
        state.terminal = None;
        self.ready.notify_all();
    }

    fn next(&self) -> Option<Vec<u8>> {
        let mut state = self.lock();
        loop {
            if state.disabled {
                return None;
            }
            if let Some(line) = state.transitions.pop_front() {
                return Some(line);
            }
            if let Some(line) = state.terminal.take() {
                return Some(line);
            }
            if let Some(line) = state.snapshot.take() {
                return Some(line);
            }
            if state.closing {
                return None;
            }
            state = self
                .ready
                .wait(state)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }

    fn lock(&self) -> MutexGuard<'_, MailboxState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

fn valid_line(line: &[u8]) -> bool {
    !line.is_empty()
        && line.len() <= MAX_LINE_BYTES
        && line.is_ascii()
        && line.last() == Some(&b'\n')
}

fn run_writer(mut writer: impl Write, shared: Arc<Mailbox>, done: mpsc::Sender<()>) {
    while let Some(line) = shared.next() {
        if writer
            .write_all(&line)
            .and_then(|()| writer.flush())
            .is_err()
        {
            shared.disable();
            break;
        }
    }
    let _ = done.send(());
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    #[derive(Clone, Default)]
    struct SharedBytes(Arc<Mutex<Vec<u8>>>);

    impl Write for SharedBytes {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl SharedBytes {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    struct FailingWriter {
        failed: Arc<AtomicBool>,
    }

    impl Write for FailingWriter {
        fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
            self.failed.store(true, Ordering::Release);
            Err(io::Error::other("synthetic progress sink failure"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct BlockingFirstWrite {
        entered: mpsc::Sender<()>,
        release: mpsc::Receiver<()>,
        blocked: bool,
    }

    struct BlockingRecordingWriter {
        bytes: SharedBytes,
        entered: mpsc::Sender<()>,
        release: mpsc::Receiver<()>,
        written: mpsc::Sender<()>,
        blocked: bool,
    }

    impl Write for BlockingRecordingWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if !self.blocked {
                self.blocked = true;
                let _ = self.entered.send(());
                let _ = self.release.recv();
            }
            self.bytes.0.lock().unwrap().extend_from_slice(bytes);
            let _ = self.written.send(());
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Write for BlockingFirstWrite {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if !self.blocked {
                self.blocked = true;
                let _ = self.entered.send(());
                let _ = self.release.recv();
            }
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn line(stage: ProgressStage, elapsed_ms: u64) -> Vec<u8> {
        render_line(
            stage,
            Duration::from_millis(elapsed_ms),
            ProgressCounts {
                accounted_requests: Some(3),
                active_verifications: Some(1),
                subjects_started: Some(2),
                subjects_processed: Some(1),
            },
            None,
        )
    }

    #[test]
    fn rendered_lines_are_bounded_ascii_and_name_last_observed_units() {
        let rendered = line(ProgressStage::AssessmentRunning, 42);
        assert!(rendered.is_ascii());
        assert!(rendered.len() <= MAX_LINE_BYTES);
        assert!(rendered.ends_with(b"\n"));
        let text = String::from_utf8(rendered).unwrap();
        assert!(text.starts_with("[progress] state=assessment_running elapsed_ms=42"));
        assert!(text.contains("accounted_requests=3"));
        assert!(text.contains("accounted_active_verifications=1"));
        assert!(text.contains("subjects_started=2 subjects_processed=1"));
        assert!(text.contains("counts=last_observed"));
    }

    #[test]
    fn missing_snapshot_counts_are_unknown_instead_of_fabricated_zeroes() {
        let rendered = render_line(
            ProgressStage::AssessmentRunning,
            Duration::ZERO,
            ProgressCounts::default(),
            None,
        );
        let text = String::from_utf8(rendered).unwrap();
        assert!(text.contains("accounted_requests=unknown"));
        assert!(text.contains("accounted_active_verifications=unknown"));
        assert!(text.contains("subjects_started=unknown subjects_processed=unknown"));
    }

    #[test]
    fn periodic_updates_coalesce_and_terminal_discards_stale_snapshot() {
        let shared = SharedBytes::default();
        let mut output = ProgressOutput::with_writer(shared.clone()).unwrap();
        output.transition(line(ProgressStage::AssessmentRunning, 0));
        for elapsed in 1..=2_000 {
            output.snapshot(line(ProgressStage::AssessmentRunning, elapsed));
        }
        output.transition(line(ProgressStage::ComposingReport, 2_001));
        output.terminal(line(ProgressStage::Completed, 2_002));

        let text = shared.text();
        assert!(text.contains("state=assessment_running"));
        assert!(text.contains("state=composing_report"));
        assert!(text.contains("state=completed"));
        assert_eq!(text.matches("state=completed").count(), 1);
        assert!(text.len() <= MAX_TOTAL_BYTES);
        assert!(text.lines().last().unwrap().contains("state=completed"));
    }

    #[test]
    fn mailbox_enforces_exact_total_budgets_and_preserves_terminal_reserve() {
        fn maximum_line(byte: u8) -> Vec<u8> {
            let mut line = vec![byte; MAX_LINE_BYTES];
            *line.last_mut().unwrap() = b'\n';
            line
        }

        let mailbox = Mailbox::default();
        for _ in 0..MAX_TRANSITIONS {
            mailbox.push_transition(maximum_line(b't'));
        }
        mailbox.push_transition(maximum_line(b'x'));
        {
            let state = mailbox.lock();
            assert_eq!(state.transitions.len(), MAX_TRANSITIONS);
            assert_eq!(state.accepted_transition_bytes, TRANSITION_RESERVE_BYTES);
        }
        for _ in 0..MAX_TRANSITIONS {
            assert_eq!(mailbox.next().unwrap().len(), MAX_LINE_BYTES);
        }
        for _ in 0..(SNAPSHOT_BUDGET_BYTES / MAX_LINE_BYTES) {
            mailbox.replace_snapshot(maximum_line(b's'));
            assert_eq!(mailbox.next().unwrap().len(), MAX_LINE_BYTES);
        }
        mailbox.replace_snapshot(maximum_line(b'x'));
        {
            let state = mailbox.lock();
            assert!(state.snapshot.is_none());
            assert_eq!(state.accepted_snapshot_bytes, SNAPSHOT_BUDGET_BYTES);
        }
        mailbox.push_terminal(maximum_line(b'f'));
        let state = mailbox.lock();
        assert_eq!(state.terminal.as_ref().map(Vec::len), Some(MAX_LINE_BYTES));
        assert_eq!(
            state.accepted_transition_bytes
                + state.accepted_snapshot_bytes
                + state.terminal.as_ref().map_or(0, Vec::len),
            MAX_TOTAL_BYTES
        );
    }

    #[test]
    fn terminal_cannot_regress_to_running_or_repeat() {
        let shared = SharedBytes::default();
        let mut output = ProgressOutput::with_writer(shared.clone()).unwrap();
        output.terminal(line(ProgressStage::Incomplete, 9));
        output.snapshot(line(ProgressStage::AssessmentRunning, 10));
        output.transition(line(ProgressStage::RenderingReport, 11));
        output.terminal(line(ProgressStage::Completed, 12));

        let text = shared.text();
        assert_eq!(text.lines().count(), 1);
        assert!(text.contains("state=incomplete"));
    }

    #[test]
    fn failing_sink_disables_output_without_blocking_producers() {
        let failed = Arc::new(AtomicBool::new(false));
        let mut output = ProgressOutput::with_writer(FailingWriter {
            failed: Arc::clone(&failed),
        })
        .unwrap();
        output.transition(line(ProgressStage::AssessmentRunning, 0));
        output.snapshot(line(ProgressStage::AssessmentRunning, 1));
        output.terminal(line(ProgressStage::Failed, 2));
        assert!(failed.load(Ordering::Acquire));
    }

    #[test]
    fn blocked_sink_has_a_bounded_shutdown_wait_and_retains_one_worker_limit() {
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let mut output = ProgressOutput::with_writer(BlockingFirstWrite {
            entered: entered_tx,
            release: release_rx,
            blocked: false,
        })
        .unwrap();
        output.transition(line(ProgressStage::AssessmentRunning, 0));
        entered_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("writer reached the synthetic blocked sink");

        let started = Instant::now();
        output.terminal(line(ProgressStage::Completed, 1));
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "shutdown must not wait indefinitely for a blocked OS sink"
        );
        release_tx.send(()).unwrap();
    }

    #[test]
    fn forward_transition_discards_a_stale_snapshot_behind_a_slow_writer() {
        let bytes = SharedBytes::default();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (written_tx, written_rx) = mpsc::channel();
        let mut output = ProgressOutput::with_writer(BlockingRecordingWriter {
            bytes: bytes.clone(),
            entered: entered_tx,
            release: release_rx,
            written: written_tx,
            blocked: false,
        })
        .unwrap();
        output.transition(line(ProgressStage::AssessmentRunning, 0));
        entered_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("writer reached the synthetic slow sink");
        output.snapshot(line(ProgressStage::AssessmentRunning, 1));
        output.transition(line(ProgressStage::ComposingReport, 2));
        release_tx.send(()).unwrap();
        written_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        written_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(
            written_rx.recv_timeout(Duration::from_millis(250)).is_err(),
            "a stale periodic snapshot was written after the forward transition"
        );

        let text = bytes.text();
        let states = text.lines().collect::<Vec<_>>();
        assert_eq!(states.len(), 2, "stale running snapshot escaped: {text}");
        assert!(states[0].contains("state=assessment_running elapsed_ms=0"));
        assert!(states[1].contains("state=composing_report elapsed_ms=2"));
        output.stop_without_terminal();
    }

    #[test]
    fn publication_commit_state_is_explicit_and_value_free() {
        let line = render_line(
            ProgressStage::Failed,
            Duration::ZERO,
            ProgressCounts::default(),
            Some(BundleCommitState::Committed),
        );
        let text = String::from_utf8(line).unwrap();
        assert!(text.contains("state=failed"));
        assert!(text.contains("bundle_commit=committed"));
    }
}
