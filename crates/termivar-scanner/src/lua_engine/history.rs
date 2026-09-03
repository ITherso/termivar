use super::source::hex_digest;
use super::{LuaExecutionReceipt, LuaScript};
use std::collections::VecDeque;
use std::time::Instant;

#[derive(Clone)]
pub(super) struct ExecutionProvenance {
    pub(super) script_id: String,
    pub(super) script_version: String,
    pub(super) source_sha256: String,
}

impl From<&LuaScript> for ExecutionProvenance {
    fn from(script: &LuaScript) -> Self {
        Self {
            script_id: script.id(),
            script_version: script.version.clone(),
            source_sha256: hex_digest(&script.source_digest),
        }
    }
}

pub(super) struct HistoryEntry {
    pub(super) sequence: u64,
    pub(super) retained_bytes: usize,
    pub(super) receipt: LuaExecutionReceipt,
}

pub(super) struct BoundedExecutionHistory {
    pub(super) entries: VecDeque<HistoryEntry>,
    pub(super) retained_bytes: usize,
}

impl BoundedExecutionHistory {
    pub(super) fn new() -> Self {
        Self {
            entries: VecDeque::new(),
            retained_bytes: 0,
        }
    }

    pub(super) fn pop_front(&mut self) -> Option<HistoryEntry> {
        let entry = self.entries.pop_front()?;
        self.retained_bytes = self.retained_bytes.saturating_sub(entry.retained_bytes);
        Some(entry)
    }

    pub(super) fn push(
        &mut self,
        sequence: u64,
        receipt: LuaExecutionReceipt,
        max_entries: usize,
        max_bytes: usize,
    ) -> bool {
        let retained_bytes = receipt.retained_bytes();
        if retained_bytes > max_bytes {
            return false;
        }
        while self.entries.len() >= max_entries
            || self.retained_bytes.saturating_add(retained_bytes) > max_bytes
        {
            if self.pop_front().is_none() {
                return false;
            }
        }
        self.retained_bytes = self.retained_bytes.saturating_add(retained_bytes);
        self.entries.push_back(HistoryEntry {
            sequence,
            retained_bytes,
            receipt,
        });
        true
    }
}

pub(super) fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}
