use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use super::coordinator::next_counter;
use super::lease::CompletionReceipt;
use super::limits::{MAX_AGGREGATE_ITEMS, MAX_RESULTS, MAX_RESULT_BYTES, MAX_TOTAL_RESULT_BYTES};
use super::model::{validate_task_command_id, Transition};
use super::DistributedError;

/// Hard limits for retained completion results and aggregate reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResultLimits {
    pub max_results: usize,
    pub max_result_bytes: usize,
    pub max_total_bytes: usize,
    pub max_aggregate_items: usize,
    pub max_aggregate_bytes: usize,
}

impl Default for ResultLimits {
    fn default() -> Self {
        Self {
            max_results: 1_024,
            max_result_bytes: 1024 * 1024,
            max_total_bytes: 16 * 1024 * 1024,
            max_aggregate_items: 1_024,
            max_aggregate_bytes: 16 * 1024 * 1024,
        }
    }
}

fn validate_result_limits(limits: ResultLimits) -> Result<(), DistributedError> {
    for (name, value) in [
        ("max_results", limits.max_results),
        ("max_result_bytes", limits.max_result_bytes),
        ("max_total_bytes", limits.max_total_bytes),
        ("max_aggregate_items", limits.max_aggregate_items),
        ("max_aggregate_bytes", limits.max_aggregate_bytes),
    ] {
        if value == 0 {
            return Err(DistributedError::InvalidLimit { name });
        }
    }
    for (name, actual, maximum) in [
        ("max_results", limits.max_results, MAX_RESULTS),
        (
            "max_result_bytes",
            limits.max_result_bytes,
            MAX_RESULT_BYTES,
        ),
        (
            "max_total_bytes",
            limits.max_total_bytes,
            MAX_TOTAL_RESULT_BYTES,
        ),
        (
            "max_aggregate_items",
            limits.max_aggregate_items,
            MAX_AGGREGATE_ITEMS,
        ),
        (
            "max_aggregate_bytes",
            limits.max_aggregate_bytes,
            MAX_TOTAL_RESULT_BYTES,
        ),
    ] {
        if actual > maximum {
            return Err(DistributedError::CountLimitExceedsMaximum {
                name,
                actual,
                maximum,
            });
        }
    }
    if limits.max_result_bytes > limits.max_total_bytes {
        return Err(DistributedError::InvalidLimitRelationship {
            reason: "max_result_bytes exceeds max_total_bytes",
        });
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredResult {
    receipt: CompletionReceipt,
    bytes: Vec<u8>,
}

struct ResultState {
    limits: ResultLimits,
    revision: u64,
    total_bytes: usize,
    results: BTreeMap<String, StoredResult>,
}

/// Idempotent result-store outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreResultOutcome {
    Stored,
    AlreadyStored,
}

/// One aggregate element in exact request order.
#[derive(Clone, PartialEq, Eq)]
pub struct AggregatedResult {
    task_id: String,
    bytes: Vec<u8>,
}

impl AggregatedResult {
    pub fn task_id(&self) -> &str {
        &self.task_id
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl std::fmt::Debug for AggregatedResult {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AggregatedResult")
            .field("task_id", &self.task_id)
            .field("result_bytes", &self.bytes.len())
            .finish()
    }
}

/// Bounded completion-receipt result store.
#[derive(Clone)]
pub struct ResultAggregator {
    state: Arc<Mutex<ResultState>>,
}

impl ResultAggregator {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(ResultState {
                limits: ResultLimits::default(),
                revision: 0,
                total_bytes: 0,
                results: BTreeMap::new(),
            })),
        }
    }

    pub fn with_limits(limits: ResultLimits) -> Result<Self, DistributedError> {
        validate_result_limits(limits)?;
        Ok(Self {
            state: Arc::new(Mutex::new(ResultState {
                limits,
                revision: 0,
                total_bytes: 0,
                results: BTreeMap::new(),
            })),
        })
    }

    /// Store a result only with a completion receipt. Exact same-byte replay is
    /// idempotent; a different receipt or bytes for an occupied task ID fails.
    /// Receipt provenance remains scoped to the caller-enforced coordinator epoch.
    pub fn store_result(
        &self,
        expected_revision: u64,
        receipt: &CompletionReceipt,
        bytes: Vec<u8>,
    ) -> Result<Transition<StoreResultOutcome>, DistributedError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| DistributedError::StatePoisoned)?;
        if expected_revision != state.revision {
            return Err(DistributedError::RevisionConflict {
                expected: expected_revision,
                actual: state.revision,
            });
        }
        if let Some(existing) = state.results.get(receipt.task_id()) {
            if existing.receipt == *receipt {
                if existing.bytes == bytes {
                    return Ok(Transition {
                        revision: state.revision,
                        value: StoreResultOutcome::AlreadyStored,
                    });
                }
                return Err(DistributedError::ConflictingResult {
                    task_id: receipt.task_id.clone(),
                });
            }
            return Err(DistributedError::MismatchedResultReceipt {
                task_id: receipt.task_id.clone(),
            });
        }
        if bytes.len() > state.limits.max_result_bytes {
            return Err(DistributedError::ResultTooLarge {
                actual: bytes.len(),
                limit: state.limits.max_result_bytes,
            });
        }
        if state.results.len() >= state.limits.max_results {
            return Err(DistributedError::ResultCapacityReached {
                limit: state.limits.max_results,
            });
        }
        let total_bytes = state.total_bytes.checked_add(bytes.len()).ok_or(
            DistributedError::TotalResultBytesExceeded {
                actual: usize::MAX,
                limit: state.limits.max_total_bytes,
            },
        )?;
        if total_bytes > state.limits.max_total_bytes {
            return Err(DistributedError::TotalResultBytesExceeded {
                actual: total_bytes,
                limit: state.limits.max_total_bytes,
            });
        }
        let revision = next_counter(state.revision, "result_revision")?;
        state.results.insert(
            receipt.task_id.clone(),
            StoredResult {
                receipt: receipt.clone(),
                bytes,
            },
        );
        state.total_bytes = total_bytes;
        state.revision = revision;
        Ok(Transition {
            revision,
            value: StoreResultOutcome::Stored,
        })
    }

    /// Aggregate all requested results in exact input order. Missing or repeated
    /// task IDs are explicit errors rather than silent filtering.
    pub fn aggregate_results(
        &self,
        task_ids: &[&str],
    ) -> Result<Vec<AggregatedResult>, DistributedError> {
        if task_ids.len() > MAX_AGGREGATE_ITEMS {
            return Err(DistributedError::AggregateItemLimitExceeded {
                actual: task_ids.len(),
                limit: MAX_AGGREGATE_ITEMS,
            });
        }
        let state = self
            .state
            .lock()
            .map_err(|_| DistributedError::StatePoisoned)?;
        if task_ids.len() > state.limits.max_aggregate_items {
            return Err(DistributedError::AggregateItemLimitExceeded {
                actual: task_ids.len(),
                limit: state.limits.max_aggregate_items,
            });
        }
        for task_id in task_ids {
            validate_task_command_id(task_id)?;
        }
        let mut seen = BTreeSet::new();
        let mut total_bytes = 0usize;
        let mut aggregate = Vec::with_capacity(task_ids.len());
        for task_id in task_ids {
            if !seen.insert(*task_id) {
                return Err(DistributedError::DuplicateAggregateTask {
                    task_id: (*task_id).to_owned(),
                });
            }
            let stored =
                state
                    .results
                    .get(*task_id)
                    .ok_or_else(|| DistributedError::MissingResult {
                        task_id: (*task_id).to_owned(),
                    })?;
            total_bytes = total_bytes.checked_add(stored.bytes.len()).ok_or(
                DistributedError::AggregateBytesExceeded {
                    actual: usize::MAX,
                    limit: state.limits.max_aggregate_bytes,
                },
            )?;
            if total_bytes > state.limits.max_aggregate_bytes {
                return Err(DistributedError::AggregateBytesExceeded {
                    actual: total_bytes,
                    limit: state.limits.max_aggregate_bytes,
                });
            }
            aggregate.push(AggregatedResult {
                task_id: (*task_id).to_owned(),
                bytes: stored.bytes.clone(),
            });
        }
        Ok(aggregate)
    }

    pub fn get_result(&self, task_id: &str) -> Result<Option<Vec<u8>>, DistributedError> {
        validate_task_command_id(task_id)?;
        Ok(self
            .state
            .lock()
            .map_err(|_| DistributedError::StatePoisoned)?
            .results
            .get(task_id)
            .map(|stored| stored.bytes.clone()))
    }

    pub fn revision(&self) -> Result<u64, DistributedError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| DistributedError::StatePoisoned)?
            .revision)
    }

    pub fn result_count(&self) -> Result<usize, DistributedError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| DistributedError::StatePoisoned)?
            .results
            .len())
    }

    pub fn total_bytes(&self) -> Result<usize, DistributedError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| DistributedError::StatePoisoned)?
            .total_bytes)
    }
}

impl Default for ResultAggregator {
    fn default() -> Self {
        Self::new()
    }
}
