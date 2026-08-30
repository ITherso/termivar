use super::history::ExecutionProvenance;
use super::registry::InvocationLease;
use super::vm::execute_snapshot;
use super::{
    LuaCancellationToken, LuaContext, LuaExecutionError, LuaExecutionResult, LuaRegistryError,
    LuaScript, LuaScriptRegistry,
};
use std::future::{poll_fn, Future};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;
use std::time::Instant;

struct RegisteredSnapshot {
    script: LuaScript,
    enabled: bool,
    generation: u64,
}

impl LuaScriptRegistry {
    pub async fn execute(
        &self,
        script_id: &str,
        context: LuaContext,
    ) -> Result<LuaExecutionResult, LuaRegistryError> {
        self.execute_with_cancellation(script_id, context, LuaCancellationToken::new())
            .await
    }

    pub async fn execute_with_cancellation(
        &self,
        script_id: &str,
        context: LuaContext,
        cancellation: LuaCancellationToken,
    ) -> Result<LuaExecutionResult, LuaRegistryError> {
        let snapshot = {
            let state = self
                .state
                .lock()
                .map_err(|_| LuaRegistryError::StateUnavailable)?;
            let entry = state
                .scripts
                .get(script_id)
                .ok_or(LuaRegistryError::ScriptNotFound)?;
            RegisteredSnapshot {
                script: entry.script.clone(),
                enabled: entry.enabled,
                generation: entry.generation,
            }
        };
        let started = Instant::now();
        if !snapshot.enabled {
            let result = LuaExecutionResult::failed(
                ExecutionProvenance::from(&snapshot.script),
                LuaExecutionError::ScriptDisabled,
                started,
            );
            self.record_result(snapshot.generation, &result)?;
            return Ok(result);
        }
        if let Err(error) = context.validate(&self.config) {
            let result = LuaExecutionResult::failed(
                ExecutionProvenance::from(&snapshot.script),
                error,
                started,
            );
            self.record_result(snapshot.generation, &result)?;
            return Ok(result);
        }
        if cancellation.is_cancelled() {
            let result = LuaExecutionResult::failed(
                ExecutionProvenance::from(&snapshot.script),
                LuaExecutionError::Cancelled,
                started,
            );
            self.record_result(snapshot.generation, &result)?;
            return Ok(result);
        }
        let runtime = match tokio::runtime::Handle::try_current() {
            Ok(runtime) => runtime,
            Err(_) => {
                let result = LuaExecutionResult::failed(
                    ExecutionProvenance::from(&snapshot.script),
                    LuaExecutionError::HostFailure,
                    started,
                );
                self.record_result(snapshot.generation, &result)?;
                return Ok(result);
            },
        };
        let permit = match Arc::clone(&self.execution_permits).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                let result = LuaExecutionResult::failed(
                    ExecutionProvenance::from(&snapshot.script),
                    LuaExecutionError::ConcurrencyLimit,
                    started,
                );
                self.record_result(snapshot.generation, &result)?;
                return Ok(result);
            },
        };
        let (script, lease, generation) = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| LuaRegistryError::StateUnavailable)?;
            let entry = state
                .scripts
                .get_mut(script_id)
                .ok_or(LuaRegistryError::ScriptNotFound)?;
            if !entry.enabled {
                let provenance = ExecutionProvenance::from(&entry.script);
                let generation = entry.generation;
                drop(state);
                drop(permit);
                let result = LuaExecutionResult::failed(
                    provenance,
                    LuaExecutionError::ScriptDisabled,
                    started,
                );
                self.record_result(generation, &result)?;
                return Ok(result);
            }
            entry.active_invocations = entry
                .active_invocations
                .checked_add(1)
                .ok_or(LuaRegistryError::InvocationLimit)?;
            let script = entry.script.clone();
            let generation = entry.generation;
            let lease = InvocationLease {
                state: Arc::clone(&self.state),
                script_id: script.id(),
                generation,
            };
            (script, lease, generation)
        };
        let config = self.config.clone();
        let fallback_provenance = ExecutionProvenance::from(&script);
        let worker = match catch_unwind(AssertUnwindSafe(|| {
            runtime.spawn_blocking(move || {
                let _permit = permit;
                let result = execute_snapshot(script, context, config, cancellation, started);
                (result, lease)
            })
        })) {
            Ok(worker) => worker,
            Err(_) => {
                let result = LuaExecutionResult::failed(
                    fallback_provenance,
                    LuaExecutionError::HostFailure,
                    started,
                );
                self.record_result(generation, &result)?;
                return Ok(result);
            },
        };
        let result = match await_worker(worker).await {
            Ok((result, lease)) => {
                self.record_result(generation, &result)?;
                drop(lease);
                result
            },
            Err(_) => {
                let result = LuaExecutionResult::failed(
                    fallback_provenance,
                    LuaExecutionError::HostFailure,
                    started,
                );
                self.record_result(generation, &result)?;
                result
            },
        };
        Ok(result)
    }
}
async fn await_worker<T>(mut worker: tokio::task::JoinHandle<T>) -> Result<T, ()> {
    poll_fn(|context| {
        match catch_unwind(AssertUnwindSafe(|| Pin::new(&mut worker).poll(context))) {
            Ok(Poll::Ready(result)) => Poll::Ready(result.map_err(|_| ())),
            Ok(Poll::Pending) => Poll::Pending,
            Err(_) => {
                worker.abort();
                Poll::Ready(Err(()))
            },
        }
    })
    .await
}
