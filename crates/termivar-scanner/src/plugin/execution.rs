use futures::FutureExt;
use std::{panic::AssertUnwindSafe, time::Instant};

use super::{
    context::{PluginContext, PluginExecutionRequest, PluginExecutionResult},
    recorder::sanitize_error_safely,
    registry::PluginRegistry,
    PluginError,
};

impl PluginRegistry {
    /// Executes one invocation and returns observation evidence only.
    pub async fn execute(
        &self,
        plugin_id: &str,
        request: PluginExecutionRequest,
    ) -> Result<PluginExecutionResult, PluginError> {
        let (plugin, stats, _invocation_lease) = {
            let entry = self.entries.get(plugin_id).ok_or(PluginError::NotFound)?;
            if !entry.config.enabled {
                return Err(PluginError::Disabled);
            }
            let stats = entry.stats.clone();
            let lease = stats.acquire_invocation()?;
            (entry.plugin.clone(), stats, lease)
        };

        let context = PluginContext::from_request(plugin_id.to_owned(), request)?;
        context.ensure_active()?;
        stats.record_execution();
        let started = Instant::now();
        let plugin_future =
            match std::panic::catch_unwind(AssertUnwindSafe(|| plugin.execute(&context))) {
                Ok(future) => future,
                Err(_) => {
                    context.discard();
                    stats.record_error();
                    return Err(PluginError::Panicked);
                },
            };
        let mut execution = Some(Box::pin(AssertUnwindSafe(plugin_future).catch_unwind()));
        let wall = tokio::time::sleep_until(context.deadline);
        tokio::pin!(wall);

        let completion = match execution.as_mut() {
            Some(execution_future) => tokio::select! {
                biased;
                () = context.cancellation.cancelled() => Err(PluginError::Cancelled),
                () = &mut wall => Err(PluginError::WallTimeExceeded),
                result = execution_future.as_mut() => match result {
                    Ok(result) => match result {
                        Ok(()) => Ok(()),
                        Err(error) => Err(sanitize_error_safely(context.redaction.as_ref(), error)
                            .unwrap_or(PluginError::HostCallbackPanicked)),
                    },
                    Err(_) => Err(PluginError::Panicked),
                },
            },
            None => Err(PluginError::HostStateUnavailable),
        };
        let drop_result = std::panic::catch_unwind(AssertUnwindSafe(|| drop(execution.take())));
        if drop_result.is_err() {
            context.discard();
            stats.record_error();
            return Err(PluginError::Panicked);
        }

        if let Err(error) = completion {
            context.discard();
            stats.record_error();
            return Err(error);
        }

        match context.finish() {
            Ok((observations, usage)) => {
                stats.record_success();
                Ok(PluginExecutionResult {
                    plugin_id: plugin_id.to_owned(),
                    observations,
                    usage,
                    elapsed_ms: elapsed_ms(started),
                })
            },
            Err(error) => {
                context.discard();
                stats.record_error();
                Err(error)
            },
        }
    }
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}
