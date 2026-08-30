use super::history::ExecutionProvenance;
use super::limits::{
    enforce_hook_controls, sticky_abort_code, terminal_control_error, StickyAbort,
};
use super::{
    LuaCancellationToken, LuaContext, LuaExecutionError, LuaExecutionResult, LuaReturnValue,
    LuaScript, ABORT_OUTPUT, ABORT_OUTPUT_ENCODING, ABORT_OUTPUT_NUMBER, ABORT_OUTPUT_TYPE,
    IMMUTABLE_CONTEXT, REGISTERED_CHUNK_NAME,
};
use crate::lua_config::LuaEngineConfig;
use mlua::{
    ChunkMode, Error as MluaError, HookTriggers, Lua, LuaOptions, MultiValue, StdLib, Value,
};
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub(super) fn execute_snapshot(
    script: LuaScript,
    context: LuaContext,
    config: LuaEngineConfig,
    cancellation: LuaCancellationToken,
    started: Instant,
) -> LuaExecutionResult {
    let provenance = ExecutionProvenance::from(&script);
    let deadline = started
        .checked_add(Duration::from_millis(config.default_timeout_ms))
        .unwrap_or(started);
    if cancellation.is_cancelled() {
        return LuaExecutionResult::failed(provenance, LuaExecutionError::Cancelled, started);
    }
    if Instant::now() >= deadline {
        return LuaExecutionResult::failed(
            provenance,
            LuaExecutionError::DeadlineExceeded,
            started,
        );
    }
    let abort = Rc::new(Cell::new(None));
    let output = Rc::new(RefCell::new(String::new()));
    let lua = match Lua::new_with(StdLib::NONE, LuaOptions::default()) {
        Ok(lua) => lua,
        Err(_) => {
            return LuaExecutionResult::failed(provenance, LuaExecutionError::HostFailure, started);
        },
    };
    if lua.set_memory_limit(config.max_memory_bytes).is_err() {
        return LuaExecutionResult::failed(provenance, LuaExecutionError::HostFailure, started);
    }
    let instruction_count = Rc::new(Cell::new(0u64));
    let hook_abort = Rc::clone(&abort);
    let hook_count = Rc::clone(&instruction_count);
    let hook_cancellation = cancellation.clone();
    let hook_interval = config.hook_interval;
    let instruction_limit = config.instruction_limit;
    lua.set_hook(
        HookTriggers::new().every_nth_instruction(hook_interval),
        move |_, _| {
            enforce_hook_controls(
                &hook_abort,
                &hook_count,
                hook_cancellation.is_cancelled(),
                Instant::now() >= deadline,
                hook_interval,
                instruction_limit,
            )
        },
    );
    let environment = match build_environment(
        &lua,
        &context,
        Rc::clone(&output),
        Rc::clone(&abort),
        config.max_output_bytes,
    ) {
        Ok(environment) => environment,
        Err(error) => {
            let code = classify_mlua_error(&error, abort.get());
            return LuaExecutionResult::failed(provenance, code, started);
        },
    };
    if let Some(error) = terminal_control_error(
        abort.get(),
        cancellation.is_cancelled(),
        Instant::now() >= deadline,
    ) {
        return LuaExecutionResult::failed(provenance, error, started);
    }
    let return_value = {
        let execution = lua
            .load(script.source.as_bytes())
            .set_name(REGISTERED_CHUNK_NAME)
            .set_mode(ChunkMode::Text)
            .set_environment(environment)
            .call::<_, MultiValue>(());
        if let Some(error) = terminal_control_error(
            abort.get(),
            cancellation.is_cancelled(),
            Instant::now() >= deadline,
        ) {
            return LuaExecutionResult::failed(provenance, error, started);
        }
        match execution {
            Ok(values) => match project_return_values(values, config.max_return_bytes) {
                Ok(value) => value,
                Err(error) => return LuaExecutionResult::failed(provenance, error, started),
            },
            Err(error) => {
                return LuaExecutionResult::failed(
                    provenance,
                    classify_mlua_error(&error, abort.get()),
                    started,
                );
            },
        }
    };
    drop(lua);
    let output =
        Rc::try_unwrap(output).map_or_else(|shared| shared.borrow().clone(), RefCell::into_inner);
    if let Some(error) = terminal_control_error(
        abort.get(),
        cancellation.is_cancelled(),
        Instant::now() >= deadline,
    ) {
        return LuaExecutionResult::failed(provenance, error, started);
    }
    LuaExecutionResult::completed(provenance, output, return_value, started)
}

fn build_environment<'lua>(
    lua: &'lua Lua,
    context: &LuaContext,
    output: Rc<RefCell<String>>,
    abort: Rc<Cell<Option<StickyAbort>>>,
    max_output_bytes: usize,
) -> mlua::Result<mlua::Table<'lua>> {
    let allowed = lua.create_table()?;
    let type_function = lua.create_function(|_, value: Value| Ok(value.type_name()))?;
    allowed.raw_set("type", type_function)?;
    let emit_output = output;
    let emit_abort = abort;
    let emit = lua.create_function(move |_, value: Value| {
        let mut buffer = emit_output.borrow_mut();
        let appended = match value {
            Value::Boolean(true) => append_emitted(&mut buffer, "true", max_output_bytes),
            Value::Boolean(false) => append_emitted(&mut buffer, "false", max_output_bytes),
            Value::Integer(value) => {
                append_emitted(&mut buffer, &value.to_string(), max_output_bytes)
            },
            Value::Number(value) if value.is_finite() => {
                append_emitted(&mut buffer, &value.to_string(), max_output_bytes)
            },
            Value::Number(_) => {
                emit_abort.set(Some(StickyAbort::NonFiniteOutput));
                return Err(MluaError::RuntimeError(ABORT_OUTPUT_NUMBER.to_owned()));
            },
            Value::String(value) => match value.to_str() {
                Ok(value) => append_emitted(&mut buffer, value, max_output_bytes),
                Err(_) => {
                    emit_abort.set(Some(StickyAbort::OutputEncoding));
                    return Err(MluaError::RuntimeError(ABORT_OUTPUT_ENCODING.to_owned()));
                },
            },
            _ => {
                emit_abort.set(Some(StickyAbort::UnsupportedOutput));
                return Err(MluaError::RuntimeError(ABORT_OUTPUT_TYPE.to_owned()));
            },
        };
        if appended.is_err() {
            emit_abort.set(Some(StickyAbort::Output));
            return Err(MluaError::RuntimeError(ABORT_OUTPUT.to_owned()));
        }
        Ok(())
    })?;
    allowed.raw_set("emit", emit)?;
    allowed.raw_set("context", build_context_proxy(lua, context)?)?;
    readonly_proxy(lua, allowed)
}

fn append_emitted(buffer: &mut String, value: &str, max_output_bytes: usize) -> Result<(), ()> {
    let next_len = buffer.len().checked_add(value.len()).ok_or(())?;
    if next_len > max_output_bytes {
        return Err(());
    }
    buffer.push_str(value);
    Ok(())
}

fn build_context_proxy<'lua>(
    lua: &'lua Lua,
    context: &LuaContext,
) -> mlua::Result<mlua::Table<'lua>> {
    let values = lua.create_table()?;
    values.raw_set("target", context.target.clone())?;
    values.raw_set("payload", context.payload.clone())?;
    values.raw_set("parameter_count", context.parameters.len())?;
    let parameters = Arc::new(context.parameters.clone());
    let lookup_parameters = Arc::clone(&parameters);
    let parameter = lua.create_function(move |_, key: mlua::String| {
        let Ok(key) = key.to_str() else {
            return Ok(None::<String>);
        };
        Ok(lookup_parameters.get(key).cloned())
    })?;
    values.raw_set("parameter", parameter)?;
    let ordered_parameters: Arc<Vec<(String, String)>> = Arc::new(
        parameters
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
    );
    let parameter_at = lua.create_function(move |_, index: usize| {
        let value = index
            .checked_sub(1)
            .and_then(|index| ordered_parameters.get(index));
        Ok(match value {
            Some((key, value)) => (Some(key.clone()), Some(value.clone())),
            None => (None::<String>, None::<String>),
        })
    })?;
    values.raw_set("parameter_at", parameter_at)?;
    readonly_proxy(lua, values)
}

fn readonly_proxy<'lua>(
    lua: &'lua Lua,
    values: mlua::Table<'lua>,
) -> mlua::Result<mlua::Table<'lua>> {
    let proxy = lua.create_table()?;
    let metatable = lua.create_table()?;
    metatable.raw_set("__index", values)?;
    metatable.raw_set(
        "__newindex",
        lua.create_function(|_, _: (Value, Value, Value)| -> mlua::Result<()> {
            Err(MluaError::RuntimeError(IMMUTABLE_CONTEXT.to_owned()))
        })?,
    )?;
    metatable.raw_set("__metatable", "locked")?;
    proxy.set_metatable(Some(metatable));
    Ok(proxy)
}

fn project_return_values(
    mut values: MultiValue<'_>,
    max_return_bytes: usize,
) -> Result<Option<LuaReturnValue>, LuaExecutionError> {
    // mlua must collect LUA_MULTRET to distinguish zero, one, and many values.
    // The source, VM-memory, and concurrency caps jointly bound this temporary
    // Rust-side container; there is no lower-level one-slot API that preserves
    // the number of returned values.
    if values.len() > 1 {
        return Err(LuaExecutionError::MultipleReturnValues);
    }
    project_return_value(values.pop_front().unwrap_or(Value::Nil), max_return_bytes)
}

fn project_return_value(
    value: Value<'_>,
    max_return_bytes: usize,
) -> Result<Option<LuaReturnValue>, LuaExecutionError> {
    match value {
        Value::Nil => Ok(None),
        Value::Boolean(value) => Ok(Some(LuaReturnValue::Boolean(value))),
        Value::Integer(value) => Ok(Some(LuaReturnValue::Integer(value))),
        Value::Number(value) if value.is_finite() => Ok(Some(LuaReturnValue::Number(value))),
        Value::Number(_) => Err(LuaExecutionError::NonFiniteReturnNumber),
        Value::String(value) => {
            let value = value
                .to_str()
                .map_err(|_| LuaExecutionError::ReturnNotUtf8)?;
            if value.len() > max_return_bytes {
                return Err(LuaExecutionError::ReturnLimit);
            }
            Ok(Some(LuaReturnValue::String(value.to_owned())))
        },
        _ => Err(LuaExecutionError::UnsupportedReturnType),
    }
}

fn classify_mlua_error(error: &MluaError, sticky_abort: Option<StickyAbort>) -> LuaExecutionError {
    if let Some(reason) = sticky_abort {
        return sticky_abort_code(reason);
    }
    match error {
        MluaError::SyntaxError { .. } => LuaExecutionError::Syntax,
        MluaError::MemoryError(_) => LuaExecutionError::MemoryLimit,
        MluaError::CallbackError { cause, .. } | MluaError::WithContext { cause, .. } => {
            classify_mlua_error(cause, sticky_abort)
        },
        _ => LuaExecutionError::Runtime,
    }
}
