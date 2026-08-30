use super::{
    LuaExecutionError, ABORT_CANCELLED, ABORT_DEADLINE, ABORT_INSTRUCTION, ABORT_OUTPUT,
    ABORT_OUTPUT_ENCODING, ABORT_OUTPUT_NUMBER, ABORT_OUTPUT_TYPE,
};
use mlua::Error as MluaError;
use std::cell::Cell;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StickyAbort {
    Cancelled,
    Deadline,
    Instruction,
    Output,
    OutputEncoding,
    UnsupportedOutput,
    NonFiniteOutput,
}

pub(super) fn enforce_hook_controls(
    sticky_abort: &Cell<Option<StickyAbort>>,
    instruction_count: &Cell<u64>,
    cancelled: bool,
    deadline_exceeded: bool,
    hook_interval: u32,
    instruction_limit: u64,
) -> mlua::Result<()> {
    if let Some(reason) = sticky_abort.get() {
        return Err(sticky_abort_error(reason));
    }
    if cancelled {
        sticky_abort.set(Some(StickyAbort::Cancelled));
        return Err(sticky_abort_error(StickyAbort::Cancelled));
    }
    if deadline_exceeded {
        sticky_abort.set(Some(StickyAbort::Deadline));
        return Err(sticky_abort_error(StickyAbort::Deadline));
    }
    let (next, exhausted) =
        instruction_quantum_status(instruction_count.get(), hook_interval, instruction_limit);
    instruction_count.set(next);
    if exhausted {
        sticky_abort.set(Some(StickyAbort::Instruction));
        return Err(sticky_abort_error(StickyAbort::Instruction));
    }
    Ok(())
}

fn sticky_abort_error(reason: StickyAbort) -> MluaError {
    MluaError::RuntimeError(
        match reason {
            StickyAbort::Cancelled => ABORT_CANCELLED,
            StickyAbort::Deadline => ABORT_DEADLINE,
            StickyAbort::Instruction => ABORT_INSTRUCTION,
            StickyAbort::Output => ABORT_OUTPUT,
            StickyAbort::OutputEncoding => ABORT_OUTPUT_ENCODING,
            StickyAbort::UnsupportedOutput => ABORT_OUTPUT_TYPE,
            StickyAbort::NonFiniteOutput => ABORT_OUTPUT_NUMBER,
        }
        .to_owned(),
    )
}

pub(super) fn sticky_abort_code(reason: StickyAbort) -> LuaExecutionError {
    match reason {
        StickyAbort::Cancelled => LuaExecutionError::Cancelled,
        StickyAbort::Deadline => LuaExecutionError::DeadlineExceeded,
        StickyAbort::Instruction => LuaExecutionError::InstructionLimit,
        StickyAbort::Output => LuaExecutionError::OutputLimit,
        StickyAbort::OutputEncoding => LuaExecutionError::OutputNotUtf8,
        StickyAbort::UnsupportedOutput => LuaExecutionError::UnsupportedOutputType,
        StickyAbort::NonFiniteOutput => LuaExecutionError::NonFiniteOutputNumber,
    }
}

pub(super) fn terminal_control_error(
    sticky_abort: Option<StickyAbort>,
    cancelled: bool,
    deadline_exceeded: bool,
) -> Option<LuaExecutionError> {
    if let Some(reason) = sticky_abort {
        Some(sticky_abort_code(reason))
    } else if cancelled {
        Some(LuaExecutionError::Cancelled)
    } else if deadline_exceeded {
        Some(LuaExecutionError::DeadlineExceeded)
    } else {
        None
    }
}

pub(super) fn instruction_quantum_status(current: u64, interval: u32, limit: u64) -> (u64, bool) {
    let quantum = u64::from(interval);
    let next = current.saturating_add(quantum);
    let following_exceeds = match next.checked_add(quantum) {
        Some(following) => following > limit,
        None => true,
    };
    (next, next >= limit || following_exceeds)
}
