use std::collections::HashMap;
use std::ffi::CString;
use std::path::Path;
use winapi::{
    shared::ntstatus::{STATUS_WX86_BREAKPOINT, STATUS_WX86_SINGLE_STEP},
    um::{
        debugapi::{ContinueDebugEvent, WaitForDebugEvent},
        memoryapi::{ReadProcessMemory, WriteProcessMemory},
        minwinbase::{
            CREATE_PROCESS_DEBUG_EVENT, CREATE_THREAD_DEBUG_EVENT, DEBUG_EVENT,
            EXCEPTION_ACCESS_VIOLATION, EXCEPTION_ARRAY_BOUNDS_EXCEEDED, EXCEPTION_BREAKPOINT,
            EXCEPTION_DATATYPE_MISALIGNMENT, EXCEPTION_DEBUG_EVENT, EXCEPTION_FLT_DENORMAL_OPERAND,
            EXCEPTION_FLT_DIVIDE_BY_ZERO, EXCEPTION_FLT_INEXACT_RESULT,
            EXCEPTION_FLT_INVALID_OPERATION, EXCEPTION_FLT_OVERFLOW, EXCEPTION_FLT_STACK_CHECK,
            EXCEPTION_FLT_UNDERFLOW, EXCEPTION_ILLEGAL_INSTRUCTION, EXCEPTION_INT_DIVIDE_BY_ZERO,
            EXCEPTION_INT_OVERFLOW, EXCEPTION_INVALID_DISPOSITION, EXCEPTION_IN_PAGE_ERROR,
            EXCEPTION_NONCONTINUABLE_EXCEPTION, EXCEPTION_PRIV_INSTRUCTION, EXCEPTION_SINGLE_STEP,
            EXCEPTION_STACK_OVERFLOW, EXIT_PROCESS_DEBUG_EVENT, EXIT_THREAD_DEBUG_EVENT,
            LOAD_DLL_DEBUG_EVENT, OUTPUT_DEBUG_STRING_EVENT, RIP_EVENT, UNLOAD_DLL_DEBUG_EVENT,
        },
        processthreadsapi::{
            CreateProcessA, GetThreadContext, SetThreadContext, PROCESS_INFORMATION, STARTUPINFOA,
        },
        winbase::{Wow64GetThreadContext, Wow64SetThreadContext, DEBUG_PROCESS, INFINITE},
        winnt::{
            CONTEXT, DBG_CONTINUE, DBG_CONTROL_C, DBG_EXCEPTION_NOT_HANDLED, DBG_REPLY_LATER,
            HANDLE, WOW64_CONTEXT, WOW64_CONTEXT_ALL, WOW64_CONTEXT_CONTROL,
        },
    },
};

const STATUS_WX86_BREAKPOINT_U32: u32 = STATUS_WX86_BREAKPOINT as u32;
const STATUS_WX86_SINGLE_STEP_U32: u32 = STATUS_WX86_SINGLE_STEP as u32;

enum State {
    Stopped {
        pid: u32,
        tid: u32,
        thread: Option<(HANDLE, WOW64_CONTEXT)>,
    },
    Running,
}

#[derive(Debug)]
pub struct DebugEvent {
    pid: u32,
    tid: u32,
    pub kind: DebugEventKind,
}

#[derive(Debug)]
pub enum DebugEventKind {
    Exception(ExceptionDebugInfo),
    CreateThread,
    CreateProcess,
    ExitThread,
    ExitProcess,
    LoadDll,
    UnloadDll,
    DebugString,
    RipInfo,
}

#[derive(Debug, PartialEq)]
#[repr(u32)]
pub enum ExceptionCode {
    AccessViolation,
    ArrayBoundsExceeded,
    Breakpoint,
    DatatypeMisalignment,
    DenormalOperand,
    FltDivideByZero,
    FltInexactResult,
    FltInvalidOperation,
    FltOverflow,
    FltStackCheck,
    FltUnderflow,
    IllegalInstruction,
    InPageError,
    IntDivideByZero,
    IntOverflow,
    InvalidDisposition,
    NoncontinuableException,
    PrivInstruction,
    SingleStep,
    StackOverflow,
    DbgControlC,
    Wx86Breakpoint,
    Wx86SingleStep,
}

impl From<u32> for ExceptionCode {
    fn from(code: u32) -> Self {
        match code {
            EXCEPTION_ACCESS_VIOLATION => ExceptionCode::AccessViolation,
            EXCEPTION_ARRAY_BOUNDS_EXCEEDED => ExceptionCode::ArrayBoundsExceeded,
            EXCEPTION_BREAKPOINT => ExceptionCode::Breakpoint,
            EXCEPTION_DATATYPE_MISALIGNMENT => ExceptionCode::DatatypeMisalignment,
            EXCEPTION_FLT_DENORMAL_OPERAND => ExceptionCode::DenormalOperand,
            EXCEPTION_FLT_DIVIDE_BY_ZERO => ExceptionCode::FltDivideByZero,
            EXCEPTION_FLT_INEXACT_RESULT => ExceptionCode::FltInexactResult,
            EXCEPTION_FLT_INVALID_OPERATION => ExceptionCode::FltInvalidOperation,
            EXCEPTION_FLT_OVERFLOW => ExceptionCode::FltOverflow,
            EXCEPTION_FLT_STACK_CHECK => ExceptionCode::FltStackCheck,
            EXCEPTION_FLT_UNDERFLOW => ExceptionCode::FltUnderflow,
            EXCEPTION_ILLEGAL_INSTRUCTION => ExceptionCode::IllegalInstruction,
            EXCEPTION_IN_PAGE_ERROR => ExceptionCode::InPageError,
            EXCEPTION_INT_DIVIDE_BY_ZERO => ExceptionCode::IntDivideByZero,
            EXCEPTION_INT_OVERFLOW => ExceptionCode::IntOverflow,
            EXCEPTION_INVALID_DISPOSITION => ExceptionCode::InvalidDisposition,
            EXCEPTION_NONCONTINUABLE_EXCEPTION => ExceptionCode::NoncontinuableException,
            EXCEPTION_PRIV_INSTRUCTION => ExceptionCode::PrivInstruction,
            EXCEPTION_SINGLE_STEP => ExceptionCode::SingleStep,
            EXCEPTION_STACK_OVERFLOW => ExceptionCode::StackOverflow,
            DBG_CONTROL_C => ExceptionCode::DbgControlC,
            STATUS_WX86_BREAKPOINT_U32 => ExceptionCode::Wx86Breakpoint,
            STATUS_WX86_SINGLE_STEP_U32 => ExceptionCode::Wx86SingleStep,
            _ => unimplemented!(),
        }
    }
}

#[derive(Debug)]
pub struct ExceptionDebugInfo {
    first_chance: bool,
    pub code: ExceptionCode,
    flags: u32,
    // TODO(bostjan): In case of chained records, serialize them into a vector.
    record: *mut (),
    pub address: usize,
    number_parameters: u32,
    information: [usize; 15],
}

impl From<DEBUG_EVENT> for DebugEvent {
    fn from(event: DEBUG_EVENT) -> Self {
        let kind = match event.dwDebugEventCode {
            EXCEPTION_DEBUG_EVENT => {
                let e = unsafe { event.u.Exception() };
                let debug_info = ExceptionDebugInfo {
                    first_chance: e.dwFirstChance == 1,
                    code: e.ExceptionRecord.ExceptionCode.into(),
                    flags: e.ExceptionRecord.ExceptionFlags,
                    record: e.ExceptionRecord.ExceptionRecord as *mut (),
                    address: e.ExceptionRecord.ExceptionAddress as usize,
                    number_parameters: e.ExceptionRecord.NumberParameters,
                    information: e.ExceptionRecord.ExceptionInformation,
                };

                DebugEventKind::Exception(debug_info)
            }

            CREATE_THREAD_DEBUG_EVENT => DebugEventKind::CreateThread,
            CREATE_PROCESS_DEBUG_EVENT => DebugEventKind::CreateProcess,
            EXIT_THREAD_DEBUG_EVENT => DebugEventKind::ExitThread,
            EXIT_PROCESS_DEBUG_EVENT => DebugEventKind::ExitProcess,
            LOAD_DLL_DEBUG_EVENT => DebugEventKind::LoadDll,
            UNLOAD_DLL_DEBUG_EVENT => DebugEventKind::UnloadDll,
            OUTPUT_DEBUG_STRING_EVENT => DebugEventKind::DebugString,
            RIP_EVENT => DebugEventKind::RipInfo,
            _ => unreachable!(),
        };

        DebugEvent {
            pid: event.dwProcessId,
            tid: event.dwThreadId,
            kind,
        }
    }
}

#[derive(Copy, Clone)]
pub enum ContinueStatus {
    Continue,
    ExceptionNotHandled,
    ReplyLater,
}

impl From<ContinueStatus> for u32 {
    fn from(status: ContinueStatus) -> u32 {
        match status {
            ContinueStatus::Continue => DBG_CONTINUE,
            ContinueStatus::ExceptionNotHandled => DBG_EXCEPTION_NOT_HANDLED,
            ContinueStatus::ReplyLater => DBG_REPLY_LATER,
        }
    }
}

struct Breakpoint {
    orig_byte: u8,
}

struct Thread {
    handle: HANDLE,

    // Breakpoint address
    address: Option<usize>,
}

pub struct WinTracer {
    pid: u32,
    process_handle: HANDLE,
    threads: HashMap<u32, Thread>,
    state: State,
    breakpoints: HashMap<usize, Breakpoint>,
}

impl WinTracer {
    pub fn spawn(program: &Path) -> Result<WinTracer, &'static str> {
        let application_name = CString::new(program.to_str().unwrap()).unwrap();

        let mut startup_info: STARTUPINFOA = unsafe { std::mem::zeroed() };
        startup_info.dwFlags = 0x1;
        startup_info.wShowWindow = 0x1;
        startup_info.cb = std::mem::size_of::<STARTUPINFOA>() as u32;

        let mut process_info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

        if unsafe {
            CreateProcessA(
                application_name.as_ptr(),
                std::ptr::null::<()>() as *mut _,
                std::ptr::null::<()>() as *mut _,
                std::ptr::null::<()>() as *mut _,
                0,
                DEBUG_PROCESS,
                std::ptr::null::<()>() as *mut _,
                std::ptr::null::<()>() as *mut _,
                &mut startup_info as *mut _,
                &mut process_info as *mut _,
            )
        } == 0
        {
            return Err("Failed to spawn tracee process");
        }

        let process_handle = process_info.hProcess;
        let thread_handle = process_info.hThread;
        let pid = process_info.dwProcessId;
        let tid = process_info.dwThreadId;

        println!(
            "process_handle: {:x?}, thread_handle: {:x?}, pid: {}, tid: {}",
            process_handle, thread_handle, pid, tid
        );

        let mut threads = HashMap::new();
        threads.insert(
            tid,
            Thread {
                handle: thread_handle,
                address: None,
            },
        );

        Ok(WinTracer {
            pid,
            process_handle,
            threads,
            state: State::Running,
            breakpoints: HashMap::new(),
        })
    }

    pub fn next(&mut self, status: ContinueStatus) -> Result<DebugEvent, &'static str> {
        if let State::Stopped { pid, tid, thread } = self.state {
            if let Some(mut thread) = thread {
                thread.1.EFlags |= 1 << 8;
                set_wow64_thread_context(thread.0, &thread.1)?;
            }

            if unsafe { ContinueDebugEvent(pid, tid, status.into()) } == 0 {
                return Err("ContinueDebugEvent failed");
            }
        }

        loop {
            let mut debug_event: DEBUG_EVENT = unsafe { std::mem::zeroed() };
            if unsafe { WaitForDebugEvent(&mut debug_event as *mut _, INFINITE) } == 0 {
                return Err("WaitForDebugEvent failed");
            }

            /*println!("debug_event: code={:x}, pid={}, tid={}",
            debug_event.dwDebugEventCode,
            debug_event.dwProcessId,
            debug_event.dwThreadId);*/

            let debug_event: DebugEvent = debug_event.into();
            let mut thread_opt = None;

            match debug_event.kind {
                DebugEventKind::Exception(ref e) => {
                    if e.first_chance {
                        match e.code {
                            ExceptionCode::Breakpoint | ExceptionCode::Wx86Breakpoint => {
                                if let Some(bp) = self.breakpoints.get(&e.address) {
                                    if let Some(mut thread) = self.threads.get_mut(&debug_event.tid)
                                    {
                                        let mut context = get_wow64_thread_context(thread.handle)?;
                                        let buffer = [bp.orig_byte];
                                        write_process_memory(
                                            self.process_handle,
                                            e.address,
                                            &buffer,
                                        )?;
                                        context.Eip -= 1;
                                        //context.ContextFlags = WOW64_CONTEXT_CONTROL;
                                        set_wow64_thread_context(thread.handle, &context)?;
                                        thread_opt = Some((thread.handle, context));

                                        // Remember the breakpoint address for the
                                        // reinserting stage.
                                        thread.address = Some(e.address);
                                    } else {
                                        return Err("Thread not found");
                                    }
                                }
                            }

                            ExceptionCode::SingleStep | ExceptionCode::Wx86SingleStep => {
                                // TODO(bostjan): We must consider three possibilities here:
                                //   a) we are single stepping
                                //   b) breakpoint was hit and we should reinsert the breakpoint
                                //   c) one-time breakpoint was hit

                                // TODO(bostjan): Reinsert breakpoint if not one-time
                                if let Some(mut thread) = self.threads.get_mut(&debug_event.tid) {
                                    if let Some(breakpoint_address) = thread.address {
                                        let buffer = [0xcc];
                                        write_process_memory(
                                            self.process_handle,
                                            breakpoint_address,
                                            &buffer,
                                        )?;

                                        // Reset address to signal that the reinserting stage
                                        // was finished.
                                        thread.address = None;

                                        // We handled an "internal" event not meant for the user.
                                        // Therefor, schedule waiting for another event.
                                        if unsafe {
                                            ContinueDebugEvent(
                                                debug_event.pid,
                                                debug_event.tid,
                                                DBG_CONTINUE,
                                            )
                                        } == 0
                                        {
                                            return Err("ContinueDebugEvent failed");
                                        }

                                        continue;
                                    }
                                } else {
                                    return Err("Thread not found");
                                }
                            }

                            _ => unimplemented!(),
                        }
                    } else {
                        // TODO(bostjan): Handle second chance exceptions
                        unimplemented!();
                    }
                }

                _ => { /*println!("Unimplemented: {:?}", debug_event);*/ }
            }

            self.state = State::Stopped {
                pid: debug_event.pid,
                tid: debug_event.tid,
                thread: thread_opt,
            };

            return Ok(debug_event);
        }
    }

    pub fn insert_breakpoint(&mut self, address: usize) -> Result<(), &'static str> {
        if self.breakpoints.contains_key(&address) {
            return Err("Cannot insert breakpoint twice at the same address");
        }

        let mut buffer = [0];
        read_process_memory(self.process_handle, address, &mut buffer)?;
        let orig_byte = buffer[0];

        buffer[0] = 0xcc;
        write_process_memory(self.process_handle, address, &mut buffer)?;

        self.breakpoints.insert(address, Breakpoint { orig_byte });

        Ok(())
    }
}

fn read_process_memory(
    process_handle: HANDLE,
    address: usize,
    buffer: &mut [u8],
) -> Result<usize, &'static str> {
    let mut bytes_read = std::mem::MaybeUninit::<usize>::uninit();
    if unsafe {
        ReadProcessMemory(
            process_handle,
            address as *const _,
            buffer as *mut _ as *mut _,
            buffer.len(),
            &mut bytes_read as *mut _ as *mut _,
        )
    } == 0
    {
        Err("ReadProcessMemory failed")
    } else {
        let bytes_read = unsafe { bytes_read.assume_init() };
        Ok(bytes_read)
    }
}

fn write_process_memory(
    process_handle: HANDLE,
    address: usize,
    buffer: &[u8],
) -> Result<usize, &'static str> {
    let mut bytes_written = std::mem::MaybeUninit::<usize>::uninit();
    if unsafe {
        WriteProcessMemory(
            process_handle,
            address as *mut _,
            buffer as *const _ as *const _,
            buffer.len(),
            &mut bytes_written as *mut _ as *mut _,
        )
    } == 0
    {
        Err("WriteProcessMemory failed")
    } else {
        let bytes_written = unsafe { bytes_written.assume_init() };
        Ok(bytes_written)
    }
}

fn get_thread_context(thread_handle: HANDLE) -> Result<CONTEXT, &'static str> {
    let mut context = std::mem::MaybeUninit::<CONTEXT>::uninit();
    if unsafe { GetThreadContext(thread_handle, &mut context as *mut _ as *mut _) } == 0 {
        Err("GetThreadContext failed")
    } else {
        let context = unsafe { context.assume_init() };
        Ok(context)
    }
}

/*fn get_wow64_thread_context(thread_handle: HANDLE) -> Result<WOW64_CONTEXT, &'static str> {
    let mut context = std::mem::MaybeUninit::<WOW64_CONTEXT>::uninit();
    if unsafe { Wow64GetThreadContext(thread_handle, &mut context as *mut _ as *mut _) } == 0 {
        Err("Wow64GetThreadContext failed")
    } else {
        let context = unsafe { context.assume_init() };
        Ok(context)
    }
}*/

fn get_wow64_thread_context(thread_handle: HANDLE) -> Result<WOW64_CONTEXT, &'static str> {
    let mut context = WOW64_CONTEXT {
        ContextFlags: WOW64_CONTEXT_CONTROL,
        ..unsafe { std::mem::zeroed() }
    };
    if unsafe { Wow64GetThreadContext(thread_handle, &mut context as *mut _ as *mut _) } == 0 {
        Err("Wow64GetThreadContext failed")
    } else {
        Ok(context)
    }
}

fn set_wow64_thread_context(
    thread_handle: HANDLE,
    context: &WOW64_CONTEXT,
) -> Result<(), &'static str> {
    if unsafe { Wow64SetThreadContext(thread_handle, context) } == 0 {
        Err("Wow64SetThreadContext failed")
    } else {
        Ok(())
    }
}
