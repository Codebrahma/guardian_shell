#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm,
        bpf_get_current_pid_tgid,
        bpf_get_current_uid_gid,
        bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::{HashMap, PerCpuArray, PerfEventArray},
    programs::TracePointContext,
};
use guardian_common::FileAccessEvent;

/// HashMap of process comm names to monitor.
/// Key: [u8; 16] (comm name, null-padded), Value: u8 (1 = watched)
/// Userspace populates this with process names from config.
#[map]
static WATCHED_COMMS: HashMap<[u8; 16], u8> = HashMap::with_max_entries(256, 0);

/// Per-CPU scratch buffer for constructing events (avoids 512-byte stack limit).
#[map]
static EVENT_BUF: PerCpuArray<FileAccessEvent> = PerCpuArray::with_max_entries(1, 0);

/// Perf event ring buffer for sending events to userspace.
#[map]
static EVENTS: PerfEventArray<FileAccessEvent> = PerfEventArray::new(0);

#[tracepoint]
pub fn guardian_file_open(ctx: TracePointContext) -> u32 {
    match try_guardian_file_open(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_guardian_file_open(ctx: &TracePointContext) -> Result<u32, i64> {
    // Get process comm name and check if it's watched
    let comm = bpf_get_current_comm().map_err(|e| e)?;
    if unsafe { WATCHED_COMMS.get(&comm) }.is_none() {
        return Ok(0);
    }

    // Get the per-CPU event buffer
    let event = unsafe {
        let ptr = EVENT_BUF.get_ptr_mut(0).ok_or(1i64)?;
        &mut *ptr
    };

    // Fill in process info
    let pid_tgid = bpf_get_current_pid_tgid();
    event.tgid = (pid_tgid >> 32) as u32;
    event.pid = pid_tgid as u32;
    event.uid = (bpf_get_current_uid_gid() & 0xFFFF_FFFF) as u32;
    event.comm = comm;

    // Read tracepoint args (x86_64 offsets)
    // Offset 24: filename pointer, Offset 32: open flags
    let filename_ptr: u64 = unsafe { ctx.read_at(24)? };
    let flags: u64 = unsafe { ctx.read_at(32)? };
    event.flags = flags as u32;

    // Read filename from userspace memory
    match unsafe { bpf_probe_read_user_str_bytes(filename_ptr as *const u8, &mut event.filename) } {
        Ok(name_bytes) => {
            event.filename_len = name_bytes.len() as u32;
        }
        Err(_) => {
            event.filename_len = 0;
        }
    }

    // Send event to userspace
    EVENTS.output(ctx, event, 0);

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
