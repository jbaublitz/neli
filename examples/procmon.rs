//! A small process monitor example using netlink connector messages.
//!
//! You must run this example with root privileges, in the root pid namespace
//!
//! See this blog post for more details:
//! https://nick-black.com/dankwiki/index.php/The_Proc_Connector_and_Socket_Filters

use neli::{
    connector::{CnMsg, ProcEvent, ProcEventHeader},
    consts::{
        connector::{CnMsgIdx, CnMsgVal, ProcCnMcastOp},
        nl::{NlmF, Nlmsg},
        socket::NlFamily,
    },
    nl::{NlPayload, NlmsghdrBuilder},
    socket::synchronous::NlSocketHandle,
    utils::Groups,
};
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let pid = std::process::id();
    let socket = NlSocketHandle::connect(
        NlFamily::Connector,
        Some(pid),
        Groups::new_bitmask(CnMsgIdx::Proc.into()),
    )?;

    let subscribe = NlmsghdrBuilder::default()
        .nl_type(Nlmsg::Done)
        .nl_flags(NlmF::empty())
        .nl_pid(pid)
        .nl_payload(NlPayload::Payload(
            neli::connector::CnMsgBuilder::default()
                .idx(CnMsgIdx::Proc)
                .val(CnMsgVal::Proc)
                .payload(ProcCnMcastOp::Listen)
                .build()?,
        ))
        .build()?;

    socket.send(&subscribe)?;

    loop {
        for event in socket.recv::<Nlmsg, CnMsg<ProcEventHeader>>()?.0 {
            let ProcEvent::Exec { process_pid, .. } = event?
                .get_payload()
                .ok_or("Failed to extract payload")?
                .payload()
                .event
            else {
                continue;
            };

            let exe = fs::read_link(format!("/proc/{process_pid}/exe"))
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| "unknown".to_string());
            let cmdline = cmdline_to_string(process_pid).unwrap_or_else(|_| "unknown".to_string());
            println!("Process created: PID: {process_pid}, Exe: {exe}, Cmdline: {cmdline}");
        }
    }
}

fn cmdline_to_string(pid: i32) -> std::io::Result<String> {
    // 1) Read the entire file into a byte‐buffer in one go
    let mut data = fs::read(format!("/proc/{pid}/cmdline"))?;

    // 2) In‐place map all remaining NULs to spaces
    for b in &mut data {
        if *b == 0 {
            *b = b' ';
        }
    }

    // 3) SAFELY convert bytes → String without re‐checking UTF‐8
    //
    //    We can do this because /proc/cmdline is guaranteed to be valid UTF-8
    //    on Linux (arguments must be passed as UTF-8), so we skip the cost
    //    of a UTF-8 validation pass.
    let s = unsafe { String::from_utf8_unchecked(data) };
    Ok(s)
}
