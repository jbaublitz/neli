use crate as neli;
use neli_proc_macros::neli_enum;

/// Values for `cmd` in [`Genlmsghdr`][crate::genl::Genlmsghdr].
#[neli_enum(serialized_type = "u32")]
pub enum CnMsgIdx {
    Proc = libc::CN_IDX_PROC,
}

/// Values for `cmd` in [`Genlmsghdr`][crate::genl::Genlmsghdr].
#[neli_enum(serialized_type = "u32")]
pub enum CnMsgVal {
    Proc = libc::CN_VAL_PROC,
}

/// Process event type as reported by the kernel connector.
#[neli::neli_enum(serialized_type = "u32")]
pub enum ProcEventType {
    None = libc::PROC_EVENT_NONE,
    Fork = libc::PROC_EVENT_FORK,
    Exec = libc::PROC_EVENT_EXEC,
    Uid = libc::PROC_EVENT_UID,
    Gid = libc::PROC_EVENT_GID,
    Sid = libc::PROC_EVENT_SID,
    Ptrace = libc::PROC_EVENT_PTRACE,
    Comm = libc::PROC_EVENT_COMM,
    NonzeroExit = libc::PROC_EVENT_NONZERO_EXIT,
    Coredump = libc::PROC_EVENT_COREDUMP,
    Exit = libc::PROC_EVENT_EXIT,
}

/// Process event operations.
#[neli::neli_enum(serialized_type = "u32")]
pub enum ProcCnMcastOp {
    Listen = libc::PROC_CN_MCAST_LISTEN,
    Ignore = libc::PROC_CN_MCAST_IGNORE,
}