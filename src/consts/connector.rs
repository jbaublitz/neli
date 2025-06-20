use crate as neli;

/// Values for `idx` in [`CnMsg`][crate::connector::CnMsg].
#[neli::neli_enum(serialized_type = "u32")]
pub enum CnMsgIdx {
    Proc = libc::CN_IDX_PROC,
    Cifs = libc::CN_IDX_CIFS,
    W1 = libc::CN_W1_IDX,
    V86d = libc::CN_IDX_V86D,
    Bb = libc::CN_IDX_BB,
    Dst = libc::CN_DST_IDX,
    Dm = libc::CN_IDX_DM,
    Drbd = libc::CN_IDX_DRBD,
    Kvp = libc::CN_KVP_IDX,
    Vss = libc::CN_VSS_IDX,
}

/// Values for `val` in [`CnMsg`][crate::connector::CnMsg].
#[neli::neli_enum(serialized_type = "u32")]
pub enum CnMsgVal {
    Proc = libc::CN_VAL_PROC,
    Cifs = libc::CN_VAL_CIFS,
    W1 = libc::CN_W1_VAL,
    V86dUvesafb = libc::CN_VAL_V86D_UVESAFB,
    Dst = libc::CN_DST_VAL,
    DmUserspaceLog = libc::CN_VAL_DM_USERSPACE_LOG,
    Drbd = libc::CN_VAL_DRBD,
    Kvp = libc::CN_KVP_VAL,
    Vss = libc::CN_VSS_VAL,
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
