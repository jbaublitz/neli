use crate as neli;

use neli_proc_macros::neli_enum;

use crate::consts::{netfilter::NetfilterMsg, rtnl::Rtm};

impl_trait!(
    /// Trait marking constants valid for use in
    /// [`Nlmsghdr`][crate::nl::Nlmsghdr] field, `nl_type`.
    pub NlType,
    u16,
    /// Wrapper that is usable with all values in
    /// [`Nlmsghdr`][crate::nl::Nlmsghdr] field,
    /// `nl_type`.
    pub NlTypeWrapper,
    Nlmsg,
    GenlId,
    Rtm,
    NetfilterMsg
);

/// Values for `nl_type` in [`Nlmsghdr`][crate::nl::Nlmsghdr]
#[neli_enum(serialized_type = "u16")]
pub enum Nlmsg {
    Noop = libc::NLMSG_NOOP as u16,
    Error = libc::NLMSG_ERROR as u16,
    Done = libc::NLMSG_DONE as u16,
    Overrun = libc::NLMSG_OVERRUN as u16,
}

/// Values for `nl_type` in [`Nlmsghdr`][crate::nl::Nlmsghdr]
#[neli_enum(serialized_type = "u16")]
pub enum GenlId {
    Ctrl = libc::GENL_ID_CTRL as u16,
    #[cfg(target_env = "gnu")]
    VfsDquot = libc::GENL_ID_VFS_DQUOT as u16,
    #[cfg(target_env = "gnu")]
    Pmcraid = libc::GENL_ID_PMCRAID as u16,
}

/// Values for `nl_flags` in [`Nlmsghdr`][crate::nl::Nlmsghdr]
#[neli_enum(serialized_type = "u16")]
pub enum NlmF {
    /// This flag is required for all kernel requests
    Request = libc::NLM_F_REQUEST as u16,
    Multi = libc::NLM_F_MULTI as u16,
    Ack = libc::NLM_F_ACK as u16,
    Echo = libc::NLM_F_ECHO as u16,
    DumpIntr = libc::NLM_F_DUMP_INTR as u16,
    DumpFiltered = libc::NLM_F_DUMP_FILTERED as u16,
    Root = libc::NLM_F_ROOT as u16,
    Match = libc::NLM_F_MATCH as u16,
    Atomic = libc::NLM_F_ATOMIC as u16,
    Dump = libc::NLM_F_DUMP as u16,
    Replace = libc::NLM_F_REPLACE as u16,
    Excl = libc::NLM_F_EXCL as u16,
    Create = libc::NLM_F_CREATE as u16,
    Append = libc::NLM_F_APPEND as u16,
}

impl_flags!(
    #[allow(missing_docs)]
    pub NlmFFlags, NlmF, u16
);
