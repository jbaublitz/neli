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

impl_flags!(
    #[allow(missing_docs)]
    pub NlmF: u16 {
        /// This flag is required for all kernel requests
        REQUEST = libc::NLM_F_REQUEST as u16,
        MULTI = libc::NLM_F_MULTI as u16,
        ACK = libc::NLM_F_ACK as u16,
        ECHO = libc::NLM_F_ECHO as u16,
        DUMP_INTR = libc::NLM_F_DUMP_INTR as u16,
        DUMP_FILTERED = libc::NLM_F_DUMP_FILTERED as u16,
        ROOT = libc::NLM_F_ROOT as u16,
        MATCH = libc::NLM_F_MATCH as u16,
        ATOMIC = libc::NLM_F_ATOMIC as u16,
        DUMP = libc::NLM_F_DUMP as u16,
        REPLACE = libc::NLM_F_REPLACE as u16,
        EXCL = libc::NLM_F_EXCL as u16,
        CREATE = libc::NLM_F_CREATE as u16,
        APPEND = libc::NLM_F_APPEND as u16,
    }
);

#[neli_enum(serialized_type = "u16")]
pub enum NlmsgerrAttr {
    Unused = 0,
    /// Error message string (string)
    Msg = 1,
    /// Offset of the invalid attribute in the original
    /// message, counting from the beginning of the
    /// header (u32)
    Offset = 2,
    /// Arbitrary subsystem specific cookie to
    /// be used - in the success case - to identify a created
    /// object or operation or similar (binary)
    Cookie = 3,
    /// Policy for a rejected attribute
    Policy = 4,
}
