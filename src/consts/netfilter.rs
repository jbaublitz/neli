//! Constants for netfilter related protocols
//!
//! Note that this doesn't cover everything yet, both the list of types and variants in enums will
//! be added over time.

use super::{NlAttrType, NlType};

impl_var_trait! {
    /// Attributes inside a netfilter log packet message.
    ///
    /// These are send by the kernel and describe a logged packet.
    NfLogAttr, u16, NlAttrType,
    PacketHdr => libc::NFULA_PACKET_HDR as u16,
    Mark => libc::NFULA_MARK as u16,
    Timestamp => libc::NFULA_TIMESTAMP as u16,
    IfindexIndev => libc::NFULA_IFINDEX_INDEV as u16,
    IfindexOutdev => libc::NFULA_IFINDEX_OUTDEV as u16,
    IfindexPhyindev => libc::NFULA_IFINDEX_PHYSINDEV as u16,
    IfindexPhyoutdev => libc::NFULA_IFINDEX_PHYSOUTDEV as u16,
    Hwaddr => libc::NFULA_HWADDR as u16,
    Payload => libc::NFULA_PAYLOAD as u16,
    Prefix => libc::NFULA_PREFIX as u16,
    Uid => libc::NFULA_UID as u16,
    Seq => libc::NFULA_SEQ as u16,
    SeqGlobal => libc::NFULA_SEQ_GLOBAL as u16,
    Gid => libc::NFULA_GID as u16,
    Hwtype => libc::NFULA_HWTYPE as u16,
    Hwheader => libc::NFULA_HWHEADER as u16,
    Hwlen => libc::NFULA_HWLEN as u16,
    Ct => libc::NFULA_CT as u16,
    CtInfo => libc::NFULA_CT_INFO as u16
}

impl_var_trait! {
    /// Configuration attributes for netfilter logging.
    ///
    /// See [LogConfigReq][crate::netfilter::LogConfigReq]
    NfLogCfg, u16, NlAttrType,
    Cmd => libc::NFULA_CFG_CMD as u16,
    Mode => libc::NFULA_CFG_MODE as u16,
    NlBufSize => libc::NFULA_CFG_NLBUFSIZ as u16,
    Timeout => libc::NFULA_CFG_TIMEOUT as u16,
    QThresh => libc::NFULA_CFG_QTHRESH as u16,
    Flags => libc::NFULA_CFG_FLAGS as u16
}

const fn nfnl_msg_type(subsys: u8, msg: u8) -> u16 {
    ((subsys as u16) << 8) | (msg as u16)
}

impl_var_trait! {
    /// Messages related to the netfilter netlink protocols.
    ///
    /// These appear on the [NlFamily::Netfilter][super::NlFamily::Netfilter] sockets.
    NetfilterMsg, u16, NlType,
    // TODO: Docs here /// A logged packet, going from kernel to userspace.
    LogPacket => nfnl_msg_type(libc::NFNL_SUBSYS_ULOG as u8, libc::NFULNL_MSG_PACKET as u8),
    // TODO: Docs here /// A logging configuration request, going from userspace to kernel.
    LogConfig => nfnl_msg_type(libc::NFNL_SUBSYS_ULOG as u8, libc::NFULNL_MSG_CONFIG as u8)
}

impl_trait! {
    /// Parameters for the [NfLogCfg::Cmd].
    LogCfgCmd, u8
}

impl_var_trait! {
    /// Command value for the [NfLogCfg::Cmd].
    LogCmd, u8, LogCfgCmd,
    Bind => libc::NFULNL_CFG_CMD_BIND as u8,
    Unbind => libc::NFULNL_CFG_CMD_UNBIND as u8,
    PfBind => libc::NFULNL_CFG_CMD_PF_BIND as u8,
    PfUnbind => libc::NFULNL_CFG_CMD_PF_UNBIND as u8
}

impl_var! {
    /// Copy mode of the logged packets.
    LogCopyMode, u8,
    None => libc::NFULNL_COPY_NONE as u8,
    Meta => libc::NFULNL_COPY_META as u8,
    Packet => libc::NFULNL_COPY_PACKET as u8
}
