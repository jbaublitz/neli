//! Netfilter protocols
//!
//! Protocols used for communicating with netfilter. Currently, this contains (partial) support for
//! NFLOG, NFQUEUE and CONNTRACK will be added later.
//!
//! See the examples in the git repository for actual, working code.

use std::ffi::CString;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::{Bytes, BytesMut};
use libc::c_int;

use crate::{
    consts::netfilter::{LogCopyMode, NfLogAttr, NfLogCfg},
    err::{DeError, SerError},
    nlattr::Nlattr,
    BeU64, Nl,
};

#[derive(Copy, Clone, Debug)]
struct Timestamp {
    secs: BeU64,
    usecs: BeU64,
}

impl Nl for Timestamp {
    fn serialize(&self, mem: BytesMut) -> Result<BytesMut, SerError> {
        Ok(serialize! {
            mem;
            self.secs;
            self.usecs
        })
    }

    fn deserialize(mem: Bytes) -> Result<Self, DeError> {
        Ok(deserialize! {
            mem;
            Timestamp {
                secs: BeU64,
                usecs: BeU64
            }
        })
    }

    fn size(&self) -> usize {
        self.secs.size() + self.usecs.size()
    }
}

impl Into<SystemTime> for Timestamp {
    fn into(self) -> SystemTime {
        let dur = Duration::new(self.secs, (self.usecs * 1000) as u32);
        UNIX_EPOCH + dur
    }
}

/// A logged packet sent from the kernel to userspace.
///
/// Note that further fields will be added over time.
#[derive(Clone, Debug)]
pub struct LogPacket {
    /// No idea what this is :-(
    pub hw_protocol: u16,
    /// No idea what this is :-(
    pub hook: u8,
    /// A packet mark.
    ///
    /// A mark used through the netfilter, working as kind of scratch memory. 0 and no mark set are
    /// considered equivalent.
    pub mark: u16,
    /// A timestamp when the packet has been captured.
    pub timestamp: SystemTime,
    /// Source hardware address (eg. MAC).
    ///
    /// This might be missing in case it is not yet known at the point of packet capture (outgoing
    /// packets before routing decisions) or on interfaces that don't have hardware addresses
    /// (`lo`).
    pub hwaddr: Vec<u8>,
    /// Payload of the packet.
    pub payload: Vec<u8>,
    /// Prefix, set at the capturing rule. May be empty.
    pub prefix: CString,
    /// Index of the inbound interface, if any.
    pub ifindex_in: Option<u32>,
    /// Index of the outbound interface, if any.
    pub ifindex_out: Option<u32>,
    /// Index of the physical inbound interface, if any.
    pub ifindex_physin: Option<u32>,
    /// Index of the physical outbound interface, if any.
    pub ifindex_physout: Option<u32>,
    /// UID of the socket this packet belongs to.
    pub uid: Option<u32>,
    /// GID of the socket this packet belongs to.
    pub gid: Option<u32>,
    // TODO: More
    // * Seq is probably not useful
    // * What is the HWTYPE/stuff?
    // * Conntrack

    // Internal use, remembering the size this was encoded as.
    // It also prevents user from creating this directly, therefore forward-proofs it as adding
    // more fields won't be a breaking change.
    attr_len: usize,
}

impl LogPacket {
    /// Creates a dummy instance.
    ///
    /// This can be used in eg. tests, or to create an instance and set certain fields. This is
    /// similar to the [Default] trait, except unlike default instances, this one doesn't actually
    /// make much sense.
    pub fn dummy_instance() -> Self {
        Self {
            hw_protocol: 0,
            hook: 0,
            mark: 0,
            timestamp: UNIX_EPOCH,
            hwaddr: Vec::new(),
            payload: Vec::new(),
            prefix: CString::default(),
            ifindex_in: None,
            ifindex_out: None,
            ifindex_physin: None,
            ifindex_physout: None,
            uid: None,
            gid: None,
            attr_len: 0,
        }
    }
}

impl Nl for LogPacket {
    fn serialize(&self, _: &mut StreamWriteBuffer) -> Result<(), SerError> {
        unimplemented!("The NFLOG protocol never sends packets to kernel, no reason to know how to serialize them");
    }
    fn deserialize<B: AsRef<[u8]>>(m: &mut StreamReadBuffer<B>) -> Result<Self, DeError> {
        let hint = m.take_size_hint().map(|h| h.saturating_sub(4));
        let hw_protocol = u16::from_be(Nl::deserialize(m)?);
        let hook = Nl::deserialize(m)?;
        let _pad: u8 = Nl::deserialize(m)?;
        m.set_size_hint(hint.unwrap_or_default());
        let attrs = Nlattrs::deserialize(m)?;
        let attr_len = attrs.asize();
        let mut result = Self::dummy_instance();
        result.hw_protocol = hw_protocol;
        result.hook = hook;
        result.attr_len = attr_len;

        for attr in attrs {
            match attr.nla_type {
                NfLogAttr::Mark => result.mark = attr.get_payload_as()?,
                NfLogAttr::Timestamp => {
                    result.timestamp = attr.get_payload_as::<Timestamp>()?.into();
                }
                NfLogAttr::Hwaddr => {
                    let mut buffer = StreamReadBuffer::new(&attr.payload);
                    let len = u16::from_be(u16::deserialize(&mut buffer)?);
                    let mut hwaddr = attr.payload;
                    // Drop the len and padding
                    hwaddr.drain(..4);
                    hwaddr.truncate(len as usize);
                    hwaddr.shrink_to_fit();
                    result.hwaddr = hwaddr;
                }
                NfLogAttr::Payload => result.payload = attr.payload,
                NfLogAttr::Prefix => {
                    let mut bytes = attr.payload;
                    // get rid of null byte, CString::new adds it and wants it not to have it there.
                    // Usually, there's only one null byte, but who knows what comes from the
                    // kernel, therefore we just make sure to do *something* in case there are
                    // nulls in the middle too.
                    bytes.retain(|b| *b != 0);
                    result.prefix = CString::new(bytes).expect("Leftover null byte");
                }
                NfLogAttr::IfindexIndev => {
                    result.ifindex_in = Some(u32::from_be(attr.get_payload_as()?))
                }
                NfLogAttr::IfindexOutdev => {
                    result.ifindex_out = Some(u32::from_be(attr.get_payload_as()?))
                }
                NfLogAttr::IfindexPhyindev => {
                    result.ifindex_physin = Some(u32::from_be(attr.get_payload_as()?))
                }
                NfLogAttr::IfindexPhyoutdev => {
                    result.ifindex_physout = Some(u32::from_be(attr.get_payload_as()?))
                }
                NfLogAttr::Uid => result.uid = Some(u32::from_be(attr.get_payload_as()?)),
                NfLogAttr::Gid => result.gid = Some(u32::from_be(attr.get_payload_as()?)),
                _ => (),
            }
        }
        Ok(result)
    }
    fn size(&self) -> usize {
        4 + self.attr_len
    }
}

/// A configuration request, to bind a socket to specific logging group.
#[derive(Debug)]
pub struct LogConfigReq {
    family: u8,
    group: u16,
    attrs: Vec<Nlattr<NfLogCfg, Vec<u8>>>,
}

impl LogConfigReq {
    /// Creates a new log configuration request.
    ///
    /// It should be sent to the kernel in a
    /// [NetfilterMsg::LogConfig][crate::consts::netfilter::NetfilterMsg::LogConfig] message.
    ///
    /// ```rust
    /// # use neli::consts::netfilter::{NfLogCfg, LogCmd, LogCopyMode};
    /// # use neli::nlattr::Nlattr;
    /// # use neli::netfilter::{LogConfigMode, LogConfigReq};
    /// // A request to attach the socket to log group 10 on the AF_INET protocol.
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let cfg = vec![
    ///     Nlattr::new(None, NfLogCfg::Cmd, LogCmd::PfUnbind)?,
    ///     Nlattr::new(None, NfLogCfg::Mode, LogConfigMode {
    ///         copy_mode: LogCopyMode::Packet,
    ///         copy_range: 50,
    ///     })?,
    ///     Nlattr::new(None, NfLogCfg::Cmd, LogCmd::PfBind)?,
    ///     Nlattr::new(None, NfLogCfg::Cmd, LogCmd::Bind)?,
    /// ];
    /// let req = LogConfigReq::new(libc::AF_INET, 10, cfg);
    /// # Ok(()) }
    /// ```
    pub fn new(family: c_int, group: u16, cfg: Vec<Nlattr<NfLogCfg, Vec<u8>>>) -> Self {
        assert!(family >= 0);
        assert!(family <= 255);
        Self {
            family: family as u8,
            group,
            attrs: cfg,
        }
    }
}

impl Nl for LogConfigReq {
    fn serialize(&self, m: &mut StreamWriteBuffer) -> Result<(), SerError> {
        self.family.serialize(m)?;
        // protocol version
        0u8.serialize(m)?;
        u16::to_be(self.group).serialize(m)?;
        self.attrs.serialize(m)?;
        self.pad(m)?;
        Ok(())
    }
    fn deserialize<B: AsRef<[u8]>>(_m: &mut StreamReadBuffer<B>) -> Result<Self, DeError> {
        unimplemented!("Config requests are never sent by the kernel")
    }
    fn size(&self) -> usize {
        self.family.size() + 0u8.size() + self.group.size() + self.attrs.asize()
    }
}

/// Configuration mode, as a parameter to [NfLogCfg::Mode].
#[derive(Clone, Debug)]
pub struct LogConfigMode {
    /// Range of bytes to copy.
    ///
    /// TODO: All lengths in netlink are u16, why is this u32? Does it mean one should specify both
    /// ends of the range somehow? How?
    pub copy_range: u32,
    /// What parts should be sent.
    pub copy_mode: LogCopyMode,
}

impl Nl for LogConfigMode {
    fn serialize(&self, m: &mut StreamWriteBuffer) -> Result<(), SerError> {
        u32::to_be(self.copy_range).serialize(m)?;
        self.copy_mode.serialize(m)?;
        // A padding
        0u8.serialize(m)?;
        Ok(())
    }
    fn deserialize<B: AsRef<[u8]>>(m: &mut StreamReadBuffer<B>) -> Result<Self, DeError> {
        let copy_range = u32::from_be(u32::deserialize(m)?);
        let copy_mode = LogCopyMode::deserialize(m)?;
        // A padding
        u8::deserialize(m)?;
        Ok(Self {
            copy_range,
            copy_mode,
        })
    }
    fn size(&self) -> usize {
        self.copy_range.size() + self.copy_mode.size() + 0u8.size()
    }
}
