use std::mem;

use buffering::copy::{StreamReadBuffer,StreamWriteBuffer};
use libc;

use Nl;
use consts::{Af,Arphrd,AddrFamily,IfaF,Iff,RtaType,RtmF,Rtn,Rtprot,RtScope};
use err::{SerError,DeError};

/// Struct representing interface information messages
pub struct Ifinfomsg {
    /// Interface address family
    pub ifi_family: AddrFamily,
    /// Interface type
    pub ifi_type: Arphrd,
    /// Interface index
    pub ifi_index: libc::c_int,
    /// Interface flags
    pub ifi_flags: Vec<Iff>,
    ifi_change: libc::c_uint,
}

impl Ifinfomsg {
    /// Create a fully initialized interface info struct
    pub fn new(ifi_family: AddrFamily, ifi_type: Arphrd, ifi_index: libc::c_int, ifi_flags: Vec<Iff>) -> Self {
        Ifinfomsg { ifi_family, ifi_type, ifi_index, ifi_flags, ifi_change: 0xffffffff }
    }
}

impl Nl for Ifinfomsg {
    type SerIn = ();
    type DeIn = ();

    fn serialize(&self, buf: &mut StreamWriteBuffer) -> Result<(), SerError> {
        self.ifi_family.serialize(buf)?;
        self.ifi_type.serialize(buf)?;
        self.ifi_index.serialize(buf)?;
        self.ifi_flags.iter().fold(0, |acc: libc::c_uint, next| {
            let next_uint: libc::c_uint = next.into();
            acc | next_uint
        }).serialize(buf)?;
        self.ifi_change.serialize(buf)?;
        Ok(())
    }

    fn deserialize<B>(buf: &mut StreamReadBuffer<B>) -> Result<Self, DeError> where B: AsRef<[u8]> {
        Ok(Ifinfomsg {
            ifi_family: AddrFamily::deserialize(buf)?,
            ifi_type: Arphrd::deserialize(buf)?,
            ifi_index: libc::c_int::deserialize(buf)?,
            ifi_flags: {
                let flags = libc::c_uint::deserialize(buf)?;
                let mut nl_flags = Vec::new();
                for i in 0..mem::size_of::<libc::c_int>() * 8 {
                    let bit = 1 << i;
                    if bit & flags == bit {
                        nl_flags.push(bit.into());
                    }
                }
                nl_flags
            },
            ifi_change: 0xffffffff,
        })
    }

    fn size(&self) -> usize {
        self.ifi_family.size() + self.ifi_type.size() + self.ifi_index.size() + mem::size_of::<libc::c_uint>()
    }
}

/// Struct representing interface address messages
pub struct Ifaddrmsg {
    /// Interface address family
    pub ifa_family: Af,
    /// Interface address prefix length
    pub ifa_prefixlen: libc::c_uchar,
    /// Interface address flags
    pub ifa_flags: Vec<IfaF>,
    /// Interface address scope
    pub ifa_scope: libc::c_uchar,
    /// Interface address index
    pub ifa_index: libc::c_int,
}

impl Nl for Ifaddrmsg {
    type SerIn = ();
    type DeIn = ();

    fn serialize(&self, buf: &mut StreamWriteBuffer) -> Result<(), SerError> {
        self.ifa_family.serialize(buf)?;
        self.ifa_prefixlen.serialize(buf)?;
        self.ifa_flags.iter().fold(0, |acc: libc::c_uchar, next| {
            let next_uint: u32 = next.into();
            acc | next_uint as libc::c_uchar
        }).serialize(buf)?;
        self.ifa_scope.serialize(buf)?;
        self.ifa_index.serialize(buf)?;
        Ok(())
    }

    fn deserialize<B>(buf: &mut StreamReadBuffer<B>) -> Result<Self, DeError> where B: AsRef<[u8]> {
        Ok(Ifaddrmsg {
            ifa_family: Af::deserialize(buf)?,
            ifa_prefixlen: libc::c_uchar::deserialize(buf)?,
            ifa_flags: {
                let flags = libc::c_uchar::deserialize(buf)?;
                let mut nl_flags = Vec::new();
                for i in 0..mem::size_of::<libc::c_uchar>() * 8 {
                    let bit = 1 << i;
                    if bit & flags == bit {
                        nl_flags.push((bit as u32).into());
                    }
                }
                nl_flags
            },
            ifa_scope: libc::c_uchar::deserialize(buf)?,
            ifa_index: libc::c_int::deserialize(buf)?,
        })
    }

    fn size(&self) -> usize {
        self.ifa_family.size() + self.ifa_prefixlen.size() + mem::size_of::<libc::c_uchar>()
            + self.ifa_scope.size() + self.ifa_index.size()
    }
}

/// Route message
pub struct Rtmsg {
    /// Address family of route
    pub rtm_family: libc::c_uchar,
    /// Length of destination
    pub rtm_dst_len: libc::c_uchar,
    /// Length of source
    pub rtm_src_len: libc::c_uchar,
    /// TOS filter
    pub rtm_tos: libc::c_uchar,
    /// Routing table ID
    pub rtm_table: libc::c_uchar,
    /// Routing protocol
    pub rtm_protocol: Rtprot,
    /// Routing scope
    pub rtm_scope: RtScope,
    /// Routing type
    pub rtm_type: Rtn,
    /// Routing flags
    pub rtm_flags: Vec<RtmF>,
}

impl Nl for Rtmsg {
    type SerIn = ();
    type DeIn = ();

    fn serialize(&self, buf: &mut StreamWriteBuffer) -> Result<(), SerError> {
        self.rtm_family.serialize(buf)?;
        self.rtm_dst_len.serialize(buf)?;
        self.rtm_src_len.serialize(buf)?;
        self.rtm_tos.serialize(buf)?;
        self.rtm_table.serialize(buf)?;
        self.rtm_protocol.serialize(buf)?;
        self.rtm_scope.serialize(buf)?;
        self.rtm_type.serialize(buf)?;
        self.rtm_flags.iter().fold(0, |acc: libc::c_uint, next| {
            let next_uint: libc::c_uint = next.into();
            acc | next_uint
        }).serialize(buf)?;
        Ok(())
    }

    fn size(&self) -> usize {
        self.rtm_family.size() + self.rtm_dst_len.size() + self.rtm_src_len.size()
            + self.rtm_tos.size() + self.rtm_table.size() + self.rtm_protocol.size()
            + self.rtm_scope.size() + self.rtm_type.size() + mem::size_of::<libc::c_uint>()
    }
}

/// Struct representing route netlink attributes
pub struct RtAttr<T> {
    /// Length of the attribute
    pub rta_len: libc::c_ushort,
    /// Type of the attribute
    pub rta_type: T,
}

impl<T> Nl for RtAttr<T> where T: RtaType {
    type SerIn = ();
    type DeIn = ();

    fn serialize(&self, buf: &mut StreamWriteBuffer) -> Result<(), SerError> {
        self.rta_len.serialize(buf)?;
        self.rta_type.serialize(buf)?;
        Ok(())
    }

    fn deserialize<B>(buf: &mut StreamReadBuffer<B>) -> Result<Self, DeError> where B: AsRef<[u8]> {
        Ok(RtAttr {
            rta_len: libc::c_ushort::deserialize(buf)?,
            rta_type: T::deserialize(buf)?,
        })
    }

    fn size(&self) -> usize {
        self.rta_len.size() + self.rta_type.size()
    }
}
