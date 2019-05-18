use std::mem;

use buffering::copy::{StreamReadBuffer,StreamWriteBuffer};
use libc;

use Nl;
use consts::{Af,Arphrd,AddrFamily,IfaF,Iff,Ntf,Nud,RtaType,RtmF,Rtn,Rtprot,RtScope,RtTable};
use err::{SerError,DeError};

impl<T, P> Nl for Vec<Rtattr<T, P>> where T: RtaType, P: Nl {
    fn serialize(&self, buf: &mut StreamWriteBuffer) -> Result<(), SerError> {
        for item in self.iter() {
            item.serialize(buf)?;
        }
        Ok(())
    }

    fn deserialize<B>(buf: &mut StreamReadBuffer<B>) -> Result<Self, DeError>
            where B: AsRef<[u8]> {
        let mut size_hint = buf.take_size_hint().ok_or(
            DeError::new("Vec of Rtattr requires a size hint to deserialize")
        )?;
        let mut vec = Vec::new();
        while size_hint > 0 {
            let attr = Rtattr::deserialize(buf)?;
            size_hint -= attr.asize();
            vec.push(attr);
        }
        Ok(vec)
    }

    fn size(&self) -> usize {
        self.iter().fold(0, |acc, item| {
            acc + item.asize()
        })
    }
}

/// Struct representing interface information messages
pub struct Ifinfomsg<T> {
    /// Interface address family
    pub ifi_family: AddrFamily,
    /// Interface type
    pub ifi_type: Arphrd,
    /// Interface index
    pub ifi_index: libc::c_int,
    /// Interface flags
    pub ifi_flags: Vec<Iff>,
    ifi_change: libc::c_uint,
    /// Payload of `Rtattr`s
    pub rtattrs: Vec<Rtattr<T, Vec<u8>>>,
}

impl<T> Ifinfomsg<T> where T: RtaType {
    /// Create a fully initialized interface info struct
    pub fn new(ifi_family: AddrFamily, ifi_type: Arphrd, ifi_index: libc::c_int,
               ifi_flags: Vec<Iff>, rtattrs: Vec<Rtattr<T, Vec<u8>>>) -> Self {
        Ifinfomsg { ifi_family, ifi_type, ifi_index, ifi_flags, ifi_change: 0xffffffff,
                    rtattrs, }
    }
}

impl<T> Nl for Ifinfomsg<T> where T: RtaType {
    fn serialize(&self, buf: &mut StreamWriteBuffer) -> Result<(), SerError> {
        self.ifi_family.serialize(buf)?;
        self.ifi_type.serialize(buf)?;
        self.ifi_index.serialize(buf)?;
        self.ifi_flags.iter().fold(0, |acc: libc::c_uint, next| {
            let next_uint: libc::c_uint = next.into();
            acc | next_uint
        }).serialize(buf)?;
        self.ifi_change.serialize(buf)?;
        self.rtattrs.serialize(buf)?;
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
            rtattrs: Vec::<Rtattr<T, Vec<u8>>>::deserialize(buf)?,
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
    pub rtm_table: RtTable,
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

    fn deserialize<B>(buf: &mut StreamReadBuffer<B>) -> Result<Self, DeError> where B: AsRef<[u8]> {
        Ok(Rtmsg {
            rtm_family: libc::c_uchar::deserialize(buf)?,
            rtm_dst_len: libc::c_uchar::deserialize(buf)?,
            rtm_src_len: libc::c_uchar::deserialize(buf)?,
            rtm_tos: libc::c_uchar::deserialize(buf)?,
            rtm_table: RtTable::deserialize(buf)?,
            rtm_protocol: Rtprot::deserialize(buf)?,
            rtm_scope: RtScope::deserialize(buf)?,
            rtm_type: Rtn::deserialize(buf)?,
            rtm_flags: {
                let flags = libc::c_int::deserialize(buf)?;
                let mut rtm_flags = Vec::new();
                for i in 0..mem::size_of::<libc::c_uint>() * 8 {
                    let bit = 1 << i;
                    if bit & flags == bit {
                        rtm_flags.push((bit as libc::c_uint).into());
                    }
                }
                rtm_flags
            },
        })
    }

    fn size(&self) -> usize {
        self.rtm_family.size() + self.rtm_dst_len.size() + self.rtm_src_len.size()
            + self.rtm_tos.size() + self.rtm_table.size() + self.rtm_protocol.size()
            + self.rtm_scope.size() + self.rtm_type.size() + mem::size_of::<libc::c_uint>()
    }
}

/// Represents an ARP (neighbor table) entry
pub struct Ndmsg {
    /// Address family of entry
    pub ndm_family: Af,
    /// Index of entry
    pub ndm_index: libc::c_int,
    /// State of entry
    pub ndm_state: Vec<Nud>,
    /// Flags for entry
    pub ndm_flags: Vec<Ntf>,
    /// Type of entry
    pub ndm_type: Rtn,
}

impl Nl for Ndmsg {
    fn serialize(&self, buf: &mut StreamWriteBuffer) -> Result<(), SerError> {
        self.ndm_family.serialize(buf)?;
        self.ndm_index.serialize(buf)?;
        self.ndm_state.iter().fold(0, |acc: u16, next| {
            let next_uint: u16 = next.into();
            acc | next_uint
        }).serialize(buf)?;
        self.ndm_flags.iter().fold(0, |acc: u8, next| {
            let next_uint: u8 = next.into();
            acc | next_uint
        }).serialize(buf)?;
        self.ndm_type.serialize(buf)?;
        Ok(())
    }

    fn deserialize<B>(buf: &mut StreamReadBuffer<B>) -> Result<Self, DeError>
            where B: AsRef<[u8]> {
        Ok(Ndmsg {
            ndm_family: Af::deserialize(buf)?,
            ndm_index: libc::c_int::deserialize(buf)?,
            ndm_state: {
                let state = u16::deserialize(buf)?;
                let mut ndm_state = Vec::new();
                for i in 0..mem::size_of::<u16>() * 8 {
                    let bit = 1 << i;
                    if bit & state == bit {
                        ndm_state.push((bit as u16).into());
                    }
                }
                ndm_state
            },
            ndm_flags: {
                let flags = u8::deserialize(buf)?;
                let mut ndm_flags = Vec::new();
                for i in 0..mem::size_of::<u8>() * 8 {
                    let bit = 1 << i;
                    if bit & flags == bit {
                        ndm_flags.push((bit as u8).into());
                    }
                }
                ndm_flags
            },
            ndm_type: Rtn::deserialize(buf)?,
        })
    }

    fn size(&self) -> usize {
        self.ndm_family.size() + self.ndm_index.size() + mem::size_of::<u16>() +
            mem::size_of::<u8>() + self.ndm_type.size()
    }
}

/// Struct representing ARP cache info
pub struct NdaCacheinfo {
    /// Confirmed
    pub ndm_confirmed: u32,
    /// Used
    pub ndm_used: u32,
    /// Updated 
    pub ndm_updated: u32,
    /// Reference count
    pub ndm_refcnt: u32,
}

impl Nl for NdaCacheinfo {
    fn serialize(&self, buf: &mut StreamWriteBuffer) -> Result<(), SerError> {
        self.ndm_confirmed.serialize(buf)?;
        self.ndm_used.serialize(buf)?;
        self.ndm_updated.serialize(buf)?;
        self.ndm_refcnt.serialize(buf)?;
        Ok(())
    }

    fn deserialize<B>(buf: &mut StreamReadBuffer<B>) -> Result<Self, DeError>
            where B: AsRef<[u8]> {
        Ok(NdaCacheinfo {
            ndm_confirmed: u32::deserialize(buf)?,
            ndm_used: u32::deserialize(buf)?,
            ndm_updated: u32::deserialize(buf)?,
            ndm_refcnt: u32::deserialize(buf)?,
        })
    }

    fn size(&self) -> usize {
        self.ndm_confirmed.size() + self.ndm_used.size() + self.ndm_updated.size() +
            self.ndm_refcnt.size()
    }
}

/// Struct representing route netlink attributes
pub struct Rtattr<T, P> {
    /// Length of the attribute
    pub rta_len: libc::c_ushort,
    /// Type of the attribute
    pub rta_type: T,
    /// Payload of the attribute
    pub rta_payload: P,
}

impl<T, P> Rtattr<T, P> where T: RtaType, P: Nl {
    /// Get the size of the payload only
    pub fn payload_size(&self) -> usize {
        self.rta_payload.size()
    }
}

impl<T, P> Nl for Rtattr<T, P> where T: RtaType, P: Nl {
    fn serialize(&self, buf: &mut StreamWriteBuffer) -> Result<(), SerError> {
        self.rta_len.serialize(buf)?;
        self.rta_type.serialize(buf)?;
        self.rta_payload.serialize(buf)?;
        Ok(())
    }

    fn deserialize<B>(buf: &mut StreamReadBuffer<B>) -> Result<Self, DeError> where B: AsRef<[u8]> {
        let rta_len = libc::c_ushort::deserialize(buf)?;
        let rta_type = T::deserialize(buf)?;
        buf.set_size_hint(rta_len as usize);
        let rta_payload = P::deserialize(buf)?;
        Ok(Rtattr {
            rta_len,
            rta_type, 
            rta_payload,
        })
    }

    fn size(&self) -> usize {
        self.rta_len.size() + self.rta_type.size() + self.rta_payload.size()
    }
}

/// Message in response to queuing discipline operations
pub struct Tcmsg {
    /// Family
    pub tcm_family: libc::c_uchar,
    /// Interface index
    pub tcm_ifindex: libc::c_int,
    /// Queuing discipline handle
    pub tcm_handle: u32,
    /// Parent queuing discipline
    pub tcm_parent: u32,
    /// Info
    pub tcm_info: u32,
}

impl Nl for Tcmsg {
    fn serialize(&self, buf: &mut StreamWriteBuffer) -> Result<(), SerError> {
        self.tcm_family.serialize(buf)?;
        self.tcm_ifindex.serialize(buf)?;
        self.tcm_handle.serialize(buf)?;
        self.tcm_parent.serialize(buf)?;
        self.tcm_info.serialize(buf)?;
        Ok(())
    }

    fn deserialize<B>(buf: &mut StreamReadBuffer<B>) -> Result<Self, DeError>
            where B: AsRef<[u8]> {
        Ok(Tcmsg {
            tcm_family: libc::c_uchar::deserialize(buf)?,
            tcm_ifindex: libc::c_int::deserialize(buf)?,
            tcm_handle: u32::deserialize(buf)?,
            tcm_parent: u32::deserialize(buf)?,
            tcm_info: u32::deserialize(buf)?,
        })
    }

    fn size(&self) -> usize {
        self.tcm_family.size() + self.tcm_ifindex.size() + self.tcm_handle.size() +
            self.tcm_parent.size() + self.tcm_info.size()
    }
}
