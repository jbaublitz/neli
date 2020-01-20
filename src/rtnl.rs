//! This module provides an implementation of routing netlink structures and the routing attributes
//! that are at the end of most routing netlink responses.
//!
//! # Design decisions
//!
//! This module is based very heavily on the information in `man 7 rtnetlink` so it is mainly a
//! series of structs organized in a style similar to the rest of the library with implementations
//! of `Nl` for each.

use bytes::{Bytes, BytesMut};
use smallvec::SmallVec;

use crate::{
    consts::{alignto, rtnl::*},
    err::{DeError, SerError},
    utils::packet_length,
    Buffer, Nl, RtBuffer,
};

/// Set of `Rtattr` structs
#[derive(Debug)]
pub struct Rtattrs<T, P>(RtBuffer<T, P>);

impl<T, P> Rtattrs<T, P>
where
    T: RtaType,
    P: Nl,
{
    /// Create an empty `Rtattrs` set
    pub fn empty() -> Self {
        Rtattrs(SmallVec::new())
    }

    /// Create an `Rtattrs` set initializing it with a vector
    pub fn new(attrs: RtBuffer<T, P>) -> Self {
        Rtattrs(attrs)
    }

    /// Return a reference iterator over underlying vector
    pub fn iter(&self) -> std::slice::Iter<Rtattr<T, P>> {
        self.0.iter()
    }
}

impl<T, P> IntoIterator for Rtattrs<T, P>
where
    T: RtaType,
    P: Nl,
{
    type Item = Rtattr<T, P>;
    type IntoIter = <RtBuffer<T, P> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<T> Rtattrs<T, Buffer>
where
    T: RtaType,
{
    /// Get an attribute contained in the set as type `R`
    pub fn get_attr_payload_as<R>(&self, attr_type: T) -> Result<Option<R>, DeError>
    where
        R: Nl,
    {
        let index = self
            .0
            .iter()
            .position(|rtattr| rtattr.rta_type == attr_type);
        let elem = match index {
            Some(i) => self.0.get(i),
            None => return Ok(None),
        };
        match elem {
            Some(ref e) => e.get_payload_as::<R>().map(Some),
            None => Ok(None),
        }
    }
}

impl<T, P> Nl for Rtattrs<T, P>
where
    T: RtaType,
    P: Nl,
{
    fn serialize(&self, mut mem: BytesMut) -> Result<BytesMut, SerError> {
        let mut pos = 0;
        for item in self.0.iter() {
            let (mem_tmp, pos_tmp) = drive_serialize!(item, mem, pos, asize);
            mem = mem_tmp;
            pos = pos_tmp;
        }
        Ok(drive_serialize!(END mem, pos))
    }

    fn deserialize(mem: Bytes) -> Result<Self, DeError> {
        let mut rtattrs = SmallVec::new();
        let mut pos = 0;
        while pos < mem.len() {
            let packet_len = packet_length(mem.as_ref(), pos);
            let (nlhdr, pos_tmp) = drive_deserialize!(
                Rtattr<T, P>, mem, pos, packet_len
            );
            pos = pos_tmp;
            rtattrs.push(nlhdr);
        }
        drive_deserialize!(END mem, pos);
        Ok(Rtattrs::new(rtattrs))
    }

    fn size(&self) -> usize {
        self.0.iter().fold(0, |acc, item| acc + item.asize())
    }

    fn type_size() -> Option<usize> {
        None
    }
}

/// Struct representing interface information messages
#[derive(Debug)]
pub struct Ifinfomsg {
    /// Interface address family
    pub ifi_family: RtAddrFamily,
    padding: u8,
    /// Interface type
    pub ifi_type: Arphrd,
    /// Interface index
    pub ifi_index: libc::c_int,
    /// Interface flags
    pub ifi_flags: IffFlags,
    /// Interface change mask
    pub ifi_change: Iff,
    /// Payload of `Rtattr`s
    pub rtattrs: Rtattrs<Ifla, Buffer>,
}

impl Ifinfomsg {
    /// Create a fully initialized interface info struct
    pub fn new(
        ifi_family: RtAddrFamily,
        ifi_type: Arphrd,
        ifi_index: libc::c_int,
        ifi_flags: IffFlags,
        ifi_change: Iff,
        rtattrs: Rtattrs<Ifla, Buffer>,
    ) -> Self {
        Ifinfomsg {
            ifi_family,
            padding: 0,
            ifi_type,
            ifi_index,
            ifi_flags,
            ifi_change,
            rtattrs,
        }
    }

    /// Set the link with the given index up (equivalent to `ip link set dev DEV up`)
    pub fn up(
        ifi_family: RtAddrFamily,
        ifi_type: Arphrd,
        ifi_index: libc::c_int,
        rtattrs: Rtattrs<Ifla, Buffer>,
    ) -> Self {
        Ifinfomsg {
            ifi_family,
            padding: 0,
            ifi_type,
            ifi_index,
            ifi_flags: IffFlags::new(&[Iff::Up]),
            ifi_change: Iff::Up,
            rtattrs,
        }
    }

    /// Set the link with the given index down (equivalent to `ip link set dev DEV down`)
    pub fn down(
        ifi_family: RtAddrFamily,
        ifi_type: Arphrd,
        ifi_index: libc::c_int,
        rtattrs: Rtattrs<Ifla, Buffer>,
    ) -> Self {
        Ifinfomsg {
            ifi_family,
            padding: 0,
            ifi_type,
            ifi_index,
            ifi_flags: IffFlags::empty(),
            ifi_change: Iff::Up,
            rtattrs,
        }
    }
}

impl Nl for Ifinfomsg {
    fn serialize(&self, mem: BytesMut) -> Result<BytesMut, SerError> {
        Ok(serialize! {
            mem;
            self.ifi_family;
            self.padding;
            self.ifi_type;
            self.ifi_change;
            self.ifi_index;
            self.ifi_flags;
            self.ifi_change;
            self.rtattrs, asize
        })
    }

    fn deserialize(mem: Bytes) -> Result<Self, DeError> {
        Ok(deserialize! {
            mem;
            Ifinfomsg {
                ifi_family: RtAddrFamily,
                padding: u8,
                ifi_type: Arphrd,
                ifi_index: libc::c_int,
                ifi_flags: IffFlags,
                ifi_change: Iff,
                rtattrs: Rtattrs<Ifla, Buffer> => mem.len().checked_sub(
                    ifi_family.size()
                    + padding.size()
                    + ifi_type.size()
                    + ifi_index.size()
                    + ifi_flags.size()
                    + ifi_change.size()
                )
                .ok_or_else(|| DeError::UnexpectedEOB)?
            }
        })
    }

    fn size(&self) -> usize {
        self.ifi_family.size()
            + self.padding.size()
            + self.ifi_type.size()
            + self.ifi_index.size()
            + self.ifi_flags.size()
            + self.ifi_change.size()
            + self.rtattrs.size()
    }

    fn type_size() -> Option<usize> {
        None
    }
}

/// Struct representing interface address messages
#[derive(Debug)]
pub struct Ifaddrmsg {
    /// Interface address family
    pub ifa_family: RtAddrFamily,
    /// Interface address prefix length
    pub ifa_prefixlen: libc::c_uchar,
    /// Interface address flags
    pub ifa_flags: IfaFFlags,
    /// Interface address scope
    pub ifa_scope: libc::c_uchar,
    /// Interface address index
    pub ifa_index: libc::c_int,
    /// Payload of `Rtattr`s
    pub rtattrs: Rtattrs<Ifa, Buffer>,
}

impl Nl for Ifaddrmsg {
    fn serialize(&self, mem: BytesMut) -> Result<BytesMut, SerError> {
        Ok(serialize! {
            mem;
            self.ifa_family;
            self.ifa_prefixlen;
            self.ifa_flags;
            self.ifa_scope;
            self.ifa_index;
            self.rtattrs, asize
        })
    }

    fn deserialize(mem: Bytes) -> Result<Self, DeError> {
        Ok(deserialize! {
            mem;
            Ifaddrmsg {
                ifa_family: RtAddrFamily,
                ifa_prefixlen: libc::c_uchar,
                ifa_flags: IfaFFlags,
                ifa_scope: libc::c_uchar,
                ifa_index: libc::c_int,
                rtattrs: Rtattrs<Ifa, Buffer> => mem.len().checked_sub(
                    ifa_family.size()
                    + ifa_prefixlen.size()
                    + ifa_flags.size()
                    + ifa_scope.size()
                    + ifa_index.size()
                )
                .ok_or_else(|| DeError::UnexpectedEOB)?
            }
        })
    }

    fn size(&self) -> usize {
        self.ifa_family.size()
            + self.ifa_prefixlen.size()
            + self.ifa_flags.size()
            + self.ifa_scope.size()
            + self.ifa_index.size()
            + self.rtattrs.size()
    }

    fn type_size() -> Option<usize> {
        None
    }
}

/// General form of address family dependent message.  Used for requesting things from via rtnetlink.
#[derive(Debug)]
pub struct Rtgenmsg {
    /// Address family for the request
    pub rtgen_family: RtAddrFamily,
}

impl Nl for Rtgenmsg {
    fn serialize(&self, mem: BytesMut) -> Result<BytesMut, SerError> {
        self.rtgen_family.serialize(mem)
    }

    fn deserialize(mem: Bytes) -> Result<Self, DeError> {
        Ok(Self {
            rtgen_family: RtAddrFamily::deserialize(mem)?,
        })
    }

    fn size(&self) -> usize {
        self.rtgen_family.size()
    }

    fn type_size() -> Option<usize> {
        RtAddrFamily::type_size()
    }
}

/// Route message
#[derive(Debug)]
pub struct Rtmsg {
    /// Address family of route
    pub rtm_family: RtAddrFamily,
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
    pub rtm_flags: RtmFFlags,
    /// Payload of `Rtattr`s
    pub rtattrs: Rtattrs<Rta, Buffer>,
}

impl Nl for Rtmsg {
    fn serialize(&self, mem: BytesMut) -> Result<BytesMut, SerError> {
        Ok(serialize! {
            mem;
            self.rtm_family;
            self.rtm_dst_len;
            self.rtm_src_len;
            self.rtm_tos;
            self.rtm_table;
            self.rtm_protocol;
            self.rtm_scope;
            self.rtm_type;
            self.rtm_flags;
            self.rtattrs, asize
        })
    }

    fn deserialize(mem: Bytes) -> Result<Self, DeError> {
        Ok(deserialize! {
            mem;
            Rtmsg {
                rtm_family: RtAddrFamily,
                rtm_dst_len: libc::c_uchar,
                rtm_src_len: libc::c_uchar,
                rtm_tos: libc::c_uchar,
                rtm_table: RtTable,
                rtm_protocol: Rtprot,
                rtm_scope: RtScope,
                rtm_type: Rtn,
                rtm_flags: RtmFFlags,
                rtattrs: Rtattrs<Rta, Buffer> => mem.len().checked_sub(
                    rtm_family.size()
                    + rtm_dst_len.size()
                    + rtm_src_len.size()
                    + rtm_tos.size()
                    + rtm_table.size()
                    + rtm_protocol.size()
                    + rtm_scope.size()
                    + rtm_type.size()
                    + rtm_flags.size()
                )
                .ok_or_else(|| DeError::UnexpectedEOB)?
            }
        })
    }

    fn size(&self) -> usize {
        self.rtm_family.size()
            + self.rtm_dst_len.size()
            + self.rtm_src_len.size()
            + self.rtm_tos.size()
            + self.rtm_table.size()
            + self.rtm_protocol.size()
            + self.rtm_scope.size()
            + self.rtm_type.size()
            + self.rtm_flags.size()
            + self.rtattrs.size()
    }

    fn type_size() -> Option<usize> {
        None
    }
}

/// Represents an ARP (neighbor table) entry
#[derive(Debug)]
pub struct Ndmsg {
    /// Address family of entry
    pub ndm_family: RtAddrFamily,
    pad1: u8,
    pad2: u16,
    /// Index of entry
    pub ndm_index: libc::c_int,
    /// State of entry
    pub ndm_state: NudFlags,
    /// Flags for entry
    pub ndm_flags: NtfFlags,
    /// Type of entry
    pub ndm_type: Rtn,
    /// Payload of `Rtattr`s
    pub rtattrs: Rtattrs<Nda, Buffer>,
}

impl Nl for Ndmsg {
    fn serialize(&self, mem: BytesMut) -> Result<BytesMut, SerError> {
        Ok(serialize! {
            mem;
            self.ndm_family;
            self.pad1;
            self.pad2;
            self.ndm_index;
            self.ndm_state;
            self.ndm_flags;
            self.ndm_type;
            self.rtattrs, asize
        })
    }

    fn deserialize(mem: Bytes) -> Result<Self, DeError> {
        Ok(deserialize! {
            mem;
            Ndmsg {
                ndm_family: RtAddrFamily,
                pad1: u8,
                pad2: u16,
                ndm_index: libc::c_int,
                ndm_state: NudFlags,
                ndm_flags: NtfFlags,
                ndm_type: Rtn,
                rtattrs: Rtattrs<Nda, Buffer> => mem.len().checked_sub(
                    ndm_family.size()
                    + pad1.size()
                    + pad2.size()
                    + ndm_index.size()
                    + ndm_state.size()
                    + ndm_flags.size()
                    + ndm_type.size()
                )
                .ok_or_else(|| DeError::UnexpectedEOB)?
            }
        })
    }

    fn size(&self) -> usize {
        self.ndm_family.size()
            + self.pad1.size()
            + self.pad2.size()
            + self.ndm_index.size()
            + self.ndm_state.size()
            + self.ndm_flags.size()
            + self.ndm_type.size()
            + self.rtattrs.asize()
    }

    fn type_size() -> Option<usize> {
        None
    }
}

/// Struct representing ARP cache info
#[derive(Debug)]
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
    fn serialize(&self, mem: BytesMut) -> Result<BytesMut, SerError> {
        Ok(serialize! {
            mem;
            self.ndm_confirmed;
            self.ndm_used;
            self.ndm_updated;
            self.ndm_refcnt
        })
    }

    fn deserialize(mem: Bytes) -> Result<Self, DeError> {
        Ok(deserialize! {
            mem;
            NdaCacheinfo {
                ndm_confirmed: u32,
                ndm_used: u32,
                ndm_updated: u32,
                ndm_refcnt: u32
            }
        })
    }

    fn size(&self) -> usize {
        self.ndm_confirmed.size()
            + self.ndm_used.size()
            + self.ndm_updated.size()
            + self.ndm_refcnt.size()
    }

    fn type_size() -> Option<usize> {
        u32::type_size().map(|s| s * 4)
    }
}

/// Message in response to queuing discipline operations
#[derive(Debug)]
pub struct Tcmsg {
    /// Family
    pub tcm_family: libc::c_uchar,
    padding1: libc::c_uchar,
    padding2: libc::c_ushort,
    /// Interface index
    pub tcm_ifindex: libc::c_int,
    /// Queuing discipline handle
    pub tcm_handle: u32,
    /// Parent queuing discipline
    pub tcm_parent: u32,
    /// Info
    pub tcm_info: u32,
    /// Payload of `Rtattr`s
    pub rtattrs: Rtattrs<Tca, Buffer>,
}

impl Nl for Tcmsg {
    fn serialize(&self, mem: BytesMut) -> Result<BytesMut, SerError> {
        Ok(serialize! {
            mem;
            self.tcm_family;
            self.padding1;
            self.padding2;
            self.tcm_ifindex;
            self.tcm_handle;
            self.tcm_parent;
            self.tcm_info;
            self.rtattrs, asize
        })
    }

    fn deserialize(mem: Bytes) -> Result<Self, DeError> {
        Ok(deserialize! {
            mem;
            Tcmsg {
                tcm_family: libc::c_uchar,
                padding1: libc::c_uchar,
                padding2: libc::c_ushort,
                tcm_ifindex: libc::c_int,
                tcm_handle: u32,
                tcm_parent: u32,
                tcm_info: u32,
                rtattrs: Rtattrs<Tca, Buffer> => mem.len().checked_sub(
                    tcm_family.size()
                    + tcm_ifindex.size()
                    + tcm_handle.size()
                    + tcm_parent.size()
                    + tcm_info.size()
                )
                .ok_or_else(|| DeError::UnexpectedEOB)?
            }

        })
    }

    fn size(&self) -> usize {
        self.tcm_family.size()
            + self.padding1.size()
            + self.padding2.size()
            + self.tcm_ifindex.size()
            + self.tcm_handle.size()
            + self.tcm_parent.size()
            + self.tcm_info.size()
    }

    fn type_size() -> Option<usize> {
        None
    }
}

/// Struct representing route netlink attributes
#[derive(Debug)]
pub struct Rtattr<T, P> {
    /// Length of the attribute
    pub rta_len: libc::c_ushort,
    /// Type of the attribute
    pub rta_type: T,
    /// Payload of the attribute
    pub rta_payload: P,
}

impl<T, P> Rtattr<T, P>
where
    T: RtaType,
    P: Nl,
{
    /// Get the size of the payload only
    pub fn payload_size(&self) -> usize {
        self.rta_payload.size()
    }
}

impl<T> Rtattr<T, Buffer>
where
    T: RtaType,
{
    /// Get payload as type implementing `Nl`
    pub fn get_payload_as<R>(&self) -> Result<R, DeError>
    where
        R: Nl,
    {
        R::deserialize(Bytes::from(self.rta_payload.as_ref()))
    }
}

impl<T, P> Nl for Rtattr<T, P>
where
    T: RtaType,
    P: Nl,
{
    fn serialize(&self, mem: BytesMut) -> Result<BytesMut, SerError> {
        Ok(serialize! {
            PAD self;
            mem;
            self.rta_len;
            self.rta_type;
            self.rta_payload
        })
    }

    fn deserialize(mem: Bytes) -> Result<Self, DeError> {
        Ok(deserialize! {
            STRIP Self;
            mem;
            Rtattr<T, P> {
                rta_len: libc::c_ushort,
                rta_type: T,
                rta_payload: P => (rta_len as usize).checked_sub(
                    rta_len.size() + rta_type.size()
                )
                .ok_or_else(|| DeError::UnexpectedEOB)?
            } => alignto(rta_len as usize) - rta_len as usize
        })
    }

    fn size(&self) -> usize {
        self.rta_len.size() + self.rta_type.size() + self.rta_payload.size()
    }

    fn type_size() -> Option<usize> {
        None
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::consts::Rta;

    #[test]
    fn test_rta_deserialize() {
        let buf = Bytes::from(&[4u8, 0, 0, 0] as &[u8]);
        assert!(Rtattr::<Rta, Buffer>::deserialize(buf).is_ok());
    }

    #[test]
    fn test_rta_deserialize_err() {
        // 3 bytes is below minimum length
        let buf = Bytes::from(&[3u8, 0, 0, 0] as &[u8]);
        assert!(Rtattr::<Rta, Buffer>::deserialize(buf).is_err());
    }

    #[test]
    fn test_rtattr_padding() {
        let attr = Rtattr {
            rta_len: 5,
            rta_type: Rta::Unspec,
            rta_payload: vec![0u8],
        };
        let buf = BytesMut::from(vec![0; attr.asize()]);

        let buf_res = attr.serialize(buf);
        assert!(buf_res.is_ok());
        // padding check
        assert_eq!(buf_res.unwrap().as_ref().len(), 8);
    }
}
