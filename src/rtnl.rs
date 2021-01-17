//! This module provides an implementation of routing netlink
//! structures and the routing attributes that are at the end of
//! most routing netlink responses.
//!
//! # Design decisions
//!
//! This module is based very heavily on the information in
//! `man 7 rtnetlink` so it is mainly a series of structs organized
//! in a style similar to the rest of the library with implementations
//! of [`Nl`] for each.

use std::convert::TryFrom;
use std::mem;

use crate::{
    attr::{AttrHandle, AttrHandleMut, Attribute},
    consts::{alignto, rtnl::*},
    err::{DeError, NlError, SerError},
    parse::packet_length_u16,
    types::{Buffer, DeBuffer, RtBuffer, SerBuffer},
    utils::serialize,
    Nl,
};

impl<T, P> Nl for RtBuffer<T, P>
where
    T: RtaType,
    P: Nl,
{
    fn serialize(&self, mem: SerBuffer) -> Result<(), SerError> {
        let mut pos = 0;
        for item in self.iter() {
            pos = drive_serialize!(item, mem, pos, asize);
        }
        drive_serialize!(END mem, pos);
        Ok(())
    }

    fn deserialize(mem: DeBuffer) -> Result<Self, DeError> {
        let mut rtattrs = RtBuffer::new();
        let mut pos = 0;
        while pos < mem.len() {
            let packet_len = packet_length_u16(mem, pos);
            let (nlhdr, pos_tmp) = drive_deserialize!(
                Rtattr<T, P>, mem, pos, alignto(packet_len)
            );
            rtattrs.push(nlhdr);
            pos = pos_tmp;
        }
        drive_deserialize!(END mem, pos);
        Ok(rtattrs)
    }

    fn size(&self) -> usize {
        self.iter().fold(0, |acc, item| acc + item.asize())
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
    /// Payload of [`Rtattr`]s
    pub rtattrs: RtBuffer<Ifla, Buffer>,
}

impl Ifinfomsg {
    /// Create a fully initialized interface info struct
    pub fn new(
        ifi_family: RtAddrFamily,
        ifi_type: Arphrd,
        ifi_index: libc::c_int,
        ifi_flags: IffFlags,
        ifi_change: Iff,
        rtattrs: RtBuffer<Ifla, Buffer>,
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

    /// Set the link with the given index up (equivalent to
    /// `ip link set dev DEV up`)
    pub fn up(
        ifi_family: RtAddrFamily,
        ifi_type: Arphrd,
        ifi_index: libc::c_int,
        rtattrs: RtBuffer<Ifla, Buffer>,
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

    /// Set the link with the given index down (equivalent to
    /// `ip link set dev DEV down`)
    pub fn down(
        ifi_family: RtAddrFamily,
        ifi_type: Arphrd,
        ifi_index: libc::c_int,
        rtattrs: RtBuffer<Ifla, Buffer>,
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
    fn serialize(&self, mem: SerBuffer) -> Result<(), SerError> {
        serialize! {
            mem;
            self.ifi_family;
            self.padding;
            self.ifi_type;
            self.ifi_index;
            self.ifi_flags;
            self.ifi_change;
            self.rtattrs, asize
        };
        Ok(())
    }

    fn deserialize(mem: DeBuffer) -> Result<Self, DeError> {
        Ok(deserialize! {
            mem;
            Ifinfomsg {
                ifi_family: RtAddrFamily,
                padding: u8,
                ifi_type: Arphrd,
                ifi_index: libc::c_int,
                ifi_flags: IffFlags,
                ifi_change: Iff,
                rtattrs: RtBuffer<Ifla, Buffer> => mem.len().checked_sub(
                    ifi_family.size()
                    + padding.size()
                    + ifi_type.size()
                    + ifi_index.size()
                    + ifi_flags.size()
                    + ifi_change.size()
                )
                .ok_or(DeError::UnexpectedEOB)?
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
    /// Payload of [`Rtattr`]s
    pub rtattrs: RtBuffer<Ifa, Buffer>,
}

impl Nl for Ifaddrmsg {
    fn serialize(&self, mem: SerBuffer) -> Result<(), SerError> {
        let flags =
            libc::c_uchar::try_from(&self.ifa_flags).map_err(|e| SerError::Msg(e.to_string()))?;
        serialize! {
            mem;
            self.ifa_family;
            self.ifa_prefixlen;
            flags;
            self.ifa_scope;
            self.ifa_index;
            self.rtattrs, asize
        };
        Ok(())
    }

    fn deserialize(mem: DeBuffer) -> Result<Self, DeError> {
        // Manual serialization to handle ifa_flags field
        let pos = 0;
        let (ifa_family, pos) = drive_deserialize!(RtAddrFamily, mem, pos);
        let (ifa_prefixlen, pos) = drive_deserialize!(libc::c_uchar, mem, pos);
        let (flags, pos) = drive_deserialize!(libc::c_uchar, mem, pos);
        let (ifa_scope, pos) = drive_deserialize!(libc::c_uchar, mem, pos);
        let (ifa_index, pos) = drive_deserialize!(libc::c_int, mem, pos);
        let rtattrs_size = mem
            .len()
            .checked_sub(
                ifa_family.size() + ifa_prefixlen.size() + 1 + ifa_scope.size() + ifa_index.size(),
            )
            .ok_or(DeError::UnexpectedEOB)?;
        let (rtattrs, pos) = drive_deserialize!(RtBuffer<Ifa, Buffer>, mem, pos, rtattrs_size);
        drive_deserialize!(END mem, pos);
        Ok(Ifaddrmsg {
            ifa_family,
            ifa_prefixlen,
            ifa_flags: IfaFFlags::from(flags),
            ifa_scope,
            ifa_index,
            rtattrs,
        })
    }

    fn size(&self) -> usize {
        self.ifa_family.size()
            + self.ifa_prefixlen.size()
            + 1
            + self.ifa_scope.size()
            + self.ifa_index.size()
            + self.rtattrs.size()
    }

    fn type_size() -> Option<usize> {
        None
    }
}

/// General form of address family dependent message.  Used for
/// requesting things from rtnetlink.
#[derive(Debug)]
pub struct Rtgenmsg {
    /// Address family for the request
    pub rtgen_family: RtAddrFamily,
}

impl Nl for Rtgenmsg {
    fn serialize(&self, mem: SerBuffer) -> Result<(), SerError> {
        self.rtgen_family.serialize(mem)
    }

    fn deserialize(mem: DeBuffer) -> Result<Self, DeError> {
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
    /// Payload of [`Rtattr`]s
    pub rtattrs: RtBuffer<Rta, Buffer>,
}

impl Nl for Rtmsg {
    fn serialize(&self, mem: SerBuffer) -> Result<(), SerError> {
        serialize! {
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
        };
        Ok(())
    }

    fn deserialize(mem: DeBuffer) -> Result<Self, DeError> {
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
                rtattrs: RtBuffer<Rta, Buffer> => mem.len().checked_sub(
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
                .ok_or(DeError::UnexpectedEOB)?
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
    /// Payload of [`Rtattr`]s
    pub rtattrs: RtBuffer<Nda, Buffer>,
}

impl Nl for Ndmsg {
    fn serialize(&self, mem: SerBuffer) -> Result<(), SerError> {
        serialize! {
            mem;
            self.ndm_family;
            self.pad1;
            self.pad2;
            self.ndm_index;
            self.ndm_state;
            self.ndm_flags;
            self.ndm_type;
            self.rtattrs, asize
        };
        Ok(())
    }

    fn deserialize(mem: DeBuffer) -> Result<Self, DeError> {
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
                rtattrs: RtBuffer<Nda, Buffer> => mem.len().checked_sub(
                    ndm_family.size()
                    + pad1.size()
                    + pad2.size()
                    + ndm_index.size()
                    + ndm_state.size()
                    + ndm_flags.size()
                    + ndm_type.size()
                )
                .ok_or(DeError::UnexpectedEOB)?
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
    fn serialize(&self, mem: SerBuffer) -> Result<(), SerError> {
        serialize! {
            mem;
            self.ndm_confirmed;
            self.ndm_used;
            self.ndm_updated;
            self.ndm_refcnt
        };
        Ok(())
    }

    fn deserialize(mem: DeBuffer) -> Result<Self, DeError> {
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
    padding_char: libc::c_uchar,
    padding_short: libc::c_ushort,
    /// Interface index
    pub tcm_ifindex: libc::c_int,
    /// Queuing discipline handle
    pub tcm_handle: u32,
    /// Parent queuing discipline
    pub tcm_parent: u32,
    /// Info
    pub tcm_info: u32,
    /// Payload of [`Rtattr`]s
    pub rtattrs: RtBuffer<Tca, Buffer>,
}

impl Nl for Tcmsg {
    fn serialize(&self, mem: SerBuffer) -> Result<(), SerError> {
        serialize! {
            mem;
            self.tcm_family;
            self.padding_char;
            self.padding_short;
            self.tcm_ifindex;
            self.tcm_handle;
            self.tcm_parent;
            self.tcm_info;
            self.rtattrs, asize
        };
        Ok(())
    }

    fn deserialize(mem: DeBuffer) -> Result<Self, DeError> {
        Ok(deserialize! {
            mem;
            Tcmsg {
                tcm_family: libc::c_uchar,
                padding_char: libc::c_uchar,
                padding_short: libc::c_ushort,
                tcm_ifindex: libc::c_int,
                tcm_handle: u32,
                tcm_parent: u32,
                tcm_info: u32,
                rtattrs: RtBuffer<Tca, Buffer> => mem.len().checked_sub(
                    tcm_family.size()
                    + tcm_ifindex.size()
                    + tcm_handle.size()
                    + tcm_parent.size()
                    + tcm_info.size()
                )
                .ok_or(DeError::UnexpectedEOB)?
            }

        })
    }

    fn size(&self) -> usize {
        self.tcm_family.size()
            + mem::size_of::<libc::c_uchar>()
            + mem::size_of::<libc::c_ushort>()
            + self.tcm_ifindex.size()
            + self.padding_char.size()
            + self.padding_short.size()
            + self.tcm_handle.size()
            + self.tcm_parent.size()
            + self.tcm_info.size()
            + self.rtattrs.size()
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

impl<T> Rtattr<T, Buffer>
where
    T: RtaType,
{
    /// Create a new [`Rtattr`].
    pub fn new<P>(rta_len: Option<u16>, rta_type: T, rta_payload: P) -> Result<Self, NlError>
    where
        P: Nl,
    {
        let mut attr = Rtattr {
            rta_len: rta_len.unwrap_or(0),
            rta_type,
            rta_payload: Buffer::new(),
        };
        attr.set_payload(&rta_payload).map_err(|e| {
            NlError::new(format!("Failed to convert payload to a byte buffer: {}", e))
        })?;
        Ok(attr)
    }

    /// Add a nested attribute to the end of the payload.
    pub fn add_nested_attribute<TT, P>(&mut self, attr: &Rtattr<TT, P>) -> Result<(), NlError>
    where
        TT: RtaType,
        P: Nl,
    {
        let ser_buffer = serialize(attr, true)?;

        self.rta_payload.extend_from_slice(ser_buffer.as_ref());
        self.rta_len += attr.asize() as u16;
        Ok(())
    }

    /// Return an [`AttrHandle`][crate::attr::AttrHandle] for
    /// attributes nested in the given attribute payload.
    pub fn get_attr_handle<R>(&self) -> Result<RtAttrHandle<R>, NlError>
    where
        R: RtaType,
    {
        Ok(AttrHandle::new(
            RtBuffer::deserialize(self.rta_payload.as_ref()).map_err(NlError::new)?,
        ))
    }

    /// Return an [`AttrHandleMut`][crate::attr::AttrHandleMut] for
    /// attributes nested in the given attribute payload.
    pub fn get_attr_handle_mut<R>(&mut self) -> Result<RtAttrHandleMut<R>, NlError>
    where
        R: RtaType,
    {
        Ok(AttrHandleMut::new(
            RtBuffer::deserialize(self.rta_payload.as_ref()).map_err(NlError::new)?,
        ))
    }
}

impl<T> Attribute<T> for Rtattr<T, Buffer>
where
    T: RtaType,
{
    fn payload(&self) -> &Buffer {
        &self.rta_payload
    }

    fn set_payload<P>(&mut self, payload: &P) -> Result<(), NlError>
    where
        P: Nl,
    {
        let ser_buffer = serialize(payload, false)?;
        self.rta_payload = Buffer::from(ser_buffer);

        // Update `Nlattr` with new length
        self.rta_len = (self.rta_len.size() + self.rta_type.size() + payload.size()) as u16;

        Ok(())
    }
}

impl<T, P> Nl for Rtattr<T, P>
where
    T: RtaType,
    P: Nl,
{
    fn serialize(&self, mem: SerBuffer) -> Result<(), SerError> {
        serialize! {
            PAD self;
            mem;
            self.rta_len;
            self.rta_type;
            self.rta_payload
        };
        Ok(())
    }

    fn deserialize(mem: DeBuffer) -> Result<Self, DeError> {
        Ok(deserialize! {
            STRIP Self;
            mem;
            Rtattr<T, P> {
                rta_len: libc::c_ushort,
                rta_type: T,
                rta_payload: P => (rta_len as usize).checked_sub(
                    rta_len.size() + rta_type.size()
                )
                .ok_or(DeError::UnexpectedEOB)?
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

type RtAttrHandle<'a, T> = AttrHandle<'a, RtBuffer<T, Buffer>, Rtattr<T, Buffer>>;
type RtAttrHandleMut<'a, T> = AttrHandleMut<'a, RtBuffer<T, Buffer>, Rtattr<T, Buffer>>;

impl<'a, T> AttrHandle<'a, RtBuffer<T, Buffer>, Rtattr<T, Buffer>>
where
    T: RtaType,
{
    /// Get the payload of an attribute as a handle for parsing
    /// nested attributes.
    pub fn get_nested_attributes<S>(&mut self, subattr: T) -> Result<RtAttrHandle<S>, NlError>
    where
        S: RtaType,
    {
        Ok(AttrHandle::new(
            RtBuffer::deserialize(
                self.get_attribute(subattr)
                    .ok_or_else(|| NlError::new("Couldn't find specified attribute"))?
                    .rta_payload
                    .as_ref(),
            )
            .map_err(NlError::new)?,
        ))
    }

    /// Get nested attributes from a parsed handle.
    pub fn get_attribute(&self, t: T) -> Option<&Rtattr<T, Buffer>> {
        for item in self.get_attrs().iter() {
            if item.rta_type == t {
                return Some(&item);
            }
        }
        None
    }

    /// Parse binary payload as a type that implements [`Nl`] using
    /// [`deserialize`][Nl::deserialize].
    pub fn get_attr_payload_as<R>(&self, attr: T) -> Result<R, NlError>
    where
        R: Nl,
    {
        match self.get_attribute(attr) {
            Some(a) => a.get_payload_as::<R>(),
            _ => Err(NlError::new("Failed to find specified attribute")),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{consts::rtnl::Rta, utils::serialize};

    #[test]
    fn test_rta_deserialize() {
        let buf = &[4u8, 0, 0, 0] as &[u8];
        assert!(Rtattr::<Rta, Buffer>::deserialize(buf).is_ok());
    }

    #[test]
    fn test_rta_deserialize_err() {
        // 3 bytes is below minimum length
        let buf = &[3u8, 0, 0, 0] as &[u8];
        assert!(Rtattr::<Rta, Buffer>::deserialize(buf).is_err());
    }

    #[test]
    fn test_rtattr_padding() {
        let attr = Rtattr {
            rta_len: 5,
            rta_type: Rta::Unspec,
            rta_payload: vec![0u8],
        };
        let buf_res = serialize(&attr, true);

        assert!(buf_res.is_ok());
        // padding check
        assert_eq!(buf_res.unwrap().as_slice().len(), 8);
    }
}
