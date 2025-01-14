//! This module provides an implementation of routing netlink
//! structures and the routing attributes that are at the end of
//! most routing netlink responses.
//!
//! # Design decisions
//!
//! This module is based very heavily on the information in
//! `man 7 rtnetlink` so it is mainly a series of structs organized
//! in a style similar to the rest of the library.

use crate as neli;

use std::io::Cursor;

use crate::{
    attr::{AttrHandle, AttrHandleMut, Attribute},
    consts::rtnl::*,
    err::{DeError, SerError},
    types::{Buffer, RtBuffer},
    FromBytes, FromBytesWithInput, Header, Size, ToBytes,
};

/// Struct representing interface information messages
#[derive(Debug, Size, ToBytes, FromBytesWithInput, Header)]
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
    pub ifi_change: IffFlags,
    /// Payload of [`Rtattr`]s
    #[neli(input = "input.checked_sub(Self::header_size()).ok_or(DeError::UnexpectedEOB)?")]
    pub rtattrs: RtBuffer<Ifla, Buffer>,
}

impl Ifinfomsg {
    /// Create a fully initialized interface info struct
    pub fn new(
        ifi_family: RtAddrFamily,
        ifi_type: Arphrd,
        ifi_index: libc::c_int,
        ifi_flags: IffFlags,
        ifi_change: IffFlags,
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
            ifi_change: IffFlags::new(&[Iff::Up]),
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
            ifi_change: IffFlags::new(&[Iff::Up]),
            rtattrs,
        }
    }
}

/// Struct representing interface address messages
#[derive(Debug, Size, ToBytes, FromBytesWithInput, Header)]
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
    #[neli(input = "input.checked_sub(Self::header_size()).ok_or(DeError::UnexpectedEOB)?")]
    pub rtattrs: RtBuffer<Ifa, Buffer>,
}

/// General form of address family dependent message.  Used for
/// requesting things from rtnetlink.
#[derive(Debug, Size, ToBytes, FromBytes)]
pub struct Rtgenmsg {
    /// Address family for the request
    pub rtgen_family: RtAddrFamily,
}

/// Route message
#[derive(Debug, Size, ToBytes, FromBytesWithInput, Header)]
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
    #[neli(input = "input.checked_sub(Self::header_size()).ok_or(DeError::UnexpectedEOB)?")]
    pub rtattrs: RtBuffer<Rta, Buffer>,
}

/// Represents an ARP (neighbor table) entry
#[derive(Debug, Size, ToBytes, FromBytesWithInput, Header)]
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
    #[neli(input = "input.checked_sub(Self::header_size()).ok_or(DeError::UnexpectedEOB)?")]
    pub rtattrs: RtBuffer<Nda, Buffer>,
}

impl Ndmsg {
    /// Create a fully initialized neighbor table struct
    pub fn new(
        ndm_family: RtAddrFamily,
        ndm_index: libc::c_int,
        ndm_state: NudFlags,
        ndm_flags: NtfFlags,
        ndm_type: Rtn,
        rtattrs: RtBuffer<Nda, Buffer>,
    ) -> Self {
        Ndmsg {
            ndm_family,
            pad1: 0,
            pad2: 0,
            ndm_index,
            ndm_state,
            ndm_flags,
            ndm_type,
            rtattrs,
        }
    }
}

/// Struct representing ARP cache info
#[derive(Debug, Size, ToBytes, FromBytes)]
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

/// Message in response to queuing discipline operations
#[derive(Debug, Size, ToBytes, FromBytesWithInput, Header)]
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
    #[neli(input = "input.checked_sub(Self::header_size()).ok_or(DeError::UnexpectedEOB)?")]
    pub rtattrs: RtBuffer<Tca, Buffer>,
}

impl Tcmsg {
    /// Create a new [`Tcmsg`] structure handling the necessary
    /// padding.
    pub fn new(
        tcm_family: libc::c_uchar,
        tcm_ifindex: libc::c_int,
        tcm_handle: u32,
        tcm_parent: u32,
        tcm_info: u32,
        rtattrs: RtBuffer<Tca, Buffer>,
    ) -> Self {
        Tcmsg {
            tcm_family,
            padding_char: 0,
            padding_short: 0,
            tcm_ifindex,
            tcm_handle,
            tcm_parent,
            tcm_info,
            rtattrs,
        }
    }
}

/// Struct representing route netlink attributes
#[derive(Debug, Size, ToBytes, FromBytes, Header)]
#[neli(header_bound = "T: RtaType")]
#[neli(from_bytes_bound = "T: RtaType")]
#[neli(from_bytes_bound = "P: FromBytesWithInput<Input = usize>")]
#[neli(padding)]
pub struct Rtattr<T, P> {
    /// Length of the attribute
    pub rta_len: libc::c_ushort,
    /// Type of the attribute
    pub rta_type: T,
    /// Payload of the attribute
    #[neli(
        input = "(rta_len as usize).checked_sub(Self::header_size()).ok_or(DeError::UnexpectedEOB)?"
    )]
    pub rta_payload: P,
}

impl<T> Rtattr<T, Buffer>
where
    T: RtaType,
{
    /// Create a new [`Rtattr`].
    pub fn new<P>(_: Option<u16>, rta_type: T, rta_payload: P) -> Result<Self, SerError>
    where
        P: Size + ToBytes,
    {
        let mut attr = Rtattr {
            rta_len: Self::header_size() as u16,
            rta_type,
            rta_payload: Buffer::new(),
        };
        attr.set_payload(&rta_payload)?;
        Ok(attr)
    }

    /// Add a nested attribute to the end of the payload.
    pub fn add_nested_attribute<TT, P>(&mut self, attr: &Rtattr<TT, P>) -> Result<(), SerError>
    where
        TT: RtaType,
        P: ToBytes,
    {
        let mut buffer = Cursor::new(Vec::new());
        attr.to_bytes(&mut buffer)?;

        self.rta_payload.extend_from_slice(buffer.get_ref());
        self.rta_len += buffer.get_ref().len() as u16;
        Ok(())
    }

    /// Return an [`AttrHandle`] for
    /// attributes nested in the given attribute payload.
    pub fn get_attr_handle<R>(&self) -> Result<RtAttrHandle<R>, DeError>
    where
        R: RtaType,
    {
        Ok(AttrHandle::new(RtBuffer::from_bytes_with_input(
            &mut Cursor::new(self.rta_payload.as_ref()),
            self.rta_payload.len(),
        )?))
    }

    /// Return an [`AttrHandleMut`] for
    /// attributes nested in the given attribute payload.
    pub fn get_attr_handle_mut<R>(&mut self) -> Result<RtAttrHandleMut<R>, DeError>
    where
        R: RtaType,
    {
        Ok(AttrHandleMut::new(RtBuffer::from_bytes_with_input(
            &mut Cursor::new(self.rta_payload.as_ref()),
            self.rta_payload.len(),
        )?))
    }
}

impl<T> Attribute<T> for Rtattr<T, Buffer>
where
    T: RtaType,
{
    fn payload(&self) -> &Buffer {
        &self.rta_payload
    }

    fn set_payload<P>(&mut self, payload: &P) -> Result<(), SerError>
    where
        P: Size + ToBytes,
    {
        let mut buffer = Cursor::new(Vec::new());
        payload.to_bytes(&mut buffer)?;

        // Update `Nlattr` with new length
        self.rta_len -= self.rta_payload.unpadded_size() as u16;
        self.rta_len += buffer.get_ref().len() as u16;

        self.rta_payload = Buffer::from(buffer.into_inner());

        Ok(())
    }
}

type RtAttrHandle<'a, T> = AttrHandle<'a, RtBuffer<T, Buffer>, Rtattr<T, Buffer>>;
type RtAttrHandleMut<'a, T> = AttrHandleMut<'a, RtBuffer<T, Buffer>, Rtattr<T, Buffer>>;

impl<T> AttrHandle<'_, RtBuffer<T, Buffer>, Rtattr<T, Buffer>>
where
    T: RtaType,
{
    /// Get the payload of an attribute as a handle for parsing
    /// nested attributes.
    pub fn get_nested_attributes<S>(&mut self, subattr: T) -> Result<RtAttrHandle<S>, DeError>
    where
        S: RtaType,
    {
        let payload = self
            .get_attribute(subattr)
            .ok_or_else(|| DeError::new("Couldn't find specified attribute"))?
            .rta_payload
            .as_ref();
        Ok(AttrHandle::new(RtBuffer::from_bytes_with_input(
            &mut Cursor::new(payload),
            payload.len(),
        )?))
    }

    /// Get nested attributes from a parsed handle.
    pub fn get_attribute(&self, t: T) -> Option<&Rtattr<T, Buffer>> {
        self.get_attrs().iter().find(|item| item.rta_type == t)
    }

    /// Parse binary payload as a type that implements [`FromBytes`].
    pub fn get_attr_payload_as<'b, R>(&'b self, attr: T) -> Result<R, DeError>
    where
        R: FromBytes<'b>,
    {
        match self.get_attribute(attr) {
            Some(a) => a.get_payload_as::<R>(),
            _ => Err(DeError::new("Failed to find specified attribute")),
        }
    }

    /// Parse binary payload as a type that implements [`FromBytesWithInput`].
    pub fn get_attr_payload_as_with_len<'b, R>(&'b self, attr: T) -> Result<R, DeError>
    where
        R: FromBytesWithInput<'b, Input = usize>,
    {
        match self.get_attribute(attr) {
            Some(a) => a.get_payload_as_with_len::<R>(),
            _ => Err(DeError::new("Failed to find specified attribute")),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::{
        consts::{
            nl::{NlmF, NlmFFlags},
            socket::NlFamily,
        },
        nl::{NlPayload, Nlmsghdr},
        socket::NlSocketHandle,
        test::setup,
    };

    #[test]
    fn test_rta_deserialize() {
        setup();

        let buf = &[4u8, 0, 0, 0] as &[u8];
        Rtattr::<Rta, Buffer>::from_bytes(&mut Cursor::new(buf)).unwrap();
    }

    #[test]
    fn test_rta_deserialize_err() {
        setup();

        // 3 bytes is below minimum length
        let buf = &[3u8, 0, 0, 0] as &[u8];
        Rtattr::<Rta, Buffer>::from_bytes(&mut Cursor::new(buf)).unwrap_err();
    }

    #[test]
    fn test_rtattr_padding() {
        setup();

        let attr = Rtattr {
            rta_len: 5,
            rta_type: Rta::Unspec,
            rta_payload: vec![0u8],
        };
        let mut buffer = Cursor::new(Vec::new());
        let buf_res = attr.to_bytes(&mut buffer);

        buf_res.unwrap();
        // padding check
        assert_eq!(buffer.into_inner().len(), 8);
    }

    #[test]
    fn real_test_ifinfomsg() {
        setup();

        let mut sock = NlSocketHandle::new(NlFamily::Route).unwrap();
        sock.send(Nlmsghdr::new(
            None,
            Rtm::Getlink,
            NlmFFlags::new(&[NlmF::Dump, NlmF::Request, NlmF::Ack]),
            None,
            None,
            NlPayload::Payload(Ifinfomsg::new(
                RtAddrFamily::Unspecified,
                Arphrd::None,
                0,
                IffFlags::empty(),
                IffFlags::empty(),
                RtBuffer::new(),
            )),
        ))
        .unwrap();
        let msgs = sock.recv_all::<Rtm, Ifinfomsg>().unwrap();
        for msg in msgs {
            let handle = msg.get_payload().unwrap().rtattrs.get_attr_handle();
            handle
                .get_attr_payload_as_with_len::<String>(Ifla::Ifname)
                .unwrap();
            // Assert length of ethernet address
            assert_eq!(
                handle
                    .get_attr_payload_as_with_len::<Vec<u8>>(Ifla::Address)
                    .unwrap()
                    .len(),
                6
            );
        }
    }

    #[test]
    fn real_test_tcmsg() {
        setup();

        let mut sock = NlSocketHandle::new(NlFamily::Route).unwrap();
        sock.send(Nlmsghdr::new(
            None,
            Rtm::Getqdisc,
            NlmFFlags::new(&[NlmF::Dump, NlmF::Request, NlmF::Ack]),
            None,
            None,
            NlPayload::Payload(Tcmsg::new(0, 0, 0, 0, 0, RtBuffer::new())),
        ))
        .unwrap();
        let msgs = sock.recv_all::<Rtm, Tcmsg>().unwrap();
        for msg in msgs {
            assert!(matches!(msg.get_payload().unwrap(), Tcmsg { .. }));
            assert_eq!(msg.nl_type, Rtm::Newqdisc);
        }
    }
}
