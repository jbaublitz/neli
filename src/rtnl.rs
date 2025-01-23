//! This module provides an implementation of routing netlink
//! structures and the routing attributes that are at the end of
//! most routing netlink responses.
//!
//! # Design decisions
//!
//! This module is based very heavily on the information in
//! `man 7 rtnetlink` so it is mainly a series of structs organized
//! in a style similar to the rest of the library.

use std::io::Cursor;

use derive_builder::{Builder, UninitializedFieldError};
use getset::Getters;

use crate::{
    self as neli,
    attr::{AttrHandle, Attribute},
    consts::rtnl::*,
    err::{DeError, SerError},
    types::{Buffer, RtBuffer},
    FromBytes, FromBytesWithInput, FromBytesWithInputBorrowed, Header, Size, ToBytes,
};

/// Struct representing interface information messages
#[derive(Builder, Getters, Clone, Debug, Size, ToBytes, FromBytesWithInput, Header)]
#[builder(pattern = "owned")]
pub struct Ifinfomsg {
    /// Interface address family
    #[getset(get = "pub")]
    ifi_family: RtAddrFamily,
    #[builder(setter(skip))]
    #[builder(default = "0")]
    padding: u8,
    /// Interface type
    #[getset(get = "pub")]
    ifi_type: Arphrd,
    /// Interface index
    #[getset(get = "pub")]
    ifi_index: libc::c_int,
    /// Interface flags
    #[getset(get = "pub")]
    #[builder(default = "Iff::empty()")]
    ifi_flags: Iff,
    /// Interface change mask
    #[getset(get = "pub")]
    #[builder(default = "Iff::empty()")]
    ifi_change: Iff,
    /// Payload of [`Rtattr`]s
    #[neli(input = "input.checked_sub(Self::header_size()).ok_or(DeError::InvalidInput(input))?")]
    #[getset(get = "pub")]
    #[builder(default = "RtBuffer::new()")]
    rtattrs: RtBuffer<Ifla, Buffer>,
}

impl IfinfomsgBuilder {
    /// Set the link with the given index up (equivalent to
    /// `ip link set dev DEV up`)
    pub fn up(mut self) -> Self {
        self.ifi_flags = Some(self.ifi_flags.unwrap_or_else(Iff::empty) | Iff::UP);
        self.ifi_change = Some(self.ifi_change.unwrap_or_else(Iff::empty) | Iff::UP);
        self
    }

    /// Set the link with the given index down (equivalent to
    /// `ip link set dev DEV down`)
    pub fn down(mut self) -> Self {
        self.ifi_flags = Some(self.ifi_flags.unwrap_or_else(Iff::empty) & !Iff::UP);
        self.ifi_change = Some(self.ifi_change.unwrap_or_else(Iff::empty) | Iff::UP);
        self
    }
}

/// Struct representing interface address messages
#[derive(Builder, Getters, Clone, Debug, Size, ToBytes, FromBytesWithInput, Header)]
#[builder(pattern = "owned")]
pub struct Ifaddrmsg {
    /// Interface address family
    #[getset(get = "pub")]
    ifa_family: RtAddrFamily,
    /// Interface address prefix length
    #[getset(get = "pub")]
    ifa_prefixlen: libc::c_uchar,
    /// Interface address flags
    #[getset(get = "pub")]
    #[builder(default = "IfaF::empty()")]
    ifa_flags: IfaF,
    /// Interface address scope
    #[getset(get = "pub")]
    ifa_scope: RtScope,
    /// Interface address index
    #[getset(get = "pub")]
    ifa_index: libc::c_uint,
    /// Payload of [`Rtattr`]s
    #[neli(input = "input.checked_sub(Self::header_size()).ok_or(DeError::InvalidInput(input))?")]
    #[getset(get = "pub")]
    #[builder(default = "RtBuffer::new()")]
    rtattrs: RtBuffer<Ifa, Buffer>,
}

/// General form of address family dependent message.  Used for
/// requesting things from rtnetlink.
#[derive(Builder, Getters, Debug, Size, ToBytes, FromBytesWithInput, Header)]
#[builder(pattern = "owned")]
pub struct Rtgenmsg {
    /// Address family for the request
    #[getset(get = "pub")]
    rtgen_family: RtAddrFamily,
    /// Payload of [`Rtattr`]s
    #[neli(input = "input.checked_sub(Self::header_size()).ok_or(DeError::InvalidInput(input))?")]
    #[getset(get = "pub")]
    #[builder(default = "RtBuffer::new()")]
    rtattrs: RtBuffer<Ifa, Buffer>,
}

/// Route message
#[derive(Builder, Getters, Clone, Debug, Size, ToBytes, FromBytesWithInput, Header)]
#[builder(pattern = "owned")]
pub struct Rtmsg {
    /// Address family of route
    #[getset(get = "pub")]
    rtm_family: RtAddrFamily,
    /// Length of destination
    #[getset(get = "pub")]
    rtm_dst_len: libc::c_uchar,
    /// Length of source
    #[getset(get = "pub")]
    rtm_src_len: libc::c_uchar,
    /// TOS filter
    #[getset(get = "pub")]
    rtm_tos: libc::c_uchar,
    /// Routing table ID
    #[getset(get = "pub")]
    rtm_table: RtTable,
    /// Routing protocol
    #[getset(get = "pub")]
    rtm_protocol: Rtprot,
    /// Routing scope
    #[getset(get = "pub")]
    rtm_scope: RtScope,
    /// Routing type
    #[getset(get = "pub")]
    rtm_type: Rtn,
    /// Routing flags
    #[builder(default = "RtmF::empty()")]
    #[getset(get = "pub")]
    rtm_flags: RtmF,
    /// Payload of [`Rtattr`]s
    #[neli(input = "input.checked_sub(Self::header_size()).ok_or(DeError::InvalidInput(input))?")]
    #[getset(get = "pub")]
    #[builder(default = "RtBuffer::new()")]
    rtattrs: RtBuffer<Rta, Buffer>,
}

/// Represents an ARP (neighbor table) entry
#[derive(Builder, Getters, Debug, Size, ToBytes, FromBytesWithInput, Header)]
#[builder(pattern = "owned")]
pub struct Ndmsg {
    /// Address family of entry
    #[getset(get = "pub")]
    ndm_family: RtAddrFamily,
    #[builder(setter(skip))]
    #[builder(default = "0")]
    pad1: u8,
    #[builder(setter(skip))]
    #[builder(default = "0")]
    pad2: u16,
    /// Index of entry
    #[getset(get = "pub")]
    ndm_index: libc::c_int,
    /// State of entry
    #[getset(get = "pub")]
    ndm_state: Nud,
    /// Flags for entry
    #[getset(get = "pub")]
    #[builder(default = "Ntf::empty()")]
    ndm_flags: Ntf,
    /// Type of entry
    #[getset(get = "pub")]
    ndm_type: Rtn,
    /// Payload of [`Rtattr`]s
    #[neli(input = "input.checked_sub(Self::header_size()).ok_or(DeError::InvalidInput(input))?")]
    #[getset(get = "pub")]
    #[builder(default = "RtBuffer::new()")]
    rtattrs: RtBuffer<Nda, Buffer>,
}

/// Struct representing ARP cache info
#[derive(Builder, Getters, Debug, Size, ToBytes, FromBytes)]
#[builder(pattern = "owned")]
pub struct NdaCacheinfo {
    /// Confirmed
    #[getset(get = "pub")]
    ndm_confirmed: u32,
    /// Used
    #[getset(get = "pub")]
    ndm_used: u32,
    /// Updated
    #[getset(get = "pub")]
    ndm_updated: u32,
    /// Reference count
    #[getset(get = "pub")]
    ndm_refcnt: u32,
}

/// Message in response to queuing discipline operations
#[derive(Builder, Getters, Clone, Debug, Size, ToBytes, FromBytesWithInput, Header)]
#[builder(pattern = "owned")]
pub struct Tcmsg {
    /// Family
    #[getset(get = "pub")]
    tcm_family: libc::c_uchar,
    #[builder(setter(skip))]
    #[builder(default = "0")]
    padding_char: libc::c_uchar,
    #[builder(setter(skip))]
    #[builder(default = "0")]
    padding_short: libc::c_ushort,
    /// Interface index
    #[getset(get = "pub")]
    tcm_ifindex: libc::c_int,
    /// Queuing discipline handle
    #[getset(get = "pub")]
    tcm_handle: u32,
    /// Parent queuing discipline
    #[getset(get = "pub")]
    tcm_parent: u32,
    /// Info
    #[getset(get = "pub")]
    tcm_info: u32,
    /// Payload of [`Rtattr`]s
    #[neli(input = "input.checked_sub(Self::header_size()).ok_or(DeError::InvalidInput(input))?")]
    #[getset(get = "pub")]
    #[builder(default = "RtBuffer::new()")]
    rtattrs: RtBuffer<Tca, Buffer>,
}

/// Struct representing route netlink attributes
#[derive(Builder, Getters, Clone, Debug, Size, ToBytes, FromBytes, Header)]
#[neli(header_bound = "T: RtaType")]
#[neli(from_bytes_bound = "T: RtaType")]
#[neli(from_bytes_bound = "P: FromBytesWithInput<Input = usize>")]
#[neli(padding)]
#[builder(pattern = "owned")]
#[builder(build_fn(skip))]
pub struct Rtattr<T, P> {
    /// Length of the attribute
    #[getset(get = "pub")]
    #[builder(setter(skip))]
    rta_len: libc::c_ushort,
    /// Type of the attribute
    #[getset(get = "pub")]
    rta_type: T,
    /// Payload of the attribute
    #[neli(
        input = "(rta_len as usize).checked_sub(Self::header_size()).ok_or(DeError::InvalidInput(rta_len as usize))?"
    )]
    #[getset(get = "pub")]
    rta_payload: P,
}

impl<T, P> RtattrBuilder<T, P>
where
    T: Size,
    P: Size + ToBytes,
{
    /// Build an [`Rtattr`].
    pub fn build(self) -> Result<Rtattr<T, Buffer>, RtattrBuilderError> {
        let rta_type = self
            .rta_type
            .ok_or_else(|| RtattrBuilderError::from(UninitializedFieldError::new("rta_type")))?;
        let rta_payload = self
            .rta_payload
            .ok_or_else(|| RtattrBuilderError::from(UninitializedFieldError::new("rta_payload")))?;
        let mut buffer = Cursor::new(vec![0; rta_payload.unpadded_size()]);
        rta_payload.to_bytes(&mut buffer).map_err(|_| {
            RtattrBuilderError::ValidationError(
                "Could not convert payload to binary representation".to_string(),
            )
        })?;

        let mut rtattr = Rtattr {
            rta_len: 0,
            rta_type,
            rta_payload: Buffer::from(buffer.into_inner()),
        };
        rtattr.rta_len = rtattr.unpadded_size() as libc::c_ushort;
        Ok(rtattr)
    }
}

impl<T> Rtattr<T, Buffer>
where
    T: RtaType,
{
    /// Builder method to add a nested attribute to the end of the payload.
    ///
    /// Use this to construct an attribute and nest attributes within it in one method chain.
    pub fn nest<TT, P>(mut self, attr: &Rtattr<TT, P>) -> Result<Self, SerError>
    where
        TT: RtaType,
        P: ToBytes,
    {
        self.add_nested_attribute(attr)?;
        Ok(self)
    }

    /// Add a nested attribute to the end of the payload.
    fn add_nested_attribute<TT, P>(&mut self, attr: &Rtattr<TT, P>) -> Result<(), SerError>
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

/// Represents a routing netlink attribute handle.
pub type RtAttrHandle<'a, T> = AttrHandle<'a, RtBuffer<T, Buffer>, Rtattr<T, Buffer>>;

impl<'a, T> RtAttrHandle<'a, T>
where
    T: RtaType,
{
    /// Get the payload of an attribute as a handle for parsing
    /// nested attributes.
    pub fn get_nested_attributes<S>(&self, subattr: T) -> Result<RtAttrHandle<S>, DeError>
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
    pub fn get_attr_payload_as<R>(&self, attr: T) -> Result<R, DeError>
    where
        R: FromBytes,
    {
        match self.get_attribute(attr) {
            Some(a) => a.get_payload_as::<R>(),
            _ => Err(DeError::new("Failed to find specified attribute")),
        }
    }

    /// Parse binary payload as a type that implements [`FromBytesWithInput`].
    pub fn get_attr_payload_as_with_len<R>(&self, attr: T) -> Result<R, DeError>
    where
        R: FromBytesWithInput<Input = usize>,
    {
        match self.get_attribute(attr) {
            Some(a) => a.get_payload_as_with_len::<R>(),
            _ => Err(DeError::new("Failed to find specified attribute")),
        }
    }

    /// Parse binary payload as a type that implements [`FromBytesWithInput`].
    pub fn get_attr_payload_as_with_len_borrowed<R>(&'a self, attr: T) -> Result<R, DeError>
    where
        R: FromBytesWithInputBorrowed<'a, Input = usize>,
    {
        match self.get_attribute(attr) {
            Some(a) => a.get_payload_as_with_len_borrowed::<R>(),
            _ => Err(DeError::new("Failed to find specified attribute")),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use std::net::Ipv4Addr;

    use crate::{
        consts::{nl::NlmF, socket::NlFamily},
        err::RouterError,
        nl::NlPayload,
        router::synchronous::NlRouter,
        test::setup,
        utils::Groups,
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

        let (sock, _) = NlRouter::connect(NlFamily::Route, None, Groups::empty()).unwrap();
        sock.enable_strict_checking(true).unwrap();
        let mut recv = sock
            .send::<_, _, Rtm, Ifinfomsg>(
                Rtm::Getlink,
                NlmF::DUMP | NlmF::ACK,
                NlPayload::Payload(
                    IfinfomsgBuilder::default()
                        .ifi_family(RtAddrFamily::Unspecified)
                        .ifi_type(Arphrd::None)
                        .ifi_index(0)
                        .build()
                        .unwrap(),
                ),
            )
            .unwrap();
        let all_msgs = recv
            .try_fold(Vec::new(), |mut v, m| {
                v.push(m?);
                Result::<_, RouterError<Rtm, Ifinfomsg>>::Ok(v)
            })
            .unwrap();
        let non_err_payloads = all_msgs.iter().fold(Vec::new(), |mut v, m| {
            if let Some(p) = m.get_payload() {
                v.push(p);
            }
            v
        });
        if non_err_payloads.is_empty() {
            panic!("Only received done message and no additional information");
        }
        for payload in non_err_payloads {
            let handle = payload.rtattrs.get_attr_handle();
            handle
                .get_attr_payload_as_with_len::<String>(Ifla::Ifname)
                .unwrap();
            // Assert length of ethernet address
            if let Ok(attr) = handle.get_attr_payload_as_with_len::<Vec<u8>>(Ifla::Address) {
                assert_eq!(attr.len(), 6);
            }
        }
    }

    #[test]
    fn real_test_tcmsg() {
        setup();

        let (sock, _) = NlRouter::connect(NlFamily::Route, None, Groups::empty()).unwrap();
        sock.enable_strict_checking(true).unwrap();
        let recv = sock
            .send::<_, _, Rtm, Tcmsg>(
                Rtm::Getqdisc,
                NlmF::DUMP | NlmF::ACK,
                NlPayload::Payload(
                    TcmsgBuilder::default()
                        .tcm_family(0)
                        .tcm_ifindex(0)
                        .tcm_handle(0)
                        .tcm_parent(0)
                        .tcm_info(0)
                        .build()
                        .unwrap(),
                ),
            )
            .unwrap();
        for msg in recv {
            let msg = msg.unwrap();
            assert!(matches!(msg.get_payload(), Some(Tcmsg { .. }) | None));
            assert!(matches!(
                msg.nl_type(),
                Rtm::Newqdisc | Rtm::UnrecognizedConst(3)
            ));
        }
    }

    #[test]
    #[cfg(target_env = "gnu")]
    fn real_test_rtmsg_search() {
        setup();

        let dstip = Ipv4Addr::new(127, 0, 0, 1);
        let raw_dstip = u32::from(dstip).to_be();
        let route_attr = RtattrBuilder::default()
            .rta_type(Rta::Dst)
            .rta_payload(raw_dstip)
            .build()
            .unwrap();

        let mut route_payload = RtBuffer::new();
        route_payload.push(route_attr);

        let (rtnl, _) = NlRouter::connect(NlFamily::Route, None, Groups::empty()).unwrap();

        let ifroutemsg = RtmsgBuilder::default()
            .rtm_family(RtAddrFamily::Inet)
            .rtm_dst_len(32)
            .rtm_src_len(0)
            .rtm_tos(0)
            .rtm_table(RtTable::Unspec)
            .rtm_protocol(Rtprot::Unspec)
            .rtm_scope(RtScope::Universe)
            .rtm_type(Rtn::Unspec)
            .rtm_flags(RtmF::from(libc::RTM_F_LOOKUP_TABLE))
            .rtattrs(route_payload)
            .build()
            .unwrap();

        let recv = rtnl
            .send::<_, _, Rtm, Rtmsg>(Rtm::Getroute, NlmF::REQUEST, NlPayload::Payload(ifroutemsg))
            .unwrap();

        assert!(recv.count() > 0);
    }
}
