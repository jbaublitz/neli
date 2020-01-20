//! This module provides an implementation of routing netlink structures and the routing attributes
//! that are at the end of most routing netlink responses.
//!
//! # Design decisions
//!
//! This module is based very heavily on the information in `man 7 rtnetlink` so it is mainly a
//! series of structs organized in a style similar to the rest of the library with implementations
//! of `Nl` for each.

use std::mem;

use buffering::{StreamReadBuffer, StreamWriteBuffer};
use libc;

use crate::{
    consts::rtnl::*,
    err::{DeError, SerError},
    Nl,
};

/// Set of `Rtattr` structs
#[derive(Debug)]
pub struct Rtattrs<T, P>(Vec<Rtattr<T, P>>);

impl<T, P> Rtattrs<T, P>
where
    T: RtaType,
    P: Nl,
{
    /// Create an empty `Rtattrs` set
    pub fn empty() -> Self {
        Rtattrs(Vec::new())
    }

    /// Create an `Rtattrs` set initializing it with a vector
    pub fn new(vec: Vec<Rtattr<T, P>>) -> Self {
        Rtattrs(vec)
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
    type IntoIter = <Vec<Self::Item> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<T> Rtattrs<T, Vec<u8>>
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
    fn serialize(&self, buf: &mut StreamWriteBuffer) -> Result<(), SerError> {
        for item in self.0.iter() {
            item.serialize(buf)?;
        }
        Ok(())
    }

    fn deserialize<B>(buf: &mut StreamReadBuffer<B>) -> Result<Self, DeError>
    where
        B: AsRef<[u8]>,
    {
        let mut size_hint = buf
            .take_size_hint()
            .ok_or_else(|| DeError::new("Vec of Rtattr requires a size hint to deserialize"))?;
        let mut vec = Vec::new();
        while size_hint > 0 {
            let attr: Rtattr<T, P> = Rtattr::deserialize(buf)?;
            size_hint = size_hint.checked_sub(attr.asize()).ok_or_else(|| {
                DeError::new(&format!(
                    "Rtattr size {} overflowed buffer size {}",
                    attr.size(),
                    size_hint
                ))
            })?;
            vec.push(attr);
        }
        Ok(Rtattrs::new(vec))
    }

    fn size(&self) -> usize {
        self.0.iter().fold(0, |acc, item| acc + item.asize())
    }
}

/// Struct representing interface information messages
#[derive(Debug)]
pub struct Ifinfomsg {
    /// Interface address family
    pub ifi_family: RtAddrFamily,
    /// Interface type
    pub ifi_type: Arphrd,
    /// Interface index
    pub ifi_index: libc::c_int,
    /// Interface flags
    pub ifi_flags: Vec<Iff>,
    /// Change mask
    pub ifi_change: Iff,
    /// Payload of `Rtattr`s
    pub rtattrs: Rtattrs<Ifla, Vec<u8>>,
}

impl Ifinfomsg {
    /// Create a fully initialized interface info struct
    pub fn new(
        ifi_family: RtAddrFamily,
        ifi_type: Arphrd,
        ifi_index: libc::c_int,
        ifi_flags: Vec<Iff>,
        rtattrs: Rtattrs<Ifla, Vec<u8>>,
    ) -> Self {
        Ifinfomsg {
            ifi_family,
            ifi_type,
            ifi_index,
            ifi_flags,
            ifi_change: Iff::from(0xffff_ffff),
            rtattrs,
        }
    }

    /// Set the link with the given index up (equivalent to `ip link set dev DEV up`)
    pub fn up(
        ifi_family: RtAddrFamily,
        ifi_type: Arphrd,
        ifi_index: libc::c_int,
        rtattrs: Rtattrs<Ifla, Vec<u8>>,
    ) -> Self {
        Ifinfomsg {
            ifi_family,
            ifi_type,
            ifi_index,
            ifi_flags: vec![Iff::Up],
            ifi_change: Iff::Up.into(),
            rtattrs,
        }
    }

    /// Set the link with the given index down (equivalent to `ip link set dev DEV down`)
    pub fn down(
        ifi_family: RtAddrFamily,
        ifi_type: Arphrd,
        ifi_index: libc::c_int,
        rtattrs: Rtattrs<Ifla, Vec<u8>>,
    ) -> Self {
        Ifinfomsg {
            ifi_family,
            ifi_type,
            ifi_index,
            ifi_flags: Vec::new(),
            ifi_change: Iff::Up.into(),
            rtattrs,
        }
    }
}

impl Nl for Ifinfomsg {
    fn serialize(&self, buf: &mut StreamWriteBuffer) -> Result<(), SerError> {
        self.ifi_family.serialize(buf)?;
        0u8.serialize(buf)?; // padding
        self.ifi_type.serialize(buf)?;
        self.ifi_index.serialize(buf)?;
        self.ifi_flags
            .iter()
            .fold(0, |acc: libc::c_uint, next| {
                let next_uint: libc::c_uint = next.into();
                acc | next_uint
            })
            .serialize(buf)?;
        self.ifi_change.serialize(buf)?;
        self.rtattrs.serialize(buf)?;
        Ok(())
    }

    fn deserialize<B>(buf: &mut StreamReadBuffer<B>) -> Result<Self, DeError>
    where
        B: AsRef<[u8]>,
    {
        let mut size_hint = buf
            .take_size_hint()
            .ok_or_else(|| DeError::new("Ifinfomsg requires a size hint to deserialize"))?;
        let ifi_family = RtAddrFamily::deserialize(buf)?;
        let padding = u8::deserialize(buf)?;
        let ifi_type = Arphrd::deserialize(buf)?;
        let ifi_index = libc::c_int::deserialize(buf)?;
        let ifi_flags = {
            let flags = libc::c_uint::deserialize(buf)?;
            let mut nl_flags = Vec::new();
            for i in 0..mem::size_of::<libc::c_int>() * 8 {
                let bit = 1 << i;
                if bit & flags == bit {
                    nl_flags.push(bit.into());
                }
            }
            nl_flags
        };
        let ifi_change: Iff = libc::c_uint::deserialize(buf)?.into();

        size_hint = size_hint
            .checked_sub(
                ifi_family.size()
                    + padding.size()
                    + ifi_type.size()
                    + ifi_index.size()
                    + mem::size_of::<libc::c_int>()
                    + ifi_change.size(),
            )
            .ok_or_else(|| DeError::new(&format!("Truncated Ifinfomsg size_hint {}", size_hint)))?;
        buf.set_size_hint(size_hint);
        let rtattrs = Rtattrs::<Ifla, Vec<u8>>::deserialize(buf)?;

        Ok(Ifinfomsg {
            ifi_family,
            ifi_type,
            ifi_index,
            ifi_flags,
            ifi_change,
            rtattrs,
        })
    }

    fn size(&self) -> usize {
        self.ifi_family.size() +
        // padding byte
        0u8.size() +
        self.ifi_type.size() + self.ifi_index.size() +
        // flags
        mem::size_of::<libc::c_uint>() +
        self.ifi_change.size() +
        self.rtattrs.asize()
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
    pub ifa_flags: Vec<IfaF>,
    /// Interface address scope
    pub ifa_scope: libc::c_uchar,
    /// Interface address index
    pub ifa_index: libc::c_int,
    /// Payload of `Rtattr`s
    pub rtattrs: Rtattrs<Ifa, Vec<u8>>,
}

impl Nl for Ifaddrmsg {
    fn serialize(&self, buf: &mut StreamWriteBuffer) -> Result<(), SerError> {
        self.ifa_family.serialize(buf)?;
        self.ifa_prefixlen.serialize(buf)?;
        self.ifa_flags
            .iter()
            .fold(0u8, |acc: libc::c_uchar, next| {
                let next_uint: u8 = u32::from(next) as u8;
                acc | next_uint as libc::c_uchar
            })
            .serialize(buf)?;
        self.ifa_scope.serialize(buf)?;
        self.ifa_index.serialize(buf)?;
        self.rtattrs.serialize(buf)?;
        Ok(())
    }

    fn deserialize<B>(buf: &mut StreamReadBuffer<B>) -> Result<Self, DeError>
    where
        B: AsRef<[u8]>,
    {
        let mut result = Ifaddrmsg {
            ifa_family: RtAddrFamily::deserialize(buf)?,
            ifa_prefixlen: libc::c_uchar::deserialize(buf)?,
            ifa_flags: {
                let flags = libc::c_uchar::deserialize(buf)?;
                let mut nl_flags = Vec::new();
                for i in 0..mem::size_of::<libc::c_uchar>() * 8 {
                    let bit = 1 << i;
                    if bit & flags == bit {
                        nl_flags.push((u32::from(bit)).into());
                    }
                }
                nl_flags
            },
            ifa_scope: libc::c_uchar::deserialize(buf)?,
            ifa_index: libc::c_int::deserialize(buf)?,
            rtattrs: Rtattrs::empty(),
        };

        let size_hint = buf
            .take_size_hint()
            .ok_or_else(|| DeError::new("Ifinfomsg requires a size hint to deserialize"))?
            - result.asize();
        buf.set_size_hint(size_hint);

        result.rtattrs = Rtattrs::deserialize(buf)?;
        Ok(result)
    }

    fn size(&self) -> usize {
        self.ifa_family.size()
            + self.ifa_prefixlen.size()
            + mem::size_of::<libc::c_uchar>()
            + self.ifa_scope.size()
            + self.ifa_index.size()
    }
}

/// General form of address family dependent message.  Used for requesting things from via rtnetlink.
#[derive(Debug)]
pub struct Rtgenmsg {
    /// Address family for the request
    pub rtgen_family: RtAddrFamily,
}

impl Nl for Rtgenmsg {
    fn serialize(&self, m: &mut StreamWriteBuffer) -> Result<(), SerError> {
        self.rtgen_family.serialize(m)
    }

    fn deserialize<T>(m: &mut StreamReadBuffer<T>) -> Result<Self, DeError>
    where
        T: AsRef<[u8]>,
    {
        Ok(Self {
            rtgen_family: RtAddrFamily::deserialize(m)?,
        })
    }

    fn size(&self) -> usize {
        self.rtgen_family.size()
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
    pub rtm_flags: Vec<RtmF>,
    /// Payload of `Rtattr`s
    pub rtattrs: Rtattrs<Rta, Vec<u8>>,
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
        self.rtm_flags
            .iter()
            .fold(0, |acc: libc::c_uint, next| {
                let next_uint: libc::c_uint = next.into();
                acc | next_uint
            })
            .serialize(buf)?;
        self.rtattrs.serialize(buf)?;
        Ok(())
    }

    fn deserialize<B>(buf: &mut StreamReadBuffer<B>) -> Result<Self, DeError>
    where
        B: AsRef<[u8]>,
    {
        let size_hint = buf
            .take_size_hint()
            .ok_or_else(|| DeError::new("Must provide size hint to deserialize Rtmsg"))?;

        let rtm_family = RtAddrFamily::deserialize(buf)?;
        let rtm_dst_len = libc::c_uchar::deserialize(buf)?;
        let rtm_src_len = libc::c_uchar::deserialize(buf)?;
        let rtm_tos = libc::c_uchar::deserialize(buf)?;
        let rtm_table = RtTable::deserialize(buf)?;
        let rtm_protocol = Rtprot::deserialize(buf)?;
        let rtm_scope = RtScope::deserialize(buf)?;
        let rtm_type = Rtn::deserialize(buf)?;
        let rtm_flags = {
            let flags = libc::c_int::deserialize(buf)?;
            let mut rtm_flags = Vec::new();
            for i in 0..mem::size_of::<libc::c_uint>() * 8 {
                let bit = 1 << i;
                if bit & flags == bit {
                    rtm_flags.push((bit as libc::c_uint).into());
                }
            }
            rtm_flags
        };

        buf.set_size_hint(
            size_hint
                - rtm_family.size()
                - rtm_dst_len.size()
                - rtm_src_len.size()
                - rtm_tos.size()
                - rtm_table.size()
                - rtm_protocol.size()
                - rtm_scope.size()
                - rtm_type.size()
                - mem::size_of::<libc::c_int>(),
        );
        let rtattrs = Rtattrs::<Rta, Vec<u8>>::deserialize(buf)?;

        Ok(Rtmsg {
            rtm_family,
            rtm_dst_len,
            rtm_src_len,
            rtm_tos,
            rtm_table,
            rtm_protocol,
            rtm_scope,
            rtm_type,
            rtm_flags,
            rtattrs,
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
            + mem::size_of::<libc::c_uint>()
            + self.rtattrs.asize()
    }
}

/// Represents an ARP (neighbor table) entry
#[derive(Debug)]
pub struct Ndmsg {
    /// Address family of entry
    pub ndm_family: RtAddrFamily,
    /// Index of entry
    pub ndm_index: libc::c_int,
    /// State of entry
    pub ndm_state: Vec<Nud>,
    /// Flags for entry
    pub ndm_flags: Vec<Ntf>,
    /// Type of entry
    pub ndm_type: Rtn,
    /// Payload of `Rtattr`s
    pub rtattrs: Rtattrs<Nda, Vec<u8>>,
}

impl Nl for Ndmsg {
    fn serialize(&self, buf: &mut StreamWriteBuffer) -> Result<(), SerError> {
        self.ndm_family.serialize(buf)?;
        0u8.serialize(buf)?; // padding
        0u16.serialize(buf)?; // padding
        self.ndm_index.serialize(buf)?;
        self.ndm_state
            .iter()
            .fold(0, |acc: u16, next| {
                let next_uint: u16 = next.into();
                acc | next_uint
            })
            .serialize(buf)?;
        self.ndm_flags
            .iter()
            .fold(0, |acc: u8, next| {
                let next_uint: u8 = next.into();
                acc | next_uint
            })
            .serialize(buf)?;
        self.ndm_type.serialize(buf)?;
        self.rtattrs.serialize(buf)?;
        Ok(())
    }

    fn deserialize<B>(buf: &mut StreamReadBuffer<B>) -> Result<Self, DeError>
    where
        B: AsRef<[u8]>,
    {
        let size_hint = buf
            .take_size_hint()
            .ok_or_else(|| DeError::new("Must provide size hint to deserialize Ndmsg"))?;

        let ndm_family = RtAddrFamily::deserialize(buf)?;
        u8::deserialize(buf)?; // padding
        u16::deserialize(buf)?; // padding
        let ndm_index = libc::c_int::deserialize(buf)?;
        let ndm_state = {
            let state = u16::deserialize(buf)?;
            let mut ndm_state = Vec::new();
            for i in 0..mem::size_of::<u16>() * 8 {
                let bit = 1 << i;
                if bit & state == bit {
                    ndm_state.push((bit as u16).into());
                }
            }
            ndm_state
        };
        let ndm_flags = {
            let flags = u8::deserialize(buf)?;
            let mut ndm_flags = Vec::new();
            for i in 0..mem::size_of::<u8>() * 8 {
                let bit = 1 << i;
                if bit & flags == bit {
                    ndm_flags.push((bit as u8).into());
                }
            }
            ndm_flags
        };
        let ndm_type = Rtn::deserialize(buf)?;

        buf.set_size_hint(
            size_hint
                - ndm_family.size()
                - 3 // padding of u8 + u16
                - ndm_index.size()
                - mem::size_of::<u16>() // ndm_state
                - mem::size_of::<u8>() // ndm_flags
                - ndm_type.size(),
        );

        let rtattrs = Rtattrs::<Nda, Vec<u8>>::deserialize(buf)?;

        Ok(Ndmsg {
            ndm_family,
            ndm_index,
            ndm_state,
            ndm_flags,
            ndm_type,
            rtattrs,
        })
    }

    fn size(&self) -> usize {
        self.ndm_family.size()
            + 3 // padding of u8 + u16
            + self.ndm_index.size()
            + mem::size_of::<u16>() // ndm_state
            + mem::size_of::<u8>() // ndm_flags
            + self.ndm_type.size()
            + self.rtattrs.asize()
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
    fn serialize(&self, buf: &mut StreamWriteBuffer) -> Result<(), SerError> {
        self.ndm_confirmed.serialize(buf)?;
        self.ndm_used.serialize(buf)?;
        self.ndm_updated.serialize(buf)?;
        self.ndm_refcnt.serialize(buf)?;
        Ok(())
    }

    fn deserialize<B>(buf: &mut StreamReadBuffer<B>) -> Result<Self, DeError>
    where
        B: AsRef<[u8]>,
    {
        Ok(NdaCacheinfo {
            ndm_confirmed: u32::deserialize(buf)?,
            ndm_used: u32::deserialize(buf)?,
            ndm_updated: u32::deserialize(buf)?,
            ndm_refcnt: u32::deserialize(buf)?,
        })
    }

    fn size(&self) -> usize {
        self.ndm_confirmed.size()
            + self.ndm_used.size()
            + self.ndm_updated.size()
            + self.ndm_refcnt.size()
    }
}

/// Message in response to queuing discipline operations
#[derive(Debug)]
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
    /// Payload of `Rtattr`s
    pub rtattrs: Rtattrs<Tca, Vec<u8>>,
}

impl Nl for Tcmsg {
    fn serialize(&self, buf: &mut StreamWriteBuffer) -> Result<(), SerError> {
        self.tcm_family.serialize(buf)?;
        self.tcm_ifindex.serialize(buf)?;
        self.tcm_handle.serialize(buf)?;
        self.tcm_parent.serialize(buf)?;
        self.tcm_info.serialize(buf)?;
        self.rtattrs.serialize(buf)?;
        Ok(())
    }

    fn deserialize<B>(buf: &mut StreamReadBuffer<B>) -> Result<Self, DeError>
    where
        B: AsRef<[u8]>,
    {
        Ok(Tcmsg {
            tcm_family: libc::c_uchar::deserialize(buf)?,
            tcm_ifindex: libc::c_int::deserialize(buf)?,
            tcm_handle: u32::deserialize(buf)?,
            tcm_parent: u32::deserialize(buf)?,
            tcm_info: u32::deserialize(buf)?,
            rtattrs: Rtattrs::<Tca, Vec<u8>>::deserialize(buf)?,
        })
    }

    fn size(&self) -> usize {
        self.tcm_family.size()
            + self.tcm_ifindex.size()
            + self.tcm_handle.size()
            + self.tcm_parent.size()
            + self.tcm_info.size()
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

impl<T> Rtattr<T, Vec<u8>>
where
    T: RtaType,
{
    /// Get payload as type implementing `Nl`
    pub fn get_payload_as<R>(&self) -> Result<R, DeError>
    where
        R: Nl,
    {
        R::deserialize(&mut StreamReadBuffer::new(&self.rta_payload))
    }
}

impl<T, P> Nl for Rtattr<T, P>
where
    T: RtaType,
    P: Nl,
{
    fn serialize(&self, buf: &mut StreamWriteBuffer) -> Result<(), SerError> {
        self.rta_len.serialize(buf)?;
        self.rta_type.serialize(buf)?;
        self.rta_payload.serialize(buf)?;
        self.pad(buf)?;
        Ok(())
    }

    fn deserialize<B>(buf: &mut StreamReadBuffer<B>) -> Result<Self, DeError>
    where
        B: AsRef<[u8]>,
    {
        let rta_len = libc::c_ushort::deserialize(buf)?;
        let rta_type = T::deserialize(buf)?;
        buf.set_size_hint(
            (rta_len as usize)
                .checked_sub(rta_len.size() + rta_type.size())
                .ok_or_else(|| {
                    DeError::new(&format!("Invalid size while reading Rtattr: {}", rta_len))
                })?,
        );
        let rta_payload = P::deserialize(buf)?;
        let rtattr = Rtattr {
            rta_len,
            rta_type,
            rta_payload,
        };
        rtattr.strip(buf)?;
        Ok(rtattr)
    }

    fn size(&self) -> usize {
        self.rta_len.size() + self.rta_type.size() + self.rta_payload.size()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::consts::Rta;

    #[test]
    fn test_rta_deserialize() {
        let mut buf = StreamReadBuffer::new(&[4u8, 0, 0, 0]);
        assert!(Rtattr::<Rta, Vec<u8>>::deserialize(&mut buf).is_ok());
    }

    #[test]
    fn test_rta_deserialize_err() {
        // 3 bytes is below minimum length
        let mut buf = StreamReadBuffer::new(&[3u8, 0, 0, 0]);
        assert!(Rtattr::<Rta, Vec<u8>>::deserialize(&mut buf).is_err());
    }

    #[test]
    fn test_rtattr_deserialize_padding() {
        let mut buf = StreamReadBuffer::new(&[5u8, 0, 0, 0, 0, 0, 0, 0, 111]);
        assert!(Rtattr::<Rta, Vec<u8>>::deserialize(&mut buf).is_ok());
        // should have stripped remainder of word
        assert_eq!(u8::deserialize(&mut buf).unwrap(), 111);
    }

    #[test]
    fn test_rtattr_padding() {
        let attr = Rtattr {
            rta_len: 5,
            rta_type: Rta::Unspec,
            rta_payload: vec![0u8],
        };
        let mut buf = StreamWriteBuffer::new_growable(None);

        assert!(attr.serialize(&mut buf).is_ok());
        // padding check
        assert_eq!(buf.as_ref().len(), 8);
    }
}
