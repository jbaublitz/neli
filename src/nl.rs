//! This module contains the top level netlink header code and attribute parsing. Every netlink
//! message will be encapsulated in a top level `Nlmsghdr`.
//!
//! `Nlmsghdr` is the structure representing a header that all netlink protocols require to be
//! passed to the correct destination.
//!
//! # Design decisions
//!
//! Payloads for `Nlmsghdr` can be any type that implements the `Nl` trait.

use bytes::{Bytes, BytesMut};
use smallvec::SmallVec;

use crate::{
    consts::{alignto, NlType, NlmFFlags},
    err::{DeError, SerError},
    utils::packet_length,
    Nl, NlBuffer,
};

impl<T, P> Nl for NlBuffer<T, P>
where
    T: NlType,
    P: Nl,
{
    fn serialize(&self, mut mem: BytesMut) -> Result<BytesMut, SerError> {
        let mut pos = 0;
        for nlhdr in self.iter() {
            let (mem_tmp, pos_tmp) = drive_serialize!(nlhdr, mem, pos);
            mem = mem_tmp;
            pos = pos_tmp;
        }
        Ok(drive_serialize!(END mem, pos))
    }

    fn deserialize(mem: Bytes) -> Result<Self, DeError> {
        let mut nlhdrs = SmallVec::new();
        let mut pos = 0;
        while pos < mem.len() {
            let packet_len = packet_length(mem.as_ref(), pos);
            let (nlhdr, pos_tmp) = drive_deserialize!(
                Nlmsghdr<T, P>, mem, pos, packet_len
            );
            pos = pos_tmp;
            nlhdrs.push(nlhdr);
        }
        drive_deserialize!(END mem, pos);
        Ok(nlhdrs)
    }

    fn type_size() -> Option<usize> {
        None
    }

    fn size(&self) -> usize {
        self.iter().fold(0, |acc, nlhdr| acc + nlhdr.size())
    }
}

/// Top level netlink header and payload
#[derive(Debug, PartialEq)]
pub struct Nlmsghdr<T, P> {
    /// Length of the netlink message
    pub nl_len: u32,
    /// Type of the netlink message
    pub nl_type: T,
    /// Flags indicating properties of the request or response
    pub nl_flags: NlmFFlags,
    /// Sequence number for netlink protocol
    pub nl_seq: u32,
    /// ID of the netlink destination for requests and source for responses
    pub nl_pid: u32,
    /// Payload of netlink message
    pub nl_payload: P,
}

impl<T, P> Nlmsghdr<T, P>
where
    T: NlType,
    P: Nl,
{
    /// Create a new top level netlink packet with a payload
    pub fn new(
        nl_len: Option<u32>,
        nl_type: T,
        nl_flags: NlmFFlags,
        nl_seq: Option<u32>,
        nl_pid: Option<u32>,
        nl_payload: P,
    ) -> Self {
        let mut nl = Nlmsghdr {
            nl_type,
            nl_flags,
            nl_seq: nl_seq.unwrap_or(0),
            nl_pid: nl_pid.unwrap_or(0),
            nl_payload,
            nl_len: 0,
        };
        nl.nl_len = nl_len.unwrap_or(nl.size() as u32);
        nl
    }
}

impl<T, P> Nl for Nlmsghdr<T, P>
where
    T: NlType,
    P: Nl,
{
    fn serialize(&self, mem: BytesMut) -> Result<BytesMut, SerError> {
        Ok(serialize! {
            PAD self;
            mem;
            self.nl_len;
            self.nl_type;
            self.nl_flags;
            self.nl_seq;
            self.nl_pid;
            self.nl_payload
        })
    }

    fn deserialize(mem: Bytes) -> Result<Self, DeError> {
        Ok(deserialize! {
            STRIP Self;
            mem;
            Nlmsghdr {
                nl_len: u32,
                nl_type: T,
                nl_flags: NlmFFlags,
                nl_seq: u32,
                nl_pid: u32,
                nl_payload: P => (nl_len as usize).checked_sub(
                    u32::type_size().expect("Must be a static size") * 3
                    + T::type_size().expect("Must be a static size")
                    + NlmFFlags::type_size().expect("Must be a static size")
                )
                .ok_or_else(|| DeError::UnexpectedEOB)?
            } => alignto(nl_len as usize) - nl_len as usize
        })
    }

    fn size(&self) -> usize {
        self.nl_len.size()
            + <T as Nl>::size(&self.nl_type)
            + self.nl_flags.size()
            + self.nl_seq.size()
            + self.nl_pid.size()
            + self.nl_payload.size()
    }

    fn type_size() -> Option<usize> {
        u32::type_size()
            .and_then(|sz| T::type_size().map(|subsz| sz + subsz))
            .and_then(|sz| NlmFFlags::type_size().map(|subsz| sz + subsz))
            .and_then(|sz| u32::type_size().map(|subsz| sz + subsz))
            .and_then(|sz| u32::type_size().map(|subsz| sz + subsz))
            .and_then(|sz| P::type_size().map(|subsz| sz + subsz))
    }
}

/// Struct indicating an empty payload
#[derive(Debug, PartialEq)]
pub struct NlEmpty;

impl Nl for NlEmpty {
    #[inline]
    fn serialize(&self, mem: BytesMut) -> Result<BytesMut, SerError> {
        Ok(mem)
    }

    #[inline]
    fn deserialize(_mem: Bytes) -> Result<Self, DeError> {
        Ok(NlEmpty)
    }

    #[inline]
    fn size(&self) -> usize {
        0
    }

    #[inline]
    fn type_size() -> Option<usize> {
        Some(0)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use std::io::Cursor;

    use byteorder::{NativeEndian, WriteBytesExt};

    use crate::consts::nl::{NlmF, Nlmsg};

    #[test]
    fn test_nlmsghdr_serialize() {
        let nl = Nlmsghdr::<Nlmsg, NlEmpty>::new(
            None,
            Nlmsg::Noop,
            NlmFFlags::empty(),
            None,
            None,
            NlEmpty,
        );
        let mut mem = BytesMut::from(vec![0u8; nl.asize()]);
        mem = nl.serialize(mem).unwrap();
        let mut s = [0u8; 16];
        {
            let mut c = Cursor::new(&mut s as &mut [u8]);
            c.write_u32::<NativeEndian>(16).unwrap();
            c.write_u16::<NativeEndian>(1).unwrap();
        };
        assert_eq!(&s, mem.as_ref())
    }

    #[test]
    fn test_nlmsghdr_deserialize() {
        let mut s = [0u8; 16];
        {
            let mut c = Cursor::new(&mut s as &mut [u8]);
            c.write_u32::<NativeEndian>(16).unwrap();
            c.write_u16::<NativeEndian>(1).unwrap();
            c.write_u16::<NativeEndian>(NlmF::Ack.into()).unwrap();
        }
        let nl = Nlmsghdr::<Nlmsg, NlEmpty>::deserialize(Bytes::from(&s as &[u8])).unwrap();
        assert_eq!(
            Nlmsghdr::<Nlmsg, NlEmpty>::new(
                None,
                Nlmsg::Noop,
                NlmFFlags::new(&[NlmF::Ack]),
                None,
                None,
                NlEmpty
            ),
            nl
        );
    }
}
