//! This module contains the top level netlink header code and attribute parsing. Every netlink
//! message will be encapsulated in a top level `Nlmsghdr`.
//!
//! `Nlmsghdr` is the structure representing a header that all netlink protocols require to be
//! passed to the correct destination.
//!
//! # Design decisions
//!
//! Payloads for `Nlmsghdr` can be any type that implements the `Nl` trait.

use std::mem;

use buffering::copy::{StreamReadBuffer, StreamWriteBuffer};

use consts::{NlType, NlmF};
use err::{DeError, SerError};
use Nl;

/// Top level netlink header and payload
#[derive(Debug, PartialEq)]
pub struct Nlmsghdr<T, P> {
    /// Length of the netlink message
    pub nl_len: u32,
    /// Type of the netlink message
    pub nl_type: T,
    /// Flags indicating properties of the request or response
    pub nl_flags: Vec<NlmF>,
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
        nl_flags: Vec<NlmF>,
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
    fn serialize(&self, mem: &mut StreamWriteBuffer) -> Result<(), SerError> {
        self.nl_len.serialize(mem)?;
        self.nl_type.serialize(mem)?;
        let val = self.nl_flags.iter().fold(0, |acc: u16, val| {
            let v: u16 = val.into();
            acc | v
        });
        val.serialize(mem)?;
        self.nl_seq.serialize(mem)?;
        self.nl_pid.serialize(mem)?;
        self.nl_payload.serialize(mem)?;
        self.pad(mem)?;

        Ok(())
    }

    fn deserialize<B>(mem: &mut StreamReadBuffer<B>) -> Result<Self, DeError>
    where
        B: AsRef<[u8]>,
    {
        let nl_len = u32::deserialize(mem)?;
        let nl_type = T::deserialize(mem)?;
        let nl_flags = {
            let flags = u16::deserialize(mem)?;
            let mut nl_flags = Vec::new();
            for i in 0..mem::size_of::<u16>() * 8 {
                let bit = 1 << i;
                if bit & flags == bit {
                    nl_flags.push(bit.into());
                }
            }
            nl_flags
        };
        let nl_seq = u32::deserialize(mem)?;
        let nl_pid = u32::deserialize(mem)?;
        let nl_payload = {
            let payload_len = nl_len as usize
                - (nl_len.size() + nl_type.size() + 0u16.size() + nl_seq.size() + nl_pid.size());
            mem.set_size_hint(payload_len);
            P::deserialize(mem)?
        };

        let nl = Nlmsghdr::<T, P> {
            nl_len,
            nl_type,
            nl_flags,
            nl_seq,
            nl_pid,
            nl_payload,
        };
        nl.strip(mem)?;

        Ok(nl)
    }

    fn size(&self) -> usize {
        self.nl_len.size()
            + <T as Nl>::size(&self.nl_type)
            + mem::size_of::<u16>()
            + self.nl_seq.size()
            + self.nl_pid.size()
            + self.nl_payload.size()
    }
}

/// Struct indicating an empty payload
#[derive(Debug, PartialEq)]
pub struct NlEmpty;

impl Nl for NlEmpty {
    #[inline]
    fn serialize(&self, _cur: &mut StreamWriteBuffer) -> Result<(), SerError> {
        Ok(())
    }

    #[inline]
    fn deserialize<B>(_cur: &mut StreamReadBuffer<B>) -> Result<Self, DeError>
    where
        B: AsRef<[u8]>,
    {
        Ok(NlEmpty)
    }

    #[inline]
    fn size(&self) -> usize {
        0
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use byteorder::{NativeEndian, WriteBytesExt};
    use consts::Nlmsg;
    use std::io::Cursor;

    #[test]
    fn test_nlhdr_serialize() {
        let mut mem = StreamWriteBuffer::new_growable(None);
        let nl =
            Nlmsghdr::<Nlmsg, NlEmpty>::new(None, Nlmsg::Noop, Vec::new(), None, None, NlEmpty);
        nl.serialize(&mut mem).unwrap();
        let s: &mut [u8] = &mut [0; 16];
        {
            let mut c = Cursor::new(&mut *s);
            c.write_u32::<NativeEndian>(16).unwrap();
            c.write_u16::<NativeEndian>(1).unwrap();
        };
        assert_eq!(&mut *s, mem.as_ref())
    }

    #[test]
    fn test_nlhdr_deserialize() {
        let s: &mut [u8] = &mut [0; 16];
        {
            let mut c = Cursor::new(&mut *s);
            c.write_u32::<NativeEndian>(16).unwrap();
            c.write_u16::<NativeEndian>(1).unwrap();
            c.write_u16::<NativeEndian>(NlmF::Ack.into()).unwrap();
        }
        let mut mem = StreamReadBuffer::new(&*s);
        let nl = Nlmsghdr::<Nlmsg, NlEmpty>::deserialize(&mut mem).unwrap();
        assert_eq!(
            Nlmsghdr::<Nlmsg, NlEmpty>::new(
                None,
                Nlmsg::Noop,
                vec![NlmF::Ack],
                None,
                None,
                NlEmpty
            ),
            nl
        );
    }
}
