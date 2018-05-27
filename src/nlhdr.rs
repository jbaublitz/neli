//! This module contains the top level netlink header code and attribute parsing.
//!
//! NlHdr is the structure representing a header that all netlink protocols require to be
//! passed to the correct kernel handler.

use std::mem;

use {Nl,MemRead,MemWrite};
use err::{SerError,DeError};
use ffi::NlmF;

/// Top level netlink header and payload
#[derive(Debug,PartialEq)]
pub struct NlHdr<T, P> {
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

impl<T, P> NlHdr<T, P> where T: Nl + Into<u16> + From<u16>, P: Nl {
    /// Create a new top level netlink packet with a payload
    pub fn new(nl_len: Option<u32>, nl_type: T, nl_flags: Vec<NlmF>,
           nl_seq: Option<u32>, nl_pid: Option<u32>, nl_payload: P) -> Self {
        let mut nl = NlHdr {
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

impl<I, P> Nl for NlHdr<I, P> where I: Nl, P: Nl {
    type SerIn = ();
    type DeIn = ();

    fn serialize(&self, mem: &mut MemWrite) -> Result<(), SerError> {
        self.nl_len.serialize(mem)?;
        self.nl_type.serialize(mem)?;
        let val = self.nl_flags.iter().fold(0, |acc: u16, val| {
            let v: u16 = val.clone().into();
            acc | v
        });
        val.serialize(mem)?;
        self.nl_seq.serialize(mem)?;
        self.nl_pid.serialize(mem)?;
        self.nl_payload.serialize(mem)?;
        Ok(())
    }

    fn deserialize(mem: &mut MemRead) -> Result<Self, DeError> {
        let nl = NlHdr::<I, P> {
            nl_len: u32::deserialize(mem)?,
            nl_type: I::deserialize(mem)?,
            nl_flags: {
                let flags = u16::deserialize(mem)?;
                let mut nl_flags = Vec::new();
                for i in 0..mem::size_of::<u16>() * 8 {
                    let bit = 1 << i;
                    if bit & flags == bit {
                        nl_flags.push(bit.into());
                    }
                }
                nl_flags
            },
            nl_seq: u32::deserialize(mem)?,
            nl_pid: u32::deserialize(mem)?,
            nl_payload: P::deserialize(mem)?,
        };
        Ok(nl)
    }

    fn size(&self) -> usize {
        self.nl_len.size() + self.nl_type.size() + mem::size_of::<u16>()
            + self.nl_seq.size() + self.nl_pid.size() + self.nl_payload.size()
    }
}

/// Struct indicating an empty payload
#[derive(Debug,PartialEq)]
pub struct NlEmpty;

impl Nl for NlEmpty {
    type SerIn = ();
    type DeIn = ();

    #[inline]
    fn serialize(&self, _cur: &mut MemWrite) -> Result<(), SerError> {
        Ok(())
    }

    #[inline]
    fn deserialize(_cur: &mut MemRead) -> Result<Self, DeError> {
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
    use ffi::Nlmsg;
    use std::io::Cursor;
    use byteorder::{NativeEndian,WriteBytesExt};

    #[test]
    fn test_nlhdr_serialize() {
        let mut mem = MemWrite::new_vec(None);
        let nl = NlHdr::<Nlmsg, NlEmpty>::new(None, Nlmsg::Noop,
                                              Vec::new(), None, None, NlEmpty);
        nl.serialize(&mut mem).unwrap();
        let s: &mut [u8] = &mut [0; 16];
        {
            let mut c = Cursor::new(&mut *s);
            c.write_u32::<NativeEndian>(16).unwrap();
            c.write_u16::<NativeEndian>(1).unwrap();
        };
        assert_eq!(&mut *s, mem.as_slice())
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
        let mut mem = MemRead::new_slice(&*s);
        let nl = NlHdr::<Nlmsg, NlEmpty>::deserialize(&mut mem).unwrap();
        assert_eq!(NlHdr::<Nlmsg, NlEmpty>::new(None, Nlmsg::Noop,
                                                 vec![NlmF::Ack], None, None, NlEmpty), nl);
    }
}
