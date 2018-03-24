use std::io::Read;
use std::mem;

use libc;

use {Nl,MemRead,MemWrite};
use err::{SerError,DeError};
use ffi::NlFlags;

/// Top level netlink header and payload
#[derive(Debug,PartialEq)]
pub struct NlHdr<I, T> {
    /// Length of the netlink message
    pub nl_len: u32,
    /// Type of the netlink message
    pub nl_type: I,
    /// Flags indicating properties of the request or response
    pub nl_flags: Vec<NlFlags>,
    /// Sequence number for netlink protocol
    pub nl_seq: u32,
    /// ID of the netlink destination for requests and source for responses
    pub nl_pid: u32,
    /// Payload of netlink message
    pub nl_payload: T,
}

impl<I, T> NlHdr<I, T> where I: Nl, T: Nl {
    /// Create a new top level netlink packet with a payload
    pub fn new(nl_len: Option<u32>, nl_type: I, nl_flags: Vec<NlFlags>,
           nl_seq: Option<u32>, nl_pid: Option<u32>, nl_payload: T) -> Self {
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

/// Struct representing netlink attributes and payloads
#[derive(Debug,PartialEq)]
pub struct NlAttrHdr<T> {
    /// Length of the attribute header and payload together
    pub nla_len: u16,
    /// Enum representing the type of the attribute payload
    pub nla_type: T,
    /// Payload of the attribute - either parsed or a binary buffer
    pub payload: Vec<u8>,
}

impl<T> NlAttrHdr<T> where T: Nl {
    /// Create new netlink attribute with a payload
    pub fn new_binary_payload(nla_len: Option<u16>, nla_type: T, payload: Vec<u8>)
            -> Self {
        let mut nla = NlAttrHdr {
            nla_type,
            payload,
            nla_len: 0, 
        };
        nla.nla_len = nla_len.unwrap_or(nla.size() as u16);
        nla
    }

    /// Create new netlink attribute with a nested payload
    pub fn new_nested<P>(nla_len: Option<u16>, nla_type: T, mut payload: Vec<NlAttrHdr<P>>)
            -> Result<Self, SerError> where P: Nl {
        let mut nla = NlAttrHdr {
            nla_type,
            payload: {
                let mut mem = MemWrite::new_vec(Some(payload.iter().fold(0, |acc, item| {
                    acc + item.asize()
                })));
                for item in payload.iter_mut() {
                    item.serialize(&mut mem)?;
                    if item.asize() != item.size() {
                        [0u8; libc::NLA_ALIGNTO as usize][0..item.asize() - item.size()]
                            .as_ref().serialize(&mut mem)?;
                    }
                }
                mem.as_slice().to_vec()
            },
            nla_len: 0,
        };
        nla.nla_len = nla_len.unwrap_or(nla.size() as u16);
        Ok(nla)
    }

    /// Create new netlink attribute payload from string, handling null byte termination
    pub fn new_string_payload(nla_len: Option<u16>, nla_type: T, string_payload: String)
            -> Result<Self, SerError> {
        let mut nla = NlAttrHdr { nla_type, payload: {
            let mut mem = MemWrite::new_vec(Some(string_payload.asize()));
            string_payload.serialize(&mut mem)?;
            if string_payload.asize() != string_payload.size() {
                [0u8; libc::NLA_ALIGNTO as usize]
                    [0..string_payload.asize() - string_payload.size()]
                    .as_ref().serialize(&mut mem)?;
            }
            mem.as_slice().to_vec()
        }, nla_len: 0 };
        nla.nla_len = nla_len.unwrap_or(nla.size() as u16);
        Ok(nla)
    }

    /// Create new netlink attribute payload from string, handling null byte termination
    pub fn new_str_payload(nla_len: Option<u16>, nla_type: T, str_payload: &str)
            -> Result<Self, SerError> {
        let string_payload = str_payload.to_string();
        Self::new_string_payload(nla_len, nla_type, string_payload)
    }
}

impl<I> Nl for NlAttrHdr<I> where I: Nl {
    type SerIn = usize;
    type DeIn = ();

    fn serialize(&self, mem: &mut MemWrite) -> Result<(), SerError> {
        self.nla_len.serialize(mem)?;
        self.nla_type.serialize(mem)?;
        self.payload.serialize(mem)?;
        if self.payload.asize() != self.payload.size() {
            [0u8; libc::NLA_ALIGNTO as usize][0..self.payload.asize() - self.payload.size()]
                .as_ref().serialize(mem)?;
        }
        Ok(())
    }

    fn deserialize(mem: &mut MemRead) -> Result<Self, DeError> {
        let nla_len = u16::deserialize(mem)?;
        let nla = NlAttrHdr {
            nla_len,
            nla_type: I::deserialize(mem)?,
            payload: {
                let payload = Vec::<u8>::deserialize(mem)?;
                if payload.asize() != nla_len as usize {
                    let mut buf = [0u8; libc::NLA_ALIGNTO as usize];
                    let padding = &mut buf[0..payload.asize() - nla_len as usize];
                    mem.read_exact(padding)?;
                }
                payload
            },
        };
        Ok(nla)
    }

    fn size(&self) -> usize {
        self.nla_len.size() + self.nla_type.size() + self.payload.size()
    }
}

/// Handle returned by `GenlHdr` for traversing nested attribute structures
pub enum AttrHandle<P> {
    /// Binary internal representation of attributes
    Bin(Vec<u8>),
    /// Rust representation of attributes
    Parsed(Vec<NlAttrHdr<P>>),
}

impl<'a, P> AttrHandle<P> where P: PartialEq + Nl {
    /// Parse a binary payload into nested attributes
    pub fn parse_nested_attributes(&mut self) -> Result<&mut AttrHandle<P>, DeError> {
        let opt_v = match *self {
            AttrHandle::Bin(ref v) => {
                let mut len = v.len();
                let mut attrs = Vec::new();
                let mut mem = MemRead::new_slice(v.as_slice());
                while len > 0 {
                    let hdr = NlAttrHdr::<P>::deserialize(&mut mem)?;
                    let mut padding_buf = [0; libc::NLA_ALIGNTO as usize];
                    if hdr.asize() != hdr.size() {
                        mem.read_exact(&mut padding_buf[0..hdr.asize() - hdr.size()])?;
                    }
                    len -= hdr.asize();
                    attrs.push(hdr);
                }
                Some(attrs)
            },
            _ => None,
        };
        match opt_v {
            Some(v) => { *self = AttrHandle::Parsed(v); },
            None => (),
        };
        Ok(self)
    }

    /// Get the payload of an attribute as a handle for parsing nested attributes
    pub fn get_nested_attributes<S>(&mut self, payload: P) -> Result<AttrHandle<S>, DeError> {
        let nested = self.parse_nested_attributes()?.get_attribute(payload);
        match nested {
            Some(a) => Ok(AttrHandle::Bin(a.payload.clone())),
            None => Err(DeError::new("Failed to find requested attribute")),
        }
    }

    /// Get nested attributes from a parsed handle
    pub fn get_attribute(&'a self, p: P) -> Option<&'a NlAttrHdr<P>> {
        match *self {
            AttrHandle::Parsed(ref parsed) => {
                for item in parsed {
                    if item.nla_type == p {
                        return Some(&item);
                    }
                }
                None
            },
            _ => None,
        }
    }

    /// Mutably get nested attributes from a parsed handle
    pub fn get_attribute_mut(&'a mut self, p: P) -> Option<&'a mut NlAttrHdr<P>> {
        match *self {
            AttrHandle::Parsed(ref mut parsed) => {
                for item in parsed {
                    if item.nla_type == p {
                        return Some(item);
                    }
                }
                None
            },
            _ => None,
        }
    }

    /// Parse binary payload as a type that implements `Nl`
    pub fn get_payload_as<R>(&mut self, attr: P) -> Result<R, DeError> where R: Nl {
        match self.parse_nested_attributes()?.get_attribute(attr) {
            Some(ref a) => {
                let mut state = MemRead::new_slice(&a.payload);
                R::deserialize(&mut state)
            },
            _ => Err(DeError::new("Failed to find specified attribute")),
        }
    }
}

/// Struct indicating an empty payload
#[derive(Debug,PartialEq)]
pub struct NlEmpty;

impl Nl for NlEmpty {
    type SerIn = ();
    type DeIn = ();

    fn serialize(&self, _cur: &mut MemWrite) -> Result<(), SerError> {
        Ok(())
    }

    fn deserialize(_cur: &mut MemRead) -> Result<Self, DeError> {
        Ok(NlEmpty)
    }

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
            c.write_u16::<NativeEndian>(NlFlags::Ack.into()).unwrap();
        }
        let mut mem = MemRead::new_slice(&*s);
        let nl = NlHdr::<Nlmsg, NlEmpty>::deserialize(&mut mem).unwrap();
        assert_eq!(NlHdr::<Nlmsg, NlEmpty>::new(None, Nlmsg::Noop,
                                                 vec![NlFlags::Ack], None, None, NlEmpty), nl);
    }
}
