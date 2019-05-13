//! Due to netlink's loose treatment of types, parsing attributes can be hard to model in
//! Rust. `neli`'s current solution is the following:
//!
//! ```no_run
//! // This was received from the socket
//! let nlmsg = neli::nl::Nlmsghdr::new(None, neli::consts::GenlId::Ctrl, Vec::new(), None, None,
//!         neli::genl::Genlmsghdr::new::<u16>(neli::consts::CtrlCmd::Unspec, 2, Vec::new()).unwrap());
//!
//! // Get parsing handler for the attributes in this message where the next call
//! // to either get_nested_attributes() or get_payload_with() will expect a u16 type
//! // to be provided
//! let mut handle = nlmsg.nl_payload.get_attr_handle::<u16>();
//!
//! // Get the nested attribute where the Nlattr field of nla_type is equal to 1 and return
//! // a handler containing only this nested attribute internally
//! let mut next = handle.get_nested_attributes::<u16>(1).unwrap();
//!
//! // Get the nested attribute where the Nlattr field of nla_type is equal to 1 and return
//! // the payload of this attribute as a u32
//! let thirty_two_bit_integer = next.get_payload::<u32>(1, None).unwrap();
//! ```

use std::io::{Read,Write};
use std::slice;

use buffering::copy::{StreamReadBuffer,StreamWriteBuffer};
use libc;

use Nl;
use err::{SerError,DeError};
use consts::{alignto,NlAttrType};

impl<T> Nl for Vec<Nlattr<T>> where T: NlAttrType {
    fn serialize(&self, mem: &mut StreamWriteBuffer) -> Result<(), SerError> {
        for item in self.iter() {
            item.serialize(mem)?;
        }
        Ok(())
    }

    fn deserialize<B>(mem: &mut StreamReadBuffer<B>) -> Result<Self, DeError>
            where B: AsRef<[u8]> {
        let mut vec = Vec::new();
        let mut size_hint = mem.take_size_hint().unwrap_or(0);
        while size_hint > 0 || !mem.at_end() {
            let next = Nlattr::<T>::deserialize(mem)?;
            if size_hint > 0 {
                size_hint -= next.asize();
            }
            vec.push(next);
        }
        Ok(vec)
    }

    fn size(&self) -> usize {
        self.iter().fold(0, |acc, next| {
            acc + alignto(next.size())
        })
    }
}

/// Struct representing netlink attributes and payloads
#[derive(Debug,PartialEq)]
pub struct Nlattr<T> {
    /// Length of the attribute header and payload together
    pub nla_len: u16,
    /// Enum representing the type of the attribute payload
    pub nla_type: T,
    /// Payload of the attribute - either parsed or a binary buffer
    pub payload: Vec<u8>,
}

impl<T> Nlattr<T> where T: NlAttrType {
    /// Create new netlink attribute with a payload
    pub fn new_binary_payload(nla_len: Option<u16>, nla_type: T, payload: Vec<u8>)
            -> Self {
        let mut nla = Nlattr {
            nla_type,
            payload,
            nla_len: 0,
        };
        nla.nla_len = nla_len.unwrap_or(nla.size() as u16);
        nla
    }

    /// Create new netlink attribute with a payload from an object implementing `Nl`
    pub fn new_nl_payload<P>(nla_len: Option<u16>, nla_type: T, payload: P)
            -> Result<Self, SerError> where P: Nl {
        let mut mem = StreamWriteBuffer::new_growable(Some(payload.asize()));
        mem.set_size_hint(payload.size());
        payload.serialize(&mut mem)?;
        let mut nla = Nlattr {
            nla_type,
            payload: mem.as_ref().to_vec(),
            nla_len: 0,
        };
        nla.nla_len = nla_len.unwrap_or(nla.size() as u16);
        Ok(nla)
    }

    /// Get handle for attribute parsing and traversal
    pub fn get_attr_handle<'a, P>(&'a self) -> AttrHandle<'a, P> where P: NlAttrType {
        AttrHandle::Bin(self.payload.as_slice())
    }
}

impl<T> Nl for Nlattr<T> where T: NlAttrType {
    fn serialize(&self, mem: &mut StreamWriteBuffer) -> Result<(), SerError> {
        self.nla_len.serialize(mem)?;
        self.nla_type.serialize(mem)?;
        self.payload.serialize(mem)?;
        let padding_len = alignto(self.nla_len as usize) - self.nla_len as usize;
        if padding_len > 0 {
            mem.write(&mut [0u8; 4][0..padding_len])?;
        }
        Ok(())
    }

    fn deserialize<B>(mem: &mut StreamReadBuffer<B>) -> Result<Self, DeError> where B: AsRef<[u8]> {
        let nla_len = u16::deserialize(mem)?;
        let nla_type = T::deserialize(mem)?;
        mem.set_size_hint(nla_len as usize - (nla_len.size() + nla_type.size()));
        let payload = Vec::<u8>::deserialize(mem)?;
        let padding_len = alignto(nla_len as usize) - nla_len as usize;
        if padding_len > 0 {
            let padding = &mut [0u8; libc::NLA_ALIGNTO as usize][0..padding_len];
            let _ = mem.read_exact(padding)?;
        }
        let nla = Nlattr {
            nla_len,
            nla_type,
            payload,
        };
        Ok(nla)
    }

    fn size(&self) -> usize {
        self.nla_len.size() + self.nla_type.size() + self.payload.size()
    }
}

/// Handle returned by `Genlmsghdr` for traversing nested attribute structures
pub enum AttrHandle<'a, P> where P: NlAttrType {
    /// Binary internal representation of attributes
    Bin(&'a [u8]),
    /// Rust representation of attributes
    Parsed(Vec<Nlattr<P>>),
}

impl<'a, P> AttrHandle<'a, P> where P: NlAttrType {
    /// Get length if attribute handle has been parsed
    pub fn len(&self) -> Option<usize> {
        match *self {
            AttrHandle::Parsed(ref v) => Some(v.len()),
            _ => None,
        }
    }

    /// If attributes are parsed, pass back iterator over attributes
    pub fn iter(&self) -> Option<slice::Iter<Nlattr<P>>> {
        match *self {
            AttrHandle::Parsed(ref v) => Some(v.iter()),
            _ => None,
        }
    }

    /// Parse a binary payload into nested attributes
    pub fn parse_nested_attributes(&mut self) -> Result<&mut AttrHandle<'a, P>, DeError> {
        let opt_v = match *self {
            AttrHandle::Bin(v) => {
                let mut len = v.asize();
                let mut attrs = Vec::new();
                let mut mem = StreamReadBuffer::new(v);
                while len > 0 {
                    let hdr = Nlattr::deserialize(&mut mem)?;
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
    pub fn get_nested_attributes<S>(&mut self, payload: P) -> Result<AttrHandle<S>, DeError>
            where S: NlAttrType {
        let nested = self.parse_nested_attributes()?.get_attribute(payload);
        match nested {
            Some(a) => Ok(AttrHandle::Bin(a.payload.as_slice())),
            None => Err(DeError::new("Failed to find requested attribute")),
        }
    }

    /// Get nested attributes from a parsed handle
    pub fn get_attribute(&'a self, p: P) -> Option<&'a Nlattr<P>> {
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
    pub fn get_attribute_mut(&'a mut self, p: P) -> Option<&'a mut Nlattr<P>> {
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

    /// Parse binary payload as a type that implements `Nl` using `deserialize` with an option size
    /// hint
    pub fn get_payload<R>(&mut self, attr: P, size_hint: Option<usize>) -> Result<R, DeError>
            where R: Nl {
        match self.parse_nested_attributes()?.get_attribute(attr) {
            Some(ref a) => {
                let mut mem = StreamReadBuffer::new(&a.payload);
                if let Some(w) = size_hint {
                    mem.set_size_hint(w);
                }
                R::deserialize(&mut mem)
            },
            _ => Err(DeError::new("Failed to find specified attribute")),
        }
    }
}
