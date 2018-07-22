//! Due to netlink's loose treatment of types, parsing attributes can be hard to model in
//! Rust. `neli`'s current solution is the following:
//!
//! ```no_run
//! // This was received from the socket
//! let nlmsg = neli::nlhdr::NlHdr::new(None, neli::ffi::GenlId::Ctrl, Vec::new(), None, None,
//!         neli::genlhdr::GenlHdr::new::<u16>(0u8, 2, Vec::new()).unwrap());
//!
//! // Get parsing handler for the attributes in this message where the next call
//! // to either get_nested_attributes() or get_payload_with() will expect a u16 type
//! // to be provided
//! let mut handle = nlmsg.nl_payload.get_attr_handle::<u16>();
//!
//! // Get the nested attribute where the NlAttrHdr field of nla_type is equal to 1 and return
//! // a handler containing only this nested attribute internally
//! let mut next = handle.get_nested_attributes::<u16>(1).unwrap();
//!
//! // Get the nested attribute where the NlAttrHdr field of nla_type is equal to 1 and return
//! // the payload of this attribute as a u32
//! let thirty_two_bit_integer = next.get_payload_with::<u32>(1, None).unwrap();
//! ```

use std::io::Read;
use std::slice;

use buffering::copy::{StreamReadBuffer,StreamWriteBuffer};
use libc;

use Nl;
use err::{SerError,DeError};
use ffi::alignto;

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

impl<T> NlAttrHdr<T> where T: Nl + Into<u16> + From<u16> {
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

    /// Create new netlink attribute with a payload from an object implementing `Nl`
    pub fn new_nl_payload<P>(nla_len: Option<u16>, nla_type: T, payload: P)
            -> Result<Self, SerError> where P: Nl {
        let mut mem = StreamWriteBuffer::new_growable(Some(payload.asize()));
        payload.serialize(&mut mem)?;
        let mut nla = NlAttrHdr {
            nla_type,
            payload: mem.as_ref().to_vec(),
            nla_len: 0,
        };
        nla.nla_len = nla_len.unwrap_or(nla.size() as u16);
        Ok(nla)
    }

    /// Create new netlink attribute with a nested payload
    pub fn new_nested<P>(nla_len: Option<u16>, nla_type: T, mut payload: Vec<NlAttrHdr<P>>)
            -> Result<Self, SerError> where P: Nl + Into<u16> + From<u16> {
        let mut nla = NlAttrHdr {
            nla_type,
            payload: {
                let mut mem = StreamWriteBuffer::new_growable(Some(payload.iter().fold(0, |acc, item| {
                    acc + item.asize()
                })));
                for item in payload.iter_mut() {
                    item.serialize(&mut mem)?;
                    if item.payload.asize() != item.payload.size() {
                        [0u8; libc::NLA_ALIGNTO as usize]
                            [0..item.payload.asize() - item.payload.size()]
                            .as_ref().serialize(&mut mem)?;
                    }
                }
                mem.as_ref().to_vec()
            },
            nla_len: 0,
        };
        nla.nla_len = nla_len.unwrap_or(nla.size() as u16);
        Ok(nla)
    }

    /// Create new netlink attribute payload from string, handling null byte termination
    pub fn new_string_payload(nla_len: Option<u16>, nla_type: T, string_payload: String)
            -> Result<Self, SerError> {
        let nla = NlAttrHdr {
            nla_len: nla_len.unwrap_or((0u16.size() + nla_type.size() + string_payload.size())
                                       as u16),
            nla_type,
            payload: {
                let mut mem = StreamWriteBuffer::new_growable(Some(string_payload.asize()));
                string_payload.serialize(&mut mem)?;
                if string_payload.asize() != string_payload.size() {
                    [0u8; libc::NLA_ALIGNTO as usize]
                        [0..string_payload.asize() - string_payload.size()]
                        .as_ref().serialize(&mut mem)?;
                }
                mem.as_ref().to_vec()
            },
        };
        Ok(nla)
    }

    /// Create new netlink attribute payload from string, handling null byte termination
    pub fn new_str_payload(nla_len: Option<u16>, nla_type: T, str_payload: &str)
            -> Result<Self, SerError> {
        let string_payload = str_payload.to_string();
        Self::new_string_payload(nla_len, nla_type, string_payload)
    }

    /// Get handle for attribute parsing and traversal
    pub fn get_attr_handle<'a, P>(&'a self) -> AttrHandle<'a, P> {
        AttrHandle::Bin(self.payload.as_slice())
    }
}

impl<T> Nl for NlAttrHdr<T> where T: Nl + Into<u16> + From<u16> {
    type SerIn = ();
    type DeIn = ();

    fn serialize(&self, mem: &mut StreamWriteBuffer) -> Result<(), SerError> {
        self.nla_len.serialize(mem)?;
        self.nla_type.serialize(mem)?;
        self.payload.serialize(mem)?;
        Ok(())
    }

    fn deserialize<B>(mem: &mut StreamReadBuffer<B>) -> Result<Self, DeError> where B: AsRef<[u8]> {
        let mut nla = NlAttrHdr {
            nla_len: u16::deserialize(mem)?,
            nla_type: T::deserialize(mem)?,
            payload: Vec::new(),
        };
        nla.payload = Vec::<u8>::deserialize_with(mem, nla.nla_len as usize -
                                                  (nla.nla_len.size() + nla.nla_type.size()))?;
        let padding = &mut [0u8; 4][0..alignto(nla.nla_len as usize) - nla.nla_len as usize];
        let _ = mem.read_exact(padding);
        Ok(nla)
    }

    fn size(&self) -> usize {
        self.nla_len.size() + self.nla_type.size() + self.payload.size()
    }
}

/// Handle returned by `GenlHdr` for traversing nested attribute structures
pub enum AttrHandle<'a, P> {
    /// Binary internal representation of attributes
    Bin(&'a [u8]),
    /// Rust representation of attributes
    Parsed(Vec<NlAttrHdr<P>>),
}

impl<'a, P> AttrHandle<'a, P> where P: PartialEq + Nl + Into<u16> + From<u16> {
    /// Get length if attribute handle has been parsed
    pub fn len(&self) -> Option<usize> {
        match *self {
            AttrHandle::Parsed(ref v) => Some(v.len()),
            _ => None,
        }
    }

    /// If attributes are parsed, pass back iterator over attributes
    pub fn iter(&self) -> Option<slice::Iter<NlAttrHdr<P>>> {
        match *self {
            AttrHandle::Parsed(ref v) => Some(v.iter()),
            _ => None,
        }
    }

    /// Parse a binary payload into nested attributes
    pub fn parse_nested_attributes(&mut self) -> Result<&mut AttrHandle<'a, P>, DeError> {
        let opt_v = match *self {
            AttrHandle::Bin(ref v) => {
                let mut len = v.asize();
                let mut attrs = Vec::new();
                let mut mem = StreamReadBuffer::new(v);
                while len > 0 {
                    let hdr = NlAttrHdr::deserialize(&mut mem)?;
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
            Some(a) => Ok(AttrHandle::Bin(a.payload.as_slice())),
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
    #[deprecated(since="0.3.0", note="Please use get_payload_with instead")]
    pub fn get_payload_as<R>(&mut self, attr: P) -> Result<R, DeError> where R: Nl {
        match self.parse_nested_attributes()?.get_attribute(attr) {
            Some(ref a) => {
                let mut state = StreamReadBuffer::new(&a.payload);
                R::deserialize(&mut state)
            },
            _ => Err(DeError::new("Failed to find specified attribute")),
        }
    }

    /// Parse binary payload as a type that implements `Nl` using `deserialize_with` if `with` is
    /// not `None`
    pub fn get_payload_with<R>(&mut self, attr: P, with: Option<R::DeIn>) -> Result<R, DeError>
            where R: Nl {
        match self.parse_nested_attributes()?.get_attribute(attr) {
            Some(ref a) => {
                let mut state = StreamReadBuffer::new(&a.payload);
                if let Some(w) = with {
                    R::deserialize_with(&mut state, w)
                } else {
                    R::deserialize(&mut state)
                }
            },
            _ => Err(DeError::new("Failed to find specified attribute")),
        }
    }
}
