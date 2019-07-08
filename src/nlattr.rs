//! This module aims to provide simple parsing for generic netlink attributes, including parsing
//! for nested attributes.
//!
//! Due to netlink's loose treatment of types, parsing attributes can be hard to model in
//! Rust. `neli`'s current solution is the following:
//!
//! ```no_run
//! // This was received from the socket
//! let nlmsg = neli::nl::Nlmsghdr::new(None, neli::consts::GenlId::Ctrl, Vec::new(), None, None,
//!         neli::genl::Genlmsghdr::new(neli::consts::CtrlCmd::Unspec, 2, Vec::new()).unwrap());
//!
//! // Get parsing handler for the attributes in this message where the next call
//! // to either get_nested_attributes() or get_payload_with() will expect a u16 type
//! // to be provided
//! let mut handle = nlmsg.nl_payload.get_attr_handle();
//!
//! // Get the nested attribute where the Nlattr field of nla_type is equal to 1 and return
//! // a handler containing only this nested attribute internally
//! let mut next = handle.get_nested_attributes::<u16>(1).unwrap();
//!
//! // Get the nested attribute where the Nlattr field of nla_type is equal to 1 and return
//! // the payload of this attribute as a u32
//! let thirty_two_bit_integer = next.get_attr_payload_as::<u32>(1).unwrap();
//! ```
//!
//! # Design decisions
//!
//! Nested attributes are represented by `Vec<u8>` payloads inside top level attributes. They are
//! parsed during traversal to provide the ability to parse one attribute header using a different
//! generic type for the nested attribute type parameters, the typical case when parsing nested
//! attributes. To
//! traverse a nested attribute, look at the documentation for `.get_nested_attributes()` and
//! `AttrHandle` as well as the `examples/` directory for code examples of how to traverse nested
//! attributes.

use std::io::{Read,Write};
use std::slice;

use buffering::copy::{StreamReadBuffer,StreamWriteBuffer};
use libc;

use Nl;
use err::{DeError,NlError,SerError};
use consts::{alignto,NlAttrType};

impl<T, P> Nl for Vec<Nlattr<T, P>> where T: NlAttrType, P: Nl {
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
            let next = Nlattr::<T, P>::deserialize(mem)?;
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
pub struct Nlattr<T, P> {
    /// Length of the attribute header and payload together
    pub nla_len: u16,
    /// Enum representing the type of the attribute payload
    pub nla_type: T,
    /// Payload of the attribute - either parsed or a binary buffer
    pub payload: P,
}

impl<T, P> Nlattr<T, P> where T: NlAttrType, P: Nl {
    /// Get the size of the payload only
    pub fn payload_size(&self) -> usize {
        self.payload.size()
    }
}

impl<T> Nlattr<T, Vec<u8>> where T: NlAttrType {
    /// This function will serialize the provided payload
    pub fn new<P>(nla_len: Option<u16>, nla_type: T, payload: P) -> Result<Self, SerError>
            where P: Nl {
        let mut attr = Nlattr {
            nla_len: nla_len.unwrap_or(0),
            nla_type,
            payload: Vec::new(),
        };
        attr.set_payload(payload)?;
        Ok(attr)
    }

    /// Set the payload to a data type that implements `Nl` -
    /// this function will overwrite the current payload
    pub fn set_payload<P>(&mut self, payload: P) -> Result<(), SerError> where P: Nl {
        let mut buffer = StreamWriteBuffer::new_growable_ref(&mut self.payload);
        payload.serialize(&mut buffer)?;

        // Update `Nlattr` with new length
        self.nla_len = (self.nla_len.size() + self.nla_type.size() + payload.size()) as u16;

        Ok(())
    }

    /// Add a nested attribute to the end of the payload
    pub fn add_nested_attribute<TT, P>(&mut self, attr: Nlattr<TT, P>) -> Result<(), SerError>
            where TT: NlAttrType, P: Nl {
        let size = self.payload.len() as u64;
        let mut buffer = StreamWriteBuffer::new_growable_ref(&mut self.payload);
        buffer.set_position(size);
        attr.serialize(&mut buffer)?;
        self.nla_len = self.size() as u16;
        Ok(())
    }

    /// Get an `Nlattr` payload as a provided type
    pub fn get_payload_as<R>(&self) -> Result<R, DeError> where R: Nl {
        let mut buf = StreamReadBuffer::new(&self.payload);
        buf.set_size_hint(self.payload_size());
        R::deserialize(&mut buf)
    }

    /// Return an `AttrHandle` for attributes nested in the given attribute payload
    pub fn get_nested_attributes<'a, R>(&'a self) -> Result<AttrHandle<'a, R>, DeError> where R: NlAttrType {
        Ok(AttrHandle::new(Vec::<Nlattr<R, Vec<u8>>>::deserialize(
            &mut StreamReadBuffer::new(&self.payload)
        )?))
    }
}

impl<T, P> Nl for Nlattr<T, P> where T: NlAttrType, P: Nl {
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
        let payload = P::deserialize(mem)?;
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
pub enum AttrHandle<'a, T> {
    /// Owned vector
    Owned(Vec<Nlattr<T, Vec<u8>>>),
    /// Vector reference
    Borrowed(&'a Vec<Nlattr<T, Vec<u8>>>),
}

impl<'a, T> AttrHandle<'a, T> where T: NlAttrType {
    /// Create new `AttrHandle`
    pub fn new(vec: Vec<Nlattr<T, Vec<u8>>>) -> Self {
        AttrHandle::Owned(vec)
    }

    /// Create new borrowed `AttrHandle`
    pub fn new_borrowed(vec: &'a Vec<Nlattr<T, Vec<u8>>>) -> Self {
        AttrHandle::Borrowed(vec)
    }

    /// Get the underlying `Vec` as a reference
    pub fn get_vec(&self) -> &Vec<Nlattr<T, Vec<u8>>> {
        match *self {
            AttrHandle::Owned(ref v) => v,
            AttrHandle::Borrowed(ref v) => v,
        }
    }

    /// Get the underlying `Vec` as a mutable reference or return `None`
    pub fn get_vec_mut(&mut self) -> Option<&mut Vec<Nlattr<T, Vec<u8>>>> {
        match self {
            AttrHandle::Owned(ref mut v) => Some(v),
            AttrHandle::Borrowed(_) => None,
        }
    }

    /// Get size of buffer required to hold attributes
    pub fn size(&self) -> usize {
        self.get_vec().size()
    }

    /// If attributes are parsed, pass back iterator over attributes
    pub fn iter(&self) -> slice::Iter<Nlattr<T, Vec<u8>>> {
        self.get_vec().iter()
    }

    /// Get the payload of an attribute as a handle for parsing nested attributes
    pub fn get_nested_attributes<S>(&mut self, subattr: T) -> Result<AttrHandle<S>, NlError>
            where S: NlAttrType {
        Ok(AttrHandle::new(Vec::<Nlattr::<S, Vec<u8>>>::deserialize(&mut StreamReadBuffer::new(
            &self.get_attribute(subattr).ok_or(NlError::new(
                "Couldn't find specified attribute"
            ))?.payload
        ))?))
    }

    /// Get nested attributes from a parsed handle
    pub fn get_attribute<'b>(&'b self, t: T) -> Option<&'b Nlattr<T, Vec<u8>>> {
        for item in self.get_vec().iter() {
            if item.nla_type == t {
                return Some(&item);
            }
        }
        None
    }

    /// Mutably get nested attributes from a parsed handle
    pub fn get_attribute_mut<'b>(&'b mut self, t: T) -> Option<&'b mut Nlattr<T, Vec<u8>>> {
        let vec_mut = self.get_vec_mut()?;
        for item in vec_mut.iter_mut() {
            if item.nla_type == t {
                return Some(item);
            }
        }
        None
    }

    /// Parse binary payload as a type that implements `Nl` using `deserialize` with an option size
    /// hint
    pub fn get_attr_payload_as<R>(&self, attr: T) -> Result<R, DeError>
            where R: Nl {
        match self.get_attribute(attr) {
            Some(a) => {
                a.get_payload_as::<R>()
            },
            _ => Err(DeError::new("Failed to find specified attribute")),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    extern crate byteorder;

    use std::io::Cursor;

    use byteorder::{NativeEndian,WriteBytesExt};

    use consts::CtrlAttr;

    #[test]
    fn test_padding_size_calculation() {
        let nlattr = Nlattr::new(None, CtrlAttr::Unspec, 4u16).unwrap();
        assert_eq!(nlattr.size(), 6);
        assert_eq!(nlattr.asize(), 8);
    }

    #[test]
    fn test_nl_nlattr() {
        let nlattr = Nlattr::new(None, CtrlAttr::Unspec, 4u16).unwrap();
        let mut nlattr_serialized = StreamWriteBuffer::new_growable(Some(nlattr.asize()));
        nlattr.serialize(&mut nlattr_serialized).unwrap();

        let mut nlattr_desired_serialized = Cursor::new(vec![0; nlattr.size()]);
        nlattr_desired_serialized.write_u16::<NativeEndian>(6).unwrap();
        nlattr_desired_serialized.write_u16::<NativeEndian>(CtrlAttr::Unspec.into()).unwrap();
        nlattr_desired_serialized.write_u16::<NativeEndian>(4).unwrap();
        nlattr_desired_serialized.write(&[0, 0]).unwrap();

        assert_eq!(nlattr_serialized.as_ref(), nlattr_desired_serialized.into_inner().as_slice());

        let nlattr_desired_deserialized = Nlattr { nla_len: 6, nla_type: CtrlAttr::Unspec,
                                                   payload: 4u16 };

        let mut nlattr_deserialize_buffer = Cursor::new(
            vec![0; nlattr_desired_deserialized.asize()]
        );
        nlattr_deserialize_buffer.write_u16::<NativeEndian>(6).unwrap();
        nlattr_deserialize_buffer.write_u16::<NativeEndian>(CtrlAttr::Unspec.into()).unwrap();
        nlattr_deserialize_buffer.write_u16::<NativeEndian>(4).unwrap();
        nlattr_deserialize_buffer.write(&[0, 0]).unwrap();
        let mut reader = StreamReadBuffer::new(nlattr_deserialize_buffer.into_inner());
        let nlattr_deserialized = Nlattr::<CtrlAttr, u16>::deserialize(&mut reader).unwrap();
        assert_eq!(nlattr_deserialized, nlattr_desired_deserialized);
    }

    #[test]
    fn test_nl_len_after_adding_nested_attributes() {
        let create_aligned_attr = ||
            Nlattr::new(None, CtrlAttr::Unspec, vec![1, 2, 3, 4]).unwrap();

        let create_unaligned_attr = ||
            Nlattr::new(None, CtrlAttr::Unspec, vec![1]).unwrap();

        let mut nlattr = Nlattr::new::<Vec<u8>>(None, CtrlAttr::Unspec, vec![]).unwrap();
        assert_eq!(nlattr.size(), 4);

        nlattr.add_nested_attribute(create_aligned_attr()).unwrap();
        assert_eq!(nlattr.size(), 12);

        nlattr.add_nested_attribute(create_unaligned_attr()).unwrap();
        // Commented out because the following fails at the moment.
        // assert_eq!(nlattr.size(), 17);
        assert_eq!(nlattr.asize(), 20);

        // The last payload was unaligned, so the next attribute should start at offset 20.
        nlattr.add_nested_attribute(create_aligned_attr()).unwrap();
        assert_eq!(nlattr.size(), 28);
    }
}
