//! This module aims to provide simple parsing for generic netlink attributes, including parsing
//! for nested attributes.
//!
//! Due to netlink's loose treatment of types, parsing attributes can be hard to model in
//! Rust. `neli`'s current solution is the following:
//!
//! ```no_run
//! // This was received from the socket
//! let nlmsg = neli::nl::Nlmsghdr::new(None, neli::consts::GenlId::Ctrl, neli::consts::NlmFFlags::empty(), None, None,
//!         neli::genl::Genlmsghdr::new(neli::consts::CtrlCmd::Unspec, 2, neli::SmallVec::new()));
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
//!
//! Padding has been reworked using `.strip()` and `.pad()`. This is to be able to reason more
//! clearly about where padding is expected and where it is not. Padding expectations in the attribute
//! case of this library is defined as follows:
//! * Attributes containing a primitive datatype (`Nl` implementation defined in `lib.rs`) should
//! always report a length that is unpadded when using `.size()` and the representation when
//! deserialized should always be stripped of padding
//! * Attributes containing nested attributes should *always* be aligned to the number of bytes
//! represented by `libc::NLA_ALIGNTO`
//!   * This is the way the kernel represents it for every standard generic netlink family
//!   I have seen
//!   * It also makes sense as every message payload should be padded by the serialization method
//!   of the header containing it
//!   * Headers encapsulating the structure on the level above it have no concept of the padding on
//!   the level below it
//!     * For example, `Genlmsghdr` will never get involved in padding for any data
//!     structure other than the payload defined for `Genlmsghdr` - this includes all of the
//!     attribute payloads contained in the `Genlmsghdr` payload
//!     * Only `Nlattr` knows what is padding and what is not in its own payload - to every other
//!     serialization and deserialization method, it may or may not be padding

use std::slice;

use bytes::{Bytes, BytesMut};
use smallvec::SmallVec;

use crate::{
    consts::{alignto, NlAttrType},
    err::{DeError, NlError, SerError},
    utils::packet_length,
    Buffer, GenlBuffer, Nl,
};

impl<T, P> Nl for GenlBuffer<T, P>
where
    T: NlAttrType,
    P: Nl + std::fmt::Debug,
{
    fn serialize(&self, mem: BytesMut) -> Result<BytesMut, SerError> {
        self.as_slice().serialize(mem)
    }

    fn deserialize(mem: Bytes) -> Result<Self, DeError> {
        let mut vec = SmallVec::new();
        let mut pos = 0;
        while pos < mem.len() {
            let (attr, pos_tmp) = drive_deserialize!(
                Nlattr<T, P>,
                mem,
                pos,
                alignto(packet_length(mem.as_ref(), pos))
            );
            vec.push(attr);
            pos = pos_tmp;
        }
        Ok(vec)
    }

    fn type_size() -> Option<usize> {
        None
    }

    fn size(&self) -> usize {
        self.as_slice().size()
    }
}

impl<'a, T, P> Nl for &'a [Nlattr<T, P>]
where
    T: NlAttrType,
    P: Nl,
{
    fn serialize(&self, mut mem: BytesMut) -> Result<BytesMut, SerError> {
        let mut pos = 0;
        for item in self.iter() {
            let (mem_tmp, pos_tmp) = drive_serialize!(item, mem, pos, asize);
            mem = mem_tmp;
            pos = pos_tmp;
        }
        Ok(drive_serialize!(END mem, pos))
    }

    fn deserialize(_: Bytes) -> Result<Self, DeError> {
        unimplemented!("Use deserialize_buf instead")
    }

    fn type_size() -> Option<usize> {
        None
    }

    fn size(&self) -> usize {
        let mut size = 0;
        for attr in self.iter() {
            size += attr.asize()
        }
        size
    }
}

/// Struct representing netlink attributes and payloads
#[derive(Debug, PartialEq)]
pub struct Nlattr<T, P> {
    /// Length of the attribute header and payload together
    pub nla_len: u16,
    /// Enum representing the type of the attribute payload
    pub nla_type: T,
    /// Payload of the attribute - either parsed or a binary buffer
    pub payload: P,
}

impl<T, P> Nlattr<T, P>
where
    T: NlAttrType,
    P: Nl,
{
    /// Get the size of the payload only
    pub fn payload_size(&self) -> usize {
        self.payload.size()
    }
}

impl<T> Nlattr<T, Buffer>
where
    T: NlAttrType,
{
    /// This function will serialize the provided payload
    pub fn new<P>(nla_len: Option<u16>, nla_type: T, payload: P) -> Result<Self, SerError>
    where
        P: Nl,
    {
        let mut attr = Nlattr {
            nla_len: nla_len.unwrap_or(0),
            nla_type,
            payload: SmallVec::new(),
        };
        attr.set_payload(payload)?;
        Ok(attr)
    }

    /// Set the payload to a data type that implements `Nl` -
    /// this function will overwrite the current payload
    pub fn set_payload<P>(&mut self, payload: P) -> Result<(), SerError>
    where
        P: Nl,
    {
        let mut buffer = BytesMut::from(vec![0; payload.size()]);
        buffer = payload.serialize(buffer)?;

        self.payload = SmallVec::from(buffer.as_ref());

        // Update `Nlattr` with new length
        self.nla_len = (self.nla_len.size() + self.nla_type.size() + payload.size()) as u16;

        Ok(())
    }

    /// Add a nested attribute to the end of the payload
    pub fn add_nested_attribute<TT, P>(&mut self, attr: &Nlattr<TT, P>) -> Result<(), SerError>
    where
        TT: NlAttrType,
        P: Nl,
    {
        let attr_size = attr.asize();
        let mut ser_buffer = BytesMut::from(vec![0; attr_size]);
        ser_buffer = attr.serialize(ser_buffer)?;

        self.payload.extend(&ser_buffer);
        self.nla_len += attr.asize() as u16;
        Ok(())
    }

    /// Get an `Nlattr` payload as a provided type
    pub fn get_payload_as<R>(&self) -> Result<R, DeError>
    where
        R: Nl,
    {
        R::deserialize(Bytes::from(self.payload.as_slice()))
    }

    /// Return an `AttrHandle` for attributes nested in the given attribute payload
    #[deprecated(since = "0.5.0", note = "Use get_attr_handle instead")]
    pub fn get_nested_attributes<R>(&self) -> Result<AttrHandle<R>, DeError>
    where
        R: NlAttrType,
    {
        self.get_attr_handle()
    }

    /// Return an `AttrHandle` for attributes nested in the given attribute payload
    pub fn get_attr_handle<R>(&self) -> Result<AttrHandle<R>, DeError>
    where
        R: NlAttrType,
    {
        Ok(AttrHandle::new(GenlBuffer::deserialize(Bytes::from(
            self.payload.as_slice(),
        ))?))
    }
}

impl<T, P> Nl for Nlattr<T, P>
where
    T: NlAttrType,
    P: Nl,
{
    fn serialize(&self, mem: BytesMut) -> Result<BytesMut, SerError> {
        Ok(serialize! {
            PAD self;
            mem;
            self.nla_len, size;
            self.nla_type, size;
            self.payload, size
        })
    }

    fn deserialize(mem: Bytes) -> Result<Self, DeError> {
        Ok(deserialize! {
            STRIP Self;
            mem;
            Nlattr<T, P> {
                nla_len: u16,
                nla_type: T,
                payload: P => (nla_len as usize).checked_sub(
                   u16::type_size().expect("Must be a static size")
                   + T::type_size().expect("Must be a static size")
                )
                .ok_or_else(|| DeError::UnexpectedEOB)?
            } => alignto(nla_len as usize) - nla_len as usize
        })
    }

    fn type_size() -> Option<usize> {
        None
    }

    fn size(&self) -> usize {
        self.nla_len.size() + self.nla_type.size() + self.payload.size()
    }
}

/// Handle returned by `Genlmsghdr` for traversing nested attribute structures
pub enum AttrHandle<'a, T> {
    /// Owned vector
    Owned(GenlBuffer<T, Buffer>),
    /// Vector reference
    Borrowed(&'a [Nlattr<T, Buffer>]),
}

impl<'a, T> AttrHandle<'a, T>
where
    T: NlAttrType,
{
    /// Create new `AttrHandle`
    pub fn new(vec: GenlBuffer<T, Buffer>) -> Self {
        AttrHandle::Owned(vec)
    }

    /// Create new borrowed `AttrHandle`
    pub fn new_borrowed(vec: &'a [Nlattr<T, Buffer>]) -> Self {
        AttrHandle::Borrowed(vec)
    }

    /// Get the underlying `Vec` as a reference
    pub fn get_slice(&self) -> &[Nlattr<T, Buffer>] {
        match *self {
            AttrHandle::Owned(ref v) => v,
            AttrHandle::Borrowed(v) => v,
        }
    }

    /// Get the underlying `Vec` as a mutable reference or return `None`
    pub fn get_vec_mut(&mut self) -> Option<&mut GenlBuffer<T, Buffer>> {
        match self {
            AttrHandle::Owned(ref mut v) => Some(v),
            AttrHandle::Borrowed(_) => None,
        }
    }

    /// Get size of buffer required to hold attributes
    pub fn size(&self) -> usize {
        self.get_slice().asize()
    }

    /// Pass back iterator over attributes
    pub fn iter(&self) -> slice::Iter<Nlattr<T, Buffer>> {
        self.get_slice().iter()
    }

    /// Get the payload of an attribute as a handle for parsing nested attributes
    pub fn get_nested_attributes<S>(&mut self, subattr: T) -> Result<AttrHandle<S>, NlError>
    where
        S: NlAttrType,
    {
        Ok(AttrHandle::new(GenlBuffer::deserialize(Bytes::from(
            self.get_attribute(subattr)
                .ok_or_else(|| NlError::new("Couldn't find specified attribute"))?
                .payload
                .as_slice(),
        ))?))
    }

    /// Get nested attributes from a parsed handle
    pub fn get_attribute<'b>(&'b self, t: T) -> Option<&'b Nlattr<T, Buffer>> {
        for item in self.get_slice().iter() {
            if item.nla_type == t {
                return Some(&item);
            }
        }
        None
    }

    /// Mutably get nested attributes from a parsed handle
    pub fn get_attribute_mut<'b>(&'b mut self, t: T) -> Option<&'b mut Nlattr<T, Buffer>> {
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
    where
        R: Nl,
    {
        match self.get_attribute(attr) {
            Some(a) => a.get_payload_as::<R>(),
            _ => Err(DeError::new("Failed to find specified attribute")),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use std::io::{Cursor, Write};

    use byteorder::{NativeEndian, WriteBytesExt};

    use crate::{consts::CtrlAttr, nl::NlEmpty};

    #[test]
    fn test_padding_size_calculation() {
        let nlattr = Nlattr::new(None, CtrlAttr::Unspec, 4u16).unwrap();
        assert_eq!(nlattr.size(), 6);
        assert_eq!(nlattr.asize(), 8);
    }

    #[test]
    fn test_nl_nlattr() {
        let nlattr = Nlattr::new(None, CtrlAttr::Unspec, 4u16).unwrap();
        let mut nlattr_serialized = BytesMut::from(vec![0; nlattr.asize()]);
        nlattr_serialized = nlattr.serialize(nlattr_serialized).unwrap();

        let mut nlattr_desired_serialized = Cursor::new(vec![0; nlattr.size()]);
        nlattr_desired_serialized
            .write_u16::<NativeEndian>(6)
            .unwrap();
        nlattr_desired_serialized
            .write_u16::<NativeEndian>(CtrlAttr::Unspec.into())
            .unwrap();
        nlattr_desired_serialized
            .write_u16::<NativeEndian>(4)
            .unwrap();
        nlattr_desired_serialized.write_all(&[0, 0]).unwrap();

        assert_eq!(
            nlattr_serialized.as_ref(),
            nlattr_desired_serialized.into_inner().as_slice()
        );

        let nlattr_desired_deserialized = Nlattr {
            nla_len: 6,
            nla_type: CtrlAttr::Unspec,
            payload: 4u16,
        };

        let mut nlattr_deserialize_buffer =
            Cursor::new(vec![0; nlattr_desired_deserialized.asize()]);
        nlattr_deserialize_buffer
            .write_u16::<NativeEndian>(6)
            .unwrap();
        nlattr_deserialize_buffer
            .write_u16::<NativeEndian>(CtrlAttr::Unspec.into())
            .unwrap();
        nlattr_deserialize_buffer
            .write_u16::<NativeEndian>(4)
            .unwrap();
        nlattr_deserialize_buffer.write_all(&[0, 0]).unwrap();
        let bytes = Bytes::from(nlattr_deserialize_buffer.into_inner());
        let nlattr_deserialized = Nlattr::<CtrlAttr, u16>::deserialize(bytes).unwrap();
        assert_eq!(nlattr_deserialized, nlattr_desired_deserialized);
    }

    #[test]
    fn test_nl_len_after_adding_nested_attributes() {
        let mut nlattr = Nlattr::new::<Vec<u8>>(None, CtrlAttr::Unspec, vec![]).unwrap();
        assert_eq!(nlattr.size(), 4);

        let aligned = Nlattr::new(None, CtrlAttr::Unspec, vec![1, 2, 3, 4]).unwrap();
        assert_eq!(aligned.size(), 8);
        let unaligned = Nlattr::new(None, CtrlAttr::FamilyId, vec![1]).unwrap();
        assert_eq!(unaligned.size(), 5);

        nlattr.add_nested_attribute(&aligned).unwrap();
        assert_eq!(nlattr.size(), 12);

        nlattr.add_nested_attribute(&unaligned).unwrap();
        assert_eq!(nlattr.size(), 20);
        assert_eq!(
            nlattr
                .get_attr_handle()
                .unwrap()
                .get_attribute(CtrlAttr::FamilyId)
                .unwrap()
                .size(),
            5
        );

        nlattr.add_nested_attribute(&aligned).unwrap();
        assert_eq!(nlattr.size(), 28);
    }

    #[test]
    fn test_vec_nlattr_nl() {
        let mut vec_nlattr_desired = Cursor::new(vec![]);

        vec_nlattr_desired.write_u16::<NativeEndian>(36).unwrap();
        vec_nlattr_desired.write_u16::<NativeEndian>(1).unwrap();

        vec_nlattr_desired.write_u16::<NativeEndian>(12).unwrap();
        vec_nlattr_desired.write_u16::<NativeEndian>(1).unwrap();
        vec_nlattr_desired
            .write_all(&[0, 1, 2, 3, 4, 5, 6, 7])
            .unwrap();

        vec_nlattr_desired.write_u16::<NativeEndian>(8).unwrap();
        vec_nlattr_desired.write_u16::<NativeEndian>(2).unwrap();
        vec_nlattr_desired.write_all(&[0, 1, 2, 3]).unwrap();

        vec_nlattr_desired.write_u16::<NativeEndian>(4).unwrap();
        vec_nlattr_desired.write_u16::<NativeEndian>(3).unwrap();

        vec_nlattr_desired.write_u16::<NativeEndian>(6).unwrap();
        vec_nlattr_desired.write_u16::<NativeEndian>(4).unwrap();
        vec_nlattr_desired.write_u16::<NativeEndian>(15).unwrap();
        vec_nlattr_desired.write_all(&[0, 0]).unwrap();

        vec_nlattr_desired.write_u16::<NativeEndian>(6).unwrap();
        vec_nlattr_desired.write_u16::<NativeEndian>(2).unwrap();
        vec_nlattr_desired.write_all(&[0, 1, 0, 0]).unwrap();

        vec_nlattr_desired.write_u16::<NativeEndian>(5).unwrap();
        vec_nlattr_desired.write_u16::<NativeEndian>(3).unwrap();
        vec_nlattr_desired.write_all(&[5, 0, 0, 0]).unwrap();

        let mut nlattr = Nlattr::new(None, 1u16, Vec::<u8>::new()).unwrap();
        nlattr
            .add_nested_attribute(
                &Nlattr::new(None, 1u16, &[0u8, 1, 2, 3, 4, 5, 6, 7] as &[u8]).unwrap(),
            )
            .unwrap();
        nlattr
            .add_nested_attribute(&Nlattr::new(None, 2u16, &[0u8, 1, 2, 3] as &[u8]).unwrap())
            .unwrap();
        nlattr
            .add_nested_attribute(&Nlattr::new(None, 3u16, NlEmpty).unwrap())
            .unwrap();
        nlattr
            .add_nested_attribute(&Nlattr::new(None, 4u16, 15u16).unwrap())
            .unwrap();
        let mut vec = GenlBuffer::new();
        vec.push(nlattr);
        vec.push(Nlattr::new(None, 2u16, vec![0, 1]).unwrap());
        vec.push(Nlattr::new(None, 3u16, 5u8).unwrap());

        let mut bytesmut = BytesMut::from(vec![0; vec.asize()]);
        bytesmut = vec.serialize(bytesmut).unwrap();

        assert_eq!(vec_nlattr_desired.get_ref().as_slice(), bytesmut.as_ref());

        let bytes = Bytes::from(vec_nlattr_desired.into_inner());
        let deserialized = GenlBuffer::deserialize(bytes).unwrap();

        assert_eq!(vec, deserialized);
    }
}
