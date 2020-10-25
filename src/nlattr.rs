//! This module aims to provide simple parsing for generic netlink attributes, including parsing
//! for nested attributes.
//!
//! Due to netlink's loose treatment of types, parsing attributes can be hard to model in
//! Rust. `neli`'s current solution is the following:
//!
//! ```no_run
//! use neli::types::GenlBufferOps;
//!
//! // This was received from the socket
//! let nlmsg = neli::nl::Nlmsghdr::new(None, neli::consts::GenlId::Ctrl, neli::consts::NlmFFlags::empty(), None, None,
//!         neli::nl::NlPayload::Payload(neli::genl::Genlmsghdr::new(neli::consts::CtrlCmd::Unspec, 2, neli::types::GenlBuffer::new())));
//!
//! // Get parsing handler for the attributes in this message where the next call
//! // to either get_nested_attributes() or get_payload_with() will expect a u16 type
//! // to be provided
//! let mut handle = nlmsg.get_payload().unwrap().get_attr_handle();
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

use crate::{
    consts::{alignto, NlAttrType},
    err::{DeError, NlError, SerError},
    parse::packet_length_u16,
    types::{
        Buffer, BufferOps, DeBuffer, DeBufferOps, GenlBuffer, GenlBufferOps, SerBuffer,
        SerBufferOps,
    },
    Nl,
};

impl<T, P> Nl for GenlBuffer<T, P>
where
    T: NlAttrType,
    P: Nl + std::fmt::Debug,
{
    fn serialize<'a>(&self, mem: SerBuffer<'a>) -> Result<SerBuffer<'a>, SerError<'a>> {
        self.as_ref().serialize(mem)
    }

    fn deserialize(mem: DeBuffer) -> Result<Self, DeError> {
        let mut vec = GenlBuffer::new();
        let mut pos = 0;
        while pos < mem.len() {
            let (attr, pos_tmp) = drive_deserialize!(
                Nlattr<T, P>,
                mem,
                pos,
                alignto(packet_length_u16(mem.as_ref(), pos))
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
        self.as_ref().size()
    }
}

impl<'a, T, P> Nl for &'a [Nlattr<T, P>]
where
    T: NlAttrType,
    P: Nl,
{
    fn serialize<'b>(&self, mut mem: SerBuffer<'b>) -> Result<SerBuffer<'b>, SerError<'b>> {
        let mut pos = 0;
        for item in self.iter() {
            let (mem_tmp, pos_tmp) = drive_serialize!(item, mem, pos, asize);
            mem = mem_tmp;
            pos = pos_tmp;
        }
        Ok(drive_serialize!(END mem, pos))
    }

    fn deserialize(_: DeBuffer) -> Result<Self, DeError> {
        Err(DeError::new(
            "Deserialize a GenlBuffer and call .as_slice()",
        ))
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
    /// If true, the payload contains nested attributes.
    pub nla_nested: bool,
    /// If true, the payload is in net work byte order.
    pub nla_network_order: bool,
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
    /// Create a new `Nlattr` with parameters for setting bitflags
    /// in the header.
    pub fn new<P>(
        nla_len: Option<u16>,
        nla_nested: bool,
        nla_network_order: bool,
        nla_type: T,
        payload: P,
    ) -> Result<Self, NlError>
    where
        P: Nl,
    {
        let mut attr = Nlattr {
            nla_len: nla_len.unwrap_or(0),
            nla_nested,
            nla_network_order,
            nla_type,
            payload: Buffer::new(),
        };
        attr.set_payload(payload).map_err(|e| {
            NlError::new(format!("Failed to convert payload to a byte buffer: {}", e))
        })?;
        Ok(attr)
    }

    /// Set the payload to a data type that implements `Nl` -
    /// this function will overwrite the current payload
    pub fn set_payload<P>(&mut self, payload: P) -> Result<(), NlError>
    where
        P: Nl,
    {
        let mut ser_buffer = SerBuffer::new(Some(payload.size()));
        ser_buffer = payload.serialize(ser_buffer).map_err(NlError::new)?;
        let mut buffer = Buffer::new();
        buffer.extend_from_slice(ser_buffer.as_ref());
        self.payload = buffer;

        // Update `Nlattr` with new length
        self.nla_len = (self.nla_len.size() + self.nla_type.size() + payload.size()) as u16;

        Ok(())
    }

    /// Add a nested attribute to the end of the payload.
    pub fn add_nested_attribute<TT, P>(&mut self, attr: &Nlattr<TT, P>) -> Result<(), NlError>
    where
        TT: NlAttrType,
        P: Nl,
    {
        let mut ser_buffer = SerBuffer::new(Some(attr.asize()));
        ser_buffer = attr.serialize(ser_buffer).map_err(NlError::new)?;

        self.payload.extend_from_slice(ser_buffer.as_ref());
        self.nla_len += attr.asize() as u16;
        Ok(())
    }

    /// Get an `Nlattr` payload as a provided type
    pub fn get_payload_as<R>(&self) -> Result<R, NlError>
    where
        R: Nl,
    {
        R::deserialize(DeBuffer::from(self.payload.as_ref())).map_err(NlError::new)
    }

    /// Return an `AttrHandle` for attributes nested in the given attribute payload
    pub fn get_attr_handle<R>(&self) -> Result<AttrHandle<R>, NlError>
    where
        R: NlAttrType,
    {
        Ok(AttrHandle::new(
            GenlBuffer::deserialize(DeBuffer::from(self.payload.as_ref())).map_err(NlError::new)?,
        ))
    }
}

/// Generate the bitflag mask for `nla_type`.
fn to_nla_type_bit_flags<T>(nla_nested: bool, nla_network_order: bool, nla_type: T) -> u16
where
    T: NlAttrType,
{
    let nla_type_u16: u16 = nla_type.into();
    (if nla_nested { 1 << 15 } else { 0u16 })
        | (if nla_network_order { 1 << 14 } else { 0u16 })
        | nla_type_u16
}

/// Get the bitflags from `nla_type`.
fn from_nla_type_bit_flags<T>(nla_type: u16) -> (bool, bool, T)
where
    T: NlAttrType,
{
    (
        nla_type & (1 << 15) != 0,
        nla_type & (1 << 14) != 0,
        T::from(nla_type & !(3 << 14)),
    )
}

impl<T, P> Nl for Nlattr<T, P>
where
    T: NlAttrType,
    P: Nl,
{
    fn serialize<'a>(&self, mem: SerBuffer<'a>) -> Result<SerBuffer<'a>, SerError<'a>> {
        let nla_type =
            to_nla_type_bit_flags(self.nla_nested, self.nla_network_order, self.nla_type);
        Ok(serialize! {
            PAD self;
            mem;
            self.nla_len, size;
            nla_type, size;
            self.payload, size
        })
    }

    fn deserialize(mem: DeBuffer) -> Result<Self, DeError> {
        let pos = 0;
        let (nla_len, pos) = drive_deserialize!(u16, mem, pos);
        let (nla_type, pos) = drive_deserialize!(u16, mem, pos);
        let (payload, pos) = drive_deserialize!(
            P,
            mem,
            pos,
            (nla_len as usize)
                .checked_sub(
                    u16::type_size().expect("Must be a static size")
                        + T::type_size().expect("Must be a static size")
                )
                .ok_or(DeError::UnexpectedEOB)?
        );
        let pos = drive_deserialize!(
            STRIP mem, pos, alignto(nla_len as usize) - nla_len as usize
        );
        drive_deserialize!(END mem, pos);

        let (nla_nested, nla_network_order, nla_type) = from_nla_type_bit_flags(nla_type);
        Ok(Nlattr::<T, P> {
            nla_len,
            nla_type,
            nla_nested,
            nla_network_order,
            payload,
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
            AttrHandle::Owned(ref v) => v.as_ref(),
            AttrHandle::Borrowed(v) => v,
        }
    }

    /// Get the underlying `Vec` as a mutable reference or return `None`
    pub fn get_mut_attrs(&mut self) -> Option<&mut GenlBuffer<T, Buffer>> {
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
        Ok(AttrHandle::new(
            GenlBuffer::deserialize(DeBuffer::from(
                self.get_attribute(subattr)
                    .ok_or_else(|| NlError::new("Couldn't find specified attribute"))?
                    .payload
                    .as_ref(),
            ))
            .map_err(NlError::new)?,
        ))
    }

    /// Get nested attributes from a parsed handle
    pub fn get_attribute(&self, t: T) -> Option<&Nlattr<T, Buffer>> {
        for item in self.get_slice().iter() {
            if item.nla_type == t {
                return Some(&item);
            }
        }
        None
    }

    /// Mutably get nested attributes from a parsed handle
    pub fn get_attribute_mut(&mut self, t: T) -> Option<&mut Nlattr<T, Buffer>> {
        let vec_mut = self.get_mut_attrs()?;
        for item in vec_mut.iter_mut() {
            if item.nla_type == t {
                return Some(item);
            }
        }
        None
    }

    /// Parse binary payload as a type that implements `Nl` using `deserialize` with an option size
    /// hint
    pub fn get_attr_payload_as<R>(&self, attr: T) -> Result<R, NlError>
    where
        R: Nl,
    {
        match self.get_attribute(attr) {
            Some(a) => a.get_payload_as::<R>(),
            _ => Err(NlError::new("Failed to find specified attribute")),
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
        let nlattr = Nlattr::new(None, false, false, CtrlAttr::Unspec, 4u16).unwrap();
        assert_eq!(nlattr.size(), 6);
        assert_eq!(nlattr.asize(), 8);
    }

    #[test]
    fn test_nlattr_bitflags() {
        let type_ = 3 << 14;
        assert_eq!((true, true, 0), from_nla_type_bit_flags(type_))
    }

    #[test]
    fn test_nl_nlattr() {
        let nlattr = Nlattr::new(None, false, false, CtrlAttr::Unspec, 4u16).unwrap();
        let mut nlattr_serialized = SerBuffer::new(Some(nlattr.asize()));
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
            nla_nested: false,
            nla_network_order: false,
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
        let bytes = DeBuffer::from(nlattr_deserialize_buffer.get_ref().as_slice());
        let nlattr_deserialized = Nlattr::<CtrlAttr, u16>::deserialize(bytes).unwrap();
        assert_eq!(nlattr_deserialized, nlattr_desired_deserialized);
    }

    #[test]
    fn test_nl_len_after_adding_nested_attributes() {
        let mut nlattr =
            Nlattr::new::<Vec<u8>>(None, true, false, CtrlAttr::Unspec, vec![]).unwrap();
        assert_eq!(nlattr.size(), 4);

        let aligned = Nlattr::new(None, false, false, CtrlAttr::Unspec, vec![1, 2, 3, 4]).unwrap();
        assert_eq!(aligned.size(), 8);
        let unaligned = Nlattr::new(None, false, false, CtrlAttr::FamilyId, vec![1]).unwrap();
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
        vec_nlattr_desired
            .write_u16::<NativeEndian>(1 << 15 | 1)
            .unwrap();

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

        let mut nlattr = Nlattr::new(None, true, false, 1u16, Vec::<u8>::new()).unwrap();
        nlattr
            .add_nested_attribute(
                &Nlattr::new(
                    None,
                    false,
                    false,
                    1u16,
                    &[0u8, 1, 2, 3, 4, 5, 6, 7] as &[u8],
                )
                .unwrap(),
            )
            .unwrap();
        nlattr
            .add_nested_attribute(
                &Nlattr::new(None, false, false, 2u16, &[0u8, 1, 2, 3] as &[u8]).unwrap(),
            )
            .unwrap();
        nlattr
            .add_nested_attribute(&Nlattr::new(None, false, false, 3u16, NlEmpty).unwrap())
            .unwrap();
        nlattr
            .add_nested_attribute(&Nlattr::new(None, false, false, 4u16, 15u16).unwrap())
            .unwrap();
        let mut vec = GenlBuffer::new();
        vec.push(nlattr);
        vec.push(Nlattr::new(None, false, false, 2u16, vec![0, 1]).unwrap());
        vec.push(Nlattr::new(None, false, false, 3u16, 5u8).unwrap());

        let mut bytesmut = SerBuffer::new(Some(vec.asize()));
        bytesmut = vec.serialize(bytesmut).unwrap();

        assert_eq!(vec_nlattr_desired.get_ref().as_slice(), bytesmut.as_ref());

        let bytes = DeBuffer::from(vec_nlattr_desired.get_ref().as_slice());
        let deserialized = GenlBuffer::deserialize(bytes).unwrap();

        assert_eq!(vec, deserialized);
    }
}
