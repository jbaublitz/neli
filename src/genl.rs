//! This module contains generic netlink parsing data structures.
//! This is all handled by the [`Genlmsghdr`]
//! header struct which contains all of the information needed for
//! the generic netlink layer.
//!
//! # Design decisions
//!
//! The generic netlink `attrs` field has been changed to a
//! [`GenlBuffer`] of
//! [`Nlattr`]s instead of the
//! original [`Vec<u8>`][Vec] to allow simpler parsing at the top
//! level when one [`Nlattr`] structure is not
//! nested within another, a use case that is instead handled using
//! [`AttrHandle`].

use crate as neli;

use std::io::Cursor;

use crate::{
    attr::{AttrHandle, AttrHandleMut, Attribute},
    consts::genl::{Cmd, NlAttrType},
    err::{DeError, SerError},
    types::{Buffer, GenlBuffer},
    FromBytes, FromBytesWithInput, Header, Size, ToBytes, TypeSize,
};

/// Struct indicating that no user header is in the generic netlink packet.
#[derive(Debug, PartialEq, Eq, Size, ToBytes, FromBytes)]
pub struct NoUserHeader;

impl TypeSize for NoUserHeader {
    fn type_size() -> usize {
        0
    }
}

/// Struct representing generic netlink header and payload
#[derive(Debug, PartialEq, Eq, Size, ToBytes, FromBytesWithInput, Header)]
#[neli(to_bytes_bound = "C: Cmd")]
#[neli(to_bytes_bound = "T: NlAttrType")]
#[neli(from_bytes_bound = "C: Cmd + TypeSize")]
#[neli(from_bytes_bound = "T: NlAttrType")]
#[neli(header_bound = "C: TypeSize")]
#[neli(from_bytes_bound = "H: TypeSize + FromBytes")]
#[neli(header_bound = "H: TypeSize")]
pub struct Genlmsghdr<C, T, H = NoUserHeader> {
    /// Generic netlink message command
    pub cmd: C,
    /// Version of generic netlink family protocol
    pub version: u8,
    reserved: u16,
    /// User specific header to send with netlink packet; defaults to an empty type
    /// to maintain backwards compatibility
    pub header: H,
    /// Attributes included in generic netlink message
    #[neli(input = "input - Self::header_size()")]
    attrs: GenlBuffer<T, Buffer>,
}

impl<C, T> Genlmsghdr<C, T>
where
    C: Cmd,
    T: NlAttrType,
{
    /// Create new generic netlink packet
    pub fn new(cmd: C, version: u8, attrs: GenlBuffer<T, Buffer>) -> Self {
        Genlmsghdr {
            cmd,
            version,
            reserved: 0,
            header: NoUserHeader,
            attrs,
        }
    }

    /// Get handle for attribute parsing and traversal
    pub fn get_attr_handle(&self) -> AttrHandle<GenlBuffer<T, Buffer>, Nlattr<T, Buffer>> {
        self.attrs.get_attr_handle()
    }

    /// Get handle for attribute mutable and traversal
    pub fn get_attr_handle_mut(
        &mut self,
    ) -> AttrHandleMut<GenlBuffer<T, Buffer>, Nlattr<T, Buffer>> {
        self.attrs.get_attr_handle_mut()
    }
}

impl<C, T, H> Genlmsghdr<C, T, H> {
    /// Create a new netlink struct with a user header
    pub fn new_with_user_header(
        cmd: C,
        version: u8,
        header: H,
        attrs: GenlBuffer<T, Buffer>,
    ) -> Self {
        Genlmsghdr {
            cmd,
            version,
            reserved: 0,
            header,
            attrs,
        }
    }
}

/// The infomation packed into `nla_type` field of `nlattr`
/// for the C data structure.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AttrType<T> {
    /// If true, the payload contains nested attributes.
    pub nla_nested: bool,
    /// If true, the payload is in net work byte order.
    pub nla_network_order: bool,
    /// Enum representing the type of the attribute payload
    pub nla_type: T,
}

impl<T> Size for AttrType<T>
where
    T: Size,
{
    fn unpadded_size(&self) -> usize {
        self.nla_type.unpadded_size()
    }
}

impl<T> TypeSize for AttrType<T>
where
    T: TypeSize,
{
    fn type_size() -> usize {
        T::type_size()
    }
}

impl<T> ToBytes for AttrType<T>
where
    T: NlAttrType,
{
    fn to_bytes(&self, buffer: &mut Cursor<Vec<u8>>) -> Result<(), SerError> {
        let int: u16 = self.into();
        int.to_bytes(buffer)
    }
}

impl<'lt, T> FromBytes<'lt> for AttrType<T>
where
    T: NlAttrType,
{
    fn from_bytes(buffer: &mut Cursor<&'lt [u8]>) -> Result<Self, DeError> {
        let int = u16::from_bytes(buffer)?;
        Ok(AttrType::from(int))
    }
}

impl<T> From<AttrType<T>> for u16
where
    T: NlAttrType,
{
    fn from(v: AttrType<T>) -> Self {
        let mut int: u16 = v.nla_type.into();
        int |= u16::from(v.nla_nested) << 15;
        int |= u16::from(v.nla_network_order) << 14;
        int
    }
}

impl<'a, T> From<&'a AttrType<T>> for u16
where
    T: NlAttrType,
{
    fn from(v: &'a AttrType<T>) -> Self {
        let mut int: u16 = v.nla_type.into();
        int |= u16::from(v.nla_nested) << 15;
        int |= u16::from(v.nla_network_order) << 14;
        int
    }
}

impl<T> From<u16> for AttrType<T>
where
    T: NlAttrType,
{
    fn from(int: u16) -> Self {
        AttrType {
            nla_nested: (int & 1 << 15) == (1 << 15),
            nla_network_order: (int & 1 << 14) == (1 << 14),
            nla_type: T::from(!(3 << 14) & int),
        }
    }
}

/// Struct representing netlink attributes and payloads
#[derive(Debug, PartialEq, Eq, Size, FromBytes, ToBytes, Header)]
#[neli(from_bytes_bound = "T: NlAttrType")]
#[neli(from_bytes_bound = "P: FromBytesWithInput<Input = usize>")]
#[neli(to_bytes_bound = "T: NlAttrType")]
#[neli(header_bound = "T: TypeSize")]
#[neli(padding)]
pub struct Nlattr<T, P> {
    /// Length of the attribute header and payload together
    pub nla_len: u16,
    /// Type information for the netlink attribute
    pub nla_type: AttrType<T>,
    /// Payload of the attribute - either parsed or a binary buffer
    #[neli(input = "nla_len as usize - Self::header_size()")]
    pub nla_payload: P,
}

impl<T> Nlattr<T, Buffer>
where
    T: NlAttrType,
{
    /// Create a new `Nlattr` with parameters for setting bitflags
    /// in the header.
    pub fn new<P>(
        nla_nested: bool,
        nla_network_order: bool,
        nla_type: T,
        nla_payload: P,
    ) -> Result<Self, SerError>
    where
        P: Size + ToBytes,
    {
        let mut attr = Nlattr {
            nla_len: Self::header_size() as u16,
            nla_type: AttrType {
                nla_nested,
                nla_network_order,
                nla_type,
            },
            nla_payload: Buffer::new(),
        };
        attr.set_payload(&nla_payload)?;
        Ok(attr)
    }

    /// Add a nested attribute to the end of the payload.
    pub fn add_nested_attribute<TT, P>(&mut self, attr: &Nlattr<TT, P>) -> Result<(), SerError>
    where
        TT: NlAttrType,
        P: ToBytes,
    {
        let mut buffer = Cursor::new(Vec::new());
        attr.to_bytes(&mut buffer)?;

        self.nla_payload.extend_from_slice(buffer.get_ref());
        self.nla_len += buffer.get_ref().len() as u16;
        Ok(())
    }

    /// Return an `AttrHandle` for attributes nested in the given attribute payload
    pub fn get_attr_handle<R>(&self) -> Result<GenlAttrHandle<R>, DeError>
    where
        R: NlAttrType,
    {
        Ok(AttrHandle::new(GenlBuffer::from_bytes_with_input(
            &mut Cursor::new(self.nla_payload.as_ref()),
            self.nla_payload.unpadded_size(),
        )?))
    }

    /// Return a mutable `AttrHandle` for attributes nested in the given attribute payload
    pub fn get_attr_handle_mut<R>(&mut self) -> Result<GenlAttrHandleMut<R>, DeError>
    where
        R: NlAttrType,
    {
        Ok(AttrHandleMut::new(GenlBuffer::from_bytes_with_input(
            &mut Cursor::new(self.nla_payload.as_ref()),
            self.nla_payload.unpadded_size(),
        )?))
    }
}

impl<T> Attribute<T> for Nlattr<T, Buffer>
where
    T: NlAttrType,
{
    fn payload(&self) -> &Buffer {
        &self.nla_payload
    }

    fn set_payload<P>(&mut self, payload: &P) -> Result<(), SerError>
    where
        P: Size + ToBytes,
    {
        let mut buffer = Cursor::new(Vec::new());
        payload.to_bytes(&mut buffer)?;

        // Update Nlattr with new length
        self.nla_len -= self.nla_payload.unpadded_size() as u16;
        self.nla_len += buffer.get_ref().len() as u16;

        self.nla_payload = Buffer::from(buffer.into_inner());

        Ok(())
    }
}

type GenlAttrHandle<'a, T> = AttrHandle<'a, GenlBuffer<T, Buffer>, Nlattr<T, Buffer>>;
type GenlAttrHandleMut<'a, T> = AttrHandleMut<'a, GenlBuffer<T, Buffer>, Nlattr<T, Buffer>>;

impl<T> AttrHandle<'_, GenlBuffer<T, Buffer>, Nlattr<T, Buffer>>
where
    T: NlAttrType,
{
    /// Get the payload of an attribute as a handle for parsing
    /// nested attributes
    pub fn get_nested_attributes<S>(&mut self, subattr: T) -> Result<GenlAttrHandle<S>, DeError>
    where
        S: NlAttrType,
    {
        let attr = self
            .get_attribute(subattr)
            .ok_or_else(|| DeError::new("Couldn't find specified attribute"))?;
        Ok(AttrHandle::new(GenlBuffer::from_bytes_with_input(
            &mut Cursor::new(attr.nla_payload.as_ref()),
            attr.nla_payload.unpadded_size(),
        )?))
    }

    /// Get nested attributes from a parsed handle
    pub fn get_attribute(&self, t: T) -> Option<&Nlattr<T, Buffer>> {
        self.get_attrs()
            .iter()
            .find(|item| item.nla_type.nla_type == t)
    }

    /// Parse binary payload as a type that implements [`FromBytes`].
    pub fn get_attr_payload_as<'b, R>(&'b self, attr: T) -> Result<R, DeError>
    where
        R: FromBytes<'b>,
    {
        match self.get_attribute(attr) {
            Some(a) => a.get_payload_as::<R>(),
            _ => Err(DeError::new("Failed to find specified attribute")),
        }
    }

    /// Parse binary payload as a type that implements
    /// [`FromBytesWithInput`]
    pub fn get_attr_payload_as_with_len<'b, R>(&'b self, attr: T) -> Result<R, DeError>
    where
        R: FromBytesWithInput<'b, Input = usize>,
    {
        match self.get_attribute(attr) {
            Some(a) => a.get_payload_as_with_len::<R>(),
            _ => Err(DeError::new("Failed to find specified attribute")),
        }
    }
}
