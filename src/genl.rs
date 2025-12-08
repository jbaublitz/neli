//! This module contains generic netlink parsing data structures.
//! This is all handled by the [`Genlmsghdr`]
//! header struct which contains all of the information needed for
//! the generic netlink layer.
//!
//! # Design decisions
//!
//! The generic netlink `attrs` field has been changed to a
//! [`GenlBuffer`] of [`Nlattr`]s instead of the
//! original [`Vec<u8>`][Vec] to allow simpler parsing at the top
//! level when one [`Nlattr`] structure is not
//! nested within another, a use case that is instead handled using
//! [`AttrHandle`].

use std::io::Cursor;

use derive_builder::{Builder, UninitializedFieldError};
use getset::Getters;

use crate::{
    self as neli,
    attr::{AttrHandle, Attribute},
    consts::genl::{Cmd, NlAttrType},
    err::{DeError, SerError},
    types::{Buffer, GenlBuffer},
    FromBytes, FromBytesWithInput, FromBytesWithInputBorrowed, Header, Size, ToBytes, TypeSize,
};

/// Struct indicating that no user header is in the generic netlink packet.
#[derive(Clone, Debug, PartialEq, Eq, Size, ToBytes, FromBytes)]
pub struct NoUserHeader;

impl TypeSize for NoUserHeader {
    fn type_size() -> usize {
        0
    }
}

/// Struct representing generic netlink header and payload
#[derive(
    Builder, Getters, Clone, Debug, PartialEq, Eq, Size, ToBytes, FromBytesWithInput, Header,
)]
#[neli(to_bytes_bound = "C: Cmd")]
#[neli(to_bytes_bound = "T: NlAttrType")]
#[neli(from_bytes_bound = "C: Cmd + TypeSize")]
#[neli(from_bytes_bound = "T: NlAttrType")]
#[neli(header_bound = "C: TypeSize")]
#[neli(from_bytes_bound = "H: TypeSize + FromBytes")]
#[neli(header_bound = "H: TypeSize")]
#[builder(pattern = "owned")]
#[builder(build_fn(skip))]
pub struct Genlmsghdr<C, T, H = NoUserHeader> {
    /// Generic netlink message command
    #[getset(get = "pub")]
    cmd: C,
    /// Version of generic netlink family protocol
    #[getset(get = "pub")]
    version: u8,
    #[builder(setter(skip))]
    reserved: u16,
    /// User specific header to send with netlink packet; defaults to an empty type
    /// to maintain backwards compatibility
    #[getset(get = "pub")]
    header: H,
    /// Attributes included in generic netlink message
    #[getset(get = "pub")]
    #[neli(input = "input.checked_sub(Self::header_size()).ok_or(DeError::InvalidInput(input))?")]
    attrs: GenlBuffer<T, Buffer>,
}

impl<C, T> GenlmsghdrBuilder<C, T, NoUserHeader> {
    /// Build a [`Genlmsghdr`].
    pub fn build(self) -> Result<Genlmsghdr<C, T>, GenlmsghdrBuilderError> {
        let cmd = self
            .cmd
            .ok_or_else(|| GenlmsghdrBuilderError::from(UninitializedFieldError::new("cmd")))?;
        let version = self
            .version
            .ok_or_else(|| GenlmsghdrBuilderError::from(UninitializedFieldError::new("version")))?;
        let reserved = 0;
        let header = self.header.unwrap_or(NoUserHeader);
        let attrs = self.attrs.unwrap_or_default();

        Ok(Genlmsghdr {
            cmd,
            version,
            reserved,
            header,
            attrs,
        })
    }
}

impl<C, T, H> GenlmsghdrBuilder<C, T, H> {
    /// Build a [`Genlmsghdr`] with a required user header type.
    pub fn build_with_header(self) -> Result<Genlmsghdr<C, T, H>, GenlmsghdrBuilderError> {
        let cmd = self
            .cmd
            .ok_or_else(|| GenlmsghdrBuilderError::from(UninitializedFieldError::new("cmd")))?;
        let version = self
            .version
            .ok_or_else(|| GenlmsghdrBuilderError::from(UninitializedFieldError::new("version")))?;
        let reserved = 0;
        let header = self
            .header
            .ok_or_else(|| GenlmsghdrBuilderError::from(UninitializedFieldError::new("header")))?;
        let attrs = self.attrs.unwrap_or_default();

        Ok(Genlmsghdr {
            cmd,
            version,
            reserved,
            header,
            attrs,
        })
    }
}

/// The infomation packed into `nla_type` field of `nlattr`
/// for the C data structure.
#[derive(Builder, Getters, Debug, PartialEq, Eq, Clone)]
#[builder(pattern = "owned")]
pub struct AttrType<T> {
    /// If true, the payload contains nested attributes.
    #[getset(get = "pub")]
    #[builder(default = "false")]
    nla_nested: bool,
    /// If true, the payload is in net work byte order.
    #[getset(get = "pub")]
    #[builder(default = "false")]
    nla_network_order: bool,
    /// Enum representing the type of the attribute payload
    #[getset(get = "pub")]
    nla_type: T,
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

impl<T> FromBytes for AttrType<T>
where
    T: NlAttrType,
{
    fn from_bytes(buffer: &mut Cursor<impl AsRef<[u8]>>) -> Result<Self, DeError> {
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
#[derive(Builder, Getters, Clone, Debug, PartialEq, Eq, Size, FromBytes, ToBytes, Header)]
#[neli(from_bytes_bound = "T: NlAttrType")]
#[neli(from_bytes_bound = "P: FromBytesWithInput<Input = usize>")]
#[neli(to_bytes_bound = "T: NlAttrType")]
#[neli(header_bound = "T: TypeSize")]
#[neli(padding)]
#[builder(pattern = "owned")]
#[builder(build_fn(skip))]
pub struct Nlattr<T, P> {
    /// Length of the attribute header and payload together
    #[getset(get = "pub")]
    #[builder(setter(skip))]
    nla_len: u16,
    /// Type information for the netlink attribute
    #[getset(get = "pub")]
    nla_type: AttrType<T>,
    /// Payload of the attribute - either parsed or a binary buffer
    #[neli(
        input = "(nla_len as usize).checked_sub(Self::header_size()).ok_or(DeError::InvalidInput(nla_len as usize))?"
    )]
    #[getset(get = "pub")]
    nla_payload: P,
}

impl<T, P> NlattrBuilder<T, P>
where
    T: Size,
    P: Size + ToBytes,
{
    /// Build [`Nlattr`].
    pub fn build(self) -> Result<Nlattr<T, Buffer>, NlattrBuilderError> {
        let nla_type = self
            .nla_type
            .ok_or_else(|| NlattrBuilderError::from(UninitializedFieldError::new("nla_type")))?;
        let nla_payload = self
            .nla_payload
            .ok_or_else(|| NlattrBuilderError::from(UninitializedFieldError::new("nla_payload")))?;
        let mut buffer = Cursor::new(vec![0; nla_payload.unpadded_size()]);
        nla_payload.to_bytes(&mut buffer).map_err(|_| {
            NlattrBuilderError::ValidationError(
                "Could not convert payload to binary representation".to_string(),
            )
        })?;
        let mut nlattr = Nlattr {
            nla_len: 0,
            nla_type,
            nla_payload: Buffer::from(buffer.into_inner()),
        };
        nlattr.nla_len = nlattr.unpadded_size() as u16;
        Ok(nlattr)
    }
}

impl<T> Nlattr<T, Buffer>
where
    T: NlAttrType,
{
    /// Builder method to add a nested attribute to the end of the payload.
    ///
    /// Use this to construct an attribute and nest attributes within it in one method chain.
    #[inline]
    pub fn nest<TT, P>(mut self, attr: &Nlattr<TT, P>) -> Result<Self, SerError>
    where
        TT: NlAttrType,
        P: ToBytes,
    {
        self.add_nested_attribute(attr)?;
        Ok(self)
    }

    /// Add a nested attribute to the end of the payload.
    fn add_nested_attribute<TT, P>(&mut self, attr: &Nlattr<TT, P>) -> Result<(), SerError>
    where
        TT: NlAttrType,
        P: ToBytes,
    {
        let mut buffer = Cursor::new(Vec::new());
        self.nla_type.nla_nested = true;
        attr.to_bytes(&mut buffer)?;

        self.nla_payload.extend_from_slice(buffer.get_ref());
        self.nla_len += buffer.get_ref().len() as u16;
        Ok(())
    }

    /// Return an `AttrHandle` for attributes nested in the given attribute payload
    pub fn get_attr_handle<R>(&self) -> Result<GenlAttrHandle<'_, R>, DeError>
    where
        R: NlAttrType,
    {
        Ok(AttrHandle::new(GenlBuffer::from_bytes_with_input(
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

/// Type representing a generic netlink attribute handle.
pub type GenlAttrHandle<'a, T> = AttrHandle<'a, GenlBuffer<T, Buffer>, Nlattr<T, Buffer>>;

impl<'a, T> GenlAttrHandle<'a, T>
where
    T: NlAttrType,
{
    /// Get the payload of an attribute as a handle for parsing
    /// nested attributes
    pub fn get_nested_attributes<S>(&self, subattr: T) -> Result<GenlAttrHandle<'_, S>, DeError>
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
    pub fn get_attr_payload_as<R>(&self, attr: T) -> Result<R, DeError>
    where
        R: FromBytes,
    {
        match self.get_attribute(attr) {
            Some(a) => a.get_payload_as::<R>(),
            _ => Err(DeError::new("Failed to find specified attribute")),
        }
    }

    /// Parse binary payload as a type that implements
    /// [`FromBytesWithInput`]
    pub fn get_attr_payload_as_with_len<R>(&self, attr: T) -> Result<R, DeError>
    where
        R: FromBytesWithInput<Input = usize>,
    {
        match self.get_attribute(attr) {
            Some(a) => a.get_payload_as_with_len::<R>(),
            _ => Err(DeError::new("Failed to find specified attribute")),
        }
    }

    /// Parse binary payload as a type that implements
    /// [`FromBytesWithInputBorrowed`]
    pub fn get_attr_payload_as_with_len_borrowed<R>(&'a self, attr: T) -> Result<R, DeError>
    where
        R: FromBytesWithInputBorrowed<'a, Input = usize>,
    {
        match self.get_attribute(attr) {
            Some(a) => a.get_payload_as_with_len_borrowed::<R>(),
            _ => Err(DeError::new("Failed to find specified attribute")),
        }
    }
}
