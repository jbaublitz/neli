//! Module containing various types used across the various netlink
//! structures used in `neli`.
//!
//! # Design decisions
//! These structures are new types rather than type aliases in most
//! cases to allow the internal representation to change without
//! resulting in a breaking change.

use std::{
    fmt::{self, Debug},
    io::{Read, Write},
    iter::FromIterator,
    slice::{Iter, IterMut},
};

use crate::{
    self as neli,
    attr::AttrHandle,
    consts::{genl::NlAttrType, nl::NlType, rtnl::RtaType},
    err::DeError,
    genl::{AttrTypeBuilder, GenlAttrHandle, Nlattr, NlattrBuilder},
    nl::Nlmsghdr,
    rtnl::{RtAttrHandle, Rtattr},
    FromBytesWithInput, Size, ToBytes,
};

/// A buffer of bytes.
#[derive(Clone, PartialEq, Eq, Size)]
pub struct Buffer(Vec<u8>);

impl FromBytesWithInput for Buffer {
    type Input = usize;

    fn from_bytes_with_input(
        buffer: &mut std::io::Cursor<impl AsRef<[u8]>>,
        input: Self::Input,
    ) -> Result<Self, DeError> {
        if buffer.position() as usize + input > buffer.get_ref().as_ref().len() {
            return Err(DeError::InvalidInput(input));
        }

        let mut vec = vec![0u8; input];

        buffer.read_exact(&mut vec)?;

        Ok(Self::from(vec))
    }
}

impl ToBytes for Buffer {
    fn to_bytes(&self, buffer: &mut std::io::Cursor<Vec<u8>>) -> Result<(), crate::err::SerError> {
        buffer.write_all(self.0.as_slice())?;
        Ok(())
    }
}

impl Debug for Buffer {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Buffer")
    }
}

impl AsRef<[u8]> for Buffer {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl AsMut<[u8]> for Buffer {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }
}

impl<'a> From<&'a [u8]> for Buffer {
    fn from(slice: &'a [u8]) -> Self {
        Buffer(Vec::from(slice))
    }
}

impl From<Vec<u8>> for Buffer {
    fn from(vec: Vec<u8>) -> Self {
        Buffer(vec)
    }
}

impl From<Buffer> for Vec<u8> {
    fn from(buf: Buffer) -> Self {
        buf.0
    }
}

impl Buffer {
    /// Create a new general purpose byte buffer.
    pub fn new() -> Self {
        Buffer(Vec::new())
    }

    /// Extend the given buffer with the contents of another slice.
    pub fn extend_from_slice(&mut self, slice: &[u8]) {
        self.0.extend_from_slice(slice)
    }

    /// Get the current length of the buffer.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Default for Buffer {
    fn default() -> Self {
        Self::new()
    }
}

/// A buffer of netlink messages.
#[derive(Debug, PartialEq, Eq, Size, FromBytesWithInput, ToBytes)]
#[neli(from_bytes_bound = "T: NlType")]
#[neli(from_bytes_bound = "P: Size + FromBytesWithInput<Input = usize>")]
pub struct NlBuffer<T, P>(#[neli(input)] Vec<Nlmsghdr<T, P>>);

impl<T, P> FromIterator<Nlmsghdr<T, P>> for NlBuffer<T, P> {
    fn from_iter<I>(i: I) -> Self
    where
        I: IntoIterator<Item = Nlmsghdr<T, P>>,
    {
        NlBuffer(Vec::from_iter(i))
    }
}

impl<T, P> AsRef<[Nlmsghdr<T, P>]> for NlBuffer<T, P> {
    fn as_ref(&self) -> &[Nlmsghdr<T, P>] {
        self.0.as_slice()
    }
}

impl<T, P> NlBuffer<T, P> {
    /// Create a new buffer of netlink messages.
    pub fn new() -> Self {
        NlBuffer(Vec::new())
    }

    /// Add a new netlink message to the end of the buffer.
    pub fn push(&mut self, msg: Nlmsghdr<T, P>) {
        self.0.push(msg);
    }

    /// Get a netlink message from the end of the buffer.
    pub fn pop(&mut self) -> Option<Nlmsghdr<T, P>> {
        self.0.pop()
    }

    /// Return an iterator over immutable references to the elements
    /// in the buffer.
    pub fn iter(&self) -> Iter<'_, Nlmsghdr<T, P>> {
        self.0.iter()
    }

    /// Return an iterator over mutable references to the elements
    /// in the buffer.
    pub fn iter_mut(&mut self) -> IterMut<'_, Nlmsghdr<T, P>> {
        self.0.iter_mut()
    }

    /// Returns the number of elements in the buffer.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether the number of elements in the buffer is 0.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<T, P> IntoIterator for NlBuffer<T, P> {
    type Item = Nlmsghdr<T, P>;
    type IntoIter = <Vec<Nlmsghdr<T, P>> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<T, P> Default for NlBuffer<T, P> {
    fn default() -> Self {
        Self::new()
    }
}

/// A buffer of generic netlink attributes.
#[derive(Clone, Debug, PartialEq, Eq, ToBytes, FromBytesWithInput)]
#[neli(to_bytes_bound = "T: NlAttrType")]
#[neli(from_bytes_bound = "T: NlAttrType")]
#[neli(from_bytes_bound = "P: FromBytesWithInput<Input = usize>")]
pub struct GenlBuffer<T, P>(#[neli(input)] Vec<Nlattr<T, P>>);

impl<T, P> neli::Size for GenlBuffer<T, P>
where
    T: Size,
    P: Size,
{
    fn unpadded_size(&self) -> usize {
        self.0.iter().map(|attr| attr.padded_size()).sum()
    }
}

impl<T> GenlBuffer<T, Buffer> {
    /// Get a data structure with an immutable reference to the
    /// underlying [`Nlattr`]s.
    pub fn get_attr_handle(&self) -> AttrHandle<Self, Nlattr<T, Buffer>> {
        AttrHandle::new_borrowed(self.0.as_ref())
    }
}

impl GenlBuffer<u16, Buffer> {
    /// Convert a [`GenlBuffer`] that can represent all types to a buffer that
    /// is of a particular type.
    pub fn get_typed_attr_handle<T>(&self) -> Result<GenlAttrHandle<T>, DeError>
    where
        T: NlAttrType,
    {
        Ok(AttrHandle::new({
            let mut attrs = GenlBuffer::new();
            for attr in self.0.iter() {
                attrs.push(
                    NlattrBuilder::default()
                        .nla_type(
                            AttrTypeBuilder::default()
                                .nla_type(T::from(*attr.nla_type().nla_type()))
                                .nla_nested(*attr.nla_type().nla_nested())
                                .nla_network_order(*attr.nla_type().nla_network_order())
                                .build()?,
                        )
                        .nla_payload(attr.nla_payload().clone())
                        .build()?,
                );
            }
            attrs
        }))
    }
}

impl<T, P> AsRef<[Nlattr<T, P>]> for GenlBuffer<T, P> {
    fn as_ref(&self) -> &[Nlattr<T, P>] {
        self.0.as_slice()
    }
}

impl<T, P> AsMut<[Nlattr<T, P>]> for GenlBuffer<T, P> {
    fn as_mut(&mut self) -> &mut [Nlattr<T, P>] {
        self.0.as_mut_slice()
    }
}

impl<T, P> FromIterator<Nlattr<T, P>> for GenlBuffer<T, P> {
    fn from_iter<I>(i: I) -> Self
    where
        I: IntoIterator<Item = Nlattr<T, P>>,
    {
        GenlBuffer(Vec::from_iter(i))
    }
}

impl<T, P> IntoIterator for GenlBuffer<T, P> {
    type Item = Nlattr<T, P>;
    type IntoIter = <Vec<Nlattr<T, P>> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<T, P> GenlBuffer<T, P> {
    /// Create a new buffer of generic netlink attributes.
    pub fn new() -> Self {
        GenlBuffer(Vec::new())
    }

    /// Add a new generic netlink attribute to the end of the buffer.
    pub fn push(&mut self, attr: Nlattr<T, P>) {
        self.0.push(attr)
    }

    /// Get a generic netlink attribute from the end of the buffer.
    pub fn pop(&mut self) -> Option<Nlattr<T, P>> {
        self.0.pop()
    }

    /// Return an iterator over immutable references to the elements
    /// in the buffer.
    pub fn iter(&self) -> Iter<'_, Nlattr<T, P>> {
        self.0.iter()
    }

    /// Return an iterator over mutable references to the elements
    /// in the buffer.
    pub fn iter_mut(&mut self) -> IterMut<'_, Nlattr<T, P>> {
        self.0.iter_mut()
    }

    /// Returns the number of elements in the buffer.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether the number of elements in the buffer is 0.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<T, P> Default for GenlBuffer<T, P> {
    fn default() -> Self {
        Self::new()
    }
}

/// A buffer of rtnetlink attributes.
#[derive(Clone, Debug, FromBytesWithInput, ToBytes)]
#[neli(from_bytes_bound = "T: RtaType")]
#[neli(from_bytes_bound = "P: FromBytesWithInput<Input = usize>")]
pub struct RtBuffer<T, P>(#[neli(input)] Vec<Rtattr<T, P>>);

impl<T, P> neli::Size for RtBuffer<T, P>
where
    T: Size,
    P: Size,
{
    fn unpadded_size(&self) -> usize {
        self.0.iter().map(|attr| attr.padded_size()).sum()
    }
}

impl<T> RtBuffer<T, Buffer> {
    /// Get a data structure with an immutable reference to the
    /// underlying [`Rtattr`]s.
    pub fn get_attr_handle(&self) -> RtAttrHandle<T> {
        AttrHandle::new_borrowed(self.0.as_ref())
    }
}

impl<T, P> FromIterator<Rtattr<T, P>> for RtBuffer<T, P> {
    fn from_iter<I>(i: I) -> Self
    where
        I: IntoIterator<Item = Rtattr<T, P>>,
    {
        RtBuffer(Vec::from_iter(i))
    }
}

impl<T, P> IntoIterator for RtBuffer<T, P> {
    type Item = Rtattr<T, P>;
    type IntoIter = <Vec<Rtattr<T, P>> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<T, P> AsRef<[Rtattr<T, P>]> for RtBuffer<T, P> {
    fn as_ref(&self) -> &[Rtattr<T, P>] {
        self.0.as_slice()
    }
}

impl<T, P> AsMut<[Rtattr<T, P>]> for RtBuffer<T, P> {
    fn as_mut(&mut self) -> &mut [Rtattr<T, P>] {
        self.0.as_mut_slice()
    }
}

impl<T, P> RtBuffer<T, P> {
    /// Create a new buffer of routing netlink attributes.
    pub fn new() -> Self {
        RtBuffer(Vec::new())
    }

    /// Add a new routing netlink attribute to the end of the buffer.
    pub fn push(&mut self, attr: Rtattr<T, P>) {
        self.0.push(attr)
    }

    /// Get a routing netlink attribute from the end of the buffer.
    pub fn pop(&mut self) -> Option<Rtattr<T, P>> {
        self.0.pop()
    }

    /// Return an iterator over immutable references to the elements
    /// in the buffer.
    pub fn iter(&self) -> Iter<'_, Rtattr<T, P>> {
        self.0.iter()
    }

    /// Return an iterator over mutable references to the elements
    /// in the buffer.
    pub fn iter_mut(&mut self) -> IterMut<'_, Rtattr<T, P>> {
        self.0.iter_mut()
    }

    /// Returns the number of elements in the buffer.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether the number of elements in the buffer is 0.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<T, P> Default for RtBuffer<T, P> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::{
        consts::{genl::Index, rtnl::Ifa},
        genl::{AttrTypeBuilder, NlattrBuilder},
        rtnl::RtattrBuilder,
    };

    #[test]
    fn test_genlbuffer_align() {
        assert_eq!(
            vec![
                NlattrBuilder::default()
                    .nla_type(
                        AttrTypeBuilder::default()
                            .nla_type(Index::from(0))
                            .build()
                            .unwrap(),
                    )
                    .nla_payload(0u8)
                    .build()
                    .unwrap(),
                NlattrBuilder::default()
                    .nla_type(
                        AttrTypeBuilder::default()
                            .nla_type(Index::from(1))
                            .build()
                            .unwrap(),
                    )
                    .nla_payload(1u8)
                    .build()
                    .unwrap(),
                NlattrBuilder::default()
                    .nla_type(
                        AttrTypeBuilder::default()
                            .nla_type(Index::from(2))
                            .build()
                            .unwrap(),
                    )
                    .nla_payload(2u8)
                    .build()
                    .unwrap(),
            ]
            .into_iter()
            .collect::<GenlBuffer<Index, Buffer>>()
            .unpadded_size(),
            24
        )
    }

    #[test]
    fn test_rtbuffer_align() {
        assert_eq!(
            vec![
                RtattrBuilder::default()
                    .rta_type(Ifa::Unspec)
                    .rta_payload(0u8)
                    .build()
                    .unwrap(),
                RtattrBuilder::default()
                    .rta_type(Ifa::Address)
                    .rta_payload(1u8)
                    .build()
                    .unwrap(),
                RtattrBuilder::default()
                    .rta_type(Ifa::Local)
                    .rta_payload(2u8)
                    .build()
                    .unwrap(),
            ]
            .into_iter()
            .collect::<RtBuffer<Ifa, Buffer>>()
            .unpadded_size(),
            24
        )
    }
}
