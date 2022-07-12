//! Module containing various types used across the various netlink
//! structures used in `neli`.
//!
//! # Design decisions
//! These structures are new types rather than type aliases in most
//! cases to allow the internal representation to change without
//! resulting in a breaking change.

use crate as neli;

use std::{
    fmt::{self, Debug},
    iter::FromIterator,
    marker::PhantomData,
    ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, Not},
    slice::{Iter, IterMut},
};

use crate::{
    attr::{AttrHandle, AttrHandleMut},
    consts::{genl::NlAttrType, nl::NlType, rtnl::RtaType},
    genl::Nlattr,
    nl::Nlmsghdr,
    rtnl::Rtattr,
    FromBytes, FromBytesWithInput, Size, ToBytes, TypeSize,
};

/// A buffer of bytes.
#[derive(PartialEq, Eq, Size, FromBytesWithInput, ToBytes)]
pub struct Buffer(#[neli(input)] Vec<u8>);

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
#[neli(from_bytes_bound = "P: FromBytesWithInput<Input = usize>")]
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
#[derive(Debug, PartialEq, Eq, ToBytes, FromBytesWithInput)]
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

    /// Get a data structure with a mutable reference to the
    /// underlying [`Nlattr`]s.
    pub fn get_attr_handle_mut(&mut self) -> AttrHandleMut<Self, Nlattr<T, Buffer>> {
        AttrHandleMut::new_borrowed(self.0.as_mut())
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
#[derive(Debug, FromBytesWithInput, ToBytes)]
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
    pub fn get_attr_handle(&self) -> AttrHandle<Self, Rtattr<T, Buffer>> {
        AttrHandle::new_borrowed(self.0.as_ref())
    }

    /// Get a data structure with a mutable reference to the
    /// underlying [`Rtattr`]s.
    pub fn get_attr_handle_mut(&mut self) -> AttrHandleMut<Self, Rtattr<T, Buffer>> {
        AttrHandleMut::new_borrowed(self.0.as_mut())
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

/// A buffer of flag constants.
// FIXME: Fix the debug implementation for flags to actually display which flags
// have been set.
#[derive(Debug, PartialEq, Eq, Size, ToBytes, FromBytes)]
#[neli(from_bytes_bound = "B: FromBytes + TypeSize + Debug")]
pub struct FlagBuffer<B, T>(B, PhantomData<T>);

impl<'a, B, T> From<&'a [T]> for FlagBuffer<B, T>
where
    B: Default + BitOr<B, Output = B> + From<&'a T>,
{
    fn from(slice: &'a [T]) -> Self {
        FlagBuffer(
            slice
                .iter()
                .fold(B::default(), |inner, flag| inner | B::from(flag)),
            PhantomData,
        )
    }
}

impl<B, T> TypeSize for FlagBuffer<B, T>
where
    B: TypeSize,
{
    fn type_size() -> usize {
        B::type_size()
    }
}

impl<'a, B, T> FlagBuffer<B, T>
where
    B: Default
        + BitAnd<B, Output = B>
        + BitAndAssign<B>
        + BitOr<B, Output = B>
        + BitOrAssign<B>
        + Not<Output = B>
        + From<&'a T>
        + PartialEq
        + Copy,
    T: 'a,
{
    /// Create an empty set of flags.
    pub fn empty() -> Self {
        FlagBuffer(B::default(), PhantomData)
    }

    /// Create a [`FlagBuffer`] from a bitmask.
    pub fn from_bitmask(bitmask: B) -> Self {
        FlagBuffer(bitmask, PhantomData)
    }

    /// Check whether the set of flags contains the given flag.
    pub fn contains(&self, elem: &'a T) -> bool {
        (self.0 & elem.into()) == elem.into()
    }

    /// Add a flag to the set of flags.
    pub fn set(&mut self, flag: &'a T) {
        self.0 |= B::from(flag)
    }

    /// Remove a flag from the set of flags.
    pub fn unset(&mut self, flag: &'a T) {
        self.0 &= !B::from(flag)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::consts::{genl::Index, rtnl::Ifa};

    #[test]
    fn test_genlbuffer_align() {
        assert_eq!(
            vec![
                Nlattr::new(false, false, Index::from(0), 0u8,).unwrap(),
                Nlattr::new(false, false, Index::from(1), 1u8,).unwrap(),
                Nlattr::new(false, false, Index::from(2), 2u8,).unwrap(),
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
                Rtattr::new(None, Ifa::Unspec, 0u8,).unwrap(),
                Rtattr::new(None, Ifa::Address, 1u8,).unwrap(),
                Rtattr::new(None, Ifa::Local, 2u8,).unwrap(),
            ]
            .into_iter()
            .collect::<RtBuffer<Ifa, Buffer>>()
            .unpadded_size(),
            24
        )
    }
}
