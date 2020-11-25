//! Module containing various types used across the various netlink
//! structures used in `neli`.
//!
//! # Design decisions
//! These structures are new types rather than type aliases in most
//! cases to allow the internal representation to change without
//! resulting in a breaking change.

pub use std::{
    cell::{Ref, RefCell, RefMut},
    iter::FromIterator,
    marker::PhantomData,
    ops::Range,
    slice::{Iter, IterMut},
};

use crate::{genl::Nlattr, neli_constants::MAX_NL_LENGTH, nl::Nlmsghdr, rtnl::Rtattr};

/// A buffer of bytes.
#[derive(Debug, PartialEq)]
pub struct Buffer(Vec<u8>);

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

impl<'a> From<Vec<u8>> for Buffer {
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

/// Type alias for a buffer to serialize into.
pub type SerBuffer<'a> = &'a mut [u8];

/// Type alias for a buffer to deserialize from.
pub type DeBuffer<'a> = &'a [u8];

/// An immutable reference to the socket buffer.
pub struct SockBufferRef<'a>(Ref<'a, Vec<u8>>);

impl<'a> AsRef<[u8]> for SockBufferRef<'a> {
    fn as_ref(&self) -> &[u8] {
        (*self.0).as_slice()
    }
}

/// A mutable reference to the socket buffer.
pub struct SockBufferRefMut<'a>(RefMut<'a, Vec<u8>>);

impl<'a> AsMut<[u8]> for SockBufferRefMut<'a> {
    fn as_mut(&mut self) -> &mut [u8] {
        (*self.0).as_mut_slice()
    }
}

/// A buffer to hold data read from sockets
pub struct SockBuffer(RefCell<Vec<u8>>);

impl SockBuffer {
    /// Create a new buffer for use when reading from a socket.
    pub fn new() -> Self {
        SockBuffer(RefCell::new(vec![0; MAX_NL_LENGTH]))
    }

    /// Get an immutable reference to the inner buffer.
    pub fn get_ref(&self) -> Option<SockBufferRef> {
        self.0.try_borrow().ok().map(SockBufferRef)
    }

    /// Get a mutable reference to the inner buffer.
    pub fn get_mut(&self) -> Option<SockBufferRefMut> {
        self.0.try_borrow_mut().ok().map(SockBufferRefMut)
    }
}

impl<'a> From<&'a [u8]> for SockBuffer {
    fn from(s: &'a [u8]) -> Self {
        SockBuffer(RefCell::new(s.to_vec()))
    }
}

impl Default for SockBuffer {
    fn default() -> Self {
        Self::new()
    }
}

/// A buffer of netlink messages.
#[derive(Debug, PartialEq)]
pub struct NlBuffer<T, P>(Vec<Nlmsghdr<T, P>>);

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
#[derive(Debug, PartialEq)]
pub struct GenlBuffer<T, P>(Vec<Nlattr<T, P>>);

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
    pub fn iter_mut<'a>(&'a mut self) -> IterMut<'a, Nlattr<T, P>> {
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
#[derive(Debug)]
pub struct RtBuffer<T, P>(Vec<Rtattr<T, P>>);

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
#[derive(Debug, PartialEq)]
pub struct FlagBuffer<T>(Vec<T>);

impl<'a, T> From<&'a [T]> for FlagBuffer<T>
where
    T: Clone,
{
    fn from(slice: &[T]) -> Self {
        FlagBuffer(Vec::from(slice))
    }
}

impl<T> FlagBuffer<T>
where
    T: PartialEq + Clone,
{
    /// Check whether the set of flags is empty.
    pub fn empty() -> Self {
        FlagBuffer(Vec::new())
    }

    /// Check whether the set of flags contains the given flag.
    pub fn contains(&self, elem: &T) -> bool {
        self.0.contains(elem)
    }

    /// Add a flag to the set of flags.
    pub fn set(&mut self, flag: T) {
        if !self.0.contains(&flag) {
            self.0.push(flag)
        }
    }

    /// Remove a flag from the set of flags.
    pub fn unset(&mut self, flag: &T) {
        self.0.retain(|e| flag != e)
    }

    /// Return an iterator over the immutable contents of the buffer.
    pub fn iter(&self) -> std::slice::Iter<T> {
        self.0.iter()
    }
}
