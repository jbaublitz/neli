//! Shared attribute code for all types of netlink attributes.
//!  
//! This module is relatively small right now and will eventually
//! contain more code once type parameters in associated
//! types defined in traits are stabilized. Due to `neli` being
//! supported on stable and nightly, I cannot currently use
//! this feature and have opted to define implementations of the
//! trait separately for [`Rtattr`][crate::rtnl::Rtattr] and
//! [`Nlattr`][crate::genl::Nlattr] types in the
//! `rtnl.rs` and `genl.rs` modules respectively.

use std::{
    io::Cursor,
    slice::{Iter, IterMut},
};

use crate::{
    err::{DeError, SerError},
    types::Buffer,
    FromBytes, FromBytesWithInput, Size, ToBytes,
};

/// Trait that defines shared operations for netlink attributes.
/// Currently, this applies to generic netlink and routing netlink
/// attributes.
pub trait Attribute<T> {
    /// Get the payload of the given attribute.
    ///
    /// Due to Rust's requirement that all elements of a [`Vec`] are of
    /// the same type, payloads are represented as a byte buffer so
    /// that nested attributes that contain multiple types for the
    /// payload can be type checked before serialization yet still
    /// contained all in the same top level attribute.
    fn payload(&self) -> &Buffer;

    /// Set the payload to a data type that implements [`ToBytes`] -
    /// this function will overwrite the current payload.
    ///
    /// This method serializes the `payload` parameter and stores
    /// the resulting byte buffer as the payload.
    fn set_payload<P>(&mut self, payload: &P) -> Result<(), SerError>
    where
        P: Size + ToBytes;

    /// Get an [`Nlattr`][crate::genl::Nlattr] payload as the
    /// provided type parameter, `R`.
    fn get_payload_as<'a, R>(&'a self) -> Result<R, DeError>
    where
        R: FromBytes<'a>,
    {
        R::from_bytes(&mut Cursor::new(self.payload().as_ref()))
    }

    /// Get an [`Nlattr`][crate::genl::Nlattr] payload as the
    /// provided type parameter, `R`.
    fn get_payload_as_with_len<'a, R>(&'a self) -> Result<R, DeError>
    where
        R: FromBytesWithInput<'a, Input = usize>,
    {
        R::from_bytes_with_input(
            &mut Cursor::new(self.payload().as_ref()),
            self.payload().len(),
        )
    }
}

/// Handle returned for traversing nested attribute structures
pub enum AttrHandle<'a, O, I> {
    /// Owned vector
    Owned(O),
    /// Vector reference
    Borrowed(&'a [I]),
}

impl<'a, O, I> AttrHandle<'a, O, I>
where
    O: AsRef<[I]>,
{
    /// Create new [`AttrHandle`]
    pub fn new(owned: O) -> Self {
        AttrHandle::Owned(owned)
    }

    /// Create new borrowed [`AttrHandle`]
    pub fn new_borrowed(borrowed: &'a [I]) -> Self {
        AttrHandle::Borrowed(borrowed)
    }

    /// Pass back iterator over attributes
    pub fn iter(&self) -> Iter<I> {
        self.get_attrs().iter()
    }

    /// Get the underlying owned value as a reference
    pub fn get_attrs(&self) -> &[I] {
        match *self {
            AttrHandle::Owned(ref o) => o.as_ref(),
            AttrHandle::Borrowed(b) => b,
        }
    }
}

/// Handle for traversing nested attribute structures mutably
pub enum AttrHandleMut<'a, O, I> {
    /// Owned vector
    Owned(O),
    /// Vector reference
    Borrowed(&'a mut [I]),
}

impl<'a, O, I> AttrHandleMut<'a, O, I>
where
    O: AsRef<[I]> + AsMut<[I]>,
{
    /// Create new `AttrHandle`
    pub fn new(owned: O) -> Self {
        AttrHandleMut::Owned(owned)
    }

    /// Create new borrowed [`AttrHandleMut`]
    pub fn new_borrowed(borrowed: &'a mut [I]) -> Self {
        AttrHandleMut::Borrowed(borrowed)
    }

    /// Pass back iterator over attributes
    pub fn iter_mut(&mut self) -> IterMut<I> {
        self.get_mut_attrs().iter_mut()
    }

    /// Get the underlying owned value as a mutable reference or
    /// return [`None`].
    pub fn get_mut_attrs(&mut self) -> &mut [I] {
        match self {
            AttrHandleMut::Owned(ref mut o) => o.as_mut(),
            AttrHandleMut::Borrowed(b) => b,
        }
    }
}
