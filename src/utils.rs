//! A module containing utilities for working with constructs like
//! bitflags and other low level operations.
//!
//! # Design decisions
//! Some of the less documented aspects of interacting with netlink
//! are handled internally in the types so that the user does not
//! have to be aware of them.

use std::{
    error::Error,
    fmt::{self, Display},
    ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, Deref, Not},
};

use crate::{err::SerError, Nl};

/// Represents an error for operations on bitmasks if the integer
/// that is being used to store the bitmask cannot represent the
/// result of requested operation.
#[derive(Debug)]
pub struct BitRepError(String);

impl BitRepError {
    fn new<D>(message: D) -> Self
    where
        D: Display,
    {
        BitRepError(message.to_string())
    }
}

impl Error for BitRepError {}

impl Display for BitRepError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Struct representing a single bit flag
#[derive(Copy, Clone)]
pub struct U32BitFlag(u32);

impl U32BitFlag {
    /// Create a new bitflag from the index of the bit to set.
    pub fn new(bit_num: u32) -> Result<Self, BitRepError> {
        if bit_num > 32 {
            return Err(BitRepError::new(
                "You specified a bit beyond the 32 bit \
                 representation of a u32",
            ));
        }
        Ok(U32BitFlag(bit_num))
    }

    /// Convert this bitflag into a bitmask with only this bit set.
    fn into_bitmask(self) -> U32Bitmask {
        U32Bitmask::from(num_to_set_mask(self.0))
    }
}

/// Struct for handling [`u32`] bitmask operations
#[derive(Copy, Clone)]
pub struct U32Bitmask(u32);

impl U32Bitmask {
    /// Create an empty bitmask
    pub fn empty() -> Self {
        U32Bitmask(0)
    }

    /// Return [`true`] if the bitmask is empty
    pub fn is_empty(&self) -> bool {
        self.0 == 0
    }

    /// Check if the bit at position `bit` is set - returns false
    /// for anything larger than 32 as that extends past the
    /// boundaries of a 32 bit integer bitmask
    pub fn is_set(&self, bit: u32) -> bool {
        if bit > 32 {
            return false;
        }
        let set_mask = num_to_set_mask(bit);
        set_mask & self.0 == set_mask
    }
}

impl Not for U32BitFlag {
    type Output = U32BitFlag;

    fn not(self) -> Self::Output {
        U32BitFlag(!self.0)
    }
}

impl BitOr<U32Bitmask> for U32Bitmask {
    type Output = U32Bitmask;

    fn bitor(self, rhs: U32Bitmask) -> Self::Output {
        U32Bitmask::from(self.0 | *rhs)
    }
}

impl BitOr<U32BitFlag> for U32Bitmask {
    type Output = U32Bitmask;

    fn bitor(self, rhs: U32BitFlag) -> Self::Output {
        self | rhs.into_bitmask()
    }
}

impl BitOr<U32Bitmask> for U32BitFlag {
    type Output = U32Bitmask;

    fn bitor(self, rhs: U32Bitmask) -> Self::Output {
        self.into_bitmask() | rhs
    }
}

impl BitAnd<U32Bitmask> for U32Bitmask {
    type Output = U32Bitmask;

    fn bitand(self, rhs: U32Bitmask) -> Self::Output {
        U32Bitmask::from(self.0 & *rhs)
    }
}

impl BitAnd<U32BitFlag> for U32Bitmask {
    type Output = U32Bitmask;

    fn bitand(self, rhs: U32BitFlag) -> Self::Output {
        self & rhs.into_bitmask()
    }
}

impl BitAnd<U32Bitmask> for U32BitFlag {
    type Output = U32Bitmask;

    fn bitand(self, rhs: U32Bitmask) -> Self::Output {
        self.into_bitmask() & rhs
    }
}

impl<'a> BitOrAssign<&'a U32BitFlag> for U32Bitmask {
    fn bitor_assign(&mut self, rhs: &U32BitFlag) {
        self.0 |= *U32Bitmask::from(*rhs)
    }
}

impl BitOrAssign<U32BitFlag> for U32Bitmask {
    fn bitor_assign(&mut self, rhs: U32BitFlag) {
        self.0 |= *U32Bitmask::from(rhs)
    }
}

impl<'a> BitOrAssign<&'a U32BitFlag> for &'a mut U32Bitmask {
    fn bitor_assign(&mut self, rhs: &U32BitFlag) {
        self.0 |= *U32Bitmask::from(*rhs)
    }
}

impl<'a> BitAndAssign<&'a U32BitFlag> for U32Bitmask {
    fn bitand_assign(&mut self, rhs: &U32BitFlag) {
        self.0 &= *U32Bitmask::from(*rhs)
    }
}

impl BitAndAssign<U32BitFlag> for U32Bitmask {
    fn bitand_assign(&mut self, rhs: U32BitFlag) {
        self.0 &= *U32Bitmask::from(rhs)
    }
}

impl<'a> BitAndAssign<&'a U32BitFlag> for &'a mut U32Bitmask {
    fn bitand_assign(&mut self, rhs: &U32BitFlag) {
        self.0 &= *U32Bitmask::from(*rhs)
    }
}

impl From<U32BitFlag> for U32Bitmask {
    fn from(v: U32BitFlag) -> Self {
        v.into_bitmask()
    }
}

impl From<u32> for U32Bitmask {
    fn from(v: u32) -> Self {
        U32Bitmask(v)
    }
}

impl Deref for U32Bitmask {
    type Target = u32;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Conversion between a group number and the necessary bitmask
/// to perform a bitwise OR that will set the bit
#[inline]
fn num_to_set_mask(grp: u32) -> u32 {
    1 << (grp - 1)
}

/// Convenience method for allocating a buffer for serialization.
pub fn serialize<N>(nl: &N, align: bool) -> Result<Vec<u8>, SerError>
where
    N: Nl,
{
    let len = if align { nl.asize() } else { nl.size() };
    let mut vec = vec![0; len];
    nl.serialize(vec.as_mut_slice())?;
    Ok(vec)
}
