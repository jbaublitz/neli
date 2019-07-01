use std::{
    error::Error,
    fmt::{self, Display},
    mem,
    ops::{BitOr, BitOrAssign, Deref},
};

use byteorder::{ByteOrder, NativeEndian};

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
    /// Create a new bitflag from which bit number to set
    pub fn new(bit_num: u32) -> Result<Self, BitRepError> {
        if bit_num > 32 {
            return Err(BitRepError::new(
                "You specified a bit beyond the 32 bit \
                 representation of a u32",
            ));
        }
        Ok(U32BitFlag(bit_num))
    }

    /// Convert this bitflag into a bitmask with only this bit set
    fn into_bitmask(self) -> U32Bitmask {
        U32Bitmask::from(num_to_set_mask(self.0))
    }
}

/// Struct for handling `u32` bitmask operations
pub struct U32Bitmask(u32);

impl U32Bitmask {
    /// Create an empty bitmask
    pub fn empty() -> Self {
        U32Bitmask(0)
    }

    /// Return `true` if the bitmask is empty
    pub fn is_empty(&self) -> bool {
        self.0 == 0
    }

    /// Check if the bit at position `bit` is set - returns false for anything
    /// larger than 32 as that extends past the boundaries of a 32 bit integer bitmask
    pub fn is_set(&self, bit: u32) -> bool {
        if bit > 32 {
            return false;
        }
        let set_mask = num_to_set_mask(bit);
        set_mask & self.0 == set_mask
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

impl<'a> BitOrAssign<&'a U32BitFlag> for U32Bitmask {
    fn bitor_assign(&mut self, rhs: &U32BitFlag) {
        self.0 |= *U32Bitmask::from(*rhs)
    }
}

impl<'a> BitOrAssign<&'a U32BitFlag> for &'a mut U32Bitmask {
    fn bitor_assign(&mut self, rhs: &U32BitFlag) {
        self.0 |= *U32Bitmask::from(*rhs)
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

/// Get the length of a netlink message from a buffer
pub fn packet_length(buffer: &[u8], position: usize) -> usize {
    let len_buffer = &buffer[position..position + mem::size_of::<u16>()];
    <NativeEndian as ByteOrder>::read_u16(len_buffer) as usize
}
