//! A module containing utilities for working with constructs like
//! bitflags and other low level operations.
//!
//! # Design decisions
//! Some of the less documented aspects of interacting with netlink
//! are handled internally in the types so that the user does not
//! have to be aware of them.

use std::mem::size_of;

type BitArrayType = u32;

/// A bit array meant to be compatible with the bit array
/// returned by the `NETLINK_LIST_MEMBERSHIPS` socket operation
/// on netlink sockets.
pub struct NetlinkBitArray(Vec<BitArrayType>);

/// bittest/bitset instrinsics are not stable in Rust so this
/// needs to be implemented this way.
#[allow(clippy::len_without_is_empty)]
impl NetlinkBitArray {
    const BIT_SIZE: usize = BitArrayType::BITS as usize;

    /// Create a new bit array.
    ///
    /// This method will round `bit_len` up to the nearest
    /// multiple of [`size_of::<u32>()`][std::mem::size_of].
    pub fn new(bit_len: usize) -> Self {
        let round = Self::BIT_SIZE - 1;
        NetlinkBitArray(vec![0; ((bit_len + round) & !round) / Self::BIT_SIZE])
    }

    /// Resize the underlying vector to have enough space for
    /// the nearest multiple of [`size_of::<u32>()`][std::mem::size_of]
    /// rounded up.
    pub fn resize_bits(&mut self, bit_len: usize) {
        let round = Self::BIT_SIZE - 1;
        self.0
            .resize(((bit_len + round) & !round) / Self::BIT_SIZE, 0);
    }

    /// Resize the underlying vector to have enough space for
    /// the nearest multiple of [`size_of::<
    pub fn resize(&mut self, bytes: usize) {
        let byte_round = size_of::<BitArrayType>() - 1;
        self.0.resize(
            ((bytes + byte_round) & !byte_round) / size_of::<BitArrayType>(),
            0,
        );
    }

    /// Returns true if the `n`th bit is set.
    pub fn is_set(&self, n: usize) -> bool {
        if n == 0 {
            return false;
        }
        let n_1 = n - 1;
        let bit_segment = self.0[n_1 / Self::BIT_SIZE];
        let bit_shifted_n = 1 << (n_1 % Self::BIT_SIZE);
        bit_segment & bit_shifted_n == bit_shifted_n
    }

    /// Set the `n`th bit.
    pub fn set(&mut self, n: usize) {
        if n == 0 {
            return;
        }
        let n_1 = n - 1;
        let bit_segment = self.0[n_1 / Self::BIT_SIZE];
        let bit_shifted_n = 1 << (n_1 % Self::BIT_SIZE);
        self.0[n_1 / Self::BIT_SIZE] = bit_segment | bit_shifted_n;
    }

    /// Get a vector representation of all of the bit positions set
    /// to 1 in this bit array.
    ///
    /// ## Example
    /// ```
    /// use neli::utils::NetlinkBitArray;
    ///
    /// let mut array = NetlinkBitArray::new(24);
    /// array.set(4);
    /// array.set(7);
    /// array.set(23);
    /// assert_eq!(array.to_vec(), vec![4, 7, 23]);
    /// ```
    pub fn to_vec(&self) -> Vec<u32> {
        let mut bits = Vec::new();
        for bit in 0..self.len_bits() {
            let bit_shifted = 1 << (bit % Self::BIT_SIZE);
            if bit_shifted & self.0[bit / Self::BIT_SIZE] == bit_shifted {
                bits.push(bit as u32 + 1);
            }
        }
        bits
    }

    /// Return the number of bits that can be contained in this bit
    /// array.
    pub fn len_bits(&self) -> usize {
        self.0.len() * Self::BIT_SIZE
    }

    /// Return the length in bytes for this bit array.
    pub fn len(&self) -> usize {
        self.0.len() * size_of::<BitArrayType>()
    }

    pub(crate) fn as_mut_slice(&mut self) -> &mut [BitArrayType] {
        self.0.as_mut_slice()
    }
}

fn slice_to_mask(groups: &[u32]) -> u32 {
    groups
        .iter()
        .fold(0, |mask, next| mask | (1 << (*next - 1)))
}

fn mask_to_vec(mask: u32) -> Vec<u32> {
    (1..size_of::<u32>() as u32 * u8::BITS)
        .filter(|i| (1 << (i - 1)) & mask == (1 << (i - 1)))
        .collect::<Vec<_>>()
}

/// Struct implementing handling of groups both as numerical values and as
/// bitmasks.
pub struct Groups(u32);

impl Groups {
    /// Create an empty set of netlink multicast groups
    pub fn empty() -> Self {
        Groups(0)
    }

    /// Create a new set of groups with a bitmask. Each bit represents a group.
    pub fn new_bitmask(mask: u32) -> Self {
        Groups(mask)
    }

    /// Add a new bitmask to the existing group set. Each bit represents a group.
    pub fn add_bitmask(&mut self, mask: u32) {
        self.0 |= mask
    }

    /// Remove a bitmask from the existing group set. Each bit represents a group
    /// and each bit set to 1 will be removed.
    pub fn remove_bitmask(&mut self, mask: u32) {
        self.0 &= !mask
    }

    /// Create a new set of groups from a list of numerical groups values. This differs
    /// from the bitmask representation where the value 3 represents group 3 in this
    /// format as opposed to 0x4 in the bitmask format.
    pub fn new_groups(groups: &[u32]) -> Self {
        Groups(slice_to_mask(groups))
    }

    /// Add a list of numerical groups values to the set of groups. This differs
    /// from the bitmask representation where the value 3 represents group 3 in this
    /// format as opposed to 0x4 in the bitmask format.
    pub fn add_groups(&mut self, groups: &[u32]) {
        self.add_bitmask(slice_to_mask(groups));
    }

    /// Remove a list of numerical groups values from the set of groups. This differs
    /// from the bitmask representation where the value 3 represents group 3 in this
    /// format as opposed to 0x4 in the bitmask format.
    pub fn remove_groups(&mut self, groups: &[u32]) {
        self.remove_bitmask(slice_to_mask(groups));
    }

    /// Return the set of groups as a bitmask. The representation of a bitmask is u32.
    pub fn as_bitmask(&self) -> u32 {
        self.0
    }

    /// Return the set of groups as a vector of group values.
    pub fn as_groups(&self) -> Vec<u32> {
        mask_to_vec(self.0)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::test::setup;

    #[test]
    fn test_bit_array() {
        setup();

        let mut bit_array = NetlinkBitArray::new(7);
        assert_eq!(bit_array.0.len(), 1);
        bit_array.set(4);
        assert_eq!(bit_array.0[0], 0b1000);
        assert!(bit_array.is_set(4));
        assert!(!bit_array.is_set(0));
        assert!(!bit_array.is_set(1));
        assert!(!bit_array.is_set(2));
        assert!(!bit_array.is_set(3));

        assert_eq!(bit_array.len(), 4);
        assert_eq!(bit_array.len_bits(), 32);

        let mut bit_array = NetlinkBitArray::new(33);
        bit_array.set(32);
        bit_array.set(33);
        assert!(bit_array.0[0] == 1 << 31);
        assert!(bit_array.0[1] == 1);
        assert!(bit_array.is_set(32));
        assert!(bit_array.is_set(33));

        let mut bit_array = NetlinkBitArray::new(32);
        assert_eq!(bit_array.len(), 4);
        bit_array.resize_bits(33);
        assert_eq!(bit_array.len(), 8);
        bit_array.resize_bits(1);
        assert_eq!(bit_array.len(), 4);

        let mut bit_array = NetlinkBitArray::new(33);
        assert_eq!(bit_array.len(), 8);
        bit_array.resize(1);
        assert_eq!(bit_array.len(), 4);
        bit_array.resize(9);
        assert_eq!(bit_array.len(), 12);

        let bit_array = NetlinkBitArray(vec![8, 8, 8]);
        assert_eq!(bit_array.to_vec(), vec![4, 36, 68]);
    }
}
