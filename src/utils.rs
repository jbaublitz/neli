//! A module containing utilities for working with constructs like
//! bitflags and other low level operations.
//!
//! # Design decisions
//! Some of the less documented aspects of interacting with netlink
//! are handled internally in the types so that the user does not
//! have to be aware of them.

use std::mem::size_of;

#[cfg(any(feature = "sync", feature = "async"))]
use crate::consts::MAX_NL_LENGTH;
use crate::err::MsgError;

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
    /// the nearest multiple of [`size_of::<BitArrayType>()`][std::mem::size_of].
    pub fn resize(&mut self, bytes: usize) {
        let byte_round = size_of::<BitArrayType>() - 1;
        self.0.resize(
            ((bytes + byte_round) & !byte_round) / size_of::<BitArrayType>(),
            0,
        );
    }

    /// Returns true if the `n`th bit is set. Not zero indexed.
    pub fn is_set(&self, n: usize) -> bool {
        if n == 0 {
            return false;
        }
        let n_1 = n - 1;
        let bit_segment = self.0[n_1 / Self::BIT_SIZE];
        if let Some(bit_shifted_n) = u32::try_from(n_1 % Self::BIT_SIZE)
            .ok()
            .and_then(|rem| 1u32.checked_shl(rem))
        {
            bit_segment & bit_shifted_n == bit_shifted_n
        } else {
            false
        }
    }

    /// Set the `n`th bit. Not zero indexed.
    pub fn set(&mut self, n: usize) {
        if n == 0 {
            return;
        }
        let n_1 = n - 1;
        let bit_segment = self.0[n_1 / Self::BIT_SIZE];
        if let Some(bit_shifted_n) = u32::try_from(n_1 % Self::BIT_SIZE)
            .ok()
            .and_then(|rem| 1u32.checked_shl(rem))
        {
            self.0[n_1 / Self::BIT_SIZE] = bit_segment | bit_shifted_n;
        }
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

fn slice_to_mask(groups: &[u32]) -> Result<u32, MsgError> {
    groups.iter().try_fold(0, |mask, next| {
        if *next == 0 {
            Ok(mask)
        } else if next - 1 > 31 {
            Err(MsgError::new(format!(
                "Group {next} cannot be represented with a bit width of 32"
            )))
        } else {
            Ok(mask | (1 << (*next - 1)))
        }
    })
}

fn mask_to_vec(mask: u32) -> Vec<u32> {
    (1..size_of::<u32>() as u32 * u8::BITS)
        .filter(|i| (1 << (i - 1)) & mask == (1 << (i - 1)))
        .collect::<Vec<_>>()
}

/// Struct implementing handling of groups both as numerical values and as
/// bitmasks.
pub struct Groups(Vec<u32>);

impl Groups {
    /// Create an empty set of netlink multicast groups
    pub fn empty() -> Self {
        Groups(vec![])
    }

    /// Create a new set of groups with a bitmask. Each bit represents a group.
    pub fn new_bitmask(mask: u32) -> Self {
        Groups(mask_to_vec(mask))
    }

    /// Add a new bitmask to the existing group set. Each bit represents a group.
    pub fn add_bitmask(&mut self, mask: u32) {
        for group in mask_to_vec(mask) {
            if !self.0.contains(&group) {
                self.0.push(group);
            }
        }
    }

    /// Remove a bitmask from the existing group set. Each bit represents a group
    /// and each bit set to 1 will be removed.
    pub fn remove_bitmask(&mut self, mask: u32) {
        let remove_items = mask_to_vec(mask);
        self.0 = self
            .0
            .drain(..)
            .filter(|g| !remove_items.contains(g))
            .collect::<Vec<_>>();
    }

    /// Create a new set of groups from a list of numerical groups values. This differs
    /// from the bitmask representation where the value 3 represents group 3 in this
    /// format as opposed to 0x4 in the bitmask format.
    pub fn new_groups(groups: &[u32]) -> Self {
        let mut vec = groups.to_owned();
        vec.retain(|g| g != &0);
        Groups(vec)
    }

    /// Add a list of numerical groups values to the set of groups. This differs
    /// from the bitmask representation where the value 3 represents group 3 in this
    /// format as opposed to 0x4 in the bitmask format.
    pub fn add_groups(&mut self, groups: &[u32]) {
        for group in groups {
            if *group != 0 && !self.0.contains(group) {
                self.0.push(*group)
            }
        }
    }

    /// Remove a list of numerical groups values from the set of groups. This differs
    /// from the bitmask representation where the value 3 represents group 3 in this
    /// format as opposed to 0x4 in the bitmask format.
    pub fn remove_groups(&mut self, groups: &[u32]) {
        self.0.retain(|g| !groups.contains(g));
    }

    /// Return the set of groups as a bitmask. The representation of a bitmask is u32.
    pub fn as_bitmask(&self) -> Result<u32, MsgError> {
        slice_to_mask(&self.0)
    }

    /// Return the set of groups as a vector of group values.
    pub fn as_groups(&self) -> Vec<u32> {
        self.0.clone()
    }

    /// Return the set of groups as a vector of group values.
    pub fn into_groups(self) -> Vec<u32> {
        self.0
    }

    /// Returns true if no group is set.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Synchronous (blocking) utils.
#[cfg(feature = "sync")]
pub mod synchronous {
    use super::*;

    use std::{
        mem::swap,
        ops::{Deref, DerefMut},
    };

    use log::trace;
    use parking_lot::{Condvar, Mutex};

    /// Type containing information pertaining to the semaphore tracking.
    struct SemInfo {
        max: u64,
        count: u64,
    }

    /// Guard indicating that a buffer has been acquired and the semaphore has been
    /// incremented.
    pub struct BufferPoolGuard<'a>(&'a BufferPool, Vec<u8>);

    impl Deref for BufferPoolGuard<'_> {
        type Target = Vec<u8>;

        fn deref(&self) -> &Self::Target {
            &self.1
        }
    }

    impl DerefMut for BufferPoolGuard<'_> {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.1
        }
    }

    impl AsRef<[u8]> for BufferPoolGuard<'_> {
        fn as_ref(&self) -> &[u8] {
            self.1.as_ref()
        }
    }

    impl AsMut<[u8]> for BufferPoolGuard<'_> {
        fn as_mut(&mut self) -> &mut [u8] {
            self.1.as_mut()
        }
    }

    impl BufferPoolGuard<'_> {
        /// Reduce the size of the internal buffer to the number of bytes read.
        pub fn reduce_size(&mut self, bytes_read: usize) {
            assert!(bytes_read <= self.1.len());
            self.1.resize(bytes_read, 0);
        }

        /// Reset the buffer to the original size.
        pub fn reset(&mut self) {
            self.1.resize(
                option_env!("NELI_AUTO_BUFFER_LEN")
                    .and_then(|s| s.parse::<usize>().ok())
                    .unwrap_or(MAX_NL_LENGTH),
                0,
            );
        }
    }

    impl Drop for BufferPoolGuard<'_> {
        fn drop(&mut self) {
            {
                let mut vec = Vec::new();
                swap(&mut self.1, &mut vec);
                let mut sem_info = self.0.sem_info.lock();
                let mut pool = self.0.pool.lock();
                sem_info.count -= 1;
                vec.resize(
                    option_env!("NELI_AUTO_BUFFER_LEN")
                        .and_then(|s| s.parse::<usize>().ok())
                        .unwrap_or(MAX_NL_LENGTH),
                    0,
                );
                pool.push(vec);
                trace!(
                    "Semaphore released; current count is {}, available is {}",
                    sem_info.count,
                    sem_info.max - sem_info.count
                );
            }
            self.0.condvar.notify_one();
        }
    }

    /// A pool of buffers available for reading concurrent netlink messages without
    /// truncation.
    pub struct BufferPool {
        pool: Mutex<Vec<Vec<u8>>>,
        sem_info: Mutex<SemInfo>,
        condvar: Condvar,
    }

    impl Default for BufferPool {
        fn default() -> Self {
            let max_parallel = option_env!("NELI_MAX_PARALLEL_READ_OPS")
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(3);
            let buffer_size = option_env!("NELI_AUTO_BUFFER_LEN")
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(MAX_NL_LENGTH);

            BufferPool {
                pool: Mutex::new(
                    (0..max_parallel)
                        .map(|_| vec![0; buffer_size])
                        .collect::<Vec<_>>(),
                ),
                sem_info: Mutex::new(SemInfo {
                    count: 0,
                    max: max_parallel,
                }),
                condvar: Condvar::new(),
            }
        }
    }

    impl BufferPool {
        /// Acquire a buffer for use.
        ///
        /// This method is backed by a semaphore.
        pub fn acquire(&self) -> BufferPoolGuard<'_> {
            let mut sem_info = self.sem_info.lock();
            self.condvar
                .wait_while(&mut sem_info, |sem_info| sem_info.count >= sem_info.max);
            let mut pool = self.pool.lock();
            sem_info.count += 1;
            trace!(
                "Semaphore acquired; current count is {}, available is {}",
                sem_info.count,
                sem_info.max - sem_info.count
            );
            BufferPoolGuard(
                self,
                pool.pop()
                    .expect("Checked that there is an available permit"),
            )
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        use std::{
            io::Write,
            thread::{scope, sleep},
            time::Duration,
        };

        use crate::test::setup;

        #[test]
        fn test_buffer_pool() {
            setup();

            let pool = BufferPool::default();
            scope(|s| {
                s.spawn(|| {
                    let mut guard = pool.acquire();
                    sleep(Duration::from_secs(2));
                    guard.as_mut_slice().write_all(&[4]).unwrap();
                    assert_eq!(Some(&4), guard.first());
                });
                s.spawn(|| {
                    let mut guard = pool.acquire();
                    sleep(Duration::from_secs(3));
                    guard.as_mut_slice().write_all(&[1]).unwrap();
                    assert_eq!(Some(&1), guard.first());
                });
                s.spawn(|| {
                    let mut guard = pool.acquire();
                    sleep(Duration::from_secs(3));
                    guard.as_mut_slice().write_all(&[1]).unwrap();
                    assert_eq!(Some(&1), guard.first());
                });
                s.spawn(|| {
                    sleep(Duration::from_secs(1));
                    let mut guard = pool.acquire();
                    guard.as_mut_slice().write_all(&[1]).unwrap();
                    assert_eq!(Some(&1), guard.first());
                });
            });
            let pool = pool.pool.lock();
            assert_eq!(pool.len(), 3);
            for buf in pool.iter() {
                assert_eq!(Some(&1), buf.first());
            }
        }
    }
}

/// Asynchronous utils.
#[cfg(feature = "async")]
pub mod asynchronous {
    use super::*;

    use std::{
        mem::swap,
        ops::{Deref, DerefMut},
    };

    use log::trace;
    use parking_lot::Mutex;
    use tokio::sync::{Semaphore, SemaphorePermit};

    /// Guard indicating that a buffer has been acquired and the semaphore has been
    /// incremented.
    #[allow(dead_code)]
    pub struct BufferPoolGuard<'a>(&'a BufferPool, SemaphorePermit<'a>, Vec<u8>);

    impl Deref for BufferPoolGuard<'_> {
        type Target = Vec<u8>;

        fn deref(&self) -> &Self::Target {
            &self.2
        }
    }

    impl DerefMut for BufferPoolGuard<'_> {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.2
        }
    }

    impl AsRef<[u8]> for BufferPoolGuard<'_> {
        fn as_ref(&self) -> &[u8] {
            self.2.as_ref()
        }
    }

    impl AsMut<[u8]> for BufferPoolGuard<'_> {
        fn as_mut(&mut self) -> &mut [u8] {
            self.2.as_mut()
        }
    }

    impl BufferPoolGuard<'_> {
        /// Reduce the size of the internal buffer to the number of bytes read.
        pub fn reduce_size(&mut self, bytes_read: usize) {
            assert!(bytes_read <= self.2.len());
            self.2.resize(bytes_read, 0);
        }

        /// Reset the buffer to the original size.
        pub fn reset(&mut self) {
            self.2.resize(
                option_env!("NELI_AUTO_BUFFER_LEN")
                    .and_then(|s| s.parse::<usize>().ok())
                    .unwrap_or(MAX_NL_LENGTH),
                0,
            );
        }
    }

    impl Drop for BufferPoolGuard<'_> {
        fn drop(&mut self) {
            {
                let mut vec = Vec::new();
                swap(&mut self.2, &mut vec);
                let mut pool = self.0.pool.lock();
                vec.resize(
                    option_env!("NELI_AUTO_BUFFER_LEN")
                        .and_then(|s| s.parse::<usize>().ok())
                        .unwrap_or(MAX_NL_LENGTH),
                    0,
                );
                pool.push(vec);
                trace!(
                    "Semaphore released; current count is {}, max is {}",
                    self.0.max - self.0.semaphore.available_permits(),
                    self.0.semaphore.available_permits()
                );
            }
        }
    }

    /// A pool of buffers available for reading concurrent netlink messages without
    /// truncation.
    pub struct BufferPool {
        pool: Mutex<Vec<Vec<u8>>>,
        max: usize,
        semaphore: Semaphore,
    }

    impl Default for BufferPool {
        fn default() -> Self {
            let max_parallel = option_env!("NELI_MAX_PARALLEL_READ_OPS")
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(3);
            let buffer_size = option_env!("NELI_AUTO_BUFFER_LEN")
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(MAX_NL_LENGTH);

            BufferPool {
                pool: Mutex::new(
                    (0..max_parallel)
                        .map(|_| vec![0; buffer_size])
                        .collect::<Vec<_>>(),
                ),
                max: max_parallel,
                semaphore: Semaphore::new(max_parallel),
            }
        }
    }

    impl BufferPool {
        /// Acquire a buffer for use.
        ///
        /// This method is backed by a semaphore.
        pub async fn acquire(&self) -> BufferPoolGuard<'_> {
            let permit = self
                .semaphore
                .acquire()
                .await
                .expect("Semaphore is never closed");
            let mut pool = self.pool.lock();
            trace!(
                "Semaphore acquired; current count is {}, available is {}",
                self.max - self.semaphore.available_permits(),
                self.semaphore.available_permits(),
            );
            BufferPoolGuard(
                self,
                permit,
                pool.pop()
                    .expect("Checked that there is an available permit"),
            )
        }
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

    #[test]
    fn test_groups() {
        setup();

        assert_eq!(Groups::new_groups(&[0, 0, 0, 0]).as_bitmask().unwrap(), 0);
        let groups = Groups::new_groups(&[0, 0, 0, 0]).as_groups();
        assert!(groups.is_empty());
    }
}
