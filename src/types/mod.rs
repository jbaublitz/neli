/// Types that default to heap usage.
#[cfg(not(any(feature = "low_heap_buffer")))]
mod heap;
#[cfg(not(any(feature = "low_heap_buffer")))]
pub use heap::*;

/// Types that minimize but still allow heap usage.
#[cfg(feature = "low_heap_buffer")]
mod low_heap;
#[cfg(feature = "low_heap_buffer")]
pub use low_heap::*;

mod traits;
pub use traits::{
    BufferOps, DeBufferOps, FlagBufferOps, GenlBufferOps, NlBufferOps, RtBufferOps, SerBufferOps,
    SockBufferOps,
};
