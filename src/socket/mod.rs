//! This module provides code that glues all of the other modules
//! together and allows message send and receive operations.
//!
//! ## Important methods
//! * [`NlSocket::send`][crate::socket::NlSocket::send] and
//!   [`NlSocket::recv`][crate::socket::NlSocket::recv] methods are meant to
//!   be the most low level calls. They essentially do what the C
//!   system calls `send` and `recv` do with very little abstraction.
//! * [`NlSocketHandle::send`][crate::socket::NlSocket::send] and
//!   [`NlSocketHandle::recv`][crate::socket::NlSocket::recv] methods
//!   are meant to provide an interface that is more idiomatic for
//!   the library.
//!
//! ## Features
//! The `async` feature exposed by `cargo` allows the socket to use
//! Rust's [tokio](https://tokio.rs) for async IO.
//!
//! ## Additional methods
//!
//! There are methods for blocking and non-blocking, resolving
//! generic netlink multicast group IDs, and other convenience
//! functions so see if your use case is supported. If it isn't,
//! please open a Github issue and submit a feature request.
//!
//! ## Design decisions
//!
//! The buffer allocated in the [`BufferPool`][crate::utils::synchronous::BufferPool]
//! structure should be allocated on the heap. This is intentional as a buffer
//! that large could be a problem on the stack.
//!
//! neli now uses [`BufferPool`][crate::utils::synchronous::BufferPool] to manage
//! parallel message receive operations. Memory usage can be tuned using the following
//! environment variables at compile time:
//! * `NELI_AUTO_BUFFER_LEN`: This configures how many bytes are allocated for each
//!   buffer in the buffer pool.
//! * `NELI_MAX_PARALLEL_READ_OPS`: This configures how many buffers of size
//!   `NELI_AUTO_BUFFER_LEN` are allocated for parallel receive operations.

/// Asynchronous socket operations
#[cfg(feature = "async")]
pub mod asynchronous;
mod shared;
/// Synchronous socket operations
#[cfg(feature = "sync")]
pub mod synchronous;

pub use crate::socket::shared::NlSocket;
