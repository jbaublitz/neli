//! High level API that performs sequence and PID checking as well as ACK validation.
//!
//! ## Workflow
//! * [`NlRouter::send`][crate::router::synchronous::NlRouter] sends a message and
//! does automatic seq handling.
//! * A thread in the background receives all messages that sent to the socket in
//! response.
//! * Each message is sent on the channel match the sequence number to the
//! [`NlRouterReceiverHandle`][crate::router::synchronous::NlRouterReceiverHandle] that corresponds
//! to the request.
//! * Errors in packet reception and parsing are broadcast to all receivers.
//! * An [`NlRouterReceiverHandle`][crate::router::synchronous::NlRouterReceiverHandle]
//! can be used as an iterator and will return [`None`][None] either when all
//! messages corresponding to the request have been received or there is a fatal error.
//!
//! ## Design decisions
//! Older users of the library might recognize some of the funtionality in
//! [`NlRouter`][crate::router::synchronous::NlRouter] as code that previously was
//! associated with [`NlSocketHandle`][crate::socket::synchronous::NlSocketHandle].
//! The reason for this migration is primarily due to some deficiencies found in the
//! previous implementation.
//! [`NlSocketHandle`][crate::socket::synchronous::NlSocketHandle]
//! relied heavily on a `.send()`/`.recv()` workflow. This meant that, while it
//! was designed to address ACK handling and receiving all responses associated
//! with a given request, the implementation actually was unable to handle two
//! separate responses corresponding to two seaparate requests interleaved with each
//! other. Effectively, this meant that the socket handle had no awareness of multiple
//! requests being sent before all data was read from the socket and would result
//! in parsing errors if used in this way.
//!
//! [`NlRouter`][crate::router::synchronous::NlRouter] aims to address this by
//! associating all messages received by the socket with a request or multicast
//! group so that messages can be interleaved and still processed in the correct
//! order by the handle associated with the request that generated it.
//!
//! ## Features
//! The `async` feature exposed by `cargo` allows the socket to use
//! Rust's [tokio](https://tokio.rs) for async IO.

/// Asynchronous packet routing functionality.
#[cfg(feature = "async")]
pub mod asynchronous;
/// Synchronous packet routing functionality.
#[cfg(feature = "sync")]
pub mod synchronous;
