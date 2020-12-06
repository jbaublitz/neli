//! Higher level API for subscribing to a stream of multicast group
//! messages.
//!
//! # Design decisions
//! * This module contains data structures that do sequence number
//! and PID tracking.
//! * Both synchronous and asynchronous variants of the data structures
//! exist and will be available based on whether neli is compiled
//! with the `async` feature.

#[cfg(feature = "async")]
mod asynchronous;
#[cfg(feature = "async")]
pub use self::asynchronous::{NetlinkStream, NetlinkStreamConnector};
