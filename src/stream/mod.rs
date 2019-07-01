#[cfg(feature = "async")]
mod asynchronous;
#[cfg(feature = "async")]
pub use self::asynchronous::{NetlinkStream, NetlinkStreamConnector};
