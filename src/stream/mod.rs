#[cfg(feature = "async")]
mod async;
#[cfg(feature = "async")]
pub use self::async::{NetlinkStream, NetlinkStreamConnector};
