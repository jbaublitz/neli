//! Connector module for netlink messages.
use crate::nl::NlmsghdrBuilderError;
use derive_builder::{Builder, UninitializedFieldError};
use getset::Getters;
use neli_proc_macros::{FromBytes, Header, Size, ToBytes};

use crate as neli;

/// Some docs
#[derive(Builder, Getters, Clone, Debug, PartialEq, Eq, Size, ToBytes, FromBytes, Header)]
#[builder(build_fn(skip))]
#[builder(pattern = "owned")]
pub struct CnMsg {
    /// Flags indicating properties of the request or response
    #[getset(get = "pub")]
    idx: u32,
    /// Sequence number for netlink protocol
    #[getset(get = "pub")]
    val: u32,
    /// Type of the netlink message
    #[getset(get = "pub")]
    seq: u32,
    /// Flags indicating properties of the request or response
    #[getset(get = "pub")]
    ack: u32,
    /// Sequence number for netlink protocol
    #[builder(setter(skip))]
    #[getset(get = "pub")]
    len: u16,
    /// ID of the netlink destination for requests and source for
    /// responses.
    #[getset(get = "pub")]
    flags: u16,
    /// Payload of netlink message
    #[getset(get = "pub")]
    payload: u32,
}

impl CnMsgBuilder {
    /// Build [`CnMsg`].
    pub fn build(self) -> Result<CnMsg, NlmsghdrBuilderError> {
        let idx = self
            .idx
            .ok_or_else(|| NlmsghdrBuilderError::from(UninitializedFieldError::new("nl_type")))?;
        let val = self
            .val
            .ok_or_else(|| NlmsghdrBuilderError::from(UninitializedFieldError::new("nl_flags")))?;
        let seq = self.seq.unwrap_or(0);
        let ack = self.ack.unwrap_or(0);
        let flags = self.flags.unwrap_or(0);
        let payload = self.payload.ok_or_else(|| {
            NlmsghdrBuilderError::from(UninitializedFieldError::new("nl_payload"))
        })?;

        let cn_msg = CnMsg {
            idx,
            val,
            seq,
            ack,
            len: size_of::<u32>() as u16,
            flags,
            payload,
        };
        Ok(cn_msg)
    }
}
