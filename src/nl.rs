//! This module contains the top level netlink header code. Every
//! netlink message will be encapsulated in a top level `Nlmsghdr`.
//!
//! [`Nlmsghdr`] is the structure representing a
//! header that all netlink protocols require to be passed to the
//! correct destination.
//!
//! # Design decisions
//!
//! Payloads for [`Nlmsghdr`] can be any type.
//!
//! The payload is wrapped in an enum to facilitate better
//! application-level error handling.

use crate as neli;

use std::{
    any::type_name,
    io::{Cursor, Read},
};

use log::trace;

use crate::{
    consts::nl::{NlType, NlmFFlags, Nlmsg},
    err::{DeError, NlError, Nlmsgerr, NlmsghdrErr},
    FromBytes, FromBytesWithInput, Header, Size, ToBytes, TypeSize,
};

/// An enum representing either the desired payload as requested
/// by the payload type parameter, an ACK received at the end
/// of a message or stream of messages, or an error.
#[derive(Debug, PartialEq, Eq, Size, ToBytes)]
pub enum NlPayload<T, P> {
    /// Represents an ACK returned by netlink.
    Ack(Nlmsgerr<T, ()>),
    /// Represents an application level error returned by netlink.
    Err(Nlmsgerr<T, P>),
    /// Represents the requested payload.
    Payload(P),
    /// Indicates an empty payload.
    Empty,
}

impl<T, P> NlPayload<T, P> {
    /// Get the payload of the netlink packet and return [`None`]
    /// if the contained data in the payload is actually an ACK
    /// or an error.
    pub fn get_payload(&self) -> Option<&P> {
        match self {
            NlPayload::Payload(ref p) => Some(p),
            _ => None,
        }
    }
}

impl<'a, T, P> FromBytesWithInput<'a> for NlPayload<T, P>
where
    P: FromBytesWithInput<'a, Input = usize>,
    T: NlType,
{
    type Input = (usize, T);

    fn from_bytes_with_input(
        buffer: &mut Cursor<&'a [u8]>,
        (input_size, input_type): (usize, T),
    ) -> Result<Self, DeError> {
        trace!("Deserializing data type {}", type_name::<Self>());
        let ty_const: u16 = input_type.into();
        if ty_const == Nlmsg::Done.into() {
            trace!("Received empty payload");
            let mut bytes = Vec::new();
            buffer.read_to_end(&mut bytes)?;
            trace!("Padding: {:?}", bytes);
            Ok(NlPayload::Empty)
        } else if ty_const == Nlmsg::Error.into() {
            trace!(
                "Deserializing field type {}",
                std::any::type_name::<libc::c_int>()
            );
            let code = libc::c_int::from_bytes(buffer)?;
            trace!("Field deserialized: {:?}", code);
            if code == 0 {
                Ok(NlPayload::Ack(Nlmsgerr {
                    error: code,
                    nlmsg: {
                        trace!(
                            "Deserializing field type {}",
                            std::any::type_name::<NlmsghdrErr<T, ()>>()
                        );
                        trace!("Input: {:?}", input_size);
                        let ok = NlmsghdrErr::<T, ()>::from_bytes_with_input(
                            buffer,
                            input_size - libc::c_int::type_size(),
                        )?;
                        trace!("Field deserialized: {:?}", ok);
                        ok
                    },
                }))
            } else {
                Ok(NlPayload::Err(Nlmsgerr {
                    error: code,
                    nlmsg: {
                        trace!(
                            "Deserializing field type {}",
                            std::any::type_name::<NlmsghdrErr<T, ()>>()
                        );
                        trace!("Input: {:?}", input_size);
                        let ok = NlmsghdrErr::<T, P>::from_bytes_with_input(
                            buffer,
                            input_size - libc::c_int::type_size(),
                        )?;
                        trace!("Field deserialized: {:?}", ok);
                        ok
                    },
                }))
            }
        } else {
            Ok(NlPayload::Payload(P::from_bytes_with_input(
                buffer, input_size,
            )?))
        }
    }
}

/// Top level netlink header and payload
#[derive(Debug, PartialEq, Eq, Size, ToBytes, FromBytes, Header)]
#[neli(header_bound = "T: TypeSize")]
#[neli(from_bytes_bound = "T: NlType")]
#[neli(from_bytes_bound = "P: FromBytesWithInput<Input = usize>")]
#[neli(padding)]
pub struct Nlmsghdr<T, P> {
    /// Length of the netlink message
    pub nl_len: u32,
    /// Type of the netlink message
    pub nl_type: T,
    /// Flags indicating properties of the request or response
    pub nl_flags: NlmFFlags,
    /// Sequence number for netlink protocol
    pub nl_seq: u32,
    /// ID of the netlink destination for requests and source for
    /// responses.
    pub nl_pid: u32,
    /// Payload of netlink message
    #[neli(input = "(nl_len as usize - Self::header_size() as usize, nl_type)")]
    #[neli(size = "nl_len as usize - Self::header_size() as usize")]
    pub nl_payload: NlPayload<T, P>,
}

impl<T, P> Nlmsghdr<T, P>
where
    T: NlType,
    P: Size,
{
    /// Create a new top level netlink packet with a payload.
    pub fn new(
        nl_len: Option<u32>,
        nl_type: T,
        nl_flags: NlmFFlags,
        nl_seq: Option<u32>,
        nl_pid: Option<u32>,
        nl_payload: NlPayload<T, P>,
    ) -> Self {
        let mut nl = Nlmsghdr {
            nl_len: 0,
            nl_type,
            nl_flags,
            nl_seq: nl_seq.unwrap_or(0),
            nl_pid: nl_pid.unwrap_or(0),
            nl_payload,
        };
        nl.nl_len = nl_len.unwrap_or(nl.padded_size() as u32);
        nl
    }

    /// Get the payload if there is one or return an error.
    pub fn get_payload(&self) -> Result<&P, NlError> {
        match self.nl_payload {
            NlPayload::Payload(ref p) => Ok(p),
            _ => Err(NlError::new("This packet does not have a payload")),
        }
    }
}
