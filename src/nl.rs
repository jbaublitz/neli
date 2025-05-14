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

use std::{
    any::type_name,
    io::Cursor,
    mem::{size_of, swap},
};

use derive_builder::{Builder, UninitializedFieldError};
use getset::Getters;
use log::trace;

use crate::{
    self as neli,
    consts::nl::{NlType, NlmF, Nlmsg},
    err::{DeError, Nlmsgerr, NlmsgerrBuilder, NlmsghdrAck, NlmsghdrErr, RouterError},
    types::{Buffer, GenlBuffer},
    FromBytes, FromBytesWithInput, Header, Size, ToBytes, TypeSize,
};

/// An enum representing either the desired payload as requested
/// by the payload type parameter, an ACK received at the end
/// of a message or stream of messages, or an error.
#[derive(Clone, Debug, PartialEq, Eq, Size, ToBytes)]
pub enum NlPayload<T, P> {
    /// Represents an ACK returned by netlink.
    Ack(Nlmsgerr<NlmsghdrAck<T>>),
    /// Represents an ACK extracted from the DONE packet returned by netlink
    /// on a DUMP.
    DumpExtAck(Nlmsgerr<()>),
    /// Represents an application level error returned by netlink.
    Err(Nlmsgerr<NlmsghdrErr<T, P>>),
    /// Represents the requested payload.
    Payload(P),
    /// Indicates an empty payload.
    Empty,
}

impl<T, P> FromBytesWithInput for NlPayload<T, P>
where
    P: Size + FromBytesWithInput<Input = usize>,
    T: NlType,
{
    type Input = (usize, T);

    fn from_bytes_with_input(
        buffer: &mut Cursor<impl AsRef<[u8]>>,
        (input_size, input_type): (usize, T),
    ) -> Result<Self, DeError> {
        let pos = buffer.position();

        let mut processing = || {
            trace!("Deserializing data type {}", type_name::<Self>());
            let ty_const: u16 = input_type.into();
            if ty_const == Nlmsg::Done.into() {
                if buffer.position() == buffer.get_ref().as_ref().len() as u64 {
                    Ok(NlPayload::Empty)
                } else {
                    trace!(
                        "Deserializing field type {}",
                        std::any::type_name::<Nlmsgerr<()>>(),
                    );
                    trace!("Input: {:?}", input_size);
                    let ext = Nlmsgerr::from_bytes_with_input(buffer, input_size)?;
                    Ok(NlPayload::DumpExtAck(ext))
                }
            } else if ty_const == Nlmsg::Error.into() {
                trace!(
                    "Deserializing field type {}",
                    std::any::type_name::<libc::c_int>()
                );
                let code = libc::c_int::from_bytes(buffer)?;
                trace!("Field deserialized: {:?}", code);
                if code == 0 {
                    trace!(
                        "Deserializing field type {}",
                        std::any::type_name::<NlmsghdrErr<T, ()>>()
                    );
                    trace!("Input: {:?}", input_size);
                    let nlmsg = NlmsghdrAck::<T>::from_bytes(buffer)?;
                    trace!("Field deserialized: {:?}", nlmsg);
                    Ok(NlPayload::Ack(
                        NlmsgerrBuilder::default().nlmsg(nlmsg).build()?,
                    ))
                } else {
                    trace!(
                        "Deserializing field type {}",
                        std::any::type_name::<NlmsghdrErr<T, ()>>()
                    );
                    let nlmsg = NlmsghdrErr::<T, P>::from_bytes(buffer)?;
                    trace!("Field deserialized: {:?}", nlmsg);

                    trace!(
                        "Deserializing field type {}",
                        std::any::type_name::<GenlBuffer<u16, Buffer>>()
                    );
                    let input = input_size - size_of::<libc::c_int>() - nlmsg.padded_size();
                    trace!("Input: {:?}", input);
                    let ext_ack = GenlBuffer::from_bytes_with_input(buffer, input)?;
                    trace!("Field deserialized: {:?}", ext_ack);

                    Ok(NlPayload::Err(
                        NlmsgerrBuilder::default()
                            .error(code)
                            .nlmsg(nlmsg)
                            .ext_ack(ext_ack)
                            .build()?,
                    ))
                }
            } else {
                Ok(NlPayload::Payload(P::from_bytes_with_input(
                    buffer, input_size,
                )?))
            }
        };

        match processing() {
            Ok(o) => Ok(o),
            Err(e) => {
                buffer.set_position(pos);
                Err(e)
            }
        }
    }
}

/// Top level netlink header and payload
#[derive(Builder, Getters, Clone, Debug, PartialEq, Eq, Size, ToBytes, FromBytes, Header)]
#[neli(header_bound = "T: TypeSize")]
#[neli(from_bytes_bound = "T: NlType")]
#[neli(from_bytes_bound = "P: Size + FromBytesWithInput<Input = usize>")]
#[neli(padding)]
#[builder(build_fn(skip))]
#[builder(pattern = "owned")]
pub struct Nlmsghdr<T, P> {
    /// Length of the netlink message
    #[builder(setter(skip))]
    #[getset(get = "pub")]
    nl_len: u32,
    /// Type of the netlink message
    #[getset(get = "pub")]
    nl_type: T,
    /// Flags indicating properties of the request or response
    #[getset(get = "pub")]
    nl_flags: NlmF,
    /// Sequence number for netlink protocol
    #[getset(get = "pub")]
    nl_seq: u32,
    /// ID of the netlink destination for requests and source for
    /// responses.
    #[getset(get = "pub")]
    nl_pid: u32,
    /// Payload of netlink message
    #[neli(input = "(nl_len as usize - Self::header_size() as usize, nl_type)")]
    #[neli(size = "nl_len as usize - Self::header_size() as usize")]
    #[getset(get = "pub")]
    pub(crate) nl_payload: NlPayload<T, P>,
}

impl<T, P> NlmsghdrBuilder<T, P>
where
    T: NlType,
    P: Size,
{
    /// Build [`Nlmsghdr`].
    pub fn build(self) -> Result<Nlmsghdr<T, P>, NlmsghdrBuilderError> {
        let nl_type = self
            .nl_type
            .ok_or_else(|| NlmsghdrBuilderError::from(UninitializedFieldError::new("nl_type")))?;
        let nl_flags = self
            .nl_flags
            .ok_or_else(|| NlmsghdrBuilderError::from(UninitializedFieldError::new("nl_flags")))?;
        let nl_seq = self.nl_seq.unwrap_or(0);
        let nl_pid = self.nl_pid.unwrap_or(0);
        let nl_payload = self.nl_payload.ok_or_else(|| {
            NlmsghdrBuilderError::from(UninitializedFieldError::new("nl_payload"))
        })?;

        let mut nl = Nlmsghdr {
            nl_len: 0,
            nl_type,
            nl_flags,
            nl_seq,
            nl_pid,
            nl_payload,
        };
        nl.nl_len = nl.padded_size() as u32;
        Ok(nl)
    }
}

impl<T, P> Nlmsghdr<T, P>
where
    T: NlType,
{
    /// Get the payload if there is one or return an error.
    pub fn get_payload(&self) -> Option<&P> {
        match self.nl_payload {
            NlPayload::Payload(ref p) => Some(p),
            _ => None,
        }
    }

    /// Get an error from the payload if it exists.
    ///
    /// Takes a mutable reference because the payload will be swapped for
    /// [`Empty`][NlPayload::Empty] to gain ownership of the error.
    pub fn get_err(&mut self) -> Option<Nlmsgerr<NlmsghdrErr<T, P>>> {
        match self.nl_payload {
            NlPayload::Err(_) => {
                let mut payload = NlPayload::Empty;
                swap(&mut self.nl_payload, &mut payload);
                match payload {
                    NlPayload::Err(e) => Some(e),
                    _ => unreachable!(),
                }
            }
            _ => None,
        }
    }
}

impl NlPayload<u16, Buffer> {
    /// Convert a typed payload from a payload that can represent all types.
    pub fn to_typed<T, P>(self, payload_size: usize) -> Result<NlPayload<T, P>, RouterError<T, P>>
    where
        T: NlType,
        P: Size + FromBytesWithInput<Input = usize>,
    {
        match self {
            NlPayload::Ack(a) => Ok(NlPayload::Ack(a.to_typed()?)),
            NlPayload::Err(e) => Ok(NlPayload::Err(e.to_typed()?)),
            NlPayload::DumpExtAck(a) => Ok(NlPayload::DumpExtAck(a)),
            NlPayload::Payload(p) => Ok(NlPayload::Payload(P::from_bytes_with_input(
                &mut Cursor::new(p),
                payload_size,
            )?)),
            NlPayload::Empty => Ok(NlPayload::Empty),
        }
    }
}

impl<T, P> Nlmsghdr<T, P>
where
    T: NlType,
    P: Size,
{
    /// Set the payload for [`Nlmsghdr`] and handle the change in length internally.
    pub fn set_payload(&mut self, p: NlPayload<T, P>) {
        self.nl_len -= self.nl_payload.padded_size() as u32;
        self.nl_len += p.padded_size() as u32;
        self.nl_payload = p;
    }
}

impl Nlmsghdr<u16, Buffer> {
    /// Set the payload for [`Nlmsghdr`] and handle the change in length internally.
    pub fn to_typed<T, P>(self) -> Result<Nlmsghdr<T, P>, RouterError<T, P>>
    where
        T: NlType,
        P: Size + FromBytesWithInput<Input = usize>,
    {
        Ok(NlmsghdrBuilder::default()
            .nl_type(T::from(self.nl_type))
            .nl_flags(self.nl_flags)
            .nl_seq(self.nl_seq)
            .nl_pid(self.nl_pid)
            .nl_payload(
                self.nl_payload
                    .to_typed::<T, P>(self.nl_len as usize - Self::header_size())?,
            )
            .build()?)
    }
}
