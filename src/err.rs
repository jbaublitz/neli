//! This is the module that contains the error types used in `neli`
//!
//! There are four main types:
//! * [`Nlmsgerr`][crate::err::Nlmsgerr] - an application error
//! returned from netlink as a packet.
//! * [`NlError`][crate::err::NlError] - a general netlink error
//! wrapping application errors, serialization and deserialization
//! errors, and other errors that occur in `neli`.
//! * [`DeError`] - error while deserializing
//! * [`SerError`] - error while serializing
//!
//! # Design decisions
//! All errors implement [`std::error::Error`] in an attempt to allow
//! them to be used in conjunction with [`Result`] for easier error
//! management even at the protocol error level.
//!
//! As of v0.6.0, deserializing the [`NlmsghdrErr`] struct has two
//! optional type parameters for specifying the type of the type
//! constant and the payload. If neither of these are provided,
//! the deserialization defaults to [`u16`] and
//! [`Buffer`][crate::types::Buffer] respectively which work for
//! all cases. See the `examples/` directory for a usage example.

use crate as neli;

use std::{
    error::Error,
    fmt::{self, Debug, Display},
    io,
    str::Utf8Error,
    string::FromUtf8Error,
};

use derive_builder::{Builder, UninitializedFieldError};
use getset::Getters;

use crate::{
    consts::nl::{NlType, NlmF, NlmsgerrAttr},
    genl::GenlmsghdrBuilderError,
    nl::NlmsghdrBuilderError,
    types::{Buffer, GenlBuffer},
    FromBytes, FromBytesWithInput, Header, Size, ToBytes, TypeSize,
};

/// A special struct that represents the contents of an error
/// returned at the application level. Because the returned
/// [`nl_len`][NlmsghdrErr::nl_len] cannot always determine the
/// length of the packet (as in the case of ACKs where no payload
/// will be returned), this data structure relies on the total
/// packet size for deserialization.
#[derive(
    Builder, Getters, Clone, Debug, PartialEq, Eq, Size, ToBytes, FromBytesWithInput, Header,
)]
#[neli(header_bound = "T: TypeSize")]
#[neli(from_bytes_bound = "T: TypeSize + FromBytes")]
#[neli(from_bytes_bound = "P: FromBytesWithInput<Input = usize>")]
#[builder(build_fn(skip))]
#[builder(pattern = "owned")]
pub struct NlmsghdrErr<T, P> {
    /// Length of the netlink message
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
    #[neli(input = "input - Self::header_size()")]
    #[getset(get = "pub")]
    nl_payload: P,
}

impl<T> NlmsghdrErrBuilder<T, ()>
where
    T: Clone + NlType,
{
    /// Build [`NlmsghdrErr`].
    pub fn build_ack(self) -> Result<NlmsghdrErr<T, ()>, NlmsghdrErrBuilderError> {
        let nl_len = self
            .nl_len
            .ok_or_else(|| NlmsghdrErrBuilderError::from(UninitializedFieldError::new("nl_len")))?;
        let nl_type = self.nl_type.ok_or_else(|| {
            NlmsghdrErrBuilderError::from(UninitializedFieldError::new("nl_type"))
        })?;
        let nl_flags = self.nl_flags.ok_or_else(|| {
            NlmsghdrErrBuilderError::from(UninitializedFieldError::new("nl_flags"))
        })?;
        let nl_seq = self.nl_seq.unwrap_or(0);
        let nl_pid = self.nl_pid.unwrap_or(0);
        self.nl_payload.map_or_else(
            || Ok(()),
            |_| {
                Err(NlmsghdrErrBuilderError::ValidationError(
                    "Building ACKs disables payload option".to_string(),
                ))
            },
        )?;

        Ok(NlmsghdrErr {
            nl_len,
            nl_type,
            nl_flags,
            nl_seq,
            nl_pid,
            nl_payload: (),
        })
    }
}

impl<'a, T, P> NlmsghdrErrBuilder<T, P>
where
    T: Clone + NlType,
    P: Clone + Size + FromBytesWithInput<'a, Input = usize>,
{
    /// Build [`NlmsghdrErr`].
    pub fn build_err(self) -> Result<NlmsghdrErr<T, P>, NlmsghdrErrBuilderError> {
        let nl_type = self.nl_type.ok_or_else(|| {
            NlmsghdrErrBuilderError::from(UninitializedFieldError::new("nl_type"))
        })?;
        let nl_flags = self.nl_flags.ok_or_else(|| {
            NlmsghdrErrBuilderError::from(UninitializedFieldError::new("nl_flags"))
        })?;
        let nl_seq = self.nl_seq.unwrap_or(0);
        let nl_pid = self.nl_pid.unwrap_or(0);
        let nl_payload = self.nl_payload.ok_or_else(|| {
            NlmsghdrErrBuilderError::from(UninitializedFieldError::new("nl_payload"))
        })?;

        let mut nl = NlmsghdrErr {
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

/// Struct representing netlink packets containing errors
#[derive(Builder, Getters, Clone, Debug, PartialEq, Eq, Size, FromBytesWithInput, ToBytes)]
#[neli(from_bytes_bound = "T: NlType")]
#[neli(from_bytes_bound = "P: Size + FromBytesWithInput<Input = usize>")]
#[builder(pattern = "owned")]
pub struct Nlmsgerr<T, P> {
    /// Error code
    #[builder(default = "0")]
    #[getset(get = "pub")]
    error: libc::c_int,
    /// Packet header for request that failed
    #[neli(input = "input - std::mem::size_of::<libc::c_int>()")]
    #[getset(get = "pub")]
    nlmsg: NlmsghdrErr<T, P>,
    #[neli(input = "input - std::mem::size_of::<libc::c_int>() - nlmsg.padded_size()")]
    /// Contains attributes representing the extended ACK
    #[builder(default = "GenlBuffer::new()")]
    #[getset(get = "pub")]
    ext_ack: GenlBuffer<NlmsgerrAttr, Buffer>,
}

impl<T, P> Display for Nlmsgerr<T, P> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", io::Error::from_raw_os_error(-self.error))
    }
}

impl<T, P> Error for Nlmsgerr<T, P>
where
    T: Debug,
    P: Debug,
{
}

#[derive(Debug)]
#[allow(missing_docs)]
pub enum BuilderError {
    #[allow(missing_docs)]
    Nlmsghdr(NlmsghdrBuilderError),
    #[allow(missing_docs)]
    Nlmsgerr(NlmsgerrBuilderError),
    #[allow(missing_docs)]
    NlmsghdrErr(NlmsghdrErrBuilderError),
    #[allow(missing_docs)]
    Genlmsghdr(GenlmsghdrBuilderError),
}

impl Display for BuilderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            BuilderError::Nlmsghdr(err) => write!(f, "{}", err),
            BuilderError::Nlmsgerr(err) => write!(f, "{}", err),
            BuilderError::NlmsghdrErr(err) => write!(f, "{}", err),
            BuilderError::Genlmsghdr(err) => write!(f, "{}", err),
        }
    }
}

impl From<NlmsghdrBuilderError> for BuilderError {
    fn from(e: NlmsghdrBuilderError) -> Self {
        BuilderError::Nlmsghdr(e)
    }
}

impl From<NlmsgerrBuilderError> for BuilderError {
    fn from(e: NlmsgerrBuilderError) -> Self {
        BuilderError::Nlmsgerr(e)
    }
}

impl From<NlmsghdrErrBuilderError> for BuilderError {
    fn from(e: NlmsghdrErrBuilderError) -> Self {
        BuilderError::NlmsghdrErr(e)
    }
}

impl From<GenlmsghdrBuilderError> for BuilderError {
    fn from(e: GenlmsghdrBuilderError) -> Self {
        BuilderError::Genlmsghdr(e)
    }
}

/// General netlink error
#[derive(Debug)]
pub enum NlError<T = u16, P = Buffer> {
    /// Variant for [`String`]-based messages.
    Msg(String),
    /// An error packet sent back by netlink.
    Nlmsgerr(Nlmsgerr<T, P>),
    /// A serialization error.
    Ser(SerError),
    /// A deserialization error.
    De(DeError),
    /// IO error.
    IO(io::Error),
    /// Error resulting from a builder invocation.
    Builder(BuilderError),
    /// No ack was received when
    /// [`NlmF::Ack`][crate::consts::nl::NlmF] was specified in the
    /// request.
    NoAck,
    /// The sequence number for the response did not match the
    /// request.
    BadSeq,
    /// Incorrect PID socket identifier in received message.
    BadPid,
}

impl<T, P> From<Nlmsgerr<T, P>> for NlError<T, P> {
    fn from(err: Nlmsgerr<T, P>) -> Self {
        NlError::Nlmsgerr(err)
    }
}

impl<T, P> From<SerError> for NlError<T, P> {
    fn from(err: SerError) -> Self {
        NlError::Ser(err)
    }
}

impl<T, P> From<DeError> for NlError<T, P> {
    fn from(err: DeError) -> Self {
        NlError::De(err)
    }
}

impl<T, P> From<io::Error> for NlError<T, P> {
    fn from(err: io::Error) -> Self {
        NlError::IO(err)
    }
}

impl<T, P, E> From<E> for NlError<T, P>
where
    BuilderError: From<E>,
{
    fn from(err: E) -> Self {
        NlError::<T, P>::Builder(BuilderError::from(err))
    }
}

impl NlError {
    /// Create new error from a data type implementing
    /// [`Display`][std::fmt::Display]
    pub fn msg<D>(s: D) -> Self
    where
        D: Display,
    {
        NlError::Msg(s.to_string())
    }
}

impl<T, P> NlError<T, P> {
    /// Create new error from a data type implementing
    /// [`Display`][std::fmt::Display]
    pub fn new<D>(s: D) -> Self
    where
        D: Display,
    {
        NlError::Msg(s.to_string())
    }
}

impl<T, P> Display for NlError<T, P>
where
    T: Debug,
    P: Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            NlError::Msg(ref msg) => write!(f, "{}", msg),
            NlError::Nlmsgerr(ref err) => {
                write!(f, "Error response received from netlink: {}", err)
            }
            NlError::Ser(ref err) => {
                write!(f, "Serialization error: {}", err)
            }
            NlError::De(ref err) => {
                write!(f, "Deserialization error: {}", err)
            }
            NlError::IO(ref err) => {
                write!(f, "IO error: {}", err)
            }
            NlError::Builder(ref err) => {
                write!(f, "Builder error: {}", err)
            }
            NlError::NoAck => write!(f, "No ack received"),
            NlError::BadSeq => write!(f, "Sequence number does not match the request"),
            NlError::BadPid => write!(f, "PID does not match the socket"),
        }
    }
}

impl<T, P> Error for NlError<T, P>
where
    T: Debug,
    P: Debug,
{
}

/// [`String`] or [`str`] UTF error.
#[derive(Debug)]
pub enum Utf8 {
    #[allow(missing_docs)]
    Str(Utf8Error),
    #[allow(missing_docs)]
    String(FromUtf8Error),
}

impl Display for Utf8 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Utf8::Str(e) => write!(f, "{}", e),
            Utf8::String(e) => write!(f, "{}", e),
        }
    }
}

/// Serialization error
#[derive(Debug)]
pub enum SerError {
    /// Abitrary error message.
    Msg(String),
    /// IO error.
    IO(io::Error),
    /// String UTF conversion error.
    Utf8(Utf8),
    /// The end of the buffer was reached before serialization finished.
    UnexpectedEOB,
    /// Serialization did not fill the buffer.
    BufferNotFilled,
}

impl SerError {
    /// Create a new error with the given message as description.
    pub fn new<D>(msg: D) -> Self
    where
        D: Display,
    {
        SerError::Msg(msg.to_string())
    }
}

impl Display for SerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SerError::Msg(ref s) => write!(f, "{}", s),
            SerError::IO(ref err) => write!(f, "IO error: {}", err),
            SerError::Utf8(ref err) => write!(f, "UTF error: {}", err),
            SerError::UnexpectedEOB => write!(
                f,
                "The buffer was too small for the requested serialization operation",
            ),
            SerError::BufferNotFilled => write!(
                f,
                "The number of bytes written to the buffer did not fill the \
                 given space",
            ),
        }
    }
}

impl Error for SerError {}

impl From<io::Error> for SerError {
    fn from(err: io::Error) -> Self {
        SerError::IO(err)
    }
}

impl From<Utf8Error> for SerError {
    fn from(err: Utf8Error) -> Self {
        SerError::Utf8(Utf8::Str(err))
    }
}

impl From<FromUtf8Error> for SerError {
    fn from(err: FromUtf8Error) -> Self {
        SerError::Utf8(Utf8::String(err))
    }
}

/// Deserialization error
#[derive(Debug)]
pub enum DeError {
    /// Abitrary error message.
    Msg(String),
    /// IO error.
    IO(io::Error),
    /// String UTF conversion error.
    Utf8(Utf8),
    /// Builder error during deserialization
    Builder(BuilderError),
    /// The end of the buffer was reached before deserialization
    /// finished.
    UnexpectedEOB,
    /// Deserialization did not fill the buffer.
    BufferNotParsed,
    /// A null byte was found before the end of the serialized
    /// [`String`].
    NullError,
    /// A null byte was not found at the end of the serialized
    /// [`String`].
    NoNullError,
}

impl DeError {
    /// Create new error from a type implementing
    /// [`Display`][std::fmt::Display]
    pub fn new<D>(s: D) -> Self
    where
        D: Display,
    {
        DeError::Msg(s.to_string())
    }
}

impl Display for DeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            DeError::Msg(ref s) => write!(f, "{}", s),
            DeError::IO(ref err) => write!(f, "IO error: {}", err),
            DeError::Utf8(ref err) => write!(f, "UTF8 error: {}", err),
            DeError::Builder(ref err) => write!(f, "Builder error: {}", err),
            DeError::UnexpectedEOB => write!(
                f,
                "The buffer was not large enough to complete the deserialize \
                 operation",
            ),
            DeError::BufferNotParsed => write!(f, "Unparsed data left in buffer"),
            DeError::NullError => write!(f, "A null was found before the end of the buffer"),
            DeError::NoNullError => write!(f, "No terminating null byte was found in the buffer"),
        }
    }
}

impl Error for DeError {}

impl From<io::Error> for DeError {
    fn from(err: io::Error) -> Self {
        DeError::IO(err)
    }
}

impl From<Utf8Error> for DeError {
    fn from(err: Utf8Error) -> Self {
        DeError::Utf8(Utf8::Str(err))
    }
}

impl From<FromUtf8Error> for DeError {
    fn from(err: FromUtf8Error) -> Self {
        DeError::Utf8(Utf8::String(err))
    }
}

impl<E> From<E> for DeError
where
    BuilderError: From<E>,
{
    fn from(err: E) -> Self {
        DeError::Builder(BuilderError::from(err))
    }
}
