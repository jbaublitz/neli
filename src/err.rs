//! This is the module that contains the error types used in `neli`
//!
//! There are four main types:
//! * [`Nlmsgerr`] - an application error
//!   returned from netlink as a packet.
//! * [`NlError`] - a general netlink error
//!   wrapping application errors, serialization and deserialization
//!   errors, and other errors that occur in `neli`.
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
//! [`Buffer`] respectively which work for
//! all cases. See the `examples/` directory for a usage example.

use crate as neli;

use std::{
    error::Error,
    fmt::{self, Debug, Display},
    io, str, string,
};

use crate::{
    consts::nl::{NlType, NlmFFlags},
    types::Buffer,
    FromBytes, FromBytesWithInput, Header, Size, ToBytes, TypeSize,
};

/// A special struct that represents the contents of an error
/// returned at the application level. Because the returned
/// [`nl_len`][NlmsghdrErr::nl_len] cannot always determine the
/// length of the packet (as in the case of ACKs where no payload
/// will be returned), this data structure relies on the total
/// packet size for deserialization.
#[derive(Debug, PartialEq, Eq, Size, ToBytes, FromBytesWithInput, Header)]
#[neli(header_bound = "T: TypeSize")]
#[neli(from_bytes_bound = "T: TypeSize + FromBytes")]
#[neli(from_bytes_bound = "P: FromBytesWithInput<Input = usize>")]
pub struct NlmsghdrErr<T, P> {
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
    #[neli(input = "input - Self::header_size()")]
    pub nl_payload: P,
}

/// Struct representing netlink packets containing errors
#[derive(Debug, PartialEq, Eq, Size, FromBytesWithInput, ToBytes, Header)]
#[neli(from_bytes_bound = "T: NlType")]
#[neli(from_bytes_bound = "P: FromBytesWithInput<Input = usize>")]
pub struct Nlmsgerr<T, P> {
    /// Error code
    pub error: libc::c_int,
    /// Packet header for request that failed
    #[neli(input = "input - Self::header_size()")]
    pub nlmsg: NlmsghdrErr<T, P>,
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

macro_rules! err_from {
    ($err:ident, $($from_err:path { $from_impl:expr }),+) => {
        $(
            impl From<$from_err> for $err {
                fn from(e: $from_err) -> Self {
                    $from_impl(e)
                }
            }
        )*
    };
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
    /// A wrapped error from lower in the call stack.
    Wrapped(WrappedError),
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
        NlError::Wrapped(WrappedError::IOError(err))
    }
}

err_from!(
    NlError,
    WrappedError { NlError::Wrapped },
    std::str::Utf8Error { |e| NlError::Wrapped(WrappedError::from(e)) },
    std::string::FromUtf8Error { |e| NlError::Wrapped(WrappedError::from(e)) },
    std::ffi::FromBytesWithNulError { |e| NlError::Wrapped(WrappedError::from(e)) }
);

impl NlError {
    /// Create new error from a data type implementing
    /// [`Display`]
    pub fn msg<D>(s: D) -> Self
    where
        D: Display,
    {
        NlError::Msg(s.to_string())
    }
}

impl<T, P> NlError<T, P> {
    /// Create new error from a data type implementing
    /// [`Display`]
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
            NlError::NoAck => write!(f, "No ack received"),
            NlError::BadSeq => write!(f, "Sequence number does not match the request"),
            NlError::BadPid => write!(f, "PID does not match the socket"),
            NlError::Wrapped(ref e) => write!(f, "Netlink failure due to error: {}", e),
        }
    }
}

impl<T, P> Error for NlError<T, P>
where
    T: Debug,
    P: Debug,
{
}

/// Serialization error
#[derive(Debug)]
pub enum SerError {
    /// Abitrary error message.
    Msg(String),
    /// A wrapped error from lower in the call stack.
    Wrapped(WrappedError),
    /// The end of the buffer was reached before serialization finished.
    UnexpectedEOB,
    /// Serialization did not fill the buffer.
    BufferNotFilled,
}

err_from!(
    SerError,
    WrappedError { SerError::Wrapped },
    std::io::Error { |e| SerError::Wrapped(WrappedError::from(e)) },
    std::str::Utf8Error { |e| SerError::Wrapped(WrappedError::from(e)) },
    std::string::FromUtf8Error { |e| SerError::Wrapped(WrappedError::from(e)) },
    std::ffi::FromBytesWithNulError { |e| SerError::Wrapped(WrappedError::from(e)) }
);

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
            SerError::Wrapped(ref e) => write!(f, "Error while serializing: {}", e),
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

err_from!(
    DeError,
    WrappedError { DeError::Wrapped },
    std::io::Error { |e| DeError::Wrapped(WrappedError::from(e)) },
    std::str::Utf8Error { |e| DeError::Wrapped(WrappedError::from(e)) },
    std::string::FromUtf8Error { |e| DeError::Wrapped(WrappedError::from(e)) },
    std::ffi::FromBytesWithNulError { |e| DeError::Wrapped(WrappedError::from(e)) }
);

/// Deserialization error
#[derive(Debug)]
pub enum DeError {
    /// Abitrary error message.
    Msg(String),
    /// A wrapped error from lower in the call stack.
    Wrapped(WrappedError),
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
    /// [`Display`]
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
            DeError::UnexpectedEOB => write!(
                f,
                "The buffer was not large enough to complete the deserialize \
                 operation",
            ),
            DeError::BufferNotParsed => write!(f, "Unparsed data left in buffer"),
            DeError::NullError => write!(f, "A null was found before the end of the buffer"),
            DeError::NoNullError => write!(f, "No terminating null byte was found in the buffer"),
            DeError::Wrapped(ref e) => write!(f, "Error while deserializing: {}", e),
        }
    }
}

impl Error for DeError {}

/// An error to wrap all system level errors in a single, higher level
/// error.
#[derive(Debug)]
pub enum WrappedError {
    /// Wrapper for [`std::io::Error`]
    IOError(io::Error),
    /// Wrapper for [`std::str::Utf8Error`]
    StrUtf8Error(str::Utf8Error),
    /// Wrapper for [`std::string::FromUtf8Error`]
    StringUtf8Error(string::FromUtf8Error),
    /// Wrapper for [`std::ffi::FromBytesWithNulError`]
    FFINullError(std::ffi::FromBytesWithNulError),
}

impl Display for WrappedError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            WrappedError::IOError(ref e) => write!(f, "Wrapped IO error: {}", e),
            WrappedError::StrUtf8Error(ref e) => write!(f, "Wrapped &str error: {}", e),
            WrappedError::StringUtf8Error(ref e) => write!(f, "Wrapped String error: {}", e),
            WrappedError::FFINullError(ref e) => write!(f, "Wrapped null error: {}", e),
        }
    }
}

impl Error for WrappedError {}

macro_rules! wrapped_err_from {
    ($($var:ident => $from_err_name:path),*) => {
        $(
            impl From<$from_err_name> for WrappedError {
                fn from(v: $from_err_name) -> Self {
                    WrappedError::$var(v)
                }
            }
        )*
    }
}

wrapped_err_from!(
    IOError => std::io::Error,
    StrUtf8Error => std::str::Utf8Error,
    StringUtf8Error => std::string::FromUtf8Error,
    FFINullError => std::ffi::FromBytesWithNulError
);
