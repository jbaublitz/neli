//! This is the module that contains the error types used in `neli`
//!
//! There are four main types:
//! * [`Nlmsgerr`][crate::err::Nlmsgerr] - an application error returned from netlink as
//! a packet.
//! * [`NlError`][crate::err::NlError] - a general netlink error wrapping application
//! errors, serialization and deserialization errors, and other
//! errors that occur in `neli`.
//! * [`DeError`] - error while deserializing
//! * [`SerError`] - error while serializing
//!
//! # Design decisions
//! All errors implement `std::error::Error` in an attempt to allow
//! them to be used in conjunction with `Result` for easier error
//! management even at the protocol error level.
//!
//! Deserializing the [`NlmsghdrErr`] struct simply consumes the
//! remaining data available in the deserialization buffer for the
//! `nl_payload` field. This is due to the fact that ACKs do not
//! contain the payload of the packet that triggered the ACK, but
//! errors do contain the payload of the packet that triggered
//! the error. This means that the `nl_len` field of [`NlmsghdrErr`]
//! cannot be relied on for deserialization. To access the payload
//! of the packet that caused the error, use
//! [`NlmsghdrErr::get_payload_as`]. See the `examples/` directory
//! for a usage example.

use std::{
    error::Error,
    fmt::{self, Debug, Display},
    io,
    mem::size_of,
    str, string,
};

use serde::{Serialize, ser};

use crate::{
    consts::nl::{NlType, NlmFFlags},
    types::{Buffer, DeBuffer, SerBuffer},
    Nl,
};

/// An [`Nlmsghdr`][crate::nl::Nlmsghdr] header with no payload
/// returned as part of errors.
#[derive(Debug, PartialEq, Serialize)]
pub struct NlmsghdrErr<T> {
    /// Length of the netlink message
    pub nl_len: u32,
    /// Type of the netlink message
    pub nl_type: T,
    /// Flags indicating properties of the request or response
    pub nl_flags: NlmFFlags,
    /// Sequence number for netlink protocol
    pub nl_seq: u32,
    /// ID of the netlink destination for requests and source for responses
    pub nl_pid: u32,
    /// Optionally the payload of the packet that caused the error
    ///
    /// For ACKs, this will be an empty vector. For errors, this
    /// will be the serialized payload of the packet that caused
    /// the error.
    nl_payload: Buffer,
}

impl<T> NlmsghdrErr<T>
where
    T: NlType,
{
    /// Create a new error packet payload.
    pub fn new(
        nl_len: u32,
        nl_type: T,
        nl_flags: NlmFFlags,
        nl_seq: u32,
        nl_pid: u32,
        nl_payload: Option<Buffer>,
    ) -> Self {
        NlmsghdrErr {
            nl_len,
            nl_type,
            nl_flags,
            nl_seq,
            nl_pid,
            nl_payload: nl_payload.unwrap_or_default(),
        }
    }

    /// Deserialize the payload received in the error packet as
    /// type parameter `P`.
    pub fn get_payload_as<P>(&self) -> Result<P, DeError>
    where
        P: Nl,
    {
        P::deserialize(self.nl_payload.as_ref())
    }
}

impl<T> Nl for NlmsghdrErr<T>
where
    T: NlType,
{
    fn serialize(&self, mem: SerBuffer) -> Result<(), SerError> {
        serialize! {
            mem;
            self.nl_len;
            self.nl_type;
            self.nl_flags;
            self.nl_seq;
            self.nl_pid;
            self.nl_payload
        }
        Ok(())
    }

    fn deserialize(mem: DeBuffer) -> Result<Self, DeError> {
        Ok(deserialize! {
            mem;
            NlmsghdrErr::<T> {
                nl_len: u32,
                nl_type: T,
                nl_flags: NlmFFlags,
                nl_seq: u32,
                nl_pid: u32,
                nl_payload: Buffer => {
                    mem.len().checked_sub(
                        size_of::<u32>() * 3
                      + T::type_size().expect("Constant size")
                      + NlmFFlags::type_size().expect("Constant size")
                    ).ok_or(DeError::UnexpectedEOB)?
                },
            }
        })
    }

    fn size(&self) -> usize {
        self.nl_len.size()
            + self.nl_type.size()
            + self.nl_flags.size()
            + self.nl_seq.size()
            + self.nl_pid.size()
            + self.nl_payload.size()
    }

    fn type_size() -> Option<usize> {
        None
    }
}

/// Struct representing netlink packets containing errors
#[derive(Debug, PartialEq, Serialize)]
pub struct Nlmsgerr<T> {
    /// Error code
    pub error: libc::c_int,
    /// Packet header for request that failed
    pub nlmsg: NlmsghdrErr<T>,
}

impl<T> Display for Nlmsgerr<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", io::Error::from_raw_os_error(self.error))
    }
}

impl<T> Error for Nlmsgerr<T> where T: Debug {}

impl<T> Nl for Nlmsgerr<T>
where
    T: NlType,
{
    fn deserialize(mem: DeBuffer) -> Result<Self, DeError> {
        Ok(deserialize! {
            mem;
            Nlmsgerr::<T> {
                error: libc::c_int,
                nlmsg: NlmsghdrErr<T> => {
                    mem.len() - size_of::<libc::c_int>()
                },
            }
        })
    }

    fn size(&self) -> usize {
        self.error.size() + self.nlmsg.size()
    }

    fn type_size() -> Option<usize> {
        NlmsghdrErr::<T>::type_size()
            .and_then(|nhdr_sz| libc::c_int::type_size().map(|cint| cint + nhdr_sz))
    }
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
pub enum NlError {
    /// Variant for [`String`]-based messages.
    Msg(String),
    /// An error packet sent back by netlink.
    Nlmsgerr(Nlmsgerr<u16>),
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

err_from!(
    NlError,
    Nlmsgerr<u16> { NlError::Nlmsgerr },
    SerError { NlError::Ser },
    DeError { NlError::De },
    WrappedError { NlError::Wrapped },
    std::io::Error { |e| NlError::Wrapped(WrappedError::from(e)) },
    std::str::Utf8Error { |e| NlError::Wrapped(WrappedError::from(e)) },
    std::string::FromUtf8Error { |e| NlError::Wrapped(WrappedError::from(e)) },
    std::ffi::FromBytesWithNulError { |e| NlError::Wrapped(WrappedError::from(e)) }
);

impl NlError {
    /// Create new error from a data type implementing
    /// [`Display`][std::fmt::Display]
    pub fn new<D>(s: D) -> Self
    where
        D: Display,
    {
        NlError::Msg(s.to_string())
    }
}

impl Display for NlError {
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

impl Error for NlError {}

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

impl ser::Error for SerError {
    fn custom<T>(msg: T) -> Self where T: Display {
        SerError::new(msg)
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
