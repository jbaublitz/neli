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

use std::{
    error::Error,
    fmt::{self, Debug, Display},
    io, str, string,
};

use crate::{
    consts::nl::{NlType, NlTypeWrapper, NlmFFlags},
    types::{DeBuffer, SerBuffer},
    Nl,
};

/// An [`Nlmsghdr`][crate::nl::Nlmsghdr] header with no payload
/// returned as part of errors.
#[derive(Debug, PartialEq)]
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
            self.nl_pid
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
                nl_pid: u32
            }
        })
    }

    fn size(&self) -> usize {
        self.nl_len.size()
            + self.nl_type.size()
            + self.nl_flags.size()
            + self.nl_seq.size()
            + self.nl_pid.size()
    }

    fn type_size() -> Option<usize> {
        Some(
            u32::type_size().expect("Must be constant size") * 3
                + T::type_size().expect("Must be constant size")
                + NlmFFlags::type_size().expect("Must be constant size"),
        )
    }
}

/// Struct representing netlink packets containing errors
#[derive(Debug, PartialEq)]
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
    fn serialize(&self, mem: SerBuffer) -> Result<(), SerError> {
        serialize! {
            mem;
            self.error;
            self.nlmsg
        };
        Ok(())
    }

    fn deserialize(mem: DeBuffer) -> Result<Self, DeError> {
        Ok(deserialize! {
            mem;
            Nlmsgerr::<T> {
                error: libc::c_int,
                nlmsg: NlmsghdrErr<T>
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
    Nlmsgerr(Nlmsgerr<NlTypeWrapper>),
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
    Nlmsgerr<NlTypeWrapper> { NlError::Nlmsgerr },
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

/// Deserialization error. Most variants contain fields for the
/// type and an optional struct field where deserialization failed.
// TODO: Remove deprecated variants in 0.6.0.
#[derive(Debug)]
pub enum DeError {
    /// Abitrary error message.
    Msg(String),
    /// A wrapped error from lower in the call stack.
    Wrapped(WrappedError),
    /// The end of the buffer was reached before deserialization
    /// finished.
    #[deprecated(since = "0.5.2", note = "Switch to DeError::IncompleteType")]
    UnexpectedEOB,
    /// The end of the buffer was reached before deserialization
    /// finished
    IncompleteType(&'static str, Option<&'static str>),
    /// Deserialization did not consume the entire buffer.
    #[deprecated(since = "0.5.2", note = "Switch to DeError::DataLeftInBuffer")]
    BufferNotParsed,
    /// There was additional data at the end of the buffer when
    /// deserialization completed.
    DataLeftInBuffer(&'static str, Option<&'static str>),
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
            #[allow(deprecated)]
            DeError::UnexpectedEOB => write!(
                f,
                "The buffer was not large enough to complete the \
                deserialize operation",
            ),
            DeError::IncompleteType(ref type_, ref field) => {
                write!(f, "Deserializing ")?;
                if let Some(field_name) = field {
                    write!(f, "{} in ", field_name,)?;
                }
                write!(
                    f,
                    "type {} could not be completed: the end of \
                    the deserialization buffer was reached before \
                    the deserialization operation could be completed; \
                    the packet being deserialized may be incomplete \
                    or an incorrectly sized deserialization buffer \
                    may have been provided to the deserialization \
                    operation",
                    type_,
                )
            }
            #[allow(deprecated)]
            DeError::BufferNotParsed => write!(f, "Unparsed data left in buffer"),
            DeError::DataLeftInBuffer(ref type_, ref field) => {
                write!(f, "Deserializing ")?;
                if let Some(field_name) = field {
                    write!(f, "{} in ", field_name,)?;
                }
                write!(
                    f,
                    "type {} could not be completed: the deserialization \
                    operation completed before all of the data in the \
                    buffer could be consumed; the packet being \
                    deserialized may be of the wrong type or an \
                    incorrectly sized deserialization buffer may have \
                    been provided to the deserialization operation",
                    type_,
                )
            }
            DeError::NullError => write!(
                f,
                "A null was found before the end of the buffer while \
                deserializing a String",
            ),
            DeError::NoNullError => write!(
                f,
                "No terminating null byte was found in the buffer \
                when deserializing a String",
            ),
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
