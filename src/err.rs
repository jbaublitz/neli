//! This is the module that contains the error types used in `neli`
//!
//! There are four main types:
//! * `Nlmsgerr` - an error returned from netlink at the protocol level
//! * `NlError` - typically socket errors
//! * `DeError` - error while deserializing
//! * `SerError` - error while serializing
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
    nl::{NlEmpty, Nlmsghdr},
    types::{DeBuffer, SerBuffer},
    Nl,
};

/// An nlmsghdr struct with no payload returned as part of errors.
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
    fn serialize<'a>(&self, mem: SerBuffer<'a>) -> Result<SerBuffer<'a>, SerError<'a>> {
        Ok(serialize! {
            mem;
            self.nl_len;
            self.nl_type;
            self.nl_flags;
            self.nl_seq;
            self.nl_pid
        })
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
    fn serialize<'a>(&self, mem: SerBuffer<'a>) -> Result<SerBuffer<'a>, SerError<'a>> {
        Ok(serialize! {
            mem;
            self.error;
            self.nlmsg
        })
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
        Nlmsghdr::<T, NlEmpty>::type_size()
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

/// Netlink protocol error
#[derive(Debug)]
pub enum NlError {
    /// Type indicating a message from a converted error
    Msg(String),
    /// An error packet sent back by netlink
    Nlmsgerr(Nlmsgerr<NlTypeWrapper>),
    /// A wrapped error from lower in the call stack
    Wrapped(WrappedError),
    /// No ack was received when `NlmF::Ack` was specified in the request
    NoAck,
    /// The sequence number for the response did not match the request
    BadSeq,
    /// Incorrect PID socket identifier in received message
    BadPid,
}

err_from!(
    NlError,
    Nlmsgerr<NlTypeWrapper> { NlError::Nlmsgerr },
    WrappedError { NlError::Wrapped },
    std::io::Error { |e| NlError::Wrapped(WrappedError::from(e)) },
    std::str::Utf8Error { |e| NlError::Wrapped(WrappedError::from(e)) },
    std::string::FromUtf8Error { |e| NlError::Wrapped(WrappedError::from(e)) },
    std::ffi::FromBytesWithNulError { |e| NlError::Wrapped(WrappedError::from(e)) }
);

impl NlError {
    /// Create new error from a data type implementing `Display`
    pub fn new<D>(s: D) -> Self
    where
        D: Display,
    {
        NlError::Msg(s.to_string())
    }
}

/// Netlink protocol error
impl Display for NlError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            NlError::Msg(ref msg) => write!(f, "{}", msg),
            NlError::Nlmsgerr(ref err) => {
                write!(f, "Error response received from netlink: {}", err)
            }
            NlError::NoAck => write!(f, "No ack received"),
            NlError::BadSeq => write!(f, "Sequence number does not match the request"),
            NlError::BadPid => write!(f, "PID does not match the socket"),
            NlError::Wrapped(ref e) => write!(f, "Netlink failure due to error: {}", e),
        }
    }
}

impl Error for NlError {}

/// The type of error associated with the cause of the serialization
/// failure.
#[derive(Debug)]
pub enum SerErrorKind {
    /// Abitrary error message.
    Msg(String),
    /// A wrapped error from lower in the call stack.
    Wrapped(WrappedError),
    /// The end of the buffer was reached before serialization finished.
    UnexpectedEOB,
    /// Serialization did not fill the buffer.
    BufferNotFilled,
}

/// Serialization error
#[derive(Debug)]
pub struct SerError<'a> {
    /// Error cause.
    kind: SerErrorKind,
    /// Buffer of data that was passed to the serialization operation.
    buffer: SerBuffer<'a>,
}

impl<'a> SerError<'a> {
    /// Create a new error with the given message as description
    pub fn new<D>(msg: D, buffer: SerBuffer<'a>) -> Self
    where
        D: Display,
    {
        SerError {
            kind: SerErrorKind::Msg(msg.to_string()),
            buffer,
        }
    }

    /// Create a new error specifying the type of the error that
    /// caused the serialization failure.
    pub fn new_with_kind(kind: SerErrorKind, buffer: SerBuffer<'a>) -> Self {
        SerError { kind, buffer }
    }

    /// Convert the error to the two components of a `SerError`:
    /// the error kind and the buffer that was being written
    /// into.
    pub fn into_parts(self) -> (SerErrorKind, SerBuffer<'a>) {
        (self.kind, self.buffer)
    }
}

impl<'a> Display for SerError<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.kind {
            SerErrorKind::Msg(ref s) => write!(f, "{}", s),
            SerErrorKind::Wrapped(ref e) => write!(f, "Error while serializing: {}", e),
            SerErrorKind::UnexpectedEOB => write!(
                f,
                "The buffer was too small for the requested serialization operation",
            ),
            SerErrorKind::BufferNotFilled => write!(
                f,
                "The number of bytes written to the buffer did not fill the \
                 given space",
            ),
        }
    }
}

impl<'a> Error for SerError<'a> {}

/// Deserialization error
#[derive(Debug)]
pub enum DeError {
    /// Abitrary error message
    Msg(String),
    /// A wrapped error from lower in the call stack
    Wrapped(WrappedError),
    /// The end of the buffer was reached before deserialization finished
    UnexpectedEOB,
    /// Deserialization did not fill the buffer
    BufferNotParsed,
    /// A null byte was found before the end of the serialized `String`
    NullError,
    /// A null byte was not found at the end of the serialized `String`
    NoNullError,
}

impl DeError {
    /// Create new error from `&str`
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
    /// Wrapper for `std::io::Error`
    IOError(io::Error),
    /// Wrapper for `std::str::Utf8Error`
    StrUtf8Error(str::Utf8Error),
    /// Wrapper for `std::string::FromUtf8Error`
    StringUtf8Error(string::FromUtf8Error),
    /// Wrapper for `std::ffi::FromBytesWithNulError`
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
