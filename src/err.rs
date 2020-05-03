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

use buffering::{StreamReadBuffer, StreamWriteBuffer};

use crate::{
    consts::NlType,
    nl::{NlEmpty, Nlmsghdr},
    Nl,
};

macro_rules! try_err_compat {
    ( $err_name:ident, $( $from_err_name:path ),* ) => {
        $(
            impl From<$from_err_name> for $err_name {
                fn from(v: $from_err_name) -> Self {
                    $err_name::new(&v.to_string())
                }
            }
        )*
    }
}

/// Struct representing netlink packets containing errors
#[derive(Debug)]
pub struct Nlmsgerr<T> {
    /// Error code
    pub error: libc::c_int,
    /// Packet header for request that failed
    pub nlmsg: Nlmsghdr<T, NlEmpty>,
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
    fn serialize(&self, mem: &mut StreamWriteBuffer) -> Result<(), SerError> {
        self.error.serialize(mem)?;
        self.nlmsg.serialize(mem)?;
        self.pad(mem)?;
        Ok(())
    }

    fn deserialize<B>(mem: &mut StreamReadBuffer<B>) -> Result<Self, DeError>
    where
        B: AsRef<[u8]>,
    {
        let nlmsg = Nlmsgerr {
            error: libc::c_int::deserialize(mem)?,
            nlmsg: Nlmsghdr::<T, NlEmpty>::deserialize(mem)?,
        };
        nlmsg.strip(mem)?;
        Ok(nlmsg)
    }

    fn size(&self) -> usize {
        self.error.size() + self.nlmsg.size()
    }
}

/// Netlink protocol error
#[derive(Debug)]
pub enum NlError {
    /// Type indicating a message from a converted error
    Msg(String),
    /// An error packet sent back by netlink
    Nlmsgerr(Nlmsgerr<u16>),
    /// No ack was received when `NlmF::Ack` was specified in the request
    NoAck,
    /// The sequence number for the response did not match the request
    BadSeq,
    /// Incorrect PID socket identifier in received message
    BadPid,
}

try_err_compat!(NlError, io::Error, SerError, DeError);

impl NlError {
    /// Create new error from `&str`
    pub fn new(s: &str) -> Self {
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
        }
    }
}

impl Error for NlError {}

/// Serialization error
#[derive(Debug)]
pub struct SerError(String);

impl SerError {
    /// Create a new error with the given message as description
    pub fn new<T: ToString>(msg: T) -> Self {
        SerError(msg.to_string())
    }
}

try_err_compat!(SerError, io::Error);

impl Display for SerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Error for SerError {}

/// Deserialization error
#[derive(Debug)]
pub struct DeError(String);

impl DeError {
    /// Create new error from `&str`
    pub fn new(s: &str) -> Self {
        DeError(s.to_string())
    }
}

try_err_compat!(
    DeError,
    io::Error,
    str::Utf8Error,
    string::FromUtf8Error,
    std::ffi::FromBytesWithNulError
);

impl Display for DeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Error for DeError {}
