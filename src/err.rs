//! This is the module that contains the error types used in `neli`
//!
//! There are three main types:
//! * `NlError` - typically socket errors
//! * `DeError` - Error while deserializing
//! * `SerError` - Error while serializing
//!
//! Additionally there is one other type: `Nlmsgerr`. This type is returned at the protocol level
//! by netlink sockets when an error has been returned in response to the given request.
//!
//! # Design decisions
//!
//! `NlError` can either be created with a custom `String` message or using three variants, one for
//! no ACK received, one for a bad PID that does not correspond to that assigned to the socket, or
//! one for a bad sequence number that does not correspond to the request sequence number.

use std;
use std::error::Error;
use std::fmt::{self, Display};
use std::io;
use std::str;
use std::string;

use buffering::copy::{StreamReadBuffer, StreamWriteBuffer};
use libc;

use consts::NlType;
use nl::{NlEmpty, Nlmsghdr};
use Nl;

macro_rules! try_err_compat {
    ( $err_name:ident, $( $from_err_name:path ),* ) => {
        $(
            impl From<$from_err_name> for $err_name {
                fn from(v: $from_err_name) -> Self {
                    $err_name::new(v.description())
                }
            }
        )*
    }
}

/// Struct representing netlink packets containing errors
pub struct Nlmsgerr<T> {
    /// Error code
    pub error: libc::c_int,
    /// Packet header for request that failed
    pub nlmsg: Nlmsghdr<T, NlEmpty>,
}

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
        let msg = match *self {
            NlError::Msg(ref msg) => msg,
            NlError::NoAck => "No ack received",
            NlError::BadSeq => "Sequence number does not match the request",
            NlError::BadPid => "PID does not match the socket",
        };
        write!(f, "{}", msg)
    }
}

impl Error for NlError {
    fn description(&self) -> &str {
        match *self {
            NlError::Msg(ref msg) => msg.as_str(),
            NlError::NoAck => "No ack received",
            NlError::BadSeq => "Sequence number does not match the request",
            NlError::BadPid => "PID does not match the socket",
        }
    }
}

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

impl Error for SerError {
    fn description(&self) -> &str {
        self.0.as_str()
    }
}

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

impl Error for DeError {
    fn description(&self) -> &str {
        self.0.as_str()
    }
}
