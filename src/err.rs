use std;
use std::error::Error;
use std::fmt::{self,Display};
use std::io;
use std::str;
use std::string;

macro_rules! try_err_compat {
    ( $err_name:ident, $( $from_err_name:path ),* ) => {
        $(
            impl From<$from_err_name> for $err_name {
                fn from(v: $from_err_name) -> Self {
                    $err_name(v.description().to_string())
                }
            }
        )*
    }
}

/// Netlink protocol error
#[derive(Debug)]
pub struct NlError(String);

try_err_compat!(NlError, io::Error, SerError, DeError);

impl NlError {
    /// Create new error from `&str`
    pub fn new(s: &str) -> Self {
        NlError(s.to_string())
    }
}

/// Netlink protocol error
impl Display for NlError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Error for NlError {
    fn description(&self) -> &str {
        self.0.as_str()
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

try_err_compat!(DeError, io::Error, str::Utf8Error, string::FromUtf8Error,
                std::ffi::FromBytesWithNulError);

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
