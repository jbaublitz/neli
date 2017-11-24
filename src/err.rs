use std::error::Error;
use std::fmt::{self,Display};
use std::io;

macro_rules! try_err_compat {
    ($err_name:ident, $from_err_name:path) => {
        impl From<$from_err_name> for $err_name {
            fn from(v: $from_err_name) -> Self {
                $err_name(v.description().to_string())
            }
        }
    }
}

#[derive(Debug)]
pub struct NlError(String);

try_err_compat!(NlError, io::Error);
try_err_compat!(NlError, SerError);
try_err_compat!(NlError, DeError);

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

#[derive(Debug)]
pub struct SerError(String);

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

#[derive(Debug)]
pub struct DeError(String);

try_err_compat!(DeError, io::Error);

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
