use std::fmt;
use std::io;
use std::error::Error;

use serde::{ser,de};

#[derive(Debug)]
pub struct NlError(String);

impl NlError {
    pub fn new(s: String) -> Self {
        NlError(s)
    }
}

impl fmt::Display for NlError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self.0)
    }
}

impl Error for NlError {
    fn description(&self) -> &str {
        &self.0.as_ref()
    }
}

impl ser::Error for NlError {
    fn custom<T>(msg: T) -> Self where T: fmt::Display {
        NlError(msg.to_string())
    }
}

impl de::Error for NlError {
    fn custom<T>(msg: T) -> Self where T: fmt::Display {
        NlError(msg.to_string())
    }
}

impl From<io::Error> for NlError {
    fn from(v: io::Error) -> Self {
        NlError(v.description().to_string())
    }
}
