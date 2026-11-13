//! Serialization of Unix names without requiring UTF-8.

use std::{
    ffi::{OsStr, OsString},
    io::{Cursor, Write},
    os::unix::ffi::{OsStrExt, OsStringExt},
};

use crate::{
    err::{DeError, SerError},
    FromBytesWithInput, Size, ToBytes,
};

impl Size for &OsStr {
    fn unpadded_size(&self) -> usize {
        self.as_bytes().len() + 1
    }
}

impl ToBytes for &OsStr {
    fn to_bytes(&self, buffer: &mut Cursor<Vec<u8>>) -> Result<(), SerError> {
        buffer.write_all(self.as_bytes())?;
        buffer.write_all(&[0])?;
        Ok(())
    }
}

impl Size for OsString {
    fn unpadded_size(&self) -> usize {
        self.as_os_str().unpadded_size()
    }
}

impl ToBytes for OsString {
    fn to_bytes(&self, buffer: &mut Cursor<Vec<u8>>) -> Result<(), SerError> {
        self.as_os_str().to_bytes(buffer)
    }
}

impl FromBytesWithInput for OsString {
    type Input = usize;

    fn from_bytes_with_input(
        buffer: &mut Cursor<impl AsRef<[u8]>>,
        input: usize,
    ) -> Result<Self, DeError> {
        let position =
            usize::try_from(buffer.position()).map_err(|_| DeError::InvalidInput(input))?;
        let end = position
            .checked_add(input)
            .ok_or(DeError::InvalidInput(input))?;
        let bytes = buffer
            .get_ref()
            .as_ref()
            .get(position..end)
            .ok_or(DeError::InvalidInput(input))?;
        let Some((&0, name)) = bytes.split_last() else {
            return Err(DeError::InvalidInput(input));
        };
        let name = OsString::from_vec(name.to_vec());
        buffer.set_position(end as u64);
        Ok(name)
    }
}
