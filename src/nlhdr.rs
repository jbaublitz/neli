use std::mem;

use {Nl,NlSerState,NlDeState};
use err::{SerError,DeError};
use ffi::{NlFlags};

/// Top level netlink header and payload
#[derive(Debug,PartialEq)]
pub struct NlHdr<I, T> {
    nl_len: u32,
    nl_type: I,
    nl_flags: Vec<NlFlags>,
    nl_seq: u32,
    nl_pid: u32,
    /// FUCK
    pub nl_pl: T,
}

impl<I: Nl, T: Nl> NlHdr<I, T> {
    /// Create a new top level netlink packet with a payload
    pub fn new(nl_len: Option<u32>, nl_type: I, nl_flags: Vec<NlFlags>,
           nl_seq: Option<u32>, nl_pid: Option<u32>, nl_pl: T) -> Self {
        let mut nl = NlHdr::default();
        nl.nl_type = nl_type;
        nl.nl_flags = nl_flags;
        nl.nl_seq = nl_seq.unwrap_or(0);
        nl.nl_pid = nl_pid.unwrap_or(0);
        nl.nl_pl = nl_pl;
        nl.nl_len = nl_len.unwrap_or(nl.size() as u32);
        nl
    }
}

impl<I: Default, T: Default> Default for NlHdr<I, T> {
    fn default() -> Self {
        NlHdr {
            nl_len: 0,
            nl_type: I::default(),
            nl_flags: Vec::new(),
            nl_seq: 0,
            nl_pid: 0,
            nl_pl: T::default(),
        }
    }
}

impl<I: Default + Nl, T: Nl> Nl for NlHdr<I, T> {
    fn serialize(&mut self, state: &mut NlSerState) -> Result<(), SerError> {
        try!(self.nl_len.serialize(state));
        try!(self.nl_type.serialize(state));
        let mut val = self.nl_flags.iter().fold(0, |acc: u16, val| {
            let v: u16 = val.clone().into();
            acc | v
        });
        try!(val.serialize(state));
        try!(self.nl_seq.serialize(state));
        try!(self.nl_pid.serialize(state));
        try!(self.nl_pl.serialize(state));
        Ok(())
    }

    fn deserialize(state: &mut NlDeState) -> Result<Self, DeError> {
        let mut nl = NlHdr::<I, T>::default();
        nl.nl_len = try!(u32::deserialize(state));
        nl.nl_type = try!(I::deserialize(state));
        let flags = try!(u16::deserialize(state));
        for i in 0..mem::size_of::<u16>() * 8 {
            let bit = 1 << i;
            if bit & flags == bit {
                nl.nl_flags.push(bit.into());
            }
        }
        nl.nl_seq = try!(u32::deserialize(state));
        nl.nl_pid = try!(u32::deserialize(state));
        nl.nl_pl = try!(T::deserialize(state));
        Ok(nl)
    }

    fn size(&self) -> usize {
        self.nl_len.size() + self.nl_type.size() + mem::size_of::<u16>()
            + self.nl_seq.size() + self.nl_pid.size() + self.nl_pl.size()
    }
}

/// Struct indicating an empty payload
#[derive(Debug,PartialEq)]
pub struct NlEmpty;

impl Default for NlEmpty {
    fn default() -> Self {
        NlEmpty
    }
}

impl Nl for NlEmpty {
    fn serialize(&mut self, _state: &mut NlSerState) -> Result<(), SerError> {
        Ok(())
    }

    fn deserialize(_state: &mut NlDeState) -> Result<Self, DeError> {
        Ok(NlEmpty)
    }

    fn size(&self) -> usize {
        0
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ffi::NlType;
    use std::io::Cursor;
    use byteorder::{NativeEndian,WriteBytesExt};

    #[test]
    fn test_nlhdr_serialize() {
        let mut state = NlSerState::new();
        let mut nl = NlHdr::<NlType, NlEmpty>::new(None, NlType::NlNoop,
                                                   Vec::new(), None, None, NlEmpty);
        nl.serialize(&mut state).unwrap();
        let s: &mut [u8] = &mut [0; 16];
        {
            let mut c = Cursor::new(&mut *s);
            c.write_u32::<NativeEndian>(16).unwrap();
            c.write_u16::<NativeEndian>(1).unwrap();
        };
        assert_eq!(&mut *s, state.into_inner().as_slice())
    }

    #[test]
    fn test_nlhdr_deserialize() {
        let s: &mut [u8] = &mut [0; 16];
        {
            let mut c = Cursor::new(&mut *s);
            c.write_u32::<NativeEndian>(16).unwrap();
            c.write_u16::<NativeEndian>(1).unwrap();
            c.write_u16::<NativeEndian>(NlFlags::NlAck.into()).unwrap();
        }
        let mut state = NlDeState::new(&mut *s);
        let nl = NlHdr::<NlType, NlEmpty>::deserialize(&mut state).unwrap();
        assert_eq!(NlHdr::<NlType, NlEmpty>::new(None, NlType::NlNoop,
                                                 vec![NlFlags::NlAck], None, None, NlEmpty), nl);
    }
}
