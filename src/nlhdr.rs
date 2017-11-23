use std::mem;
use std::fmt;
use std::marker::PhantomData;

use {Nl,NlSerState,NlDeState};
use err::{SerError,DeError};
use ffi::{NlType,NlFlags};

#[derive(Debug,PartialEq)]
pub struct NlHdr<T> {
    nl_len: u32,
    nl_type: NlType,
    nl_flags: Vec<NlFlags>,
    nl_seq: u32,
    nl_pid: u32,
    nl_pl: T,
}

impl<T: Default> Default for NlHdr<T> {
    fn default() -> Self {
        NlHdr {
            nl_len: 0,
            nl_type: NlType::default(),
            nl_flags: Vec::new(),
            nl_seq: 0,
            nl_pid: 0,
            nl_pl: T::default(),
        }
    }
}

impl<T: Nl> Nl for NlHdr<T> {
    type Input = ();

    fn serialize(&mut self, state: &mut NlSerState) -> Result<(), SerError> {
        try!(<u32 as Nl>::serialize(&mut self.nl_len, state));
        try!(<NlType as Nl>::serialize(&mut self.nl_type, state));
        let mut val = self.nl_flags.iter().fold(0, |acc: u16, val| {
            let v: u16 = val.clone().into();
            acc | v
        });
        try!(<u16 as Nl>::serialize(&mut val, state));
        try!(<u32 as Nl>::serialize(&mut self.nl_seq, state));
        try!(<u32 as Nl>::serialize(&mut self.nl_pid, state));
        try!(<T as Nl>::serialize(&mut self.nl_pl, state));
        Ok(())
    }

    fn deserialize_with(state: &mut NlDeState, input: Self::Input)
                        -> Result<Self, DeError> {
        let mut nl = NlHdr::<T>::default();
        nl.nl_len = try!(<u32 as Nl>::deserialize(state));
        nl.nl_type = try!(<NlType as Nl>::deserialize(state));
        let flags = try!(<u16 as Nl>::deserialize(state));
        for i in 0..mem::size_of::<u16>() {
            let bit = 1 << i;
            if bit & flags == bit {
                nl.nl_flags.push(bit.into());
            }
        }
        nl.nl_seq = try!(<u32 as Nl>::deserialize(state));
        nl.nl_pid = try!(<u32 as Nl>::deserialize(state));
        nl.nl_pl = try!(<T as Nl>::deserialize(state));
        Ok(nl)
    }

    fn size(&self) -> usize {
        self.nl_len.size() + self.nl_type.size() + mem::size_of::<u16>()
            + self.nl_seq.size() + self.nl_pid.size() + self.nl_pl.size()
    }
}

#[derive(Debug,PartialEq)]
pub struct NlEmpty;

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_nlhdr_serialize() {
    }

    #[test]
    fn test_nlhdr_deserialize() {
    }
}
