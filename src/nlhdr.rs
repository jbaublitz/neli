use std::mem;
use std::fmt;

use serde::{Serialize,Serializer,Deserialize,Deserializer};
use serde::de::{Visitor,Error};

use Nl;
use ffi::{NlType,NlFlags};

fn flags_ser<S>(flags: &Vec<NlFlags>, ser: S) -> Result<S::Ok, S::Error> where S: Serializer {
    let val = flags.iter().fold(0, |acc: u16, val| {
        let v: u16 = val.clone().into();
        acc | v
    });
    val.serialize(ser)
}

fn flags_de<'a, D>(de: D) -> Result<Vec<NlFlags>, D::Error> where D: Deserializer<'a> {
    struct U16Visitor;

    impl<'a> Visitor<'a> for U16Visitor {
        type Value = u16;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "a u16 typed integer")
        }

        fn visit_u16<E>(self, v: u16) -> Result<Self::Value, E> where E: Error {
            Ok(v)
        }
    }

    let flags = try!(de.deserialize_u16(U16Visitor));
    let mut vec = Vec::<NlFlags>::new();
    for i in 0..mem::size_of::<u16>() {
        let bit = 1 << i;
        if bit & flags == bit {
            vec.push(bit.into());
        }
    }
    Ok(vec)
}

#[derive(Serialize,Deserialize,Debug,PartialEq)]
pub struct NlHdr<T> {
    nl_len: u32,
    nl_type: NlType,
    #[serde(serialize_with="flags_ser", deserialize_with="flags_de")]
    nl_flags: Vec<NlFlags>,
    nl_seq: u32,
    nl_pid: u32,
    nl_pl: T,
}

impl<'a, T: Serialize + Deserialize<'a> + Nl> NlHdr<T> {
    pub fn new(nl_len: Option<u32>, nl_type: NlType, nl_flags: Vec<NlFlags>,
               nl_seq: Option<u32>, nl_pid: Option<u32>, nl_pl: T) -> Self {
        let mut nl = NlHdr {
            nl_len: nl_len.unwrap_or(0),
            nl_type,
            nl_flags,
            nl_seq: nl_seq.unwrap_or(0),
            nl_pid: nl_pid.unwrap_or(0),
            nl_pl
        };
        if let None = nl_len {
            nl.nl_len = nl.asize() as u32;
        }
        nl
    }
}

impl<T: Nl> Nl for NlHdr<T> {
    fn size(&self) -> usize {
        mem::size_of::<u32>() * 3 + self.nl_type.size()
            + self.nl_flags.iter().nth(0).unwrap_or(&NlFlags::NlRequest).size() + self.nl_pl.size()
    }
}

#[derive(Serialize,Deserialize,Debug,PartialEq)]
pub struct NlEmpty;

impl Nl for NlEmpty {
    fn size(&self) -> usize {
        0
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ser::NlSerializer;
    use de::NlDeserializer;
    use serde::{Serialize,Deserialize};

    #[test]
    fn test_nlhdr_serialize() {
        let mut ser = NlSerializer::new();
        let hdr = NlHdr::new(None, NlType::NlNoop, Vec::new(), None, None, NlEmpty);
        match hdr.serialize(&mut ser) {
            Ok(_) => (),
            Err(_) => panic!(),
        };
        assert_eq!(ser.into_inner(), &[16, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    }

    #[test]
    fn test_nlhdr_deserialize() {
        let hdr_bytes = &[16, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut de = NlDeserializer::new(hdr_bytes);
        let nlhdr = match NlHdr::<NlEmpty>::deserialize(&mut de) {
            Ok(n) => n,
            Err(_) => panic!(),
        };
        assert_eq!(nlhdr, NlHdr::new(
            None, NlType::NlNoop, Vec::new(), None, None, NlEmpty
        ))
    }
}
