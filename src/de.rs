use std::io::Cursor;

use serde::Deserializer;
use serde::de::{DeserializeSeed,Visitor,SeqAccess};
use byteorder::{NativeEndian,ReadBytesExt};

use err::NlError;

pub struct NlDeserializer<'a> {
    buf: Cursor<&'a [u8]>,
}

impl<'a> NlDeserializer<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        NlDeserializer{ buf: Cursor::new(buf) }
    }
}

impl<'de: 'a, 'a> Deserializer<'de> for &'a mut NlDeserializer<'de> {
    type Error = NlError;

    fn deserialize_any<V>(self, _visitor: V) -> Result<V::Value, Self::Error> where V: Visitor<'de> {
        unimplemented!()
    }

    fn deserialize_u8<V>(self, visitor: V) -> Result<V::Value, Self::Error> where V: Visitor<'de> {
        visitor.visit_u8(try!(self.buf.read_u8()))
    }

    fn deserialize_u16<V>(self, visitor: V) -> Result<V::Value, Self::Error> where V: Visitor<'de> {
        visitor.visit_u16(try!(self.buf.read_u16::<NativeEndian>()))
    }

    fn deserialize_u32<V>(self, visitor: V) -> Result<V::Value, Self::Error> where V: Visitor<'de> {
        visitor.visit_u32(try!(self.buf.read_u32::<NativeEndian>()))
    }

    fn deserialize_struct<V>(mut self, _name: &'static str,
                             _fields: &'static [&'static str],
                             visitor: V) -> Result<V::Value, Self::Error>
                             where V: Visitor<'de> {
        struct NlSeqAccess<'de: 'a, 'a> {
            de: &'a mut NlDeserializer<'de>,
        }

        impl<'de: 'a, 'a> SeqAccess<'de> for NlSeqAccess<'de, 'a> {
            type Error = NlError;

            fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>, Self::Error>
                                    where T: DeserializeSeed<'de> {
                seed.deserialize(&mut *self.de).map(Some)
            }
        }

        visitor.visit_seq(NlSeqAccess { de: &mut self })
    }

    forward_to_deserialize_any!{
        bool i8 i16 i32 i64 u64 f32 f64 char str string
        bytes byte_buf option unit unit_struct newtype_struct seq
        tuple tuple_struct map enum identifier ignored_any
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug,Deserialize)]
    struct Something {
        onefish: u16,
        twofish: u16,
        redfish: u16,
        bluefish: u16,
    }

    #[test]
    fn test_deserialize_struct() {
        let mut nde = NlDeserializer::new(&[0x1, 0x1, 0xf, 0x1, 0x0, 0x0, 0x0, 0x1]);
        let s = match Something::deserialize(&mut nde) {
            Ok(v) => v,
            _ => panic!(),
        };
        assert_eq!(s.onefish, 257);
        assert_eq!(s.twofish, 271);
        assert_eq!(s.redfish, 0);
        assert_eq!(s.bluefish, 256);
    }
}
