use std::io::Cursor;

use serde::{Serialize,Serializer};
use serde:: ser::{SerializeSeq,SerializeTuple,SerializeTupleStruct,SerializeTupleVariant,
				  SerializeMap,SerializeStruct,SerializeStructVariant};
use byteorder::{NativeEndian,WriteBytesExt};

use err::NlError;

pub struct NlSerializer {
    buf: Cursor<Vec<u8>>,
}

impl NlSerializer {
    pub fn new() -> Self {
        NlSerializer { buf: Cursor::new(Vec::new()) }
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.buf.into_inner()
    }
}

impl<'a> Serializer for &'a mut NlSerializer {
    type Ok = ();
    type Error = NlError;
    type SerializeSeq = Self;
    type SerializeTuple = Self;
    type SerializeTupleStruct = Self;
    type SerializeTupleVariant = Self;
    type SerializeMap = Self;
    type SerializeStruct = Self;
    type SerializeStructVariant = Self;

	fn serialize_bool(self, _v: bool) -> Result<Self::Ok, Self::Error> {
		unimplemented!()
	}

	fn serialize_i8(self, _v: i8) -> Result<Self::Ok, Self::Error> {
		unimplemented!()
	}

	fn serialize_i16(self, _v: i16) -> Result<Self::Ok, Self::Error> {
		unimplemented!()
	}

	fn serialize_i32(self, _v: i32) -> Result<Self::Ok, Self::Error> {
		unimplemented!()
	}

	fn serialize_i64(self, _v: i64) -> Result<Self::Ok, Self::Error> {
		unimplemented!()
	}

	fn serialize_u8(self, v: u8) -> Result<Self::Ok, Self::Error> {
        Ok(try!(self.buf.write_u8(v)))
	}

	fn serialize_u16(self, v: u16) -> Result<Self::Ok, Self::Error> {
        Ok(try!(self.buf.write_u16::<NativeEndian>(v)))
	}

	fn serialize_u32(self, v: u32) -> Result<Self::Ok, Self::Error> {
        Ok(try!(self.buf.write_u32::<NativeEndian>(v)))
	}

	fn serialize_u64(self, _v: u64) -> Result<Self::Ok, Self::Error> {
		unimplemented!()
	}

	fn serialize_f32(self, _v: f32) -> Result<Self::Ok, Self::Error> {
		unimplemented!()
	}

	fn serialize_f64(self, _v: f64) -> Result<Self::Ok, Self::Error> {
		unimplemented!()
	}

	fn serialize_char(self, _v: char) -> Result<Self::Ok, Self::Error> {
		unimplemented!()
	}

	fn serialize_str(self, _v: &str) -> Result<Self::Ok, Self::Error> {
		unimplemented!()
	}

	fn serialize_bytes(self, _v: &[u8]) -> Result<Self::Ok, Self::Error> {
		unimplemented!()
	}

	fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
		self.serialize_unit()
	}

	fn serialize_some<T: ?Sized>(self, _value: &T) -> Result<Self::Ok, Self::Error>
								 where T: Serialize {
		unimplemented!()
	}

	fn serialize_unit(self) -> Result<Self::Ok, Self::Error> {
		Ok(())
	}

	fn serialize_unit_struct(self, _name: &'static str) -> Result<Self::Ok, Self::Error> {
        self.serialize_unit()
	}

	fn serialize_unit_variant(self, _name: &'static str, _variant_index: u32,
                              _variant: &'static str) -> Result<Self::Ok, Self::Error> {
		unimplemented!()
	}

	fn serialize_newtype_struct<T: ?Sized>(self, _name: &'static str, _value: &T)
										   -> Result<Self::Ok, Self::Error> where T: Serialize {
		unimplemented!()
	}

	fn serialize_newtype_variant<T: ?Sized>(self, _name: &'static str, _variant_index: u32, 
											_variant: &'static str, _value: &T)
											-> Result<Self::Ok, Self::Error> {
        unimplemented!()
    }

    fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        unimplemented!()
    }

    fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple, Self::Error> {
        unimplemented!()
    }

    fn serialize_tuple_struct(self, _name: &'static str, _len: usize)
                              -> Result<Self::SerializeTupleStruct, Self::Error> {
        unimplemented!()
    }

    fn serialize_map(self, _len: Option<usize>)
                     -> Result<Self::SerializeMap, Self::Error> {
        unimplemented!()
    }

    fn serialize_tuple_variant(self, _name: &'static str, _variant_index: u32,
                               _variant: &'static str, _len: usize)
                               -> Result<Self::SerializeTupleVariant, Self::Error> {
        unimplemented!()
    }

    fn serialize_struct(self, _name: &'static str, _len: usize)
                        -> Result<Self::SerializeStruct, Self::Error> {
        Ok(self)
    }

    fn serialize_struct_variant(self, _name: &'static str, _variant_index: u32,
                                _variant: &'static str, _len: usize)
                                -> Result<Self::SerializeStructVariant, Self::Error> {
        unimplemented!()
    }
}

impl<'a> SerializeSeq for &'a mut NlSerializer {
    type Ok = ();
    type Error = NlError;

    fn serialize_element<T: ?Sized>(&mut self, _elem: &T) -> Result<Self::Ok, Self::Error> {
        unimplemented!()
    }

    fn end(self) -> Result<(), Self::Error> {
        unimplemented!()
    }
}

impl<'a> SerializeTuple for &'a mut NlSerializer {
    type Ok = ();
    type Error = NlError;

    fn serialize_element<T: ?Sized>(&mut self, _elem: &T) -> Result<Self::Ok, Self::Error> {
        unimplemented!()
    }

    fn end(self) -> Result<(), Self::Error> {
        unimplemented!()
    }
}

impl<'a> SerializeTupleStruct for &'a mut NlSerializer {
    type Ok = ();
    type Error = NlError;

    fn serialize_field<T: ?Sized>(&mut self, _elem: &T) -> Result<Self::Ok, Self::Error> {
        unimplemented!()
    }

    fn end(self) -> Result<(), Self::Error> {
        unimplemented!()
    }
}

impl<'a> SerializeMap for &'a mut NlSerializer {
    type Ok = ();
    type Error = NlError;

    fn serialize_key<T: ?Sized>(&mut self, _elem: &T) -> Result<Self::Ok, Self::Error> {
        unimplemented!()
    }

    fn serialize_value<T: ?Sized>(&mut self, _elem: &T) -> Result<Self::Ok, Self::Error> {
        unimplemented!()
    }

    fn end(self) -> Result<(), Self::Error> {
        unimplemented!()
    }
}

impl<'a> SerializeStruct for &'a mut NlSerializer {
    type Ok = ();
    type Error = NlError;

	fn serialize_field<T: ?Sized>(&mut self, _key: &'static str, value: &T)
								  -> Result<(), Self::Error> where T: Serialize {
        value.serialize(&mut **self)
	}

    fn end(self) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl<'a> SerializeStructVariant for &'a mut NlSerializer {
    type Ok = ();
    type Error = NlError;

	fn serialize_field<T: ?Sized>(&mut self, _key: &'static str, _value: &T)
								  -> Result<(), Self::Error> where T: Serialize {
		unimplemented!()
	}

    fn end(self) -> Result<(), Self::Error> {
        unimplemented!()
    }
}

impl<'a> SerializeTupleVariant for &'a mut NlSerializer {
    type Ok = ();
    type Error = NlError;

    fn serialize_field<T: ?Sized>(&mut self, _elem: &T) -> Result<Self::Ok, Self::Error> {
        unimplemented!()
    }

    fn end(self) -> Result<(), Self::Error> {
        unimplemented!()
    }
}

#[cfg(test)]
mod test {
	use super::*;

    #[derive(Serialize)]
    struct Something {
        one: u8,
        two: u16,
        three: u32,
    }

	#[test]
    fn test_serialize_struct() {
        let mut ser = NlSerializer::new();
        let obj = Something { one: 0, two: 1, three: 3 };
        match obj.serialize(&mut ser) {
            Ok(_) => (),
            Err(_) => panic!(),
        };
        assert_eq!(ser.into_inner(), &[0, 1, 0, 3, 0, 0, 0])
    }
}
