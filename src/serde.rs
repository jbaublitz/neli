//! Serialization and deserialization code.

use std::io::{Cursor, Write};

use serde::{
    ser::{SerializeMap, SerializeSeq, SerializeStruct, SerializeStructVariant, SerializeTuple, SerializeTupleStruct, SerializeTupleVariant},
    Serialize, Serializer,
};

use crate::{log, err::SerError};

macro_rules! impl_unimplemented {
    ($func_name:ident, $param:ty) => {
        fn $func_name(self, _param: $param) -> std::result::Result<Self::Ok, Self::Error> {
            unimplemented!()
        }
    }
}

macro_rules! byte_impl {
    ($func_name:ident, $byte:ty) => {
        fn $func_name(self, int: $byte) -> Result<Self::Ok, Self::Error> {
            self.buffer.write_all(&[int as u8])?;
            Ok(())
        }
    }
}

macro_rules! int_impl {
    ($func_name:ident, $int:ty, $write_func:ident) => {
        fn $func_name(self, int: $int) -> std::result::Result<Self::Ok, Self::Error> {
            <Cursor::<&mut [u8]> as byteorder::WriteBytesExt>::$write_func::<byteorder::NativeEndian>(
                &mut self.buffer,
                int,
            )?;
            Ok(())
        }
    }
}

macro_rules! empty_impl {
    ($func_name:ident) => {
        fn $func_name(self) -> std::result::Result<Self::Ok, Self::Error> {
            Ok(())
        }
    }
}

macro_rules! align {
    ($serializer:expr) => {
        $crate::log!("Adding padding");
        if $serializer.alignment {
            let pos = $serializer.buffer.position() as usize;
            let bytes_to_write = $crate::alignto(pos) - pos;
            &[0; libc::NLA_ALIGNTO as usize][..bytes_to_write].serialize($serializer)?;
        }
    }
}

pub struct NeliSeq<'a, 'b> {
    serializer: &'a mut NeliSerializer<'b>,
}

impl<'a, 'b> SerializeSeq for NeliSeq<'a, 'b> {
    type Ok = ();
    type Error = SerError;

    fn serialize_element<T>(&mut self, elem: &T) -> Result<Self::Ok, Self::Error> where T: ?Sized + Serialize {
        log!("Serializing sequence");
        elem.serialize(&mut *self.serializer)?;
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        align!(self.serializer);
        Ok(())
    }
}

impl<'a, 'b> SerializeTuple for NeliSeq<'a, 'b> {
    type Ok = ();
    type Error = SerError;

    fn serialize_element<T>(&mut self, elem: &T) -> Result<Self::Ok, Self::Error> where T: ?Sized + Serialize {
        log!("Serializing tuple");
        elem.serialize(&mut *self.serializer)?;
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        align!(self.serializer);
        Ok(())
    }
}

impl<'a, 'b> SerializeTupleStruct for NeliSeq<'a, 'b> {
    type Ok = ();
    type Error = SerError;

    fn serialize_field<T>(&mut self, elem: &T) -> Result<Self::Ok, Self::Error> where T: ?Sized + Serialize {
        log!("Serializing tuple struct");
        elem.serialize(&mut *self.serializer)?;
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        align!(self.serializer);
        Ok(())
    }
}

impl<'a, 'b> SerializeTupleVariant for NeliSeq<'a, 'b> {
    type Ok = ();
    type Error = SerError;

    fn serialize_field<T>(&mut self, elem: &T) -> Result<Self::Ok, Self::Error> where T: ?Sized + Serialize {
        log!("Serializing tuple variant");
        elem.serialize(&mut *self.serializer)?;
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        align!(self.serializer);
        Ok(())
    }
}

impl<'a, 'b> SerializeMap for NeliSeq<'a, 'b> {
    type Ok = ();
    type Error = SerError;

    fn serialize_key<T>(&mut self, _: &T) -> Result<Self::Ok, Self::Error> where T: ?Sized + Serialize {
        unimplemented!()
    }

    fn serialize_value<T>(&mut self, _: &T) -> Result<Self::Ok, Self::Error> where T: ?Sized + Serialize {
        unimplemented!()
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        unimplemented!()
    }
}

impl<'a, 'b> SerializeStruct for NeliSeq<'a, 'b> {
    type Ok = ();
    type Error = SerError;

    fn serialize_field<T>(&mut self, _field_name: &'static str, elem: &T) -> Result<Self::Ok, Self::Error> where T: ?Sized + Serialize {
        log!("Serializing struct field {}", _field_name);
        elem.serialize(&mut *self.serializer)?;
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        align!(self.serializer);
        Ok(())
    }
}

impl<'a, 'b> SerializeStructVariant for NeliSeq<'a, 'b> {
    type Ok = ();
    type Error = SerError;

    fn serialize_field<T>(&mut self, _field_name: &'static str, elem: &T) -> Result<Self::Ok, Self::Error> where T: ?Sized + Serialize {
        log!("Serializing struct variant field {}", _field_name);
        elem.serialize(&mut *self.serializer)?;
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        align!(self.serializer);
        Ok(())
    }
}

pub struct NeliSerializer<'a> {
    buffer: Cursor<&'a mut [u8]>,
    alignment: bool,
}

impl<'a> NeliSerializer<'a> {
    fn new(buffer: &'a mut [u8]) -> Self {
        NeliSerializer {
            buffer: Cursor::new(buffer),
            alignment: true,
        }
    }
}

impl<'a, 'b: 'a> Serializer for &'a mut NeliSerializer<'b> {
    type Ok = ();
    type Error = SerError;
    type SerializeSeq = NeliSeq<'a, 'b>;
    type SerializeTuple = NeliSeq<'a, 'b>;
    type SerializeTupleStruct = NeliSeq<'a, 'b>;
    type SerializeTupleVariant = NeliSeq<'a, 'b>;
    type SerializeMap = NeliSeq<'a, 'b>;
    type SerializeStruct = NeliSeq<'a, 'b>;
    type SerializeStructVariant = NeliSeq<'a, 'b>;

    fn serialize_str(self, st: &str) -> Result<Self::Ok, Self::Error> {
        log!("Serializing &str {}", st);
        self.serialize_bytes(st.as_bytes())
    }

    fn serialize_bytes(self, bytes: &[u8]) -> Result<Self::Ok, Self::Error> {
        log!("Serializing bytes {:?}", bytes);
        self.buffer.write_all(bytes)?;
        Ok(())
    }

    fn serialize_some<T>(self, elem: &T) -> Result<Self::Ok, Self::Error> where T: ?Sized + Serialize {
        log!("Serializing elemement wrapped in Some(_)");
        elem.serialize(self)?;
        Ok(())
    }

    fn serialize_seq(self, size: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        log!("Serializing sequence");
        if let Some(_s) = size {
            log!("Size: {}", _s);
        }
        Ok(NeliSeq { serializer: self })
    }

    fn serialize_tuple(self, _size: usize) -> Result<Self::SerializeTuple, Self::Error> {
        log!("Serializing tuple with size {}", _size);
        Ok(NeliSeq { serializer: self })
    }

    fn serialize_tuple_struct(self, _name: &'static str, _fields: usize) -> Result<Self::SerializeTupleStruct, Self::Error> {
        log!("Serializing tuple struct {} with {} fields", _name, _fields);
        Ok(NeliSeq { serializer: self })
    }

    fn serialize_tuple_variant(self, _name: &'static str, _: u32, _variant_name: &'static str, _num_elements: usize) -> Result<Self::SerializeTupleStruct, Self::Error> {
        log!("Serializing tuple enum {} variant {} with {} elements", _name, _variant_name, _num_elements);
        Ok(NeliSeq { serializer: self })
    }

    fn serialize_map(self, _: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        unimplemented!()
    }

    fn serialize_unit_struct(self, _name: &'static str) -> Result<Self::Ok, Self::Error> {
        log!("Serializing unit struct {}", _name);
        Ok(())
    }

    fn serialize_newtype_struct<T>(self, _name: &'static str, elem: &T) -> Result<Self::Ok, Self::Error> where T: ?Sized + Serialize {
        log!("Serializing newtype struct {}", _name);
        elem.serialize(self)?;
        Ok(())
    }

    fn serialize_newtype_variant<T>(self, _name: &'static str, _: u32, _variant_name: &'static str, elem: &T) -> Result<Self::Ok, Self::Error> where T: ?Sized + Serialize {
        log!("Serializing enum {} newtype variant {}", _name, _variant_name);
        elem.serialize(self)?;
        Ok(())
    }

    fn serialize_unit_variant(self, _name: &'static str, _: u32, _variant_name: &'static str) -> Result<Self::Ok, Self::Error> {
        log!("Serializing enum {} unit variant {}", _name, _variant_name);
        Ok(())
    }

    fn serialize_struct(self, _name: &'static str, _fields: usize) -> Result<Self::SerializeStruct, Self::Error> {
        log!("Serializing struct {} with {} fields", _name, _fields);
        Ok(NeliSeq { serializer: self })
    }

    fn serialize_struct_variant(self, _name: &'static str, _: u32, _variant_name: &'static str, _fields: usize) -> Result<Self::SerializeStructVariant, Self::Error> {
        log!("Serializing enum {} struct variant {} with {} fields", _name, _variant_name, _fields);
        Ok(NeliSeq { serializer: self })
    }

    impl_unimplemented!(serialize_bool, bool);
    byte_impl!(serialize_i8, i8);
    byte_impl!(serialize_u8, u8);
    byte_impl!(serialize_char, char);
    int_impl!(serialize_i16, i16, write_i16);
    int_impl!(serialize_i32, i32, write_i32);
    int_impl!(serialize_i64, i64, write_i64);
    int_impl!(serialize_u16, u16, write_u16);
    int_impl!(serialize_u32, u32, write_u32);
    int_impl!(serialize_u64, u64, write_u64);
    impl_unimplemented!(serialize_f32, f32);
    impl_unimplemented!(serialize_f64, f64);
    empty_impl!(serialize_none);
    empty_impl!(serialize_unit);
}
