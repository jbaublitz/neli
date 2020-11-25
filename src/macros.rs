/// This macro can be used to serialize a single field in a struct.
///
/// # Examples
///
/// ```
/// use neli::{err::SerError, Nl};
///
/// fn drive_serialize() -> Result<(), SerError> {
///     let int = 6u16;
///     
///     let mut vec = vec![0; int.size()];
///     let pos = neli::drive_serialize!(&int, vec.as_mut_slice(), 0);
///     neli::drive_serialize!(END vec.as_mut_slice(), pos);
///     Ok(())
/// }
///
/// ```
#[macro_export]
macro_rules! drive_serialize {
    ($to_ser:expr, $buffer:expr, $pos:expr) => {{
        let size = $crate::Nl::size($to_ser);
        if $pos + size > $buffer.len() {
            return Err($crate::err::SerError::UnexpectedEOB);
        }
        let subbuffer = &mut $buffer[$pos..$pos + size];
        match $crate::Nl::serialize($to_ser, subbuffer) {
            Ok(()) => $pos + size,
            Err(e) => return Err(e),
        }
    }};
    ($to_ser:expr, $buffer:expr, $pos:expr, $size:ident) => {{
        let size = $crate::Nl::$size($to_ser);
        if $pos + size > $buffer.len() {
            return Err($crate::err::SerError::UnexpectedEOB);
        }
        let subbuffer = &mut $buffer[$pos..$pos + size];
        match $to_ser.serialize(subbuffer) {
            Ok(()) => $pos + size,
            Err(e) => return Err(e),
        }
    }};
    (PAD $self:expr, $buffer:expr, $pos:expr) => {{
        let size = $crate::Nl::asize($self) - $crate::Nl::size($self);
        if $pos + size > $buffer.len() {
            return Err($crate::err::SerError::UnexpectedEOB);
        }
        match $self.pad(&mut $buffer[$pos..$pos + size]) {
            Ok(()) => $pos + size,
            Err(e) => return Err(e),
        }
    }};
    (END $buffer:expr, $pos:expr) => {{
        if $buffer.len() != $pos {
            return Err($crate::err::SerError::BufferNotFilled);
        }
    }};
}

/// This macro can be used to declaratively define serialization for a struct.
///
/// # Examples
/// ```
/// use neli::err::SerError;
///
/// struct MyStruct {
///     field_one: u16,
///     field_two: String,
///     field_three: Vec<u8>,
/// }
///
/// fn serialize_my_struct() -> Result<(), SerError> {
///     let my_struct = MyStruct {
///         field_one: 6,
///         field_two: "Hello!".to_string(),
///         field_three: vec![5; 5],
///     };
///     let mut vec = vec![0; 2048];
///     neli::serialize! {
///         vec.as_mut_slice();
///         my_struct.field_one;
///         my_struct.field_two;
///         my_struct.field_three
///     }
///     
///     Ok(())
/// }
///
/// ```
#[macro_export]
macro_rules! serialize {
    (PAD $self:ident; $buffer:expr; $($to_ser:expr $(, $size:ident)?);*) => {{
        let pos = 0;
        $(
            let pos = $crate::drive_serialize!(&$to_ser, $buffer, pos $(, $size)?);
        )*
        let pos = $crate::drive_serialize!(PAD $self, $buffer, pos);
        $crate::drive_serialize!(END $buffer, pos)
    }};
    ($buffer:expr; $($to_ser:expr $(, $size:ident)?);*) => {{
        let pos = 0;
        $(
            let pos = $crate::drive_serialize!(&$to_ser, $buffer, pos $(, $size)?);
        )*
        $crate::drive_serialize!(END $buffer, pos)
    }};
}

/// This macro calculates size from `type_size` methods and returns
/// an error if `type_size` evaluates to [`None`].
///
/// # Examples
/// ```
/// use neli::err::DeError;
///
/// fn check_type_size() -> Result<(), DeError> {
///     assert_eq!(neli::deserialize_type_size!(u16 => type_size), 2);
///     Ok(())
/// }
///
/// check_type_size().unwrap()
/// ```
#[macro_export]
macro_rules! deserialize_type_size {
    ($de_type:ty => $de_size:ident) => {
        match <$de_type as $crate::Nl>::$de_size() {
            Some(s) => s,
            None => {
                return Err($crate::err::DeError::Msg(format!(
                    "Type {} has no static size associated with it",
                    stringify!($de_type),
                )))
            }
        }
    };
    ($de_type:ty) => {
        match (
            <$de_type as $crate::Nl>::type_asize(),
            <$de_type as $crate::Nl>::type_size(),
        ) {
            (Some(a), Some(s)) => a - s,
            (_, _) => {
                return Err($crate::err::DeError::Msg(format!(
                    "Type {} has no static size associated with it",
                    stringify!($de_type),
                )))
            }
        }
    };
}

/// This macro can be used to deserialize a single field in a struct.
#[macro_export]
macro_rules! drive_deserialize {
    ($de_type:ty, $buffer:ident, $pos:expr) => {{
        let size = deserialize_type_size!($de_type => type_size);
        if $pos + size > $buffer.len() {
            return Err(DeError::UnexpectedEOB);
        }
        let subbuffer = &$buffer[$pos..$pos + size];
        let t = <$de_type>::deserialize(subbuffer)?;
        (t, $pos + size)
    }};
    ($de_type:ty, $buffer:ident, $pos:expr, $size:expr) => {{
        let size = $size;
        if $pos + size > $buffer.len() {
            return Err(DeError::UnexpectedEOB);
        }
        let subbuffer = &$buffer[$pos..$pos + size];
        let t = <$de_type>::deserialize(&subbuffer)?;
        (t, $pos + size)
    }};
    (STRIP $buffer:ident, $pos:ident, $size:expr) => {{
        let size = $size;
        if $pos + size > $buffer.len() {
            return Err(DeError::UnexpectedEOB);
        }
        $pos + size
    }};
    (END $buffer:ident, $pos:ident) => {{
        if $buffer.len() != $pos {
            return Err(DeError::BufferNotParsed);
        }
    }};
}

/// This macro can be used to declaratively define deserialization for a struct.
#[macro_export]
macro_rules! deserialize {
    (STRIP $self_de_type:ident; $buffer:ident; $struct_type:path {
        $($de_name:ident: $de_type:ty $(=> $size:expr)?),*
    } => $struct_size:expr) => {{
        let pos = 0;
        $(
            let ($de_name, pos) = drive_deserialize!(
                $de_type, $buffer, pos $(, $size)?
            );
        )*
        let pos = drive_deserialize!(STRIP $buffer, pos, $struct_size);
        drive_deserialize!(END $buffer, pos);
        $struct_type {
            $( $de_name ),*
        }
    }};
    ($buffer:ident; $struct_type:path {
        $($de_name:ident: $de_type:ty $(=> $size:expr)?),*
    }) => {{
        let pos = 0;
        $(
            let ($de_name, pos) = drive_deserialize!(
                $de_type, $buffer, pos $(, $size)?
            );
        )*
        drive_deserialize!(END $buffer, pos);
        $struct_type {
            $( $de_name ),*
        }
    }};
}

macro_rules! get_int {
    ($bytes:ident, $get_int:ident) => {{
        let size = Self::type_size().expect("Integers have static size");
        if $bytes.len() < size {
            return Err($crate::err::DeError::UnexpectedEOB);
        } else if $bytes.len() > size {
            return Err($crate::err::DeError::BufferNotParsed);
        }
        byteorder::NativeEndian::$get_int($bytes.as_ref())
    }};
    ($bytes:ident, $get_int:ident, $endian:ty) => {{
        let size = Self::type_size().expect("Integers have static size");
        if $bytes.len() < size {
            return Err($crate::err::DeError::UnexpectedEOB);
        } else if $bytes.len() > size {
            return Err($crate::err::DeError::BufferNotParsed);
        }
        <$endian>::$get_int($bytes.as_ref())
    }};
}

macro_rules! put_int {
    ($to_ser:expr, $bytes:ident, $put_int:ident) => {{
        let size = $to_ser.size();
        if $bytes.len() < size {
            return Err($crate::err::SerError::UnexpectedEOB);
        } else if $bytes.len() > size {
            return Err($crate::err::SerError::BufferNotFilled);
        }
        byteorder::NativeEndian::$put_int($bytes.as_mut(), $to_ser);
    }};
    ($to_ser:expr, $bytes:ident, $put_int:ident, $endian:ty) => {{
        let size = $to_ser.size();
        if $bytes.len() < size {
            return Err($crate::err::SerError::UnexpectedEOB);
        } else if $bytes.len() > size {
            return Err($crate::err::SerError::BufferNotFilled);
        }
        <$endian>::$put_int($bytes.as_mut(), $to_ser);
        $bytes
    }};
}
