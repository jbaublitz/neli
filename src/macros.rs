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
    ($to_ser:expr, $buffer:expr, $pos:expr $(,)?) => {{
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
    ($to_ser:expr, $buffer:expr, $pos:expr, $size:ident $(,)?) => {{
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
    (PAD $self:expr, $buffer:expr, $pos:expr $(,)?) => {{
        let size = $crate::Nl::asize($self) - $crate::Nl::size($self);
        if $pos + size > $buffer.len() {
            return Err($crate::err::SerError::UnexpectedEOB);
        }
        match $self.pad(&mut $buffer[$pos..$pos + size]) {
            Ok(()) => $pos + size,
            Err(e) => return Err(e),
        }
    }};
    (END $buffer:expr, $pos:expr $(,)?) => {{
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

/// This macro calculates size from
/// [`type_size`][crate::Nl::type_size] methods and returns an error
/// if [`type_size`][crate::Nl::type_size] evaluates to [`None`].
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
///
/// # Examples
/// ```
/// use neli::err::DeError;
///
/// struct TestStruct {
///     field_name: u8,
/// }
///
/// fn drive_deserialize() -> Result<(), DeError> {
///     let vec = vec![1];
///     assert_eq!(
///         neli::drive_deserialize!(u8, vec.as_slice(), 0, TestStruct, field_name),
///         (1u8, 1)
///     );
///     Ok(())
/// }
///
/// drive_deserialize().unwrap();
/// ```
#[macro_export]
macro_rules! drive_deserialize {
    ($de_type:ty, $buffer:expr, $pos:expr $(,)?) => {{
        // FIXME: Deprecated; remove in 0.6.0
        let size = $crate::deserialize_type_size!($de_type => type_size);
        if $pos + size > $buffer.len() {
            return Err($crate::err::DeError::UnexpectedEOB);
        }
        let subbuffer = &$buffer[$pos..$pos + size];
        let t = <$de_type as $crate::Nl>::deserialize(subbuffer)?;
        (t, $pos + size)
    }};
    ($de_type:ty, $buffer:expr, $pos:expr, $size:expr $(,)?) => {{
        // FIXME: Deprecated; remove in 0.6.0
        let size = $size;
        if $pos + size > $buffer.len() {
            return Err($crate::err::DeError::UnexpectedEOB);
        }
        let subbuffer = &$buffer[$pos..$pos + size];
        let t = <$de_type as $crate::Nl>::deserialize(&subbuffer)?;
        (t, $pos + size)
    }};
    (STRIP $buffer:expr, $pos:expr, $size:expr $(,)?) => {{
        // FIXME: Deprecated; remove in 0.6.0
        let size = $size;
        if $pos + size > $buffer.len() {
            return Err($crate::err::DeError::UnexpectedEOB);
        }
        $pos + size
    }};
    (END $buffer:expr, $pos:expr $(,)?) => {{
        // FIXME: Deprecated; remove in 0.6.0
        if $buffer.len() != $pos {
            return Err($crate::err::DeError::BufferNotParsed);
        }
    }};
    ($de_type:ty, $buffer:expr, $pos:expr, $size:expr, $struct_name:path, $field_name:ident $(,)?) => {{
        let size = $size;
        if $pos + size > $buffer.len() {
            return Err($crate::err::DeError::IncompleteType(stringify!($struct_name), Some(stringify!($field_name))));
        }
        let subbuffer = &$buffer[$pos..$pos + size];
        let t = <$de_type as $crate::Nl>::deserialize(&subbuffer)?;
        (t, $pos + size)
    }};
    ($de_type:ty, $buffer:expr, $pos:expr, $struct_name:path, $field_name:ident $(,)?) => {{
        let size = $crate::deserialize_type_size!($de_type => type_size);
        if $pos + size > $buffer.len() {
            return Err($crate::err::DeError::IncompleteType(stringify!($struct_name), Some(stringify!($field_name))));
        }
        let subbuffer = &$buffer[$pos..$pos + size];
        let t = <$de_type as $crate::Nl>::deserialize(subbuffer)?;
        (t, $pos + size)
    }};
    (STRIP $buffer:expr, $pos:expr, $size:expr, $struct_name:path $(,)?) => {{
        let size = $size;
        if $pos + size > $buffer.len() {
            return Err($crate::err::DeError::IncompleteType(stringify!($struct_name), Some("padding")));
        }
        $pos + size
    }};
    (END $buffer:expr, $pos:expr, $struct_name:path $(,)?) => {{
        if $buffer.len() != $pos {
            return Err($crate::err::DeError::DataLeftInBuffer(stringify!($struct_name), None));
        }
    }};
}

/// This macro can be used to declaratively define deserialization for a struct.
///
/// # Examples
/// ```
/// use neli::err::DeError;
///
/// fn deserialize() -> Result<(), DeError> {
///     struct MyStruct {
///         field_one: u16,
///         field_two: u32,
///         field_three: u16,
///     }
///
///     let mut vec = vec![0; 8];
///     neli::deserialize! {
///         vec.as_mut_slice();
///         MyStruct {
///             field_one: u16,
///             field_two: u32,
///             field_three: u16
///         }
///     };
///
///     Ok(())
/// }
/// ```
#[macro_export]
macro_rules! deserialize {
    (STRIP $self_de_type:ident; $buffer:expr; $struct_type:path {
        $($de_name:ident: $de_type:ty $(=> $size:expr)?),* $(,)?
    } => $struct_size:expr) => {{
        let pos = 0;
        $(
            let ($de_name, pos) = drive_deserialize!(
                $de_type, $buffer, pos $(, $size)?, $struct_type, $de_name
            );
        )*
        let pos = $crate::drive_deserialize!(STRIP $buffer, pos, $struct_size, $struct_type);
        $crate::drive_deserialize!(END $buffer, pos, $struct_type);
        $struct_type {
            $( $de_name ),*
        }
    }};
    ($buffer:expr; $struct_type:path {
        $($de_name:ident: $de_type:ty $(=> $size:expr)?),* $(,)?
    }) => {{
        let pos = 0;
        $(
            let ($de_name, pos) = $crate::drive_deserialize!(
                $de_type, $buffer, pos $(, $size)?, $struct_type, $de_name
            );
        )*
        $crate::drive_deserialize!(END $buffer, pos, $struct_type);
        $struct_type {
            $( $de_name ),*
        }
    }};
}

macro_rules! get_int {
    ($bytes:ident, $get_int:ident) => {{
        // FIXME: Deprecated; remove in 0.6.0
        let size = Self::type_size().expect("Integers have static size");
        if $bytes.len() < size {
            return Err($crate::err::DeError::UnexpectedEOB);
        } else if $bytes.len() > size {
            return Err($crate::err::DeError::BufferNotParsed);
        }
        byteorder::NativeEndian::$get_int($bytes.as_ref())
    }};
    ($bytes:ident, $get_int:ident, $de_type:ty) => {{
        let size = Self::type_size().expect("Integers have static size");
        if $bytes.len() < size {
            return Err($crate::err::DeError::IncompleteType(
                stringify!($de_type),
                None,
            ));
        } else if $bytes.len() > size {
            return Err($crate::err::DeError::DataLeftInBuffer(
                stringify!($de_type),
                None,
            ));
        }
        byteorder::NativeEndian::$get_int($bytes.as_ref())
    }};
    ($bytes:ident, $get_int:ident, $endian:ty) => {{
        // FIXME: Deprecated; remove in 0.6.0
        let size = Self::type_size().expect("Integers have static size");
        if $bytes.len() < size {
            return Err($crate::err::DeError::UnexpectedEOB);
        } else if $bytes.len() > size {
            return Err($crate::err::DeError::BufferNotParsed);
        }
        <$endian>::$get_int($bytes.as_ref())
    }};
    ($bytes:ident, $get_int:ident, $endian:ty, $de_type:ty) => {{
        let size = Self::type_size().expect("Integers have static size");
        if $bytes.len() < size {
            return Err($crate::err::DeError::IncompleteType(
                stringify!($de_type),
                None,
            ));
        } else if $bytes.len() > size {
            return Err($crate::err::DeError::DataLeftInBuffer(
                stringify!($de_type),
                None,
            ));
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
