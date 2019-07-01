/// This macro can be used to serialize a single field in a struct.
#[macro_export]
macro_rules! drive_serialize {
    ($to_ser:expr, $buffer:ident, $pos:expr) => {{
        let mut buffer = $buffer;
        let size = $to_ser.size();
        if $pos + size > buffer.len() {
            return Err($crate::SerError::UnexpectedEOB(buffer));
        }
        let mut end = buffer.split_off($pos);
        let subbuffer = end.split_to(size);
        match $to_ser.serialize(subbuffer) {
            Ok(b) => {
                buffer.unsplit(b);
                buffer.unsplit(end);
                (buffer, $pos + size)
            }
            Err(e) => return Err(e.reconstruct(Some(buffer), Some(end))),
        }
    }};
    ($to_ser:expr, $buffer:ident, $pos:expr, $size:ident) => {{
        let mut buffer = $buffer;
        let size = $to_ser.$size();
        if $pos + size > buffer.len() {
            return Err($crate::SerError::UnexpectedEOB(buffer));
        }
        let mut end = buffer.split_off($pos);
        let subbuffer = end.split_to(size);
        match $to_ser.serialize(subbuffer) {
            Ok(b) => {
                buffer.unsplit(b);
                buffer.unsplit(end);
                (buffer, $pos + size)
            }
            Err(e) => return Err(e.reconstruct(Some(buffer), Some(end))),
        }
    }};
    (PAD $self:expr, $buffer:ident, $pos:ident) => {{
        let mut buffer = $buffer;
        let size = $self.asize() - $self.size();
        if $pos + size > buffer.len() {
            return Err(SerError::UnexpectedEOB(buffer));
        }
        let subbuffer = buffer.split_off($pos);
        match $self.pad(subbuffer) {
            Ok(b) => {
                buffer.unsplit(b);
                (buffer, $pos + size)
            }
            Err(e) => return Err(e.reconstruct(Some(buffer), None)),
        }
    }};
    (END $buffer:ident, $pos:ident) => {{
        if $buffer.len() != $pos {
            return Err(SerError::BufferNotFilled($buffer));
        }
        $buffer
    }};
}

/// This macro can be used to declaratively define serialization for a struct.
#[macro_export]
macro_rules! serialize {
    (PAD $self:ident; $buffer:ident; $($to_ser:expr $(, $size:ident)?);*) => {{
        let pos = 0;
        let buffer = $buffer;
        $(
            let (buffer, pos) = drive_serialize!($to_ser, buffer, pos $(, $size)?);
        )*
        let (buffer, pos) = drive_serialize!(PAD $self, buffer, pos);
        drive_serialize!(END buffer, pos)
    }};
    ($buffer:ident; $($to_ser:expr $(, $size:ident)?);*) => {{
        let pos = 0;
        let buffer = $buffer;
        $(
            let (buffer, pos) = drive_serialize!($to_ser, buffer, pos $(, $size)?);
        )*
        drive_serialize!(END buffer, pos)
    }};
}

/// This macro calculates size from `type_size` methods and returns an error
/// if `type_size` evaluates to `None`.
#[macro_export]
macro_rules! deserialize_type_size {
    ($de_type:ty => $de_size:ident) => {
        match <$de_type>::$de_size() {
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
        match (<$de_type>::type_asize(), <$de_type>::type_size()) {
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
        let subbuffer = $buffer.slice($pos, $pos + size);
        let t = <$de_type>::deserialize(subbuffer)?;
        (t, $pos + size)
    }};
    ($de_type:ty, $buffer:ident, $pos:expr, $size:expr) => {{
        let size = $size;
        if $pos + size > $buffer.len() {
            return Err(DeError::UnexpectedEOB);
        }
        let subbuffer = $buffer.slice($pos, $pos + size);
        let t = <$de_type>::deserialize(subbuffer)?;
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
            return Err($crate::err::SerError::UnexpectedEOB($bytes));
        } else if $bytes.len() > size {
            return Err($crate::err::SerError::BufferNotFilled($bytes));
        }
        byteorder::NativeEndian::$put_int($bytes.as_mut(), $to_ser);
        $bytes
    }};
    ($to_ser:expr, $bytes:ident, $put_int:ident, $endian:ty) => {{
        let size = $to_ser.size();
        if $bytes.len() < size {
            return Err($crate::err::SerError::UnexpectedEOB($bytes));
        } else if $bytes.len() > size {
            return Err($crate::err::SerError::BufferNotFilled($bytes));
        }
        <$endian>::$put_int($bytes.as_mut(), $to_ser);
        $bytes
    }};
}
