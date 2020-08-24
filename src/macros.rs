/// This macro can be used to serialize a single field in a struct.
#[macro_export]
macro_rules! drive_serialize {
    ($to_ser:expr, $buffer:ident, $pos:expr) => {{
        let buffer = $buffer;
        let size = $to_ser.size();
        if $pos + size > <$crate::types::SerBuffer as $crate::types::SerBufferOps>::len(&buffer) {
            return Err($crate::SerError::new_with_kind(
                $crate::err::SerErrorKind::UnexpectedEOB,
                buffer,
            ));
        }
        let (start, subbuffer, end) =
            <$crate::types::SerBuffer as $crate::types::SerBufferOps>::split(
                buffer,
                $pos,
                $pos + size,
            )?;
        match $to_ser.serialize(subbuffer) {
            Ok(mut b) => {
                <$crate::types::SerBuffer as $crate::types::SerBufferOps>::join(
                    &mut b, start, end,
                )?;
                (b, $pos + size)
            }
            Err(e) => {
                let (kind, mut buffer) = e.into_parts();
                <$crate::types::SerBuffer as $crate::types::SerBufferOps>::join(
                    &mut buffer,
                    start,
                    end,
                )?;
                return Err($crate::err::SerError::new_with_kind(kind, buffer));
            }
        }
    }};
    ($to_ser:expr, $buffer:ident, $pos:expr, $size:ident) => {{
        let buffer = $buffer;
        let size = $to_ser.$size();
        if $pos + size > <$crate::types::SerBuffer as $crate::types::SerBufferOps>::len(&buffer) {
            return Err($crate::err::SerError::new_with_kind(
                $crate::err::SerErrorKind::UnexpectedEOB,
                buffer,
            ));
        }
        let (start, subbuffer, end) =
            <$crate::types::SerBuffer as $crate::types::SerBufferOps>::split(
                buffer,
                $pos,
                $pos + size,
            )?;
        match $to_ser.serialize(subbuffer) {
            Ok(mut b) => {
                <$crate::types::SerBuffer as $crate::types::SerBufferOps>::join(
                    &mut b, start, end,
                )?;
                (b, $pos + size)
            }
            Err(e) => {
                let (kind, mut buffer) = e.into_parts();
                <$crate::types::SerBuffer as $crate::types::SerBufferOps>::join(
                    &mut buffer,
                    start,
                    end,
                )?;
                return Err($crate::err::SerError::new_with_kind(kind, buffer));
            }
        }
    }};
    (PAD $self:expr, $buffer:ident, $pos:ident) => {{
        let buffer = $buffer;
        let size = $self.asize() - $self.size();
        if $pos + size > <$crate::types::SerBuffer as $crate::types::SerBufferOps>::len(&buffer) {
            return Err($crate::err::SerError::new_with_kind(
                $crate::err::SerErrorKind::UnexpectedEOB,
                buffer,
            ));
        }
        let (start, subbuffer, end) =
            <$crate::types::SerBuffer as $crate::types::SerBufferOps>::split(
                buffer,
                $pos,
                $pos + size,
            )?;
        match $self.pad(subbuffer) {
            Ok(mut b) => {
                <$crate::types::SerBuffer as $crate::types::SerBufferOps>::join(
                    &mut b, start, end,
                )?;
                (b, $pos + size)
            }
            Err(e) => {
                let (kind, mut buffer) = e.into_parts();
                <$crate::types::SerBuffer as $crate::types::SerBufferOps>::join(
                    &mut buffer,
                    start,
                    end,
                )?;
                return Err($crate::err::SerError::new_with_kind(kind, buffer));
            }
        }
    }};
    (END $buffer:ident, $pos:ident) => {{
        let buffer = $buffer;
        if <$crate::types::SerBuffer as $crate::SerBufferOps>::len(&buffer) != $pos {
            return Err(SerError::new_with_kind(
                $crate::err::SerErrorKind::BufferNotFilled,
                buffer,
            ));
        }
        buffer
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
        if $pos + size > <$crate::types::DeBuffer as $crate::types::DeBufferOps>::len(&$buffer) {
            return Err(DeError::UnexpectedEOB);
        }
        let subbuffer =
            <$crate::types::DeBuffer as $crate::types::DeBufferOps>::slice(
                &$buffer,
                $pos,
                $pos + size,
            ).map_err(DeError::new)?;
        let t = <$de_type>::deserialize(subbuffer)?;
        (t, $pos + size)
    }};
    ($de_type:ty, $buffer:ident, $pos:expr, $size:expr) => {{
        let size = $size;
        if $pos + size > $buffer.len() {
            return Err(DeError::UnexpectedEOB);
        }
        let subbuffer =
            <$crate::types::DeBuffer as $crate::types::DeBufferOps>::slice(
                &$buffer,
                $pos,
                $pos + size,
            )
            .map_err(DeError::new)?;
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
        if <$crate::types::DeBuffer as $crate::types::DeBufferOps>::len(&$buffer) != $pos {
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
            return Err($crate::err::SerError::new_with_kind(
                $crate::err::SerErrorKind::UnexpectedEOB,
                $bytes,
            ));
        } else if $bytes.len() > size {
            return Err($crate::err::SerError::new_with_kind(
                $crate::err::SerErrorKind::BufferNotFilled,
                $bytes,
            ));
        }
        byteorder::NativeEndian::$put_int($bytes.as_mut(), $to_ser);
        $bytes
    }};
    ($to_ser:expr, $bytes:ident, $put_int:ident, $endian:ty) => {{
        let size = $to_ser.size();
        if $bytes.len() < size {
            return Err($crate::err::SerError::new_with_kind(
                $crate::err::SerErrorKind::UnexpectedEOB,
                $bytes,
            ));
        } else if $bytes.len() > size {
            return Err($crate::err::SerError::new_with_kind(
                $crate::err::SerErrorKind::BufferNotFilled,
                $bytes,
            ));
        }
        <$endian>::$put_int($bytes.as_mut(), $to_ser);
        $bytes
    }};
}
