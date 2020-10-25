/// For naming a new enum, passing in what type it serializes to and deserializes
/// from, and providing a mapping from variants to expressions (such as libc consts) that
/// will ultimately be used in the serialization/deserialization step when sending the netlink
/// message over the wire.
///
/// # Usage
///  Create an `enum` named "MyNetlinkProtoAttrs" that can be serialized into `u16`s to use with Netlink.
///  Possibly represents the fields on a message you received from Netlink.
///  ```ignore
///  impl_var!(MyNetlinkProtoAttrs, u16,
///     Id => 16 as u16,
///     Name => 17 as u16,
///     Size => 18 as u16
///  );
/// ```
/// Or, with doc comments (if you're developing a library)
/// ```ignore
///  impl_var!(
///     /// These are the attributes returned
///     /// by a fake netlink protocol.
///     ( MyNetlinkProtoAttrs, u16,
///     Id => 16 as u16,
///     Name => 17 as u16,
///     Size => 18 as u16 )
///  );
/// ```
///
#[macro_export]
macro_rules! impl_var {
    (
        $( #[$outer:meta] )*
        $vis:vis $name:ident, $ty:ty,
        $(
            $( #[cfg($meta:meta)] )*
            $var:ident => $val:expr
        ),*
    ) => (
        $(#[$outer])*
        #[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        $vis enum $name {
            $(
                $(
                    #[cfg($meta)]
                )*
                #[allow(missing_docs)]
                $var,
            )*
            /// Variant that signifies an invalid value while deserializing
            UnrecognizedVariant($ty),
        }

        impl $name {
            /// Returns true if no variant corresponds to the value it was parsed from
            pub fn is_unrecognized(&self) -> bool {
                matches!(*self, $name::UnrecognizedVariant(_))
            }
        }

        impl From<$ty> for $name {
            fn from(v: $ty) -> Self {
                match v {
                    $(
                        $(
                            #[cfg($meta)]
                        )*
                        i if i == $val => $name::$var,
                    )*
                    i => $name::UnrecognizedVariant(i)
                }
            }
        }

        impl From<$name> for $ty {
            fn from(v: $name) -> Self {
                match v {
                    $(
                        $(
                            #[cfg($meta)]
                        )*
                        $name::$var => $val,
                    )*
                    $name::UnrecognizedVariant(i) => i,
                }
            }
        }

        impl<'a> From<&'a $name> for $ty {
            fn from(v: &'a $name) -> Self {
                match *v {
                    $(
                        $(
                            #[cfg($meta)]
                        )*
                        $name::$var => $val,
                    )*
                    $name::UnrecognizedVariant(i) => i,
                }
            }
        }

        impl $crate::Nl for $name {
            fn serialize<'a>(&self, mem: $crate::types::SerBuffer<'a>) -> Result<$crate::types::SerBuffer<'a>, $crate::err::SerError<'a>> {
                let v: $ty = self.clone().into();
                v.serialize(mem)
            }

            fn deserialize(mem: $crate::types::DeBuffer) -> Result<Self, $crate::err::DeError> {
                let v = <$ty>::deserialize(mem)?;
                Ok(v.into())
            }

            fn size(&self) -> usize {
                std::mem::size_of::<$ty>()
            }

            fn type_size() -> Option<usize> {
                Some(std::mem::size_of::<$ty>())
            }
        }
    );
}

/// For generating a marker trait that flags a new enum as usable in a field that accepts a generic
/// type.
/// This way, the type can be constrained when the impl is provided to only accept enums that
/// implement the marker trait that corresponds to the given marker trait. The current
/// convention is to use `impl_trait` to create the trait with the name of the field that
/// is the generic type and then use `impl_var_trait` to flag the new enum as usable in
/// this field.
#[macro_export]
macro_rules! impl_trait {
    (
        $(#[$outer:meta])*
        $vis_trait:vis $trait_name:ident,
        $to_from_ty:ty,
        $(
            #[$wrapper_outer:meta]
        )*
        $vis_enum:vis $wrapper_type:ident,
        $( $const_enum:ident ),+
    ) => {
        $(#[$outer])*
        $vis_trait trait $trait_name: $crate::Nl
            + PartialEq
            + Clone
            + From<$to_from_ty>
            + Into<$to_from_ty>
            + Copy
        {}

        impl $trait_name for $to_from_ty {}

        $(
            impl $trait_name for $const_enum {}
        )+

        #[derive(Debug, PartialEq, Clone, Copy)]
        $(
            #[$wrapper_outer]
        )*
        $vis_enum enum $wrapper_type {
            $(
                #[allow(missing_docs)]
                $const_enum($const_enum),
            )+
            /// Constant could not be parsed into a type
            UnrecognizedConst($to_from_ty),
        }

        impl $trait_name for $wrapper_type {}

        impl Into<$to_from_ty> for $wrapper_type {
            fn into(self) -> $to_from_ty {
                match self {
                    $(
                        $wrapper_type::$const_enum(inner) => inner.into(),
                    )+
                    $wrapper_type::UnrecognizedConst(v) => v,
                }
            }
        }

        impl From<$to_from_ty> for $wrapper_type {
            fn from(v: $to_from_ty) -> Self {
                $(
                    let var = $const_enum::from(v);
                    if !var.is_unrecognized() {
                        return $wrapper_type::$const_enum(var);
                    }
                )*
                $wrapper_type::UnrecognizedConst(v)
            }
        }

        impl $crate::Nl for $wrapper_type {
            fn serialize<'a>(&self, mem: $crate::types::SerBuffer<'a>) -> Result<$crate::SerBuffer<'a>, $crate::err::SerError<'a>> {
                match *self {
                    $(
                        $wrapper_type::$const_enum(ref inner) => inner.serialize(mem),
                    )+
                    $wrapper_type::UnrecognizedConst(v) => v.serialize(mem),
                }
            }

            fn deserialize(mem: $crate::types::DeBuffer) -> Result<Self, $crate::err::DeError> {
                let v = <$to_from_ty>::deserialize(mem)?;
                Ok($wrapper_type::from(v))
            }

            fn size(&self) -> usize {
                std::mem::size_of::<$to_from_ty>()
            }

            fn type_size() -> Option<usize> {
                Some(std::mem::size_of::<$to_from_ty>())
            }
        }
    };
}

/// Implement a container for bit flag enums of a certain type.
#[macro_export]
macro_rules! impl_flags {
    ($(#[$outer:meta])* $vis:vis $name:ident, $type:ty, $bin_type:ty) => {
        #[derive(Debug, PartialEq)]
        $(#[$outer])*
        $vis struct $name($crate::types::FlagBuffer<$type>);

        impl $name {
            /// Create an empty flag container
            pub fn empty() -> Self {
                $name(<$crate::types::FlagBuffer<$type> as $crate::types::FlagBufferOps<$type>>::empty())
            }

            /// Initialize a flag container with the given flags
            pub fn new(flags: &[$type]) -> Self {
                $name(<$crate::types::FlagBuffer<$type> as From<&[$type]>>::from(flags))
            }

            /// Add a flag
            pub fn set(&mut self, flag: $type) {
                <$crate::types::FlagBuffer<$type> as $crate::types::FlagBufferOps<$type>>::set(&mut self.0, flag)
            }

            /// Add a flag
            pub fn unset(&mut self, flag: &$type) {
                <$crate::types::FlagBuffer<$type> as $crate::types::FlagBufferOps<$type>>::unset(&mut self.0, &flag)
            }

            /// Contains a flag
            pub fn contains(&self, flag: &$type) -> bool {
                <$crate::types::FlagBuffer<$type> as $crate::types::FlagBufferOps<$type>>::contains(&self.0, &flag)
            }
        }

        impl $crate::Nl for $name {
            fn serialize<'a>(
                &self,
                mem: $crate::SerBuffer<'a>,
            ) -> Result<$crate::SerBuffer<'a>, $crate::err::SerError<'a>> {
                let int_rep = <$crate::types::FlagBuffer<$type> as $crate::types::FlagBufferOps<$type>>::iter(
                    &self.0
                ).fold(0, |acc, next| {
                    let result: $bin_type = next.into();
                    acc | result
                });
                int_rep.serialize(mem)
            }

            fn deserialize(mem: $crate::DeBuffer) -> Result<Self, $crate::err::DeError> {
                let int_rep = <$bin_type>::deserialize(mem)?;
                let mut flags = <$crate::types::FlagBuffer<$type> as $crate::types::FlagBufferOps<$type>>::empty();
                for i in 0..std::mem::size_of::<$bin_type>() * 8 {
                    let set_bit = 1 << i;
                    if int_rep & set_bit == set_bit {
                        <$crate::types::FlagBuffer<$type> as $crate::types::FlagBufferOps<$type>>::set(&mut flags, <$type>::from(set_bit))
                    }
                }
                Ok($name(flags))
            }

            fn size(&self) -> usize {
                std::mem::size_of::<$bin_type>()
            }

            fn type_size() -> Option<usize> {
                Some(std::mem::size_of::<$bin_type>())
            }
        }
    };
}
