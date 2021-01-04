/// For naming a new enum, passing in what type it serializes to and
/// deserializes from, and providing a mapping from variants to
/// expressions (such as libc consts) that will ultimately be used in
/// the serialization/deserialization step when sending the netlink
/// message over the wire.
///
/// # Usage
/// Create an enum named `MyNetlinkProtoAttrs` that can be serialized
/// into `u16`s to use with Netlink.  Represents the
/// fields on a message you received from Netlink.
///
///
/// Here is an example specifying the enum visibility:
///
///  ```
///  neli::impl_var!(
///     pub MyNetlinkProtoAttrs,
///     u16,
///     Id => 16u16,
///     Name => 17u16,
///     Size => 18u16
///  );
/// ```
///
/// or with doc comments:
///
/// ```
///  neli::impl_var!(
///     /// These are the attributes returned
///     /// by a fake netlink protocol.
///     MyNetlinkProtoAttrs, u16,
///     Id => 16u16,
///     Name => 17u16,
///     Size => 18u16
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
            /// Variant that signifies an invalid value while
            /// deserializing
            UnrecognizedVariant($ty),
        }

        impl $name {
            /// Returns true if no variant corresponds to the value
            /// it was parsed from
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
            fn serialize(&self, mem: $crate::types::SerBuffer) -> Result<(), $crate::err::SerError> {
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

/// For generating a marker trait that flags a new enum as usable in a
/// field that accepts a generic type. This way, the type parameter
/// can be constrained by a trait bound to only accept enums that
/// implement the marker trait.
///
/// # Usage
///
/// ```
/// /// Define an enum
/// neli::impl_var!(
///     MyFamilyEnum,
///     u16,
///     One => 1,
///     Two => 2,
///     Three => 3
/// );
///
/// /// Define another enum
/// neli::impl_var!(
///     MyOtherFamilyEnum,
///     u16,
///     Four => 4,
///     Five => 5,
///     Six => 6
/// );
///
/// /// Define a marker trait and implement it for MyFamilyEnum and
/// /// MyOtherFamilyEnum.
/// neli::impl_trait!(
///     MyMarkerTrait,
///     u16,
///     MyFamilyWrapperType,
///     MyFamilyEnum,
///     MyOtherFamilyEnum
/// );
/// ```
///
/// The result of the example above will be:
/// * One enum called `MyFamilyEnum`.
/// * Another called `MyOtherFamilyEnum`.
/// * A marker trait called `MyMarkerTrait`. This can be used to
/// constain type parameter so that only `MyFamilyEnum` and
/// `MyOtherFamilyEnum` variants can be passed in as a value.
/// * A wrapper enum called `MyFamilyWrapperType`. The definition is
/// as follows:
/// ```
/// enum MyFamilyEnum {
///     One,
///     Two,
///     Three,
/// }
///
/// enum MyOtherFamilyEnum {
///     Four,
///     Five,
///     Six,
/// }
///
/// enum MyFamilyWrapperType {
///     MyFamilyEnum(MyFamilyEnum),
///     MyOtherFamilyEnum(MyOtherFamilyEnum),
/// }
/// ```
/// If you are unsure of which type will be passed back, the wrapper
/// type can be used to automatically determine this for you when
/// deserializing and accept all values defined across both enums.
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

        $(
            impl From<$const_enum> for $wrapper_type {
                fn from(e: $const_enum) -> Self {
                    $wrapper_type::$const_enum(e)
                }
            }
        )+

        #[allow(clippy::from_over_into)]
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
            fn serialize(&self, mem: $crate::types::SerBuffer) -> Result<(), $crate::err::SerError> {
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

/// Implement a container for bit flag enums where the set of flags
/// will be condensed into a single value.
///
/// # Usage
///
/// ```
/// neli::impl_var!(
///     MyFlags,
///     u16,
///     ThisFlag => 1,
///     ThatFlag => 2
/// );
///
/// neli::impl_flags!(
///     MyFlagSet,
///     MyFlags,
///     u16
/// );
/// ```
///
/// This creates a struct called `MyFlagSet` that has the following
/// autogenerated methods:
/// * `fn empty() -> Self`
/// * `fn new(flags: &[MyFlags]) -> Self`
/// * `fn set(&mut self, flag: MyFlags)`
/// * `fn unset(&mut self, flag: &MyFlags)`
/// * `fn contains(&self, flag: &MyFlags) -> bool`
///
/// When the following example is serialized, all flags contained in
/// the set at the time of serialization will be converted into
/// `u16`s and bitwise or-ed.
#[macro_export]
macro_rules! impl_flags {
    ($(#[$outer:meta])* $vis:vis $name:ident, $type:ty, $bin_type:ty) => {
        #[derive(Debug, PartialEq)]
        $(#[$outer])*
        $vis struct $name($crate::types::FlagBuffer::<$type>);

        impl $name {
            /// Create an empty flag container
            pub fn empty() -> Self {
                $name($crate::types::FlagBuffer::<$type>::empty())
            }

            /// Initialize a flag container with the given flags
            pub fn new(flags: &[$type]) -> Self {
                $name(<$crate::types::FlagBuffer::<$type> as From<&[$type]>>::from(flags))
            }

            /// Add a flag
            pub fn set(&mut self, flag: $type) {
                $crate::types::FlagBuffer::<$type>::set(&mut self.0, flag)
            }

            /// Add a flag
            pub fn unset(&mut self, flag: &$type) {
                $crate::types::FlagBuffer::<$type>::unset(&mut self.0, &flag)
            }

            /// Contains a flag
            pub fn contains(&self, flag: &$type) -> bool {
                $crate::types::FlagBuffer::<$type>::contains(&self.0, &flag)
            }
        }

        impl $crate::Nl for $name {
            fn serialize(
                &self,
                mem: $crate::types::SerBuffer,
            ) -> Result<(), $crate::err::SerError> {
                let int_rep = $crate::types::FlagBuffer::<$type>::iter(
                    &self.0
                ).fold(0, |acc, next| {
                    let result: $bin_type = next.into();
                    acc | result
                });
                int_rep.serialize(mem)
            }

            fn deserialize(mem: $crate::types::DeBuffer) -> Result<Self, $crate::err::DeError> {
                let int_rep = <$bin_type>::deserialize(mem)?;
                let mut flags = $crate::types::FlagBuffer::<$type>::empty();
                for i in 0..std::mem::size_of::<$bin_type>() * 8 {
                    let set_bit = 1 << i;
                    if int_rep & set_bit == set_bit {
                        $crate::types::FlagBuffer::<$type>::set(&mut flags, <$type>::from(set_bit))
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
