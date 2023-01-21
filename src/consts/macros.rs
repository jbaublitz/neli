/// For generating a marker trait that flags a new enum as usable in a
/// field that accepts a generic type. This way, the type parameter
/// can be constrained by a trait bound to only accept enums that
/// implement the marker trait.
///
/// # Usage
///
/// ```
/// use neli::neli_enum;
///
/// /// Define an enum
/// #[neli_enum(serialized_type = "u16")]
/// pub enum MyFamilyEnum {
///     One = 1,
///     Two = 2,
///     Three = 3
/// }
///
/// /// Define another enum
/// #[neli_enum(serialized_type = "u16")]
/// pub enum MyOtherFamilyEnum {
///     Four = 4,
///     Five = 5,
///     Six = 6,
/// }
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
        $(,)?
    ) => {
        $(#[$outer])*
        $vis_trait trait $trait_name: PartialEq
            + Clone
            + From<$to_from_ty>
            + Into<$to_from_ty>
            + Copy
            + $crate::Size
            + $crate::TypeSize
            + $crate::FromBytes
            + $crate::ToBytes
            + std::fmt::Debug
        {}

        impl $trait_name for $to_from_ty {}

        $(
            impl $trait_name for $const_enum {}
        )+

        #[derive(Debug, PartialEq, Eq, Clone, Copy)]
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

        impl $crate::Size for $wrapper_type {
            fn unpadded_size(&self) -> usize {
                std::mem::size_of::<$to_from_ty>()
            }
        }

        impl $crate::TypeSize for $wrapper_type {
            fn type_size() -> usize {
                std::mem::size_of::<$to_from_ty>()
            }
        }

        impl $crate::ToBytes for $wrapper_type {
            fn to_bytes(&self, buffer: &mut std::io::Cursor<Vec<u8>>) -> Result<(), $crate::err::SerError> {
                Ok(match self {
                    $(
                        $wrapper_type::$const_enum(val) => val.to_bytes(buffer)?,
                    )*
                    $wrapper_type::UnrecognizedConst(val) => val.to_bytes(buffer)?,
                })
            }
        }

        impl $crate::FromBytes for $wrapper_type {
            fn from_bytes(buffer: &mut std::io::Cursor<impl AsRef<[u8]>>) -> Result<Self, $crate::err::DeError> {
                Ok($wrapper_type::from(<$to_from_ty as $crate::FromBytes>::from_bytes(
                    buffer
                )?))
            }
        }

        impl $trait_name for $wrapper_type {}

        $(
            impl From<$const_enum> for $wrapper_type {
                fn from(e: $const_enum) -> Self {
                    $wrapper_type::$const_enum(e)
                }
            }
        )+

        impl From<$wrapper_type> for $to_from_ty {
            fn from(w: $wrapper_type) -> Self {
                match w {
                    $(
                        $wrapper_type::$const_enum(inner) => inner.into(),
                    )+
                    $wrapper_type::UnrecognizedConst(v) => v,
                }
            }
        }

        impl From<&$wrapper_type> for $to_from_ty {
            fn from(w: &$wrapper_type) -> Self {
                match w {
                    $(
                        $wrapper_type::$const_enum(inner) => inner.into(),
                    )+
                    $wrapper_type::UnrecognizedConst(v) => *v,
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
    };
}

/// Implement a container for bit flag enums using the [`bitflags`][bitflags] crate.
///
/// # Usage
///
/// ```
/// use neli::neli_enum;
///
/// neli::impl_flags!(
///     pub MyFlags: u16 {
///         ThisFlag = 1,
///         ThatFlag = 2,
///     }
/// );
/// ```
///
/// See [here][bitflags] for the methods that are autogenerated by `bitflags` on
/// the struct.
#[macro_export]
macro_rules! impl_flags {
    ($(#[$outer:meta])* $vis:vis $name:ident: $bin_type:ty {
        $($(#[$inner:ident $($tt:tt)*])* $var:ident = $const:expr),*
        $(,)?
    }) => {
        bitflags::bitflags! {
            $(#[$outer])*
            #[derive(neli_proc_macros::Size, neli_proc_macros::FromBytes, neli_proc_macros::ToBytes)]
            $vis struct $name: $bin_type {
                $(
                    $(#[$inner $($tt)*])*
                    #[allow(missing_docs)]
                    const $var = $const;
                )*
            }
        }

        impl From<$bin_type> for $name {
            fn from(bin: $bin_type) ->  Self {
                $name::from_bits_truncate(bin)
            }
        }

        impl From<$name> for $bin_type {
            fn from(ty: $name) ->  Self {
                ty.bits
            }
        }

        impl $crate::TypeSize for $name {
            fn type_size() -> usize {
                <$bin_type as $crate::TypeSize>::type_size()
            }
        }
    };
}
