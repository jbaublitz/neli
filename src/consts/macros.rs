// This is to facillitate the two different ways to call
// `impl_var`: one with doc comments and one without.
#[macro_export]
#[doc(hidden)]
macro_rules! impl_var_base {
    ($name:ident, $ty:ty, $( $( #[cfg($meta:meta)] )* $var:ident => $val:expr ),* ) => {
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
            fn serialize(&self, mem: &mut $crate::StreamWriteBuffer) -> Result<(), $crate::err::SerError> {
                let v: $ty = self.clone().into();
                v.serialize(mem)
            }

            fn deserialize<T>(mem: &mut $crate::StreamReadBuffer<T>) -> Result<Self, $crate::err::DeError>
                    where T: AsRef<[u8]> {
                let v = <$ty>::deserialize(mem)?;
                Ok(v.into())
            }

            fn size(&self) -> usize {
                std::mem::size_of::<$ty>()
            }
        }
    };
}

#[macro_export]
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
macro_rules! impl_var {
    (
        $( #[$outer:meta] )*
        $name:ident, $ty:ty, $( $( #[cfg($meta:meta)] )* $var:ident => $val:expr ),*
    ) => ( // with comments
        $(#[$outer])*
        #[derive(Clone,Debug,Eq,PartialEq)]
        pub enum $name {
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

        impl_var_base!($name, $ty, $( $( #[cfg($meta)] )* $var => $val),* );
    );
    (
        $name:ident, $ty:ty,
        $( $( #[cfg($meta:meta)] )* $var:ident => $val:expr ),*
    ) => ( // without comments
        #[allow(missing_docs)]
        #[derive(Clone,Debug,Eq,PartialEq)]
        pub enum $name {
            #[allow(missing_docs)]
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

        impl_var_base!($name, $ty, $( $( #[cfg($meta:meta)] )* $var => $val),* );
    );
}

#[macro_export]
/// For generating a marker trait that flags a new enum as usable in a field that accepts a generic
/// type.
/// This way, the type can be constrained when the impl is provided to only accept enums that
/// implement the marker trait that corresponds to the given marker trait. The current
/// convention is to use `impl_trait` to create the trait with the name of the field that
/// is the generic type and then use `impl_var_trait` to flag the new enum as usable in
/// this field. See the examples below for more details.
macro_rules! impl_trait {
    ( $(#[$outer:meta])* $trait_name:ident, $to_from_ty:ty ) => { // with comments
        $(#[$outer])*
        pub trait $trait_name: $crate::Nl + PartialEq + From<$to_from_ty> + Into<$to_from_ty> {}

        impl $trait_name for $to_from_ty {}
    };
    ( $trait_name:ident, $to_from_ty:ty ) => { // without comments
        #[allow(missing_docs)]
        pub trait $trait_name: $crate::Nl + PartialEq + From<$to_from_ty> + Into<$to_from_ty> {}

        impl $trait_name for $to_from_ty {}
    };
}

#[macro_export]
/// For defining a new enum implementing the provided marker trait.
/// It accepts a name for the enum and the target type for serialization and
/// deserialization conversions, as well as value conversions
/// for serialization and deserialization.
macro_rules! impl_var_trait {
    ( $( #[$outer:meta] )* $name:ident, $ty:ty, $impl_name:ident,
      $( $( #[cfg($meta:meta)] )* $var:ident => $val:expr ),* ) => ( // with comments
        impl_var!( $(#[$outer])*
            $name, $ty, $( $( #[cfg($meta)] )* $var => $val ),*
        );

        impl $impl_name for $name {}
    );
    ( $name:ident, $ty:ty, $impl_name:ident,
      $( $( #[cfg($meta:meta)] )* $var:ident => $val:expr ),* ) => ( // without comments
        impl_var!($name, $ty, $( $( #[cfg($meta)] )* $var => $val ),* );

        impl $impl_name for $name {}
    );
}
