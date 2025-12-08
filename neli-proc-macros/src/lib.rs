//! Procedural macros to be used with the library
//! [`neli`](https://github.com/jbaublitz/neli).
//!
//! All derive macros other than `Header` generate implicit type
//! parameter bounds on every type parameter which can be overriden
//! with struct attributes.

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse, Item, Meta};

#[macro_use]
mod shared;

mod derive_frombytes;
mod derive_header;
mod derive_size;
mod derive_tobytes;
mod neli_enum;

use derive_frombytes::*;
use derive_header::*;
use derive_size::*;
use derive_tobytes::*;
use neli_enum::*;

/// Converts an enum from the form:
///
/// ```no_compile
/// use neli_proc_macros::neli_enum;
///
/// #[neli_enum(serialized_type = "u16")]
/// pub enum MyConstants {
///     ConstOne = 1,
///     ConstTwo = 2,
///     ConstThree = 3,
/// }
/// ```
///
/// to:
///
/// ```
/// pub enum MyConstants {
///     ConstOne,
///     ConstTwo,
///     ConstThree,
/// }
/// ```
///
/// with [`From`] implemented reflexively for `MyConstants` and
/// [`u16`].
#[proc_macro_attribute]
pub fn neli_enum(attr: TokenStream, item: TokenStream) -> TokenStream {
    let attr_string = attr.to_string();
    let meta =
        parse::<Meta>(attr).unwrap_or_else(|_| panic!("{} is not a valid attribute", attr_string));
    let enum_item = parse::<Item>(item).unwrap();

    let enm = if let Item::Enum(e) = enum_item {
        e
    } else {
        panic!("This macro only operates on enums");
    };

    TokenStream::from(generate_neli_enum(enm, meta))
}

/// Derives the neli `Size` trait for a struct or enum.
///
/// Acceptable struct attribute is:
/// * `#[neli(size_bound = "T: MyTrait")]` which will generate a
///   trait bound in the impl for the specified type parameter.
///
/// Implicit type parameter bound: `Size`.
#[proc_macro_derive(Size, attributes(neli))]
pub fn proc_macro_size(ts: TokenStream) -> TokenStream {
    let item = parse::<Item>(ts).unwrap();
    TokenStream::from(match item {
        Item::Struct(strct) => impl_size_struct(strct),
        Item::Enum(enm) => impl_size_enum(enm),
        _ => panic!("Size can only be derived for structs and enums"),
    })
}

/// Derives the neli `Header` trait for a struct or enum. Unlike
/// other derive macros in this crate, the `Header` derive macro
/// does not impose type parameter bounds on type parameters.
/// See the accepted attribute for more information. The reason for
/// this is that the last field is considered to be the payload.
/// Because the payload may be represented by a type parameter,
/// we cannot blindly restrict type parameters or else we impose
/// an artificial restriction of `TypeSize` on the payload type
/// parameter. This is a problem for the `Header` trait as the
/// payload may be unsized even if the rest of the header is
/// composed exclusively of statically sized types and are therefore
/// compatible with the `TypeSize` trait.
///
/// Acceptable struct attribute is:
/// * `#[neli(header_bound = "T: MyTrait")]` which will generate a
///   trait bound in the impl for the specified type parameter.
///
/// While there is no implicit type parameter bound, every type
/// parameter that does not correspond to a payload should have
/// a specified type parameter bound of `TypeSize`.
#[proc_macro_derive(Header, attributes(neli))]
pub fn proc_macro_header(ts: TokenStream) -> TokenStream {
    let item = parse::<Item>(ts).unwrap();
    TokenStream::from(match item {
        Item::Struct(strct) => impl_header_struct(strct),
        _ => panic!("Header can only be derived for structs"),
    })
}

/// Derives the neli `FromBytes` trait for a struct.
///
/// Acceptable struct attribute is:
/// * `#[neli(from_bytes_bound = "T: MyTrait")]` which will generate
///   a trait bound in the impl for the specified type parameter.
/// * `#[neli(padding)]` which will add special handling for padding
///   for this struct.
///
/// Acceptable field attribute forms are:
/// * `#[neli(input = "input_expression")]` which may only be used
///   once for a struct. The behavior of this attribute is that a
///   bound requirement will change from the implicit `FromBytes` to
///   an implicit `FromBytesWithInput` bound. The method in this trait
///   will be called with `input_expression` as the input provided.
/// * `#[neli(input)]` which will transparently pass the input
///   provided in the `FromBytesWithInput` method through to the
///   `FromBytesWithInput` method for this field unchanged according
///   to the rules described above.
/// * `#[neli(size = "size_var_name")]` which allows specifying a size of the data type
///   that is different from the input specified by `#[neli(input)]`. Not specifying
///   this attribute defaults to using `input` as the size as well.
///
/// Implicit type parameter bound: `FromBytes`.
#[proc_macro_derive(FromBytes, attributes(neli))]
pub fn proc_macro_frombytes(ts: TokenStream) -> TokenStream {
    let item = parse::<Item>(ts).unwrap();
    TokenStream::from(match item {
        Item::Struct(strct) => impl_frombytes_struct(strct, "FromBytes", "from_bytes", None, None),
        _ => panic!("FromBytes can only be derived for structs"),
    })
}

/// Derives the neli `FromBytesWithInput` trait for a struct.
///
/// Acceptable struct attribute is:
/// * `#[neli(from_bytes_bound = "T: MyTrait")]` which will generate
///   a trait bound in the impl for the specified type parameter.
/// * `#[neli(padding)]` which will add special handling for padding
///   for this struct.
///
/// Acceptable field attribute forms are:
/// * `#[neli(input = "input_expression")]` which may only be used
///   once for a struct. The behavior of this attribute is that a
///   bound requirement will change from the implicit `FromBytes` to
///   an implicit `FromBytesWithInput` bound. The method in this trait
///   will be called with `input_expression` as the input provided.
/// * `#[neli(input)]` which will transparently pass the input
///   provided in the `FromBytesWithInput` method through to the
///   `FromBytesWithInput` method for this field unchanged according
///   to the rules described above.
/// * `#[neli(size = "size_var_name")]` which allows specifying a size of the data type
///   that is different from the input specified by `#[neli(input)]`. Not specifying
///   this attribute defaults to using `input` as the size as well.
///
/// Implicit type parameter bound: `FromBytes`.
#[proc_macro_derive(FromBytesWithInput, attributes(neli))]
pub fn proc_macro_frombyteswithinput(ts: TokenStream) -> TokenStream {
    let item = parse::<Item>(ts).unwrap();
    TokenStream::from(match item {
        Item::Struct(strct) => impl_frombytes_struct(
            strct,
            "FromBytesWithInput",
            "from_bytes_with_input",
            Some(quote! {
                type Input = usize;
            }),
            Some(quote! {
                , input: Self::Input
            }),
        ),
        _ => panic!("FromBytesWithInput can only be derived for structs"),
    })
}

/// Derives the neli `ToBytes` trait for a struct or enum.
///
/// Acceptable struct attribute is:
/// * `#[neli(to_bytes_bound = "T: MyTrait")]` which will generate a
///   trait bound in the impl for the specified type parameter.
/// * `#[neli(padding)]` which will add special handling for padding
///   for this struct.
///
/// Implicit type parameter bound: `ToBytes`.
#[proc_macro_derive(ToBytes, attributes(neli))]
pub fn proc_macro_tobytes(ts: TokenStream) -> TokenStream {
    let item = parse::<Item>(ts).unwrap();
    TokenStream::from(match item {
        Item::Struct(strct) => impl_tobytes_struct(strct),
        Item::Enum(enm) => impl_tobytes_enum(enm),
        _ => panic!("ToBytes can only be derived for structs and enums"),
    })
}
