//! Procedural macros to be used with the library
//! [`neli`](https://github.com/jbaublitz/neli).

use proc_macro::TokenStream;
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

#[proc_macro_derive(Size, attributes(neli))]
pub fn proc_macro_size(ts: TokenStream) -> TokenStream {
    let item = parse::<Item>(ts).unwrap();
    TokenStream::from(match item {
        Item::Struct(strct) => impl_size_struct(strct),
        Item::Enum(enm) => impl_size_enum(enm),
        _ => panic!("Size can only be derived for structs and enums"),
    })
}

#[proc_macro_derive(Header, attributes(neli))]
pub fn proc_macro_header(ts: TokenStream) -> TokenStream {
    let item = parse::<Item>(ts).unwrap();
    TokenStream::from(match item {
        Item::Struct(strct) => impl_header_struct(strct),
        _ => panic!("Header can only be derived for structs"),
    })
}

#[proc_macro_derive(FromBytes)]
pub fn proc_macro_frombytes(ts: TokenStream) -> TokenStream {
    let item = parse::<Item>(ts).unwrap();
    TokenStream::from(match item {
        Item::Struct(strct) => impl_frombytes_struct(strct),
        _ => panic!("FromBytes can only be derived for structs"),
    })
}

#[proc_macro_derive(FromBytesWithInput)]
pub fn proc_macro_frombyteswithinput(ts: TokenStream) -> TokenStream {
    let item = parse::<Item>(ts).unwrap();
    TokenStream::from(match item {
        Item::Struct(strct) => impl_frombyteswithinput_struct(strct),
        _ => panic!("FromBytesWithInput can only be derived for structs"),
    })
}

#[proc_macro_derive(ToBytes)]
pub fn proc_macro_tobytes(ts: TokenStream) -> TokenStream {
    let item = parse::<Item>(ts).unwrap();
    TokenStream::from(match item {
        Item::Struct(strct) => impl_tobytes_struct(strct),
        Item::Enum(enm) => impl_tobytes_enum(enm),
        _ => panic!("ToBytes can only be derived for structs and enums"),
    })
}
