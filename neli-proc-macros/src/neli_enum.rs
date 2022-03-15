use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::quote;
use syn::{
    parse, parse_str, Arm, Attribute, Expr, Ident, ItemEnum, Lit, Meta, Path, Token, Type, Variant,
};

use crate::shared::remove_bad_attrs;

fn parse_type_attr(attr: Meta) -> Type {
    if let Meta::NameValue(nv) = attr {
        if nv.path == parse_str::<Path>("serialized_type").unwrap() {
            if let Lit::Str(ls) = nv.lit {
                return parse_str::<Type>(&ls.value())
                    .unwrap_or_else(|_| panic!("Invalid type supplied: {}", ls.value()));
            }
        }
    }

    panic!("Attribute in the form #[neli(serialized_type = \"TYPE_LITERAL_STR\")] required")
}

fn parse_enum(enm: &mut ItemEnum, ty: &Type) -> Vec<(Vec<Attribute>, Ident, Expr)> {
    let exprs = enm
        .variants
        .iter_mut()
        .map(|var| {
            if let Some((_, expr)) = var.discriminant.take() {
                (var.attrs.clone(), var.ident.clone(), expr)
            } else {
                panic!("All variants in the provided enum require an expression assignment")
            }
        })
        .collect();
    if !enm.variants.trailing_punct() {
        enm.variants.push_punct(Token![,](Span::call_site()));
    }
    enm.variants.push_value(
        parse::<Variant>(TokenStream::from(quote! {
            UnrecognizedConst(#ty)
        }))
        .expect("Could not parse tokens as a variant"),
    );
    exprs
}

fn parse_from_info(
    enum_name: Ident,
    var_info: Vec<(Vec<Attribute>, Ident, Expr)>,
) -> (Vec<Arm>, Vec<Arm>) {
    let mut from_const_info = Vec::new();
    let mut from_type_info = Vec::new();
    for (mut attributes, ident, expr) in var_info {
        attributes = remove_bad_attrs(attributes);
        let mut from_const_arm = parse::<Arm>(TokenStream::from(quote! {
            #(
                #attributes
            )*
            i if i == #expr => #enum_name::#ident,
        }))
        .expect("Failed to parse tokens as a match arm");
        from_const_arm.attrs = attributes.clone();
        from_const_info.push(from_const_arm);

        let mut from_type_arm = parse::<Arm>(TokenStream::from(quote! {
            #(
                #attributes
            )*
            #enum_name::#ident => #expr,
        }))
        .expect("Failed to parse tokens as a match arm");
        from_type_arm.attrs = attributes.clone();
        from_type_info.push(from_type_arm);
    }
    (from_const_info, from_type_info)
}

pub fn generate_neli_enum(mut enm: ItemEnum, meta: Meta) -> TokenStream2 {
    let enum_name = enm.ident.clone();
    let ty = parse_type_attr(meta);

    let variant_info = parse_enum(&mut enm, &ty);
    let (from_const_info, from_type_info) = parse_from_info(enum_name.clone(), variant_info);

    quote! {
        #[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        #[allow(missing_docs)]
        #enm

        impl #enum_name {
            /// Check whether a given method is an unrecognized
            /// constant for the set of possible constants
            /// associated with the current type.
            pub fn is_unrecognized(&self) -> bool {
                match *self {
                    #enum_name::UnrecognizedConst(_) => true,
                    _ => false,
                }
            }
        }

        impl neli::Size for #enum_name {
            fn unpadded_size(&self) -> usize {
                std::mem::size_of::<#ty>()
            }
        }

        impl neli::TypeSize for #enum_name {
            fn type_size() -> usize {
                std::mem::size_of::<#ty>()
            }
        }

        impl neli::ToBytes for #enum_name {
            fn to_bytes(&self, buffer: &mut std::io::Cursor<Vec<u8>>) -> Result<(), neli::err::SerError> {
                let bin_rep: #ty = self.into();
                bin_rep.to_bytes(buffer)
            }
        }

        impl<'lt> neli::FromBytes<'lt> for #enum_name {
            fn from_bytes(buffer: &mut std::io::Cursor<&'lt [u8]>) -> Result<Self, neli::err::DeError> {
                Ok(#enum_name::from(<#ty as neli::FromBytes>::from_bytes(
                    buffer
                )?))
            }
        }

        impl From<#ty> for #enum_name {
            fn from(cnst: #ty) -> Self {
                match cnst {
                    #(
                        #from_const_info
                    )*
                    i => #enum_name::UnrecognizedConst(i),
                }
            }
        }

        impl From<#enum_name> for #ty {
            fn from(enm: #enum_name) -> Self {
                match enm {
                    #(
                        #from_type_info
                    )*
                    #enum_name::UnrecognizedConst(i) => i,
                }
            }
        }

        impl From<&#enum_name> for #ty {
            fn from(enm: &#enum_name) -> Self {
                match *enm {
                    #(
                        #from_type_info
                    )*
                    #enum_name::UnrecognizedConst(i) => i,
                }
            }
        }
    }
}
