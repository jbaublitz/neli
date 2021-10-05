use proc_macro2::TokenStream as TokenStream2;
use quote::{quote, ToTokens};
use syn::{Attribute, Fields, Generics, Ident, ItemStruct, Type, WherePredicate};

use crate::shared::{generate_named_fields, generate_trait_bounds, generate_unnamed_field_indices};

fn generate_header<I>(
    struct_name: Ident,
    generics: Generics,
    generics_without_bounds: Generics,
    trait_bounds: Vec<WherePredicate>,
    _: Vec<I>,
    mut field_types: Vec<Type>,
    _: Vec<Vec<Attribute>>,
    _: bool,
) -> TokenStream2
where
    I: ToTokens,
{
    let trait_bounds = generate_trait_bounds(trait_bounds);
    let _ = field_types.pop();

    quote! {
        impl#generics neli::Header for #struct_name#generics_without_bounds #trait_bounds {
            fn header_size() -> usize {
                #( <#field_types as neli::TypeSize>::type_size() )+*
            }
        }
    }
}

pub fn impl_header_struct(is: ItemStruct) -> TokenStream2 {
    match is.fields {
        Fields::Named(fields) => {
            process_fields!(
                generate_named_fields,
                fields,
                None,
                "header_bound",
                is,
                generate_header
            )
        }
        Fields::Unnamed(fields) => {
            process_fields!(
                generate_unnamed_field_indices,
                fields,
                None,
                "header_bound",
                is,
                generate_header
            )
        }
        Fields::Unit => {
            let struct_name = is.ident;
            quote! {
                impl neli::Header for #struct_name {
                    fn header_size() -> usize {
                        0
                    }
                }
            }
        }
    }
}
