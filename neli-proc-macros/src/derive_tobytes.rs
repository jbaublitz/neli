use proc_macro2::TokenStream as TokenStream2;
use quote::{quote, ToTokens};
use syn::{
    Attribute, Fields, FieldsNamed, FieldsUnnamed, Generics, Ident, ItemEnum, ItemStruct, Type,
    WherePredicate,
};

use crate::shared::{
    generate_arms, generate_named_fields, generate_trait_bounds, generate_unnamed_field_indices,
    generate_unnamed_fields, process_impl_generics, process_trait_bounds,
};

#[allow(clippy::too_many_arguments)]
fn generate_tobytes<I>(
    struct_name: Ident,
    generics: Generics,
    generics_without_bounds: Generics,
    trait_bounds: Vec<WherePredicate>,
    field_names: Vec<I>,
    field_types: Vec<Type>,
    _: Vec<Vec<Attribute>>,
    padded: bool,
) -> TokenStream2
where
    I: ToTokens,
{
    let trait_bounds = generate_trait_bounds(trait_bounds);
    let padding = if padded {
        quote! {
            <#struct_name#generics_without_bounds as neli::ToBytes>::pad(&self, buffer)?;
        }
    } else {
        TokenStream2::new()
    };
    quote! {
        impl#generics neli::ToBytes for #struct_name#generics_without_bounds #trait_bounds {
            fn to_bytes(&self, buffer: &mut std::io::Cursor<Vec<u8>>) -> Result<(), neli::err::SerError> {
                #( <#field_types as neli::ToBytes>::to_bytes(&self.#field_names, buffer)?; )*
                #padding
                Ok(())
            }
        }
    }
}

pub fn impl_tobytes_struct(is: ItemStruct) -> TokenStream2 {
    match is.fields {
        Fields::Named(fields) => {
            process_fields!(
                generate_named_fields,
                fields,
                Some("ToBytes"),
                "to_bytes_bound",
                is,
                generate_tobytes
            )
        }
        Fields::Unnamed(fields) => {
            process_fields!(
                generate_unnamed_field_indices,
                fields,
                Some("ToBytes"),
                "to_bytes_bound",
                is,
                generate_tobytes
            )
        }
        Fields::Unit => {
            let struct_name = is.ident;
            quote! {
                impl neli::ToBytes for #struct_name {
                    fn to_bytes(&self, _: &mut std::io::Cursor<Vec<u8>>) -> Result<(), neli::err::SerError> {
                        Ok(())
                    }
                }
            }
        }
    }
}

fn generate_named_pat_and_expr(
    enum_name: Ident,
    var_name: Ident,
    fields: FieldsNamed,
) -> TokenStream2 {
    let (field_names, types, _) = generate_named_fields(fields);
    quote! {
        #enum_name::#var_name {
            #(#field_names),*
        } => {
            #(<#types as neli::ToBytes>::to_bytes(&#field_names, buffer)?; )*
            Ok(())
        },
    }
}

fn generate_unnamed_pat_and_expr(
    enum_name: Ident,
    var_name: Ident,
    fields: FieldsUnnamed,
) -> TokenStream2 {
    let (field_names, types, _) = generate_unnamed_fields(fields);
    quote! {
        #enum_name::#var_name(
            #( #field_names ),*
        ) => {
            #( <#types as neli::ToBytes>::to_bytes(#field_names, buffer)?; )*
            Ok(())
        }
    }
}

pub fn impl_tobytes_enum(ie: ItemEnum) -> TokenStream2 {
    let (generics, generics_without_bounds) = process_impl_generics(ie.generics, Some("ToBytes"));
    let trait_bounds = process_trait_bounds(&ie.attrs, "to_bytes_bound");

    let enum_name = ie.ident;
    let arms = generate_arms(
        enum_name.clone(),
        ie.variants.into_iter().collect::<Vec<_>>(),
        generate_named_pat_and_expr,
        generate_unnamed_pat_and_expr,
        quote! {
            Ok(())
        },
    );
    quote! {
        impl#generics neli::ToBytes for #enum_name#generics_without_bounds where #( #trait_bounds ),* {
            fn to_bytes(&self, buffer: &mut std::io::Cursor<Vec<u8>>) -> Result<(), neli::err::SerError> {
                match self {
                    #(#arms)*
                }
            }
        }
    }
}
