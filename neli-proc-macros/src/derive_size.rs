use proc_macro2::TokenStream as TokenStream2;
use quote::{quote, ToTokens};
use syn::{
    Attribute, Fields, FieldsNamed, FieldsUnnamed, Generics, Ident, ItemEnum, ItemStruct, Type,
    WherePredicate,
};

use crate::shared::{
    generate_arms, generate_named_fields, generate_trait_bounds, generate_unnamed_field_indices,
    generate_unnamed_fields, process_impl_generics,
};

#[allow(clippy::too_many_arguments)]
fn generate_size<I>(
    struct_name: Ident,
    generics: Generics,
    generics_without_bounds: Generics,
    trait_bounds: Vec<WherePredicate>,
    field_names: Vec<I>,
    field_types: Vec<Type>,
    _: Vec<Vec<Attribute>>,
    _: bool,
) -> TokenStream2
where
    I: ToTokens,
{
    let trait_bounds = generate_trait_bounds(trait_bounds);

    quote! {
        impl#generics neli::Size for #struct_name#generics_without_bounds #trait_bounds {
            fn unpadded_size(&self) -> usize {
                #( <#field_types as neli::Size>::unpadded_size(&self.#field_names) )+*
            }
        }
    }
}

pub fn impl_size_struct(is: ItemStruct) -> TokenStream2 {
    match is.fields {
        Fields::Named(fields) => {
            process_fields!(
                generate_named_fields,
                fields,
                Some("Size"),
                "size_bound",
                is,
                generate_size
            )
        }
        Fields::Unnamed(fields) => {
            process_fields!(
                generate_unnamed_field_indices,
                fields,
                Some("Size"),
                "size_bound",
                is,
                generate_size
            )
        }
        Fields::Unit => {
            let struct_name = is.ident;
            quote! {
                impl neli::Size for #struct_name {
                    fn unpadded_size(&self) -> usize {
                        0
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
            #(<#types as neli::Size>::unpadded_size(&#field_names))+*
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
            #( <#types as neli::Size>::unpadded_size(&#field_names) )+*
        }
    }
}

pub fn impl_size_enum(ie: ItemEnum) -> TokenStream2 {
    let (generics, generics_without_bounds) = process_impl_generics(ie.generics, Some("Size"));

    let enum_name = ie.ident;
    let arms = generate_arms(
        enum_name.clone(),
        ie.variants.into_iter().collect::<Vec<_>>(),
        generate_named_pat_and_expr,
        generate_unnamed_pat_and_expr,
        quote! {
            0
        },
    );
    quote! {
        impl#generics neli::Size for #enum_name#generics_without_bounds {
            fn unpadded_size(&self) -> usize {
                match self {
                    #(#arms)*
                }
            }
        }
    }
}
