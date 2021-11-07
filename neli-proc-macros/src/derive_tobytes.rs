use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{FieldsNamed, FieldsUnnamed, Ident, ItemEnum, ItemStruct};

use crate::shared::{
    generate_arms, generate_named_fields, generate_unnamed_fields, process_impl_generics,
    process_trait_bounds, FieldInfo, StructInfo,
};

pub fn impl_tobytes_struct(is: ItemStruct) -> TokenStream2 {
    let info = StructInfo::from_item_struct(is, Some("ToBytes"), "to_bytes_bound", true);
    let (struct_name, generics, generics_without_bounds, field_names, field_types, _, padded) =
        info.into_tuple();

    if field_names.is_empty() {
        return quote! {
            impl neli::ToBytes for #struct_name {
                fn to_bytes(&self, _: &mut std::io::Cursor<Vec<u8>>) -> Result<(), neli::err::SerError> {
                    Ok(())
                }
            }
        };
    }

    let padding = if padded {
        quote! {
            <#struct_name#generics_without_bounds as neli::ToBytes>::pad(&self, buffer)?;
        }
    } else {
        TokenStream2::new()
    };

    quote! {
        impl#generics neli::ToBytes for #struct_name#generics_without_bounds {
            fn to_bytes(&self, buffer: &mut std::io::Cursor<Vec<u8>>) -> Result<(), neli::err::SerError> {
                #( <#field_types as neli::ToBytes>::to_bytes(&self.#field_names, buffer)?; )*
                #padding
                Ok(())
            }
        }
    }
}

fn generate_named_pat_and_expr(
    enum_name: Ident,
    var_name: Ident,
    fields: FieldsNamed,
) -> TokenStream2 {
    let (field_names, types, _) = FieldInfo::to_vecs(generate_named_fields(fields).into_iter());
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
    let (field_names, types, _) =
        FieldInfo::to_vecs(generate_unnamed_fields(fields, false).into_iter());
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
