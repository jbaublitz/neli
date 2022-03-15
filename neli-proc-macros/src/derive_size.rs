use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{FieldsNamed, FieldsUnnamed, Ident, ItemEnum, ItemStruct};

use crate::shared::{
    generate_arms, generate_named_fields, generate_unnamed_fields, process_impl_generics,
    FieldInfo, StructInfo,
};

fn generate_size(i: StructInfo) -> TokenStream2 {
    let (struct_name, generics, generics_without_bounds, field_names, field_types, _, _) =
        i.into_tuple();

    if field_types.is_empty() {
        quote! {
            impl#generics neli::Size for #struct_name#generics_without_bounds {
                fn unpadded_size(&self) -> usize {
                    0
                }
            }
        }
    } else {
        quote! {
            impl#generics neli::Size for #struct_name#generics_without_bounds {
                fn unpadded_size(&self) -> usize {
                    #( <#field_types as neli::Size>::unpadded_size(&self.#field_names) )+*
                }
            }
        }
    }
}

pub fn impl_size_struct(is: ItemStruct) -> TokenStream2 {
    let struct_info = StructInfo::from_item_struct(is, Some("Size"), "size_bound", true);
    generate_size(struct_info)
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
            #(<#types as neli::Size>::unpadded_size(&#field_names))+*
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
