use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::ItemStruct;

use crate::shared::StructInfo;

fn generate_header(mut i: StructInfo) -> TokenStream2 {
    i.pop_field();

    let (struct_name, generics, generics_without_bounds, _, field_types, _, _) = i.into_tuple();

    quote! {
        impl#generics neli::Header for #struct_name#generics_without_bounds {
            fn header_size() -> usize {
                #( <#field_types as neli::TypeSize>::type_size() )+*
            }
        }
    }
}

pub fn impl_header_struct(is: ItemStruct) -> TokenStream2 {
    let info = StructInfo::from_item_struct(is, None, "header_bound", false);
    generate_header(info)
}
