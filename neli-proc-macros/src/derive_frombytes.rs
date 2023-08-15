use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::quote;
use syn::{parse_str, Attribute, Fields, Ident, ItemStruct, Type};

use crate::shared::{process_input, process_size, process_skip_debug, StructInfo};

fn process_attrs(field_type: Type, field_attrs: Vec<Attribute>) -> TokenStream2 {
    let input = process_input(&field_attrs);
    let skip_debug = process_skip_debug(&field_attrs);
    let size = process_size(&field_attrs)
        .unwrap_or_else(|| parse_str("input").expect("input is a valid expression"));
    match (input, skip_debug) {
        (Some(Some(input)), _) => quote! {
            {
                let input = #input;
                log::trace!(
                    "Deserializing field type {}",
                    std::any::type_name::<#field_type>(),
                );
                let position = buffer.position() as usize;
                log::trace!(
                    "Buffer to be deserialized: {:?}",
                    &buffer.get_ref().as_ref()[position..position + #size],
                );
                let ok = <#field_type as neli::FromBytesWithInput>::from_bytes_with_input(
                    buffer,
                    input,
                )?;
                log::trace!("Field deserialized: {:?}", ok);
                ok
            }
        },
        (Some(None), _) => quote! {
            {
                log::trace!(
                    "Deserializing field type {}",
                    std::any::type_name::<#field_type>(),
                );
                let position = buffer.position() as usize;
                log::trace!(
                    "Buffer to be deserialized: {:?}",
                    &buffer.get_ref().as_ref()[position..position + #size],
                );
                let ok = <#field_type as neli::FromBytesWithInput>::from_bytes_with_input(
                    buffer,
                    input,
                )?;
                log::trace!("Field deserialized: {:?}", ok);
                ok
            }
        },
        (None, true) => quote! {
            {
                log::trace!(
                    "Deserializing field type {}",
                    std::any::type_name::<#field_type>(),
                );
                let position = buffer.position() as usize;
                let ok = <#field_type as neli::FromBytes>::from_bytes(buffer)?;
                log::trace!("Field deserialized: {:?}", ok);
                ok
            }
        },
        (None, false) => quote! {
            {
                log::trace!(
                    "Deserializing field type {}",
                    std::any::type_name::<#field_type>(),
                );
                let position = buffer.position() as usize;
                log::trace!(
                    "Buffer to be deserialized: {:?}",
                    &buffer.get_ref().as_ref()[position..position + <#field_type as neli::TypeSize>::type_size()],
                );
                let ok = <#field_type as neli::FromBytes>::from_bytes(buffer)?;
                log::trace!("Field deserialized: {:?}", ok);
                ok
            }
        },
    }
}

pub fn impl_frombytes_struct(
    is: ItemStruct,
    trt: &str,
    method_name: &str,
    input_type: Option<TokenStream2>,
    input: Option<TokenStream2>,
) -> TokenStream2 {
    let is_named = matches!(is.fields, Fields::Named(_));

    let info = StructInfo::from_item_struct(is, Some(trt), "from_bytes_bound", false);

    let trt = Ident::new(trt, Span::call_site());
    let method_name = Ident::new(method_name, Span::call_site());

    let (
        struct_name,
        generics,
        generics_without_bounds,
        field_names,
        field_types,
        field_attrs,
        padded,
    ) = info.into_tuple();

    if field_names.is_empty() {
        return quote! {
            impl#generics neli::#trt for #struct_name#generics_without_bounds {
                #input_type

                fn #method_name(buffer: &mut std::io::Cursor<impl AsRef<[u8]>> #input) -> Result<Self, neli::err::DeError> {
                    Ok(#struct_name)
                }
            }
        };
    }

    let struct_expr = if is_named {
        quote! {
            #struct_name {
                #( #field_names, )*
            }
        }
    } else {
        quote! {
            #struct_name(
                #( #field_names, )*
            )
        }
    };

    let from_bytes_exprs = field_types
        .into_iter()
        .zip(field_attrs)
        .map(|(field_type, field_attrs)| process_attrs(field_type, field_attrs));

    let padding = if padded {
        quote! {
            <#struct_name#generics_without_bounds as neli::FromBytes>::strip(buffer)?;
        }
    } else {
        TokenStream2::new()
    };

    quote! {
        impl#generics neli::#trt for #struct_name#generics_without_bounds {
            #input_type

            fn #method_name(buffer: &mut std::io::Cursor<impl AsRef<[u8]>> #input) -> Result<Self, neli::err::DeError> {
                let pos = buffer.position();

                let res = {
                    let mut from_bytes_impl = || {
                        log::trace!("Deserializing data type {}", stringify!(#struct_name));
                        #(
                            let #field_names = #from_bytes_exprs;
                        )*
                        #padding
                        Ok(#struct_expr)
                    };
                    from_bytes_impl()
                };

                match res {
                    Ok(res) => Ok(res),
                    Err(e) => {
                        buffer.set_position(pos);
                        Err(e)
                    },
                }
            }
        }
    }
}
