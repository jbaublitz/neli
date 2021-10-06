use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::quote;
use syn::{
    parse_str, AngleBracketedGenericArguments, Attribute, Fields, GenericArgument, GenericParam,
    Generics, Ident, ItemStruct, LifetimeDef, PathArguments, Token, TraitBound, Type,
    TypeParamBound, WherePredicate,
};

use crate::shared::{
    generate_named_fields, generate_trait_bounds, generate_unnamed_fields, process_input,
    process_lifetime,
};

fn add_lifetime(trt: &mut TraitBound, lt: &LifetimeDef) {
    trt.path.segments.iter_mut().for_each(|elem| {
        if elem.ident == parse_str::<Ident>("FromBytes").unwrap()
            || elem.ident == parse_str::<Ident>("FromBytesWithInput").unwrap()
        {
            if let PathArguments::AngleBracketed(ref mut args) = elem.arguments {
                args.args = std::iter::once(GenericArgument::Lifetime(lt.lifetime.clone()))
                    .chain(args.args.clone())
                    .collect();
            } else if let PathArguments::None = elem.arguments {
                elem.arguments = PathArguments::AngleBracketed(AngleBracketedGenericArguments {
                    colon2_token: Some(Token![::](Span::call_site())),
                    lt_token: Token![<](Span::call_site()),
                    args: std::iter::once(GenericArgument::Lifetime(lt.lifetime.clone())).collect(),
                    gt_token: Token![>](Span::call_site()),
                });
            }
        }
    });
}

fn process_input_attr(
    lt: &LifetimeDef,
    field_type: Type,
    field_attrs: Vec<Attribute>,
) -> TokenStream2 {
    match process_input(&field_attrs) {
        Some(Some(input)) => quote! {
            {
                let input = #input;
                log::trace!("Deserializing field type {}", std::any::type_name::<#field_type>());
                log::trace!("Input: {:?}", input);
                let ok = <#field_type as neli::FromBytesWithInput<#lt>>::from_bytes_with_input(buffer, input)?;
                log::trace!("Field deserialized: {:?}", ok);
                ok
            }
        },
        Some(None) => quote! {
            {
                log::trace!("Deserializing field type {}", std::any::type_name::<#field_type>());
                log::trace!("Input: {:?}", input);
                let ok = <#field_type as neli::FromBytesWithInput<#lt>>::from_bytes_with_input(buffer, input)?;
                log::trace!("Field deserialized: {:?}", ok);
                ok
            }
        },
        None => quote! {
            {
                log::trace!("Deserializing field type {}", std::any::type_name::<#field_type>());
                let ok = <#field_type as neli::FromBytes<#lt>>::from_bytes(buffer)?;
                log::trace!("Field deserialized: {:?}", ok);
                ok
            }
        },
    }
}

#[allow(clippy::too_many_arguments)]
fn generate_from_bytes_shared(
    struct_name: Ident,
    mut generics: Generics,
    generics_without_bounds: Generics,
    mut trait_bounds: Vec<WherePredicate>,
    field_names: Vec<Ident>,
    field_types: Vec<Type>,
    field_attrs: Vec<Vec<Attribute>>,
    struct_expr: TokenStream2,
    padded: bool,
) -> TokenStream2 {
    let lt = process_lifetime(&mut generics);
    for generic in generics.params.iter_mut() {
        if let GenericParam::Type(ref mut ty) = generic {
            for bound in ty.bounds.iter_mut() {
                if let TypeParamBound::Trait(ref mut trt) = bound {
                    add_lifetime(trt, &lt);
                }
            }
        }
    }
    for where_predicate in trait_bounds.iter_mut() {
        if let WherePredicate::Type(ty) = where_predicate {
            for bound in ty.bounds.iter_mut() {
                if let TypeParamBound::Trait(ref mut trt) = bound {
                    add_lifetime(trt, &lt);
                }
            }
        }
    }

    let from_bytes_exprs = field_types
        .into_iter()
        .zip(field_attrs.into_iter())
        .map(|(field_type, field_attrs)| process_input_attr(&lt, field_type, field_attrs));

    let trait_bounds = generate_trait_bounds(trait_bounds);
    let padding = if padded {
        quote! {
            <#struct_name#generics_without_bounds as neli::FromBytes<#lt>>::strip(buffer)?;
        }
    } else {
        TokenStream2::new()
    };
    quote! {
        impl#generics neli::FromBytes<#lt> for #struct_name#generics_without_bounds #trait_bounds {
            fn from_bytes(buffer: &mut std::io::Cursor<&#lt [u8]>) -> Result<Self, neli::err::DeError> {
                log::trace!("Deserializing data type {}", std::any::type_name::<#struct_name#generics_without_bounds>());
                let pos = buffer.position();

                let res = {
                    let mut from_bytes_impl = || {
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

#[allow(clippy::too_many_arguments)]
fn generate_from_bytes_named(
    struct_name: Ident,
    generics: Generics,
    generics_without_bounds: Generics,
    trait_bounds: Vec<WherePredicate>,
    field_names: Vec<Ident>,
    field_types: Vec<Type>,
    field_attrs: Vec<Vec<Attribute>>,
    padded: bool,
) -> TokenStream2 {
    let struct_expr = quote! {
        #struct_name {
            #( #field_names, )*
        }
    };
    generate_from_bytes_shared(
        struct_name,
        generics,
        generics_without_bounds,
        trait_bounds,
        field_names,
        field_types,
        field_attrs,
        struct_expr,
        padded,
    )
}

#[allow(clippy::too_many_arguments)]
fn generate_from_bytes_unnamed(
    struct_name: Ident,
    generics: Generics,
    generics_without_bounds: Generics,
    trait_bounds: Vec<WherePredicate>,
    field_names: Vec<Ident>,
    field_types: Vec<Type>,
    field_attrs: Vec<Vec<Attribute>>,
    padded: bool,
) -> TokenStream2 {
    let struct_expr = quote! {
        #struct_name(
            #( #field_names, )*
        )
    };
    generate_from_bytes_shared(
        struct_name,
        generics,
        generics_without_bounds,
        trait_bounds,
        field_names,
        field_types,
        field_attrs,
        struct_expr,
        padded,
    )
}

pub fn impl_frombytes_struct(is: ItemStruct) -> TokenStream2 {
    match is.fields {
        Fields::Named(fields) => {
            process_fields!(
                generate_named_fields,
                fields,
                Some("FromBytes"),
                "from_bytes_bound",
                is,
                generate_from_bytes_named
            )
        }
        Fields::Unnamed(fields) => {
            process_fields!(
                generate_unnamed_fields,
                fields,
                Some("FromBytes"),
                "from_bytes_bound",
                is,
                generate_from_bytes_unnamed
            )
        }
        Fields::Unit => {
            let struct_name = is.ident;
            quote! {
                impl<'lt> neli::FromBytes<'lt> for #struct_name {
                    fn from_bytes(_: &mut std::io::Cursor<&'lt [u8]>) -> Result<Self, neli::err::DeError> {
                        Ok(#struct_name)
                    }
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn generate_from_bytes_with_input_shared(
    struct_name: Ident,
    mut generics: Generics,
    generics_without_bounds: Generics,
    mut trait_bounds: Vec<WherePredicate>,
    field_names: Vec<Ident>,
    field_types: Vec<Type>,
    field_attrs: Vec<Vec<Attribute>>,
    struct_expr: TokenStream2,
    padded: bool,
) -> TokenStream2 {
    let lt = process_lifetime(&mut generics);
    for generic in generics.params.iter_mut() {
        if let GenericParam::Type(ref mut ty) = generic {
            for bound in ty.bounds.iter_mut() {
                if let TypeParamBound::Trait(ref mut trt) = bound {
                    add_lifetime(trt, &lt);
                }
            }
        }
    }
    for where_predicate in trait_bounds.iter_mut() {
        if let WherePredicate::Type(ty) = where_predicate {
            for bound in ty.bounds.iter_mut() {
                if let TypeParamBound::Trait(ref mut trt) = bound {
                    add_lifetime(trt, &lt);
                }
            }
        }
    }

    let from_bytes_exprs = field_types
        .into_iter()
        .zip(field_attrs.into_iter())
        .map(|(field_type, field_attrs)| process_input_attr(&lt, field_type, field_attrs));

    let trait_bounds = generate_trait_bounds(trait_bounds);
    let padding = if padded {
        quote! {
            <#struct_name#generics_without_bounds as $crate::FromBytes<#lt>>::strip(buffer)?;
        }
    } else {
        TokenStream2::new()
    };
    quote! {
        impl#generics neli::FromBytesWithInput<#lt> for #struct_name#generics_without_bounds #trait_bounds {
            type Input = usize;

            fn from_bytes_with_input(buffer: &mut std::io::Cursor<&#lt [u8]>, input: Self::Input) -> Result<Self, neli::err::DeError> {
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

#[allow(clippy::too_many_arguments)]
fn generate_from_bytes_with_input_named(
    struct_name: Ident,
    generics: Generics,
    generics_without_bounds: Generics,
    trait_bounds: Vec<WherePredicate>,
    field_names: Vec<Ident>,
    field_types: Vec<Type>,
    field_attrs: Vec<Vec<Attribute>>,
    padded: bool,
) -> TokenStream2 {
    let struct_expr = quote! {
        #struct_name {
            #( #field_names, )*
        }
    };
    generate_from_bytes_with_input_shared(
        struct_name,
        generics,
        generics_without_bounds,
        trait_bounds,
        field_names,
        field_types,
        field_attrs,
        struct_expr,
        padded,
    )
}

#[allow(clippy::too_many_arguments)]
fn generate_from_bytes_with_input_unnamed(
    struct_name: Ident,
    generics: Generics,
    generics_without_bounds: Generics,
    trait_bounds: Vec<WherePredicate>,
    field_names: Vec<Ident>,
    field_types: Vec<Type>,
    field_attrs: Vec<Vec<Attribute>>,
    padded: bool,
) -> TokenStream2 {
    let struct_expr = quote! {
        #struct_name(
            #( #field_names, )*
        )
    };
    generate_from_bytes_with_input_shared(
        struct_name,
        generics,
        generics_without_bounds,
        trait_bounds,
        field_names,
        field_types,
        field_attrs,
        struct_expr,
        padded,
    )
}

pub fn impl_frombyteswithinput_struct(is: ItemStruct) -> TokenStream2 {
    match is.fields {
        Fields::Named(fields) => {
            process_fields!(
                generate_named_fields,
                fields,
                Some("FromBytes"),
                "from_bytes_bound",
                is,
                generate_from_bytes_with_input_named
            )
        }
        Fields::Unnamed(fields) => {
            process_fields!(
                generate_unnamed_fields,
                fields,
                Some("FromBytes"),
                "from_bytes_bound",
                is,
                generate_from_bytes_with_input_unnamed
            )
        }
        Fields::Unit => {
            let struct_name = is.ident;
            quote! {
                impl<'lt> neli::FromBytesWithInput<'lt> for #struct_name {
                    type Input = usize;

                    fn from_bytes_with_input(_: &mut std::io::Cursor<&'lt [u8]>, _: Self::Input) -> Result<Self, neli::err::DeError> {
                        Ok(#struct_name)
                    }
                }
            }
        }
    }
}
