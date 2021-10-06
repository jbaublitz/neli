use std::any::type_name;

use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::{quote, ToTokens};
use syn::{
    parse, parse::Parse, parse_str, punctuated::Punctuated, token::Colon2, Attribute, Expr, Fields,
    FieldsNamed, FieldsUnnamed, GenericParam, Generics, Ident, Index, LifetimeDef, Lit, Meta,
    MetaNameValue, NestedMeta, Path, PathArguments, PathSegment, Token, TraitBound,
    TraitBoundModifier, Type, TypeParamBound, Variant, WherePredicate,
};

fn path_from_idents(idents: Vec<Ident>) -> Path {
    Path {
        leading_colon: None,
        segments: idents
            .into_iter()
            .map(|ident| PathSegment {
                ident,
                arguments: PathArguments::None,
            })
            .collect::<Punctuated<PathSegment, Colon2>>(),
    }
}

pub fn process_impl_generics(
    mut generics: Generics,
    required_trait: Option<&str>,
) -> (Generics, Generics) {
    if let Some(rt) = required_trait {
        for gen in generics.params.iter_mut() {
            if let GenericParam::Type(param) = gen {
                param.colon_token = Some(Token![:](Span::call_site()));
                param.bounds.push(TypeParamBound::Trait(TraitBound {
                    paren_token: None,
                    modifier: TraitBoundModifier::None,
                    lifetimes: None,
                    path: path_from_idents(vec![
                        Ident::new("neli", Span::call_site()),
                        Ident::new(rt, Span::call_site()),
                    ]),
                }));
                param.eq_token = None;
                param.default = None;
            }
        }
    }

    let mut generics_without_bounds: Generics = generics.clone();
    for gen in generics_without_bounds.params.iter_mut() {
        if let GenericParam::Type(param) = gen {
            param.colon_token = None;
            param.bounds.clear();
            param.eq_token = None;
            param.default = None;
        }
    }

    (generics, generics_without_bounds)
}

fn remove_bad_attrs(attrs: Vec<Attribute>) -> Vec<Attribute> {
    attrs
        .into_iter()
        .filter(|attr| {
            if let Ok(meta) = attr.parse_meta() {
                match meta {
                    Meta::NameValue(MetaNameValue { path, .. }) => {
                        !(path == parse_str::<Path>("doc").expect("doc should be valid path"))
                    }
                    _ => true,
                }
            } else {
                panic!("Could not parse provided attribute {}", attr.tokens,)
            }
        })
        .collect()
}

fn generate_pat_and_expr<N, U>(
    enum_name: Ident,
    var_name: Ident,
    fields: Fields,
    generate_named_pat_and_expr: &N,
    generate_unnamed_pat_and_expr: &U,
    unit: &TokenStream2,
) -> TokenStream2
where
    N: Fn(Ident, Ident, FieldsNamed) -> TokenStream2,
    U: Fn(Ident, Ident, FieldsUnnamed) -> TokenStream2,
{
    match fields {
        Fields::Named(fields) => generate_named_pat_and_expr(enum_name, var_name, fields),
        Fields::Unnamed(fields) => generate_unnamed_pat_and_expr(enum_name, var_name, fields),
        Fields::Unit => quote! {
            #enum_name::#var_name => #unit,
        },
    }
}

fn generate_arm<N, U>(
    attrs: Vec<Attribute>,
    enum_name: Ident,
    var_name: Ident,
    fields: Fields,
    generate_named_pat_and_expr: &N,
    generate_unnamed_pat_and_expr: &U,
    unit: &TokenStream2,
) -> TokenStream2
where
    N: Fn(Ident, Ident, FieldsNamed) -> TokenStream2,
    U: Fn(Ident, Ident, FieldsUnnamed) -> TokenStream2,
{
    let attrs = remove_bad_attrs(attrs)
        .into_iter()
        .map(|attr| {
            attr.parse_meta()
                .unwrap_or_else(|_| panic!("Failed to parse attribute {}", attr.tokens))
        })
        .collect::<Vec<_>>();
    let arm = generate_pat_and_expr(
        enum_name,
        var_name,
        fields,
        generate_named_pat_and_expr,
        generate_unnamed_pat_and_expr,
        unit,
    );
    quote! {
        #(
            #attrs
        )*
        #arm
    }
}

pub fn generate_arms<N, U>(
    enum_name: Ident,
    variants: Vec<Variant>,
    generate_named_pat_and_expr: N,
    generate_unnamed_pat_and_expr: U,
    unit: TokenStream2,
) -> Vec<TokenStream2>
where
    N: Fn(Ident, Ident, FieldsNamed) -> TokenStream2,
    U: Fn(Ident, Ident, FieldsUnnamed) -> TokenStream2,
{
    variants
        .into_iter()
        .map(|var| {
            let variant_name = var.ident;
            generate_arm(
                var.attrs,
                enum_name.clone(),
                variant_name,
                var.fields,
                &generate_named_pat_and_expr,
                &generate_unnamed_pat_and_expr,
                &unit,
            )
        })
        .collect()
}

pub fn generate_named_fields(fields: FieldsNamed) -> (Vec<Ident>, Vec<Type>, Vec<Vec<Attribute>>) {
    fields.named.into_iter().fold(
        (Vec::new(), Vec::new(), Vec::new()),
        |(mut names, mut types, mut attrs), field| {
            names.push(field.ident.expect("Must be named"));
            types.push(field.ty);
            attrs.push(field.attrs);
            (names, types, attrs)
        },
    )
}

pub fn generate_unnamed_fields(
    fields: FieldsUnnamed,
) -> (Vec<Ident>, Vec<Type>, Vec<Vec<Attribute>>) {
    fields.unnamed.into_iter().enumerate().fold(
        (Vec::new(), Vec::new(), Vec::new()),
        |(mut names, mut types, mut attrs), (index, field)| {
            names.push(Ident::new(
                &String::from((b'a' + index as u8) as char),
                Span::call_site(),
            ));
            types.push(field.ty);
            attrs.push(field.attrs);
            (names, types, attrs)
        },
    )
}

pub fn generate_unnamed_field_indices(
    fields: FieldsUnnamed,
) -> (Vec<Index>, Vec<Type>, Vec<Vec<Attribute>>) {
    fields.unnamed.into_iter().enumerate().fold(
        (Vec::new(), Vec::new(), Vec::new()),
        |(mut names, mut types, mut attrs), (index, field)| {
            names.push(Index {
                index: index as u32,
                span: Span::call_site(),
            });
            types.push(field.ty);
            attrs.push(field.attrs);
            (names, types, attrs)
        },
    )
}

fn attr_present(attrs: &[Attribute], attr_name: &str) -> bool {
    for attr in attrs {
        let meta = attr
            .parse_meta()
            .unwrap_or_else(|_| panic!("Failed to parse attribute {}", attr.tokens));
        if let Meta::List(list) = meta {
            if list.path == parse_str::<Path>("neli").expect("neli is valid path") {
                for nested in list.nested {
                    if let NestedMeta::Meta(Meta::Path(path)) = nested {
                        if path
                            == parse_str::<Path>(attr_name)
                                .unwrap_or_else(|_| panic!("{} should be valid path", attr_name))
                        {
                            return true;
                        }
                    }
                }
            }
        }
    }
    false
}

fn process_attr<T>(attrs: &[Attribute], attr_name: &str) -> Vec<Option<T>>
where
    T: Parse,
{
    let mut output = Vec::new();
    for attr in attrs {
        let meta = attr
            .parse_meta()
            .unwrap_or_else(|_| panic!("Failed to parse attribute {}", attr.tokens));
        if let Meta::List(list) = meta {
            if list.path == parse_str::<Path>("neli").expect("neli is valid path") {
                for nested in list.nested {
                    if let NestedMeta::Meta(Meta::NameValue(MetaNameValue {
                        path,
                        lit: Lit::Str(lit),
                        ..
                    })) = nested
                    {
                        if path
                            == parse_str::<Path>(attr_name)
                                .unwrap_or_else(|_| panic!("{} should be valid path", attr_name))
                        {
                            output.push(Some(parse_str::<T>(&lit.value()).unwrap_or_else(|_| {
                                panic!(
                                    "{} should be valid tokens of type {}",
                                    &lit.value(),
                                    type_name::<T>()
                                )
                            })));
                        }
                    } else if let NestedMeta::Meta(Meta::Path(path)) = nested {
                        if path
                            == parse_str::<Path>(attr_name)
                                .unwrap_or_else(|_| panic!("{} should be valid path", attr_name))
                        {
                            output.push(None);
                        }
                    }
                }
            }
        }
    }
    output
}

pub fn process_trait_bounds(attrs: &[Attribute], trait_bound_path: &str) -> Vec<WherePredicate> {
    process_attr(attrs, trait_bound_path)
        .into_iter()
        .flatten()
        .collect()
}

pub fn process_padding(attrs: &[Attribute]) -> bool {
    attr_present(attrs, "padding")
}

/// Returns:
/// * [`None`] if the attribute is not present
/// * [`Some(None)`] if the attribute is present and has no
/// associated expression
/// * [`Some(Some(_))`] if the attribute is present and
/// has an associated expression
pub fn process_input(attrs: &[Attribute]) -> Option<Option<Expr>> {
    let mut exprs = process_attr(attrs, "input");
    if exprs.len() > 1 {
        panic!("Only one input expression allowed for attribute #[neli(input = \"...\")]");
    } else {
        exprs.pop()
    }
}

#[allow(clippy::too_many_arguments)]
pub fn process_fields<F, I>(
    attrs: &[Attribute],
    trait_name: Option<&str>,
    trait_bound_path: &str,
    struct_name: Ident,
    generics: Generics,
    field_names: Vec<I>,
    field_types: Vec<Type>,
    field_attrs: Vec<Vec<Attribute>>,
    token_generation: F,
) -> TokenStream2
where
    I: ToTokens,
    F: Fn(
        Ident,
        Generics,
        Generics,
        Vec<WherePredicate>,
        Vec<I>,
        Vec<Type>,
        Vec<Vec<Attribute>>,
        bool,
    ) -> TokenStream2,
{
    let (mut generics, generics_without_bounds) = process_impl_generics(generics, trait_name);
    let trait_bounds = process_trait_bounds(attrs, trait_bound_path);
    override_trait_bounds_on_generics(&mut generics, &trait_bounds);
    token_generation(
        struct_name,
        generics,
        generics_without_bounds,
        trait_bounds,
        field_names,
        field_types,
        field_attrs,
        process_padding(attrs),
    )
}

macro_rules! process_fields {
    ($generate_fields:expr, $fields:expr, $trait_name:expr, $trait_bound_name:tt, $is:expr, $fn:ident) => {{
        let (field_names, field_types, field_attrs) = $generate_fields($fields);
        $crate::shared::process_fields(
            &$is.attrs,
            $trait_name,
            $trait_bound_name,
            $is.ident,
            $is.generics,
            field_names,
            field_types,
            field_attrs,
            $fn,
        )
    }};
}

pub fn process_lifetime(generics: &mut Generics) -> LifetimeDef {
    if let Some(GenericParam::Lifetime(lt)) = generics.params.first() {
        lt.clone()
    } else {
        let mut punc = Punctuated::new();
        let lt = parse::<LifetimeDef>(TokenStream::from(quote! {
            'lifetime
        }))
        .expect("'lifetime should be valid lifetime");
        punc.push(GenericParam::Lifetime(lt.clone()));
        punc.push_punct(Token![,](Span::call_site()));
        punc.extend(generics.params.iter().cloned());
        generics.params = punc;
        lt
    }
}

pub fn generate_trait_bounds(where_predicates: Vec<WherePredicate>) -> TokenStream2 {
    if where_predicates.is_empty() {
        TokenStream2::new()
    } else {
        quote! {
            where #( #where_predicates ),*
        }
    }
}

fn override_trait_bounds_on_generics(
    generics: &mut Generics,
    trait_bound_overrides: &[WherePredicate],
) {
    let mut types = trait_bound_overrides.iter().filter_map(|bound| {
        if let WherePredicate::Type(ref ty) = bound {
            if let Type::Path(ref path) = ty.bounded_ty {
                Some(path.path.clone())
            } else {
                None
            }
        } else {
            None
        }
    });

    for generic in generics.params.iter_mut() {
        if let GenericParam::Type(ref mut ty) = generic {
            let ident = &ty.ident;
            let path = parse::<Path>(TokenStream::from(quote! {
                #ident
            }))
            .unwrap();
            if types.any(|ty| ty == path) {
                ty.colon_token = None;
                ty.bounds.clear();
                ty.eq_token = None;
                ty.default = None;
            }
        }
    }
}
