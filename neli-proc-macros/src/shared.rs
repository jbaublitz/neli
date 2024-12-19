use std::{any::type_name, collections::HashMap};

use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::{quote, ToTokens};
use syn::{
    parse,
    parse::Parse,
    parse_str,
    punctuated::Punctuated,
    token::{Add, Colon2},
    Attribute, Expr, Fields, FieldsNamed, FieldsUnnamed, GenericParam, Generics, Ident, Index,
    ItemStruct, LifetimeDef, Lit, Meta, MetaNameValue, NestedMeta, Path, PathArguments,
    PathSegment, Token, TraitBound, TraitBoundModifier, Type, TypeParam, TypeParamBound, Variant,
};

/// Represents a field as either an identifier or an index.
pub enum FieldRepr {
    Index(Index),
    Ident(Ident),
}

impl ToTokens for FieldRepr {
    fn to_tokens(&self, tokens: &mut TokenStream2) {
        match self {
            FieldRepr::Index(i) => i.to_tokens(tokens),
            FieldRepr::Ident(i) => i.to_tokens(tokens),
        }
    }
}

/// Represents the field name, type, and all attributes associated
/// with this field.
pub struct FieldInfo {
    field_name: FieldRepr,
    field_type: Type,
    field_attrs: Vec<Attribute>,
}

impl FieldInfo {
    /// Convert field info to a tuple.
    fn into_tuple(self) -> (FieldRepr, Type, Vec<Attribute>) {
        (self.field_name, self.field_type, self.field_attrs)
    }

    /// Convert a vector of [`FieldInfo`]s to a tuple of vectors
    /// each containing name, type, or attributes.
    pub fn to_vecs<I>(v: I) -> (Vec<FieldRepr>, Vec<Type>, Vec<Vec<Attribute>>)
    where
        I: Iterator<Item = Self>,
    {
        v.into_iter().fold(
            (Vec::new(), Vec::new(), Vec::new()),
            |(mut names, mut types, mut attrs), info| {
                let (name, ty, attr) = info.into_tuple();
                names.push(name);
                types.push(ty);
                attrs.push(attr);
                (names, types, attrs)
            },
        )
    }
}

/// Necessary information for a given struct to generate trait
/// implementations.
pub struct StructInfo {
    struct_name: Ident,
    generics: Generics,
    generics_without_bounds: Generics,
    field_info: Vec<FieldInfo>,
    padded: bool,
}

type StructInfoTuple = (
    Ident,
    Generics,
    Generics,
    Vec<FieldRepr>,
    Vec<Type>,
    Vec<Vec<Attribute>>,
    bool,
);

impl StructInfo {
    /// Extract the necessary information from an
    /// [`ItemStruct`][syn::ItemStruct] data structure.
    pub fn from_item_struct(
        i: ItemStruct,
        trait_name: Option<&str>,
        trait_bound_path: &str,
        uses_self: bool,
    ) -> Self {
        let (mut generics, generics_without_bounds) = process_impl_generics(i.generics, trait_name);
        let trait_bounds = process_trait_bounds(&i.attrs, trait_bound_path);
        override_trait_bounds_on_generics(&mut generics, &trait_bounds);
        let field_info = match i.fields {
            Fields::Named(fields_named) => generate_named_fields(fields_named),
            Fields::Unnamed(fields_unnamed) => generate_unnamed_fields(fields_unnamed, uses_self),
            Fields::Unit => Vec::new(),
        };
        let padded = process_padding(&i.attrs);

        StructInfo {
            struct_name: i.ident,
            generics,
            generics_without_bounds,
            field_info,
            padded,
        }
    }

    /// Remove the last field from the record.
    pub fn pop_field(&mut self) {
        let _ = self.field_info.pop();
    }

    /// Convert all necessary struct information into a tuple of
    /// values.
    pub fn into_tuple(mut self) -> StructInfoTuple {
        let (field_names, field_types, field_attrs) = self.field_info();
        (
            self.struct_name,
            self.generics,
            self.generics_without_bounds,
            field_names,
            field_types,
            field_attrs,
            self.padded,
        )
    }

    /// Convert all field information into a tuple.
    fn field_info(&mut self) -> (Vec<FieldRepr>, Vec<Type>, Vec<Vec<Attribute>>) {
        FieldInfo::to_vecs(self.field_info.drain(..))
    }
}

/// Convert a list of identifiers into a path where the path segments
/// are added in the order that they appear in the list.
fn path_from_idents(idents: &[&str]) -> Path {
    Path {
        leading_colon: None,
        segments: idents
            .iter()
            .map(|ident| PathSegment {
                ident: Ident::new(ident, Span::call_site()),
                arguments: PathArguments::None,
            })
            .collect::<Punctuated<PathSegment, Colon2>>(),
    }
}

/// Process all type parameters in the type parameter definition for
/// an `impl` block. Optionally add a trait bound for all type parameters
/// if `required_trait` is `Some(_)`.
///
/// The first return value in the tuple is the list of type parameters
/// with trait bounds added. The second argument is a list of type
/// parameters without trait bounds to be passed into the type parameter
/// list for a struct.
///
/// # Example:
/// ## impl block
///
/// ```no_compile
/// trait MyTrait {}
///
/// impl<T, P> MyStruct<T, P> {
///     fn nothing() {}
/// }
/// ```
///
/// ## Method call
/// `neli_proc_macros::process_impl_generics(generics, Some("MyTrait"))`
///
/// ## Result
/// ```no_compile
/// (<T: MyTrait, P: MyTrait>, <T, P>)
/// ```
///
/// or rather:
///
/// ```no_compile
/// impl<T: MyTrait, P: MyTrait> MyStruct<T, P> {
///     fn nothing() {}
/// }
/// ```
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
                    path: path_from_idents(&["neli", rt]),
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

/// Remove attributes that should not be carried over to an `impl`
/// definition and only belong in the data structure like documentation
/// attributes.
pub fn remove_bad_attrs(attrs: Vec<Attribute>) -> Vec<Attribute> {
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

/// Generate a pattern and associated expression for each variant
/// in an enum.
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

/// Convert an enum variant into an arm of a match statement.
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

/// Generate all arms of a match statement.
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

/// Generate a list of named fields in accordance with the struct.
pub fn generate_named_fields(fields: FieldsNamed) -> Vec<FieldInfo> {
    fields
        .named
        .into_iter()
        .fold(Vec::new(), |mut info, field| {
            info.push(FieldInfo {
                field_name: FieldRepr::Ident(field.ident.expect("Must be named")),
                field_type: field.ty,
                field_attrs: field.attrs,
            });
            info
        })
}

/// Generate unnamed fields as either indicies to be accessed using
/// `self` or placeholder variable names for match-style patterns.
pub fn generate_unnamed_fields(fields: FieldsUnnamed, uses_self: bool) -> Vec<FieldInfo> {
    fields
        .unnamed
        .into_iter()
        .enumerate()
        .fold(Vec::new(), |mut fields, (index, field)| {
            fields.push(FieldInfo {
                field_name: if uses_self {
                    FieldRepr::Index(Index {
                        index: index as u32,
                        span: Span::call_site(),
                    })
                } else {
                    FieldRepr::Ident(Ident::new(
                        &String::from((b'a' + index as u8) as char),
                        Span::call_site(),
                    ))
                },
                field_type: field.ty,
                field_attrs: field.attrs,
            });
            fields
        })
}

/// Returns [`true`] if the given attribute is present in the list.
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

/// Process attributes to find all attributes with the name `attr_name`.
/// Return a [`Vec`] of [`Option`] types with the associated literal parsed
/// into type parameter `T`. `T` must allow parsing from a string to be
/// used with this method.
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

pub fn process_trait_bounds(attrs: &[Attribute], trait_bound_path: &str) -> Vec<TypeParam> {
    process_attr(attrs, trait_bound_path)
        .into_iter()
        .flatten()
        .collect()
}

/// Handles the attribute `#[neli(padding)]`.
pub fn process_padding(attrs: &[Attribute]) -> bool {
    attr_present(attrs, "padding")
}

/// Handles the attribute `#[neli(input)]` or `#[neli(input = "...")]`
/// when deriving [`FromBytes`][neli::FromBytes] implementations.
///
/// Returns:
/// * [`None`] if the attribute is not present
/// * [`Some(None)`] if the attribute is present and has no
///   associated expression
/// * [`Some(Some(_))`] if the attribute is present and
///   has an associated expression
pub fn process_input(attrs: &[Attribute]) -> Option<Option<Expr>> {
    let mut exprs = process_attr(attrs, "input");
    if exprs.len() > 1 {
        panic!("Only one input expression allowed for attribute #[neli(input = \"...\")]");
    } else {
        exprs.pop()
    }
}

/// Handles the attribute `#[neli(size = "...")]`
/// when deriving [`FromBytes`][neli::FromBytes] implementations.
///
/// Returns:
/// * [`None`] if the attribute is not present
///   associated expression
/// * [`Some(_)`] if the attribute is present and has an associated expression
pub fn process_size(attrs: &[Attribute]) -> Option<Expr> {
    let mut exprs = process_attr(attrs, "size");
    if exprs.len() > 1 {
        panic!("Only one input expression allowed for attribute #[neli(size = \"...\")]");
    } else {
        exprs
            .pop()
            .map(|opt| opt.expect("#[neli(size = \"...\")] must have associated expression"))
    }
}

/// If the first type parameter of a list of type parameters is a lifetime,
/// extract it for use in other parts of the procedural macro code.
///
/// # Example
/// `impl<'a, I, P>` would return `'a`.
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

/// Allow overriding the trait bounds specified by the method
/// [`process_impl_generics`][process_impl_generics].
///
/// # Example
/// ```no_compile
/// use std::marker::PhantomData;
///
/// struct MyStruct<I, A>(PhantomData<I>, PhantomData<A>);
///
/// trait MyTrait {}
/// trait AnotherTrait {}
///
/// // Input
///
/// impl<I: MyTrait, A: MyTrait> MyStruct<I, A> {
///     fn nothing() {}
/// }
///
/// // Result
///
/// impl<I: AnotherTrait, A: MyTrait> MyStruct<I, A> {
///     fn nothing() {}
/// }
/// ```
fn override_trait_bounds_on_generics(generics: &mut Generics, trait_bound_overrides: &[TypeParam]) {
    let mut overrides = trait_bound_overrides.iter().cloned().fold(
        HashMap::<Ident, Punctuated<TypeParamBound, Add>>::new(),
        |mut map, param| {
            if let Some(bounds) = map.get_mut(&param.ident) {
                bounds.extend(param.bounds);
            } else {
                map.insert(param.ident, param.bounds);
            }
            map
        },
    );

    for generic in generics.params.iter_mut() {
        if let GenericParam::Type(ref mut ty) = generic {
            let ident = &ty.ident;
            if let Some(ors) = overrides.remove(ident) {
                ty.colon_token = Some(Token![:](Span::call_site()));
                ty.bounds = ors;
                ty.eq_token = None;
                ty.default = None;
            }
        }
    }
}
