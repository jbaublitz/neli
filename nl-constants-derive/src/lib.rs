extern crate proc_macro;
extern crate syn;
#[macro_use]
extern crate quote;
#[macro_use]
extern crate nom;
extern crate regex;

use std::fs::File;
use std::io::Read;
use std::collections::HashMap;

use proc_macro::TokenStream;
use syn::{Ident,Lit,AttrStyle,MetaItem};

named!(parse_defines<&str, ConstMap>, fold_many1!(
    opt!(do_parse!(
        tag!("#define") >>
        name: re_match!(r"([A-Z0-9_]+)_") >>
        var: re_match!(r"[A-Z0-9]+") >>
        val: re_match!(r"([0-9]+)") >>
        (name, var, val.parse::<u64>().unwrap())
    )),
    HashMap::new(), |mut acc: ConstMap, opt: Option<(&str, &str, u64)>| {
        if let Some((name, var, val)) = opt {
            let contains = acc.contains_key(name);
            if !contains {
                let mut submap = HashMap::new();
                submap.insert(var.to_string(), val);
                acc.insert(name.to_string(), submap);
            } else {
                acc.get_mut(name).unwrap().insert(var.to_string(), val);
            }
        }
        acc
    }
));

struct Headers {
    netlink: String,
    genetlink: String,
}

impl Headers {
    fn override_defaults(&mut self, ast: &syn::DeriveInput) -> &mut Self {
        for attr in ast.attrs.iter() {
            match (&attr.style, &attr.value) {
                (&AttrStyle::Inner, &MetaItem::NameValue(ref idt, ref lit)) => {
                    if *idt == Ident::from("netlink") {
                        match *lit {
                            Lit::Str(ref string, _) => {
                                self.netlink = string.clone();
                            },
                            _ => { continue; },
                        };
                    }
                    if *idt == Ident::from("genetlink") {
                        match *lit {
                            Lit::Str(ref string, _) => {
                                self.genetlink = string.clone();
                            },
                            _ => { continue; },
                        };
                    }
                },
                _ => { continue; },
            };
        }
        self
    }

    fn parse_headers(&self) -> NlConsts {
        let mut nl_contents = String::new();
        File::open(&self.netlink).unwrap().read_to_string(&mut nl_contents).unwrap();
        let nl_consts = parse_defines(&nl_contents).to_result().unwrap();

        let mut genl_contents = String::new();
        File::open(&self.genetlink).unwrap().read_to_string(&mut genl_contents).unwrap();
        let genl_consts = parse_defines(&genl_contents).to_result().unwrap();

        NlConsts {
            netlink: nl_consts,
            genetlink: genl_consts,
        }
    }
}

impl Default for Headers {
    fn default() -> Self {
        Headers {
            netlink: "/usr/include/linux/netlink.h".to_string(),
            genetlink: "/usr/include/linux/genetlink.h".to_string(),
        }
    }
}

type ConstMap = HashMap<String, HashMap<String, u64>>;

struct NlConsts {
    pub netlink: ConstMap,
    pub genetlink: ConstMap,
}

#[proc_macro_derive(NlConstMod)]
pub fn nl_const_mod(ts: TokenStream) -> TokenStream {
    let string = ts.to_string();
    let ast = syn::parse_derive_input(&string).unwrap();

    let mut hdrs = Headers::default();

    let consts = hdrs.override_defaults(&ast).parse_headers();

    let tokens = quote! {
    };

    tokens.parse::<TokenStream>().unwrap()
}
