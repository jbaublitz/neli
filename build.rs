use std::env::var;

use bindgen::Builder;

fn main() {
    let bindings = Builder::default()
        .header("/usr/include/linux/nl80211.h")
        .generate()
        .unwrap();

    bindings
        .write_to_file(format!("{}/bindings.rs", var("OUT_DIR").unwrap()))
        .unwrap();
}
