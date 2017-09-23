extern crate cc;

pub fn main() {
    cc::Build::new()
        .file("src/c/netlink.c")
        .compile("libnetlink.so");
}
