//! Userland component written in Rust, that uses neli to talk to a custom Netlink
//! family via Generic Netlink. The family is called "gnl_foobar_xmpl" and the
//! kernel module must be loaded first. Otherwise the family doesn't exist.
//!
//! A working kernel module implementation, with that you can use this binary,
//! can be found here: https://github.com/phip1611/generic-netlink-user-kernel-rust
//!
//! Output might look like this (if the kernel module is loaded)
//! ```
//! Generic family number is 35
//! Send to kernel: 'Some data that has `Nl` trait implemented, like &str'
//! Received from kernel: 'Some data that has `Nl` trait implemented, like &str'
//! ```

use neli::{
    consts::{
        nl::{NlmF, NlmFFlags},
        socket::NlFamily,
    },
    genl::{Genlmsghdr, Nlattr},
    nl::{NlPayload, Nlmsghdr},
    socket::NlSocketHandle,
    types::{Buffer, GenlBuffer},
    utils::U32Bitmask,
};
use std::{process, process::exit};

/// Name of the Netlink family registered via Generic Netlink
const FAMILY_NAME: &str = "gnl_foobar_xmpl";

/// Data we want to send to kernel.
const ECHO_MSG: &str = "Some data that has `Nl` trait implemented, like &str";

// Implements the necessary trait for the "neli" lib on an enum called "NlFoobarXmplOperation".
// NlFoobarXmplOperation corresponds to "enum NlFoobarXmplCommand" in kernel module C code.
// Describes what callback function shall be invoked in the linux kernel module.
// This is for the "cmd" field in Generic Netlink header.
neli::impl_var!(
    NlFoobarXmplOperation,
    u8,
    Unspec => 0,
    Echo => 1
);
impl neli::consts::genl::Cmd for NlFoobarXmplOperation {}

// Implements the necessary trait for the "neli" lib on an enum called "NlFoobarXmplAttribute".
// NlFoobarXmplAttribute corresponds to "enum NlFoobarXmplAttribute" in kernel module C code.
// Describes the value type to data mappings inside the generic netlink packet payload.
// This is for the Netlink Attributes (the actual payload) we want to send.
neli::impl_var!(
    NlFoobarXmplAttribute,
    u16,
    Unspec => 0,
    Msg => 1
);
impl neli::consts::genl::NlAttrType for NlFoobarXmplAttribute {}

fn main() {
    let mut sock = NlSocketHandle::connect(
        NlFamily::Generic,
        // 0 is pid of kernel -> socket is connected to kernel
        Some(0),
        U32Bitmask::empty(),
    )
    .unwrap();

    let family_id;
    let res = sock.resolve_genl_family(FAMILY_NAME);
    match res {
        Ok(id) => family_id = id,
        Err(e) => {
            eprintln!(
                "The Netlink family '{}' can't be found. Is the kernel module loaded yet? neli-error='{}'",
                FAMILY_NAME, e
            );
            // exit without error in order for Continuous Integration and automatic testing not to fail
            // when the kernel module is not loaded
            exit(0);
        }
    }

    println!("Generic family number is {}", family_id);

    // We want to send an Echo command
    // 1) prepare NlFoobarXmpl Attribute
    let mut attrs: GenlBuffer<NlFoobarXmplAttribute, Buffer> = GenlBuffer::new();
    attrs.push(
        Nlattr::new(
            None,
            false,
            false,
            // the type of the attribute. This is an u16 and corresponds
            // to an enum on the receiving side
            NlFoobarXmplAttribute::Msg,
            ECHO_MSG,
        )
        .unwrap(),
    );
    // 2) prepare Generic Netlink Header. The Generic Netlink Header contains the
    //    attributes (actual data) as payload.
    let gnmsghdr = Genlmsghdr::new(
        NlFoobarXmplOperation::Echo,
        // You can evolve your application over time using different versions or ignore it
        // Application specific; receiver must take care of it
        1,
        // actual payload
        attrs,
    );
    // 3) Prepare Netlink header. The Netlink header contains the Generic Netlink header
    //    as payload.
    let nlmsghdr = Nlmsghdr::new(
        None,
        family_id,
        // This depends on the receiving side. Do you check there if any flags are present?
        // Request-flag is required (TODO by neli or by netlink?)
        // others are up to you
        NlmFFlags::new(&[NlmF::Request]),
        None,
        // Port ID. Not necessarily the process id of the current process. This field
        // could be used to identify different points or threads inside your application
        // that send data to the kernel. This has nothing to do with "routing" the packet to
        // the kernel, because this is done by the socket itself
        Some(process::id()),
        NlPayload::Payload(gnmsghdr),
    );

    println!("Send to kernel: '{}'", ECHO_MSG);

    // Send data
    sock.send(nlmsghdr).expect("Send must work");

    // receive echo'ed message
    let res: Nlmsghdr<u16, Genlmsghdr<NlFoobarXmplOperation, NlFoobarXmplAttribute>> =
        sock.recv().expect("Should receive a message").unwrap();

    /* USELESS, just note: this is always the case. Otherwise neli would have returned Error
    if res.nl_type == family_id {
        println!("Received successful reply!");
    }*/

    let attr_handle = res.get_payload().unwrap().get_attr_handle();
    let received = attr_handle
        .get_attr_payload_as::<String>(NlFoobarXmplAttribute::Msg)
        .unwrap();
    println!("Received from kernel: '{}'", received);
}
