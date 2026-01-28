use neli::{
    consts::{
        nl::{NlmF, Nlmsg},
        rtnl::{Frattr, Frf, RtAddrFamily, Rtm},
        socket::NlFamily,
    },
    err::Nlmsgerr,
    nl::{NlPayload, NlmsghdrBuilder},
    rtnl::{FibmsgBuilder, RtattrBuilder},
    socket::synchronous::NlSocketHandle,
    types::RtBuffer,
    utils::Groups,
};

/// Must either have network permissions (setcap) or run as sudo
///
/// Will make the following rule:
/// [PRIORITY]:  not from all fwmark 0xca6c lookup 246813579
///
/// Check via: ip rule show
/// Delete the rule via: sudo ip rule del priority [PRIORITY]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let socket = NlSocketHandle::connect(NlFamily::Route, None, Groups::empty())?;
    socket.enable_ext_ack(true)?;
    socket.enable_strict_checking(true)?;

    let mut attrs = RtBuffer::new();
    attrs.push(
        RtattrBuilder::default()
            .rta_type(Frattr::Fwmark)
            .rta_payload(51820)
            .build()?,
    );

    attrs.push(
        RtattrBuilder::default()
            .rta_type(Frattr::Table)
            // avoid collisions with common table names
            .rta_payload(246813579)
            .build()?,
    );

    attrs.push(
        RtattrBuilder::default()
            .rta_type(Frattr::Priority)
            .rta_payload(32765)
            .build()?,
    );
    let attrs_clone = attrs.clone();

    let fibmsg = FibmsgBuilder::default()
        .fib_family(RtAddrFamily::Inet)
        .fib_dst_len(0)
        .fib_src_len(0)
        .fib_tos(0)
        .fib_flags(Frf::INVERT)
        .fib_table(neli::consts::rtnl::RtTable::Unspec)
        .fib_action(neli::consts::rtnl::FrAct::FrActToTbl)
        .rtattrs(attrs)
        .build()?;

    let nlmsg = NlmsghdrBuilder::default()
        .nl_type(Rtm::Newrule)
        .nl_flags(NlmF::REQUEST | NlmF::ACK | NlmF::CREATE)
        .nl_payload(NlPayload::Payload(fibmsg))
        .build()?;

    socket.send(&nlmsg)?;

    if let Ok(messages) = socket.recv::<Nlmsg, Nlmsgerr<Rtm>>() {
        for msg in messages.0 {
            match msg {
                Ok(val) => {
                    if *val.nl_type() == Nlmsg::Error {
                        if let NlPayload::Ack(err) = val.nl_payload() {
                            if *err.error() == 0 {
                                println!("Successfully created routing rule");
                            } else {
                                eprintln!(
                                    "Failed to create routing rule with error code: {}",
                                    err.error()
                                );
                            }
                        } else {
                            eprintln!("Received an error message with an unexpected payload.");
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Error: Have you set network permissions for the file?");
                    return Err(Box::new(e));
                }
            }
        }
    } else {
        eprintln!("Failed to receive acknowledgment for Newrule.");
    }

    // delete the table we just made
    println!("\nDeleting the routing rule...");

    let fibmsg = FibmsgBuilder::default()
        .fib_family(RtAddrFamily::Inet)
        .fib_dst_len(0)
        .fib_src_len(0)
        .fib_tos(0)
        .fib_flags(Frf::INVERT)
        .fib_table(neli::consts::rtnl::RtTable::Unspec)
        .fib_action(neli::consts::rtnl::FrAct::FrActToTbl)
        .rtattrs(attrs_clone)
        .build()?;

    let nlmsg = NlmsghdrBuilder::default()
        .nl_type(Rtm::Delrule)
        .nl_flags(NlmF::REQUEST | NlmF::ACK)
        .nl_payload(NlPayload::Payload(fibmsg))
        .build()?;

    // comment this out to see
    // the rule get created
    socket.send(&nlmsg)?;

    Ok(())
}
