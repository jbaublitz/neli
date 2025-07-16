use neli::{
    consts::{
        nl::{NlmF, NlmsgerrAttr},
        rtnl::{Ifla, IflaInfo, IflaVlan, RtAddrFamily, Rtm},
        socket::NlFamily,
    },
    err::MsgError,
    nl::NlPayload,
    router::synchronous::NlRouter,
    rtnl::{Ifinfomsg, IfinfomsgBuilder, RtattrBuilder},
    types::{Buffer, RtBuffer},
    utils::Groups,
};
use std::{env, error::Error};

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let if_name = env::args()
        .nth(1)
        .ok_or_else(|| MsgError::new("Interface name required"))?;

    let vlan_id = env::args()
        .nth(2)
        .ok_or_else(|| MsgError::new("VLAN number required"))
        .and_then(|arg| arg.parse::<u32>().map_err(|e| MsgError::new(e.to_string())))?;

    let (rtnl, _) = NlRouter::connect(NlFamily::Route, None, Groups::empty())?;
    rtnl.enable_ext_ack(true)?;
    rtnl.enable_strict_checking(true)?;

    let mut recv = rtnl.send::<Rtm, Ifinfomsg, Rtm, Ifinfomsg>(
        Rtm::Getlink,
        NlmF::ROOT,
        NlPayload::<Rtm, Ifinfomsg>::Payload(
            IfinfomsgBuilder::default()
                .ifi_family(RtAddrFamily::Netlink)
                .build()?,
        ),
    )?;

    let if_index = recv
        .try_fold(None, |prev, response| -> Result<_, Box<dyn Error>> {
            if let Some(prev) = prev {
                return Ok(Some(prev));
            }

            let header = response?;

            if let NlPayload::Payload(if_info) = header.nl_payload() {
                if header.nl_type() != &Rtm::Newlink {
                    return Err(Box::new(MsgError::new("Netlink error retrieving info")).into());
                }
                if if_info
                    .rtattrs()
                    .get_attr_handle()
                    .get_attr_payload_as_with_len_borrowed::<&str>(Ifla::Ifname)
                    .map(|name| name.trim_end_matches('\0') == if_name)
                    .unwrap_or_default()
                {
                    return Ok(Some(*if_info.ifi_index()));
                }
            }

            Ok(None)
        })?
        .ok_or_else(|| Box::new(MsgError::new("Interface index not found")))?;

    let mut attrs = RtBuffer::<Ifla, Buffer>::new();

    let name = format!("{if_name}.{vlan_id}");
    attrs.push(
        RtattrBuilder::default()
            .rta_type(Ifla::Ifname)
            .rta_payload(name)
            .build()?,
    );

    attrs.push(
        RtattrBuilder::default()
            .rta_type(Ifla::Link)
            .rta_payload(if_index)
            .build()?,
    );

    let mut vlan_attrs = RtBuffer::<IflaVlan, Buffer>::new();
    vlan_attrs.push(
        RtattrBuilder::default()
            .rta_type(IflaVlan::Id)
            .rta_payload(vlan_id)
            .build()?,
    );

    let mut info_attrs = RtBuffer::<IflaInfo, Buffer>::new();
    info_attrs.push(
        RtattrBuilder::default()
            .rta_type(IflaInfo::Kind)
            .rta_payload("vlan\0")
            .build()?,
    );
    info_attrs.push(
        RtattrBuilder::default()
            .rta_type(IflaInfo::Data)
            .rta_payload(vlan_attrs)
            .build()?,
    );

    attrs.push(
        RtattrBuilder::default()
            .rta_type(Ifla::Linkinfo)
            .rta_payload(info_attrs)
            .build()?,
    );

    let ifinfomsg = IfinfomsgBuilder::default()
        .ifi_family(RtAddrFamily::Netlink)
        .rtattrs(attrs)
        .build()?;

    let recv = rtnl.send::<_, _, Rtm, Ifinfomsg>(
        Rtm::Newlink,
        NlmF::CREATE | NlmF::EXCL | NlmF::ACK,
        NlPayload::Payload(ifinfomsg),
    )?;

    for response in recv {
        if let NlPayload::DumpExtAck(ack) = response?.nl_payload() {
            println!("{ack:?}");
            println!(
                "MSG: {}",
                ack.ext_ack()
                    .get_attr_handle()
                    .get_attr_payload_as_with_len::<String>(NlmsgerrAttr::Msg)?
            );
        }
    }

    Ok(())
}
