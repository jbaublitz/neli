use neli::{
    consts::{
        nl::NlmF,
        rtnl::{Ifla, IflaInfo, IflaVlan, RtAddrFamily, Rtm},
        socket::NlFamily,
    },
    nl::NlPayload,
    router::synchronous::NlRouter,
    rtnl::{Ifinfomsg, IfinfomsgBuilder},
    utils::Groups,
};
use std::collections::HashMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let (rtnl, _) = NlRouter::connect(NlFamily::Route, None, Groups::empty())?;
    rtnl.enable_ext_ack(true)?;
    rtnl.enable_strict_checking(true)?;
    let ifinfomsg = IfinfomsgBuilder::default()
        .ifi_family(RtAddrFamily::Netlink)
        .build()?;

    let recv = rtnl.send::<_, _, Rtm, Ifinfomsg>(
        Rtm::Getlink,
        NlmF::DUMP | NlmF::ACK,
        NlPayload::Payload(ifinfomsg),
    )?;

    // vlan index => (if index)
    let mut vlans = HashMap::new();
    // if index => (if name, Option<if link>)
    let mut ifaces = HashMap::new();

    for response in recv {
        if let Some(payload) = response?.get_payload() {
            let attrs = payload.rtattrs().get_attr_handle();

            let index = *payload.ifi_index();
            let name = attrs.get_attr_payload_as_with_len::<String>(Ifla::Ifname)?;
            let link = attrs.get_attr_payload_as::<i32>(Ifla::Link).ok();

            ifaces.insert(index, (name, link));

            if let Some(vlan_id) = get_vlan_id(payload) {
                vlans.insert(vlan_id, index);
            }
        }
    }

    for (vlan_id, vlan_index) in &vlans {
        if let Some((name, link)) = ifaces.get(vlan_index)
            && let Some((link, _)) = link.as_ref().and_then(|link| ifaces.get(link))
        {
            println!("- vlan: {vlan_id}, name: {name}, link: {link}");
        }
    }

    Ok(())
}

fn get_vlan_id(payload: &Ifinfomsg) -> Option<u16> {
    let attrs = payload.rtattrs().get_attr_handle();
    let info = attrs
        .get_nested_attributes::<IflaInfo>(Ifla::Linkinfo)
        .ok()?;
    let kind: &str = info
        .get_attr_payload_as_with_len_borrowed(IflaInfo::Kind)
        .ok()?;
    if kind != "vlan\0" {
        return None;
    }
    let data = info
        .get_nested_attributes::<IflaVlan>(IflaInfo::Data)
        .ok()?;
    data.get_attr_payload_as(IflaVlan::Id).ok()
}
