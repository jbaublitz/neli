extern crate neli;

use std::error::Error;

use neli::Nl;
use neli::consts;
use neli::nl::Nlmsghdr;
use neli::genl::Genlmsghdr;
use neli::nlattr::Nlattr;

pub fn main() -> Result<(), Box<dyn Error>> {
    let attrs = vec![Nlattr::new(None, 1, vec![Nlattr::new(None, 1, "this_family")]),
                     Nlattr::new(None, 2, vec![Nlattr::new(None, 1, "that_family")])];
    let genlmsg = Genlmsghdr::new(consts::CtrlCmd::Getfamily, 2, attrs)?;
    let nlmsg = Nlmsghdr::new(None, consts::Nlmsg::Noop, vec![consts::NlmF::Request], None, None,
                              genlmsg);
    let mut buffer = neli::StreamWriteBuffer::new_growable(Some(nlmsg.asize()));
    nlmsg.serialize(&mut buffer)?;
    println!("{:?}", buffer.as_ref());
    Ok(())
}
