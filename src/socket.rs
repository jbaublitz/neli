//! # Socket code around `libc`
//! 
//! ## Notes
//! 
//! This module provides a low level one-to-one mapping between `libc` system call wrappers
//! with defaults specific to netlink sockets as well as a higher level API for simplification
//! of netlink code.

use std::io;
use std::os::unix::io::{AsRawFd,IntoRawFd,RawFd};
use std::marker::PhantomData;
use std::mem::{zeroed,size_of};
#[cfg(feature = "stream")]
use std::time::Duration;

use libc::{self,c_int,c_void};
#[cfg(feature = "evented")]
use mio::{self,Evented};
#[cfg(feature = "stream")]
use tokio::prelude::{Async,Stream};

use {Nl,MemRead,MemWrite};
#[cfg(feature = "stream")]
use MAX_NL_LENGTH;
use err::NlError;
use ffi::{NlFamily,GenlId,CtrlCmd,CtrlAttr,CtrlAttrMcastGrp,NlmF};
use genlhdr::GenlHdr;
use nlhdr::{NlHdr,NlAttrHdr};

/// Handle for the socket file descriptor
#[cfg(feature = "stream")]
pub struct NlSocket<I, P> {
    fd: c_int,
    poll: mio::Poll,
    data_type: PhantomData<I>,
    data_payload: PhantomData<P>,
}

/// Handle for the socket file descriptor
#[cfg(not(feature = "stream"))]
pub struct NlSocket<I, P> {
    fd: c_int,
    data_type: PhantomData<I>,
    data_payload: PhantomData<P>,
}

impl<I, P> NlSocket<I, P> where I: Nl, P: Nl {
    /// Wrapper around `socket()` syscall filling in the netlink-specific information
    #[cfg(feature = "stream")]
    pub fn new(proto: NlFamily) -> Result<Self, io::Error> {
        let fd = match unsafe {
            libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, proto.into())
        } {
            i if i >= 0 => Ok(i),
            _ => Err(io::Error::last_os_error()),
        }?;
        let poll = mio::Poll::new()?;
        let socket = NlSocket { fd, poll, data_type: PhantomData, data_payload: PhantomData };
        socket.register(&socket.poll, mio::Token(0), mio::Ready::readable(), mio::PollOpt::edge())?;
        Ok(socket)
    }

    /// Wrapper around `socket()` syscall filling in the netlink-specific information
    #[cfg(not(feature = "stream"))]
    pub fn new(proto: NlFamily) -> Result<Self, io::Error> {
        let fd = match unsafe {
            libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, proto.into())
        } {
            i if i >= 0 => Ok(i),
            _ => Err(io::Error::last_os_error()),
        }?;
        Ok(NlSocket { fd, data_type: PhantomData, data_payload: PhantomData })
    }

    /// Use this function to bind to a netlink ID and subscribe to groups. See netlink(7)
    /// man pages for more information on netlink IDs and groups.
    pub fn bind(&mut self, pid: Option<u32>, groups: Option<u32>) -> Result<(), io::Error> {
        let mut nladdr = unsafe { zeroed::<libc::sockaddr_nl>() };
        nladdr.nl_family = libc::AF_NETLINK as u16;
        nladdr.nl_pid = pid.unwrap_or(0);
        nladdr.nl_groups = groups.unwrap_or(0);
        match unsafe {
            libc::bind(self.fd, &nladdr as *const _ as *const libc::sockaddr,
                       size_of::<libc::sockaddr_nl>() as u32)
        } {
            i if i >= 0 => Ok(()),
            _ => Err(io::Error::last_os_error()),
        }
    }

    /// Send message encoded as byte slice to the netlink ID specified in the netlink header
    /// (`neli::nlhdr::NlHdr`).
    pub fn send(&mut self, buf: MemRead, flags: i32) -> Result<isize, io::Error> {
        match unsafe {
            libc::send(self.fd, buf.as_slice() as *const _ as *const c_void, buf.len(), flags)
        } {
            i if i >= 0 => Ok(i),
            _ => Err(io::Error::last_os_error()),
        }
    }

    /// Receive message encoded as byte slice from the netlink socket.
    pub fn recv<'a>(&mut self, mut buf: MemWrite<'a>, flags: i32)
            -> Result<MemRead<'a>, io::Error> {
        match unsafe {
            libc::recv(self.fd, buf.as_mut_slice() as *mut _ as *mut c_void, buf.len(), flags)
        } {
            i if i >= 0 => Ok(buf.shrink(i as usize).into()),
            _ => Err(io::Error::last_os_error()),
        }
    }

    /// Equivalent of `socket` and `bind` calls.
    pub fn connect(proto: NlFamily, pid: Option<u32>, groups: Option<u32>)
                   -> Result<Self, io::Error> {
        let mut s = try!(NlSocket::new(proto));
        try!(s.bind(pid, groups));
        Ok(s)
    }

    /// Convenience function for resolving a `&str` containing the multicast group name to a
    /// numeric netlink ID
    pub fn resolve_nl_mcast_group(family_name: &str, mcast_name: &str) -> Result<u32, NlError> {
        let mut socket = Self::connect(NlFamily::Generic, None, None)?;
        let attrs = vec![NlAttrHdr::new_str_payload(None, CtrlAttr::FamilyName, family_name)?];
        let genlhdr = GenlHdr::new(CtrlCmd::Getfamily, 2, attrs)?;
        let nlhdr = NlHdr::new(None, GenlId::Ctrl,
                               vec![NlmF::Request, NlmF::Ack], None, None, genlhdr);
        let mut mem_req = MemWrite::new_vec(Some(nlhdr.asize()));
        nlhdr.serialize(&mut mem_req)?;
        socket.send(mem_req.into(), 0)?;

        let mem_resp = MemWrite::new_vec(Some(4096));
        let mut mem_resp_recv = socket.recv(mem_resp, 0)?;
        let nlhdr = NlHdr::<GenlId, GenlHdr<CtrlCmd>>::deserialize(&mut mem_resp_recv)?;
        let mut handle = nlhdr.nl_payload.get_attr_handle::<CtrlAttr>();
        let mcast_groups = handle.get_nested_attributes::<u16>(CtrlAttr::McastGroups)?;
        let mut id = None;
        if let Some(iter) = mcast_groups.iter() {
            for attribute in iter {
                let attribute_len = attribute.nla_len;
                let mut handle = attribute.get_attr_handle();
                let string = handle.get_payload_with::<String>(CtrlAttrMcastGrp::Name,
                    Some(attribute_len as usize))?;
                if string.as_str() == mcast_name {
                    id = handle.get_payload_as::<u32>(CtrlAttrMcastGrp::Id).ok();
                }
            }
        }
        id.ok_or(NlError::new("Failed to resolve multicast group ID"))
    }
}

impl<I, P> AsRawFd for NlSocket<I, P> {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl<I, P> IntoRawFd for NlSocket<I, P> {
    fn into_raw_fd(self) -> RawFd {
        self.fd
    }
}

#[cfg(feature = "stream")]
impl<I, P> Stream for NlSocket<I, P> where I: Nl, P: Nl {
    type Item = NlHdr<I, P>;
    type Error = ();

    fn poll(&mut self) -> Result<Async<Option<Self::Item>>, Self::Error> {
        let mem = MemWrite::new_vec(Some(MAX_NL_LENGTH));
        let mut events = mio::Events::with_capacity(1);
        match self.poll.poll(&mut events, Some(Duration::from_secs(0))) {
            Ok(_) => (),
            Err(_) => return Err(()),
        };
        if let Some(event) = events.iter().nth(0) {
            if !event.readiness().is_readable() {
                return Ok(Async::NotReady);
            }
        }
        let mut mem_read = match self.recv(mem, 0) {
            Ok(mr) => mr,
            Err(_) => return Err(()),
        };
        if mem_read.as_slice().len() == 0 {
            return Ok(Async::Ready(None));
        }
        let hdr = match NlHdr::<I, P>::deserialize(&mut mem_read) {
            Ok(h) => h,
            Err(_) => return Err(()),
        };
        Ok(Async::Ready(Some(hdr)))
    }
}

#[cfg(feature = "evented")]
impl<I, P> Evented for NlSocket<I, P> {
    fn register(&self, poll: &mio::Poll, token: mio::Token, interest: mio::Ready,
                opts: mio::PollOpt) -> io::Result<()> {
        poll.register(&mio::unix::EventedFd(&self.as_raw_fd()), token, interest, opts)
    }

    fn reregister(&self, poll: &mio::Poll, token: mio::Token, interest: mio::Ready,
                  opts: mio::PollOpt) -> io::Result<()> {
        poll.reregister(&mio::unix::EventedFd(&self.as_raw_fd()), token, interest, opts)
    }

    fn deregister(&self, poll: &mio::Poll) -> io::Result<()> {
        poll.deregister(&mio::unix::EventedFd(&self.as_raw_fd()))
    }
}

impl<I, P> Drop for NlSocket<I, P> {
    /// Closes underlying file descriptor to avoid file descriptor leaks.
    fn drop(&mut self) {
        unsafe { libc::close(self.fd); }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ffi::Nlmsg;
    use genlhdr::GenlHdr;

    #[test]
    fn test_socket_creation() {
        match NlSocket::<Nlmsg, GenlHdr>::connect(NlFamily::Generic, None, None) {
            Err(_) => panic!(),
            _ => (),
        }
    }
}
