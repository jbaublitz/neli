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

use buffering::copy::{StreamReadBuffer,StreamWriteBuffer};
use libc::{self,c_int,c_void};
#[cfg(feature = "evented")]
use mio::{self,Evented};
#[cfg(feature = "stream")]
use tokio::io::AsyncRead;
#[cfg(feature = "stream")]
use tokio::prelude::{Async,Stream};

use {Nl,MAX_NL_LENGTH};
use err::{NlError,Nlmsgerr};
use ffi::{self,NlFamily,GenlId,CtrlCmd,CtrlAttr,CtrlAttrMcastGrp,NlmF};
use genlhdr::GenlHdr;
use nlattr::NlAttrHdr;
use nlhdr::NlHdr;

/// Handle for the socket file descriptor
#[cfg(feature = "evented")]
pub struct NlSocket<T, P> {
    fd: c_int,
    poll: mio::Poll,
    data_type: PhantomData<T>,
    data_payload: PhantomData<P>,
}

/// Handle for the socket file descriptor
#[cfg(not(feature = "evented"))]
pub struct NlSocket<T, P> {
    fd: c_int,
    data_type: PhantomData<T>,
    data_payload: PhantomData<P>,
}

impl<T, P> NlSocket<T, P> where T: Nl, P: Nl {
    /// Wrapper around `socket()` syscall filling in the netlink-specific information
    #[cfg(feature = "evented")]
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
    #[cfg(not(feature = "evented"))]
    pub fn new(proto: NlFamily) -> Result<Self, io::Error> {
        let fd = match unsafe {
            libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, proto.into())
        } {
            i if i >= 0 => Ok(i),
            _ => Err(io::Error::last_os_error()),
        }?;
        Ok(NlSocket { fd, data_type: PhantomData, data_payload: PhantomData })
    }

    /// Set underlying socket file descriptor to be blocking
    pub fn block(&mut self) -> Result<&mut Self, io::Error> {
        match unsafe { libc::fcntl(self.fd, libc::F_SETFL,
                                   libc::fcntl(self.fd, libc::F_GETFL, 0) & !libc::O_NONBLOCK) } {
            i if i < 0 => return Err(io::Error::last_os_error()),
            _ => Ok(self),
        }
    }

    /// Set underlying socket file descriptor to be non blocking
    pub fn nonblock(&mut self) -> Result<&mut Self, io::Error> {
        match unsafe { libc::fcntl(self.fd, libc::F_SETFL,
                                   libc::fcntl(self.fd, libc::F_GETFL, 0) | libc::O_NONBLOCK) } {
            i if i < 0 => return Err(io::Error::last_os_error()),
            _ => Ok(self),
        }
    }

    /// Determines if underlying file descriptor is blocking - `Stream` feature will throw an
    /// error if this function returns false
    pub fn is_blocking(&self) -> Result<bool, io::Error> {
        let is_blocking = match unsafe { libc::fcntl(self.fd, libc::F_GETFL, 0) } {
            i if i >= 0 => i & libc::O_NONBLOCK == 0,
            _ => return Err(io::Error::last_os_error()),
        };
        Ok(is_blocking)
    }

    /// Use this function to bind to a netlink ID and subscribe to groups. See netlink(7)
    /// man pages for more information on netlink IDs and groups.
    pub fn bind(&mut self, pid: Option<u32>, groups: Vec<u32>) -> Result<(), io::Error> {
        let mut nladdr = unsafe { zeroed::<libc::sockaddr_nl>() };
        nladdr.nl_family = libc::AF_NETLINK as u16;
        nladdr.nl_pid = pid.unwrap_or(0);
        nladdr.nl_groups = groups.into_iter().fold(0, |acc, next| {
            acc | (1 << (next - 1))
        });
        match unsafe {
            libc::bind(self.fd, &nladdr as *const _ as *const libc::sockaddr,
                       size_of::<libc::sockaddr_nl>() as u32)
        } {
            i if i >= 0 => Ok(()),
            _ => Err(io::Error::last_os_error()),
        }
    }

    /// Send message encoded as byte slice to the netlink ID specified in the netlink header
    /// (`neli::nlhdr::NlHdr`)
    pub fn send<B>(&mut self, buf: StreamReadBuffer<B>, flags: i32) -> Result<isize, io::Error>
            where B: AsRef<[u8]> {
        match unsafe {
            libc::send(self.fd, buf.as_ref() as *const _ as *const c_void, buf.as_ref().len(), flags)
        } {
            i if i >= 0 => Ok(i),
            _ => Err(io::Error::last_os_error()),
        }
    }

    /// Convenience function to send an `NlHdr` struct
    pub fn send_nl(&mut self, msg: NlHdr<T, P>) -> Result<(), NlError> {
        let mut mem = StreamWriteBuffer::new_growable(Some(msg.asize()));
        msg.serialize(&mut mem)?;
        self.send(StreamReadBuffer::new(mem), 0)?;
        Ok(())
    }

    /// Receive message encoded as byte slice from the netlink socket
    pub fn recv<'a>(&mut self, mut buf: StreamWriteBuffer<'a>, flags: i32)
            -> Result<StreamReadBuffer<StreamWriteBuffer<'a>>, io::Error> {
        match unsafe {
            libc::recv(self.fd, buf.as_mut() as *mut _ as *mut c_void, buf.as_mut().len(), flags)
        } {
            i if i >= 0 => {
                buf.set_bytes_written(i as usize)?;
                Ok(StreamReadBuffer::new(buf))
            },
            _ => Err(io::Error::last_os_error()),
        }
    }

    /// Convenience function to receive an `NlHdr` struct
    pub fn recv_nl(&mut self, buf_sz: Option<usize>) -> Result<NlHdr<T, P>, NlError> {
        let mem_write = StreamWriteBuffer::new_growable(buf_sz.or(Some(MAX_NL_LENGTH)));
        let mut mem_read = self.recv(mem_write, 0)?;
        Ok(NlHdr::<T, P>::deserialize(&mut mem_read)?)
    }

    /// Convenience function to receive an `NlHdr` struct with function type parameters
    /// that determine deserialization type
    pub fn recv_nl_typed<TT, PP>(&mut self, buf_sz: Option<usize>)
            -> Result<NlHdr<TT, PP>, NlError> where TT: Nl + Into<u16> + From<u16>, PP: Nl {
        let mem_write = StreamWriteBuffer::new_growable(buf_sz.or(Some(MAX_NL_LENGTH)));
        let mut mem_read = self.recv(mem_write, 0)?;
        Ok(NlHdr::<TT, PP>::deserialize(&mut mem_read)?)
    }

    /// Consume an ACK and return an error if an ACK is not found
    pub fn recv_ack(&mut self, buf_sz: Option<usize>) -> Result<(), NlError> {
        let ack = self.recv_nl_typed::<ffi::Nlmsg, Nlmsgerr<ffi::Nlmsg>>(buf_sz)?;
        if ack.nl_type == ffi::Nlmsg::Error && ack.nl_payload.error == 0 {
            Ok(())
        } else {
            Err(NlError::NoAck)
        }
    }

    /// Equivalent of `socket` and `bind` calls.
    pub fn connect(proto: NlFamily, pid: Option<u32>, groups: Vec<u32>)
                   -> Result<Self, io::Error> {
        let mut s = try!(NlSocket::new(proto));
        try!(s.bind(pid, groups));
        Ok(s)
    }
}

impl NlSocket<GenlId, GenlHdr<CtrlCmd>> {
    /// Create generic netlink resolution socket
    pub fn new_genl() -> Result<NlSocket<GenlId, GenlHdr<CtrlCmd>>, io::Error> {
        Self::connect(NlFamily::Generic, None, Vec::new())
    }

    fn get_genl_family(&mut self, family_name: &str)
            -> Result<NlHdr<GenlId, GenlHdr<CtrlCmd>>, NlError> {
        let attrs = vec![NlAttrHdr::new_str_payload(None, CtrlAttr::FamilyName, family_name)?];
        let genlhdr = GenlHdr::new(CtrlCmd::Getfamily, 2, attrs)?;
        let nlhdr = NlHdr::new(None, GenlId::Ctrl,
                               vec![NlmF::Request], None, None, genlhdr);
        self.send_nl(nlhdr)?;

        Ok(self.recv_nl(Some(4096))?)
    }

    /// Convenience function for resolving a `&str` containing the multicast group name to a
    /// numeric netlink ID
    pub fn resolve_genl_family(&mut self, family_name: &str) -> Result<u16, NlError> {
        let nlhdr = self.get_genl_family(family_name)?;
        let mut handle = nlhdr.nl_payload.get_attr_handle::<CtrlAttr>();
        Ok(handle.get_payload_with::<u16>(CtrlAttr::FamilyId, None)?)
    }

    /// Convenience function for resolving a `&str` containing the multicast group name to a
    /// numeric netlink ID
    pub fn resolve_nl_mcast_group(&mut self, family_name: &str, mcast_name: &str)
            -> Result<u32, NlError> {
        let nlhdr = self.get_genl_family(family_name)?;
        let mut handle = nlhdr.nl_payload.get_attr_handle::<CtrlAttr>();
        let mut mcast_groups = handle.get_nested_attributes::<u16>(CtrlAttr::McastGroups)?;
        mcast_groups.parse_nested_attributes()?;
        let mut id = None;
        if let Some(iter) = mcast_groups.iter() {
            for attribute in iter {
                let attribute_len = attribute.nla_len;
                let mut handle = attribute.get_attr_handle();
                let string = handle.get_payload_with::<String>(CtrlAttrMcastGrp::Name,
                    Some(attribute_len as usize))?;
                if string.as_str() == mcast_name {
                    id = handle.get_payload_with::<u32>(CtrlAttrMcastGrp::Id, None).ok();
                }
            }
        }
        id.ok_or(NlError::new("Failed to resolve multicast group ID"))
    }
}

impl<T, P> AsRawFd for NlSocket<T, P> {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl<T, P> IntoRawFd for NlSocket<T, P> {
    fn into_raw_fd(self) -> RawFd {
        self.fd
    }
}

impl<T, P> io::Read for NlSocket<T, P> where T: Nl, P: Nl {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match unsafe {
            libc::recv(self.fd, buf as *mut _ as *mut c_void, buf.len(), 0)
        } {
            i if i >= 0 => Ok(i as usize),
            _ => Err(io::Error::last_os_error()),
        }
    }
}

#[cfg(feature = "stream")]
impl<T, P> AsyncRead for NlSocket<T, P> where T: Nl, P: Nl { }

#[cfg(feature = "stream")]
impl<T, P> Stream for NlSocket<T, P> where T: Nl, P: Nl {
    type Item = NlHdr<T, P>;
    type Error = ();

    fn poll(&mut self) -> Result<Async<Option<Self::Item>>, Self::Error> {
        if !self.is_blocking().map_err(|_| ())? {
            return Err(());
        }
        let mut mem = StreamWriteBuffer::new_growable(Some(MAX_NL_LENGTH));
        let bytes_written = match self.poll_read(mem.as_mut()) {
            Ok(Async::NotReady) => return Ok(Async::NotReady),
            Ok(Async::Ready(0)) => return Ok(Async::Ready(None)),
            Ok(Async::Ready(i)) => i,
            Err(_) => return Err(()),
        };
        mem.set_bytes_written(bytes_written);
        let mut mem_read = StreamReadBuffer::new(mem);
        let hdr = match NlHdr::<T, P>::deserialize(&mut mem_read) {
            Ok(h) => h,
            Err(_) => return Err(()),
        };
        Ok(Async::Ready(Some(hdr)))
    }
}

#[cfg(feature = "evented")]
impl<T, P> Evented for NlSocket<T, P> {
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

impl<T, P> Drop for NlSocket<T, P> {
    /// Closes underlying file descriptor to avoid file descriptor leaks.
    fn drop(&mut self) {
        unsafe { libc::close(self.fd); }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ffi::{CtrlCmd,Nlmsg};
    use genlhdr::GenlHdr;

    #[test]
    fn test_socket_creation() {
       NlSocket::<Nlmsg, GenlHdr<CtrlCmd>>::connect(NlFamily::Generic, None, Vec::new()).unwrap();
    }

    #[ignore]
    #[test]
    fn test_genl_family_resolve() {
        let mut sock = NlSocket::new_genl().unwrap();
        assert_eq!(19, sock.resolve_genl_family("nl80211").unwrap());
    }

    #[ignore]
    #[test]
    fn test_nl_mcast_group_resolve() {
        let mut sock = NlSocket::new_genl().unwrap();
        assert_eq!(5, sock.resolve_nl_mcast_group("nl80211", "mlme").unwrap());
    }
}
