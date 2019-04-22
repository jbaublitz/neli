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

use {Nl,MAX_NL_LENGTH};
use err::{NlError,Nlmsgerr};
use consts::{self,AddrFamily,CtrlCmd,CtrlAttr,CtrlAttrMcastGrp,GenlId,NlmF,NlFamily,NlType};
use genl::Genlmsghdr;
use nlattr::Nlattr;
use nl::Nlmsghdr;

/// Iterator over messages returned from a `recv_nl` call
pub struct NlMessageIter<T, P, B> {
    recv_buffer: StreamReadBuffer<B>,
    data_type: PhantomData<T>,
    data_payload: PhantomData<P>,
}

impl<T, P, B> NlMessageIter<T, P, B> where T: Nl + NlType, P: Nl, B: AsRef<[u8]> {
    /// Construct a new iterator that yields `Nlmsghdr` structs from the provided buffer
    pub fn new(mem: B) -> Self {
        NlMessageIter { recv_buffer: StreamReadBuffer::new(mem), data_type: PhantomData,
                        data_payload: PhantomData, }
    }

    /// Extract and parse the next message in the buffer stream
    pub fn nl_next(&mut self) -> Option<Result<Nlmsghdr<T, P>, NlError>> {
        if self.recv_buffer.at_end() {
            return None;
        }
        let msg = Nlmsghdr::<T, P>::deserialize(&mut self.recv_buffer);
        let msg_ret = match msg {
            Ok(m) => m,
            Err(e) => return Some(Err(NlError::Msg(e.to_string()))),
        };
        Some(Ok(msg_ret))
    }

    /// Extract and parse the next message in the buffer stream, overriding the provided struct generic
    /// types with other types
    pub fn nl_next_override<TT, PP>(&mut self) -> Option<Result<Nlmsghdr<TT, PP>, NlError>>
            where TT: Nl + NlType, PP: Nl{
        if self.recv_buffer.at_end() {
            return None;
        }
        let msg = Nlmsghdr::<TT, PP>::deserialize(&mut self.recv_buffer);
        let msg_ret = match msg {
            Ok(m) => m,
            Err(e) => return Some(Err(NlError::Msg(e.to_string()))),
        };
        Some(Ok(msg_ret))
    }

    /// Consume an ACK and return an error if an ACK is not found
    pub fn recv_ack(&mut self) -> Result<(), NlError> {
        if let Some(Ok(ack)) = self.nl_next_override::<consts::Nlmsg, Nlmsgerr<consts::Nlmsg>>() {
            if ack.nl_type == consts::Nlmsg::Error && ack.nl_payload.error == 0 {
                Ok(())
            } else {
                Err(NlError::NoAck)
            }
        } else {
            Err(NlError::NoAck)
        }
    }
}

impl<T, P, B> Iterator for NlMessageIter<T, P, B> where T: Nl + NlType, P: Nl, B: AsRef<[u8]> {
    type Item = Nlmsghdr<T, P>;

    fn next(&mut self) -> Option<Nlmsghdr<T, P>> {
        if let Some(Ok(msg)) = self.nl_next() {
            Some(msg)
        } else {
            None
        }
    }
}

/// Handle for the socket file descriptor
pub struct NlSocket {
    fd: c_int,
}

impl NlSocket {
    /// Wrapper around `socket()` syscall filling in the netlink-specific information
    pub fn new(proto: NlFamily) -> Result<Self, io::Error> {
        let fd = match unsafe {
            libc::socket(AddrFamily::Netlink.into(), libc::SOCK_RAW, proto.into())
        } {
            i if i >= 0 => Ok(i),
            _ => Err(io::Error::last_os_error()),
        }?;
        Ok(NlSocket { fd })
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
        nladdr.nl_family = libc::c_int::from(AddrFamily::Netlink) as u16;
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
    /// (`neli::nl::Nlmsghdr`)
    pub fn send<B>(&mut self, buf: B, flags: i32) -> Result<libc::ssize_t, io::Error> where B: AsRef<[u8]> {
        match unsafe {
            libc::send(self.fd, buf.as_ref() as *const _ as *const c_void, buf.as_ref().len(), flags)
        } {
            i if i >= 0 => Ok(i),
            _ => Err(io::Error::last_os_error()),
        }
    }

    /// Receive message encoded as byte slice from the netlink socket
    pub fn recv<'a, B>(&mut self, mut buf: B, flags: i32) -> Result<libc::ssize_t, io::Error> where B: AsMut<[u8]> {
        match unsafe {
            libc::recv(self.fd, buf.as_mut() as *mut _ as *mut c_void, buf.as_mut().len(), flags)
        } {
            i if i >= 0 => Ok(i),
            _ => Err(io::Error::last_os_error()),
        }
    }

    /// Equivalent of `socket` and `bind` calls.
    pub fn connect(proto: NlFamily, pid: Option<u32>, groups: Vec<u32>)
                   -> Result<Self, io::Error> {
        let mut s = try!(NlSocket::new(proto));
        try!(s.bind(pid, groups));
        Ok(s)
    }

    /// Create generic netlink resolution socket
    pub fn new_genl() -> Result<NlSocket, io::Error> {
        Self::connect(NlFamily::Generic, None, Vec::new())
    }

    fn get_genl_family(&mut self, family_name: &str)
            -> Result<Nlmsghdr<GenlId, Genlmsghdr<CtrlCmd>>, NlError> {
        let attrs = vec![Nlattr::new_str_payload(None, CtrlAttr::FamilyName, family_name)?];
        let genlhdr = Genlmsghdr::new(CtrlCmd::Getfamily, 2, attrs)?;
        let nlhdr = Nlmsghdr::new(None, GenlId::Ctrl,
                               vec![NlmF::Request], None, None, genlhdr);
        self.send_nl(nlhdr)?;

        let mut iter = self.recv_nl(Some(4096))?;
        if let Some(msg) = iter.nl_next() {
            msg
        } else {
            Err(NlError::new("No genetlink message received in response to request"))
        }
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

    /// Convenience function to send an `Nlmsghdr` struct
    pub fn send_nl<T, P>(&mut self, msg: Nlmsghdr<T, P>) -> Result<(), NlError> where T: Nl + NlType,
            P: Nl {
        let mut mem = StreamWriteBuffer::new_growable(Some(msg.asize()));
        msg.serialize(&mut mem)?;
        self.send(mem, 0)?;
        Ok(())
    }

    /// Convenience function to begin receiving a stream of `Nlmsghdr` structs
    pub fn recv_nl<T, P>(&mut self, buf_sz: Option<usize>)
            -> Result<NlMessageIter<T, P, Vec<u8>>, NlError> where T: Nl + NlType, P: Nl {
        let mut mem = vec![0; buf_sz.unwrap_or(MAX_NL_LENGTH)];
        let mem_read = self.recv(&mut mem, 0)?;
        mem.truncate(mem_read as usize);
        Ok(NlMessageIter::new(mem))
    }
}

impl AsRawFd for NlSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl IntoRawFd for NlSocket {
    fn into_raw_fd(self) -> RawFd {
        self.fd
    }
}

impl io::Read for NlSocket {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match unsafe {
            libc::recv(self.fd, buf as *mut _ as *mut c_void, buf.len(), 0)
        } {
            i if i >= 0 => Ok(i as usize),
            _ => Err(io::Error::last_os_error()),
        }
    }
}

/// Tokio-specific features for neli
#[cfg(feature = "stream")]
pub mod tokio {
    use super::*;

    use std::io::{ErrorKind,Read};

    use mio::{self,Evented,Ready};
    use tokio::prelude::{Async,AsyncRead,Stream};
    use tokio::reactor::PollEvented2;

    /// Tokio-enabled Netlink socket struct
    pub struct NlSocket<T, P>(PollEvented2<super::NlSocket<T, P>>);

    impl<T, P> NlSocket<T, P> where T: NlType {
        /// Setup NlSocket for use with tokio - set to nonblocking state and wrap in polling mechanism
        pub fn new(mut sock: super::NlSocket<T, P>) -> io::Result<Self> {
            if sock.is_blocking()? {
                sock.nonblock()?;
            }
            Ok(NlSocket(PollEvented2::new(sock)))
        }
    }

    impl<T, P> Read for NlSocket<T, P> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.0.get_mut().read(buf)
        }
    }

    impl<T, P> AsyncRead for NlSocket<T, P> {}

    impl<T, P> Stream for NlSocket<T, P> where T: NlType, P: Nl {
        type Item = Nlmsghdr<T, P>;
        type Error = io::Error;

        fn poll(&mut self) -> Result<Async<Option<Self::Item>>, Self::Error> {
            let readiness = self.0.poll_read_ready(Ready::readable())?;
            match readiness {
                Async::NotReady => return Ok(Async::NotReady),
                Async::Ready(_) => (),
            }

            let mut mem = vec![0; MAX_NL_LENGTH];
            let bytes_written = match self.read(mem.as_mut_slice()) {
                Ok(0) => return Ok(Async::Ready(None)),
                Ok(i) => i,
                Err(e) => {
                    if e.kind() == ErrorKind::WouldBlock {
                        self.0.clear_read_ready(Ready::readable())?;
                        return Ok(Async::NotReady);
                    } else {
                        return Err(e);
                    }
                }
            };
            mem.truncate(bytes_written);
            let mut mem_read = StreamReadBuffer::new(mem);
            let hdr = match Nlmsghdr::<T, P>::deserialize(&mut mem_read) {
                Ok(h) => h,
                Err(_) => return Err(io::Error::from(io::ErrorKind::Other)),
            };
            Ok(Async::Ready(Some(hdr)))
        }
    }

    impl<T, P> Evented for super::NlSocket<T, P> {
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
}

impl Drop for NlSocket {
    /// Closes underlying file descriptor to avoid file descriptor leaks.
    fn drop(&mut self) {
        unsafe { libc::close(self.fd); }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use consts::{CtrlCmd,Nlmsg};
    use genl::Genlmsghdr;

    #[test]
    fn test_socket_creation() {
       NlSocket::<Nlmsg, Genlmsghdr<CtrlCmd>>::connect(NlFamily::Generic, None, Vec::new()).unwrap();
    }
}
