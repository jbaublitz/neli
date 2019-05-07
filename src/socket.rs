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
pub struct NlMessageIter<'a, T, P> {
    socket_ref: &'a mut NlSocket,
    data_type: PhantomData<T>,
    data_payload: PhantomData<P>,
}

impl<'a, T, P> NlMessageIter<'a, T, P> where T: Nl + NlType, P: Nl {
    /// Construct a new iterator that yields `Nlmsghdr` structs from the provided buffer
    pub fn new(socket_ref: &'a mut NlSocket) -> Self {
        NlMessageIter { socket_ref, data_type: PhantomData, data_payload: PhantomData, }
    }
}


impl<'a, T, P> Iterator for NlMessageIter<'a, T, P> where T: Nl + NlType, P: Nl {
    type Item = Result<Nlmsghdr<T, P>, NlError>;

    fn next(&mut self) -> Option<Result<Nlmsghdr<T, P>, NlError>> {
        match self.socket_ref.recv_nl(None) {
            Ok(rn) => Some(Ok(rn)),
            Err(e) => return Some(Err(e)),
        }
    }
}

/// Handle for the socket file descriptor
pub struct NlSocket {
    fd: c_int,
    buffer: Option<StreamReadBuffer<Vec<u8>>>,
    pid: Option<u32>,
    seq: Option<u32>,
}

impl NlSocket {
    /// Wrapper around `socket()` syscall filling in the netlink-specific information
    pub fn new(proto: NlFamily, track_seq: bool) -> Result<Self, io::Error> {
        let fd = match unsafe {
            libc::socket(AddrFamily::Netlink.into(), libc::SOCK_RAW, proto.into())
        } {
            i if i >= 0 => Ok(i),
            _ => Err(io::Error::last_os_error()),
        }?;
        Ok(NlSocket { fd, buffer: None, pid: None, seq: if track_seq { Some(0) } else { None }, })
    }

    /// Manually increment sequence number
    pub fn increment_seq(&mut self) {
        self.seq.map(|seq| seq + 1);
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
    pub fn bind(&mut self, pid: Option<u32>, groups: Option<Vec<u32>>) -> Result<(), io::Error> {
        let mut nladdr = unsafe { zeroed::<libc::sockaddr_nl>() };
        nladdr.nl_family = libc::c_int::from(AddrFamily::Netlink) as u16;
        nladdr.nl_pid = pid.unwrap_or(0);
        nladdr.nl_groups = 0;
        match unsafe {
            libc::bind(self.fd, &nladdr as *const _ as *const libc::sockaddr,
                       size_of::<libc::sockaddr_nl>() as u32)
        } {
            i if i >= 0 => (),
            _ => return Err(io::Error::last_os_error()),
        };
        if let Some(grps) = groups {
            self.set_mcast_groups(grps)?;
        }
        Ok(())
    }

    /// Set multicast groups for socket
    pub fn set_mcast_groups(&mut self, groups: Vec<u32>) -> Result<(), io::Error> {
        let grps = groups.into_iter().fold(0, |acc, next| { acc | (1 << (next - 1)) });
        match unsafe {
            libc::setsockopt(self.fd, libc::SOL_NETLINK,
                             libc::NETLINK_ADD_MEMBERSHIP,
                             &grps as *const _ as *const libc::c_void,
                             size_of::<u32>() as libc::socklen_t)
        } {
            i if i == 0 => Ok(()),
            _ => return Err(io::Error::last_os_error()),
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
    pub fn connect(proto: NlFamily, pid: Option<u32>, groups: Option<Vec<u32>>, track_seq: bool)
                   -> Result<Self, io::Error> {
        let mut s = try!(NlSocket::new(proto, track_seq));
        try!(s.bind(pid, groups));
        Ok(s)
    }

    fn get_genl_family(&mut self, family_name: &str)
            -> Result<Nlmsghdr<GenlId, Genlmsghdr<CtrlCmd>>, NlError> {
        let attrs = vec![Nlattr::new_str_payload(None, CtrlAttr::FamilyName, family_name)?];
        let genlhdr = Genlmsghdr::new(CtrlCmd::Getfamily, 2, attrs)?;
        let nlhdr = Nlmsghdr::new(None, GenlId::Ctrl,
                               vec![NlmF::Request, NlmF::Ack], None, None, genlhdr);
        self.send_nl(nlhdr)?;

        let msg = self.recv_nl(None)?;
        self.recv_ack()?;
        Ok(msg)
    }

    /// Convenience function for resolving a `&str` containing the multicast group name to a
    /// numeric netlink ID
    pub fn resolve_genl_family(&mut self, family_name: &str) -> Result<u16, NlError> {
        let nlhdr = self.get_genl_family(family_name)?;
        let mut handle = nlhdr.nl_payload.get_attr_handle::<CtrlAttr>();
        Ok(handle.get_payload::<u16>(CtrlAttr::FamilyId, None)?)
    }

    /// Convenience function for resolving a `&str` containing the multicast group name to a
    /// numeric netlink ID
    pub fn resolve_nl_mcast_group(&mut self, family_name: &str, mcast_name: &str)
            -> Result<u32, NlError> {
        let nlhdr = self.get_genl_family(family_name)?;
        let mut handle = nlhdr.nl_payload.get_attr_handle::<CtrlAttr>();
        let mut mcast_groups = handle.get_nested_attributes::<CtrlAttrMcastGrp>(CtrlAttr::McastGroups)?;
        mcast_groups.parse_nested_attributes()?;
        let mut id = None;
        if let Some(iter) = mcast_groups.iter() {
            for attribute in iter {
                let attribute_len = attribute.nla_len;
                let mut handle = attribute.get_attr_handle();
                let string = handle.get_payload::<String>(CtrlAttrMcastGrp::Name,
                    Some(attribute_len as usize - (attribute.nla_len.size() +
                                                   attribute.nla_type.size())))?;
                if string.as_str() == mcast_name {
                    id = handle.get_payload::<u32>(CtrlAttrMcastGrp::Id, None).ok();
                }
            }
        }
        id.ok_or(NlError::new("Failed to resolve multicast group ID"))
    }

    /// Convenience function to send an `Nlmsghdr` struct
    pub fn send_nl<T, P>(&mut self, mut msg: Nlmsghdr<T, P>) -> Result<(), NlError>
            where T: Nl + NlType, P: Nl {
        let mut mem = StreamWriteBuffer::new_growable(Some(msg.asize()));
        if let Some(seq) = self.seq {
            msg.nl_seq = seq;
        }
        msg.serialize(&mut mem)?;
        self.send(mem, 0)?;
        Ok(())
    }

    /// Convenience function to begin receiving a stream of `Nlmsghdr` structs
    pub fn recv_nl<T, P>(&mut self, buf_sz: Option<usize>)
            -> Result<Nlmsghdr<T, P>, NlError> where T: Nl + NlType, P: Nl {
        if self.buffer.is_none() {
            let mut mem = vec![0; buf_sz.unwrap_or(MAX_NL_LENGTH)];
            let mem_read = self.recv(&mut mem, 0)?;
            if mem_read == 0 {
                return Err(NlError::new("No data could be read from the socket"));
            }
            mem.truncate(mem_read as usize);
            self.buffer = Some(StreamReadBuffer::new(mem));
        }
        let msg = match self.buffer {
            Some(ref mut b) => Nlmsghdr::deserialize(b)?,
            None => unreachable!(),
        };
        if let Some(true) = self.buffer.as_ref().map(|b| b.at_end()) {
            self.buffer = None;
        }
        Ok(msg)
    }

    /// Consume an ACK and return an error if an ACK is not found
    pub fn recv_ack(&mut self) -> Result<(), NlError> {
        if let Ok(ack) = self.recv_nl::<consts::Nlmsg, Nlmsgerr<consts::Nlmsg>>(None) {
            if ack.nl_type == consts::Nlmsg::Error && ack.nl_payload.error == 0 {
                if self.pid.is_none() {
                    self.pid = Some(ack.nl_pid);
                }
                Ok(())
            } else {
                self.buffer.as_mut().map(|b| b.rewind());
                Err(NlError::NoAck)
            }
        } else {
            Err(NlError::NoAck)
        }
    }

    /// Return an iterator object
    pub fn iter<'a, T, P>(&'a mut self) -> NlMessageIter<'a, T, P> where T: NlType, P: Nl {
        NlMessageIter::new(self)
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
        self.recv(buf, 0).map(|i| i as usize)
    }
}

/// Tokio-specific features for neli
#[cfg(feature = "stream")]
pub mod tokio {
    use super::*;

    use mio::{self,Evented};
    use tokio::prelude::{Async,AsyncRead,Stream};
    use tokio::reactor::PollEvented2;

    /// Tokio-enabled Netlink socket struct
    pub struct NlSocket<T, P> {
        socket: PollEvented2<super::NlSocket>,
        buffer: Option<StreamReadBuffer<Vec<u8>>>,
        type_data: PhantomData<T>,
        payload_data: PhantomData<P>,
    }

    impl<T, P> NlSocket<T, P> where T: NlType {
        /// Setup NlSocket for use with tokio - set to nonblocking state and wrap in polling mechanism
        pub fn new(mut sock: super::NlSocket) -> io::Result<Self> {
            if sock.is_blocking()? {
                sock.nonblock()?;
            }
            Ok(NlSocket { socket: PollEvented2::new(sock), buffer: None,
                    type_data: PhantomData, payload_data: PhantomData, })
        }

        /// Check if underlying received message buffer is empty
        pub fn empty(&self) -> bool {
            if let Some(ref buf) = self.buffer {
                buf.at_end()
            } else {
                true
            }
        }
    }

    impl<T, P> Stream for NlSocket<T, P> where T: NlType, P: Nl {
        type Item = Nlmsghdr<T, P>;
        type Error = io::Error;

        fn poll(&mut self) -> Result<Async<Option<Self::Item>>, Self::Error> {
            if self.empty() {
                let mut mem = vec![0; MAX_NL_LENGTH];
                let bytes_read = match self.socket.poll_read(mem.as_mut_slice()) {
                    Ok(Async::Ready(0)) => return Ok(Async::Ready(None)),
                    Ok(Async::Ready(i)) => i,
                    Ok(Async::NotReady) => return Ok(Async::NotReady),
                    Err(e) => return Err(e),
                };
                mem.truncate(bytes_read);
                self.buffer = Some(StreamReadBuffer::new(mem));
            }

            match self.buffer {
                Some(ref mut buf) => Ok(
                    Async::Ready(Some(Nlmsghdr::<T, P>::deserialize(buf).map_err(|_| {
                        io::ErrorKind::InvalidData
                    })?))
                ),
                None => Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
            }
        }
    }

    impl Evented for super::NlSocket {
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
    extern crate tokio;

    use super::*;

    use std::io::Read;

    use tokio::prelude::Stream;

    #[test]
    fn test_socket_nonblock() {
        let mut s = NlSocket::connect(NlFamily::Generic, None, Vec::new()).unwrap();
        s.nonblock().unwrap();
        assert_eq!(s.is_blocking().unwrap(), false);
        let buf = &mut [0; 4];
        match s.read(buf) {
            Err(e) => {
                if e.kind() != io::ErrorKind::WouldBlock {
                    panic!("Error: {}", e);
                }
            },
            Ok(_) => {
                panic!("Should not return data");
            }
        }
    }
}
