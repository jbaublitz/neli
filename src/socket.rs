//! This module provides code that glues all of the other modules together and allows message send
//! and receive operations. This module relies heavily on the `buffering` crate. See `buffering`
//! for more information on the serialization and deserialization implementations.
//!
//! ## Important methods
//! * `send` and `recv` methods are meant to be the most low level calls. They essentially do what
//! the C system calls `send` and `recv` do with very little abstraction.
//! * `send_nl` and `recv_nl` methods are meant to provide an interface that is more idiomatic for
//! the library. The are able to operate on any structure wrapped in an `Nlmsghdr` struct that implements
//! the `Nl` trait.
//! * `iter` provides a loop based iteration through messages that are received in a stream over
//! the socket.
//! * `recv_ack` receives an ACK message and verifies it matches the request.
//!
//! ## Features
//! The `async` feature exposed by `cargo` allows the socket to use Rust's tokio for async IO.
//!
//! ## Additional methods
//!
//! There are methods for blocking and non-blocking, resolving generic netlink multicast group IDs,
//! and other convenience functions so see if your use case is supported. If it isn't, please open
//! a Github issue and submit a feature request.

use std::io;
use std::marker::PhantomData;
use std::mem::{size_of, zeroed};
use std::os::unix::io::{AsRawFd, IntoRawFd, RawFd};

use buffering::copy::{StreamReadBuffer, StreamWriteBuffer};
use libc::{self, c_int, c_void};

use consts::{
    self, AddrFamily, CtrlAttr, CtrlAttrMcastGrp, CtrlCmd, GenlId, Index, NlAttrType, NlFamily,
    NlType, NlmF, Nlmsg,
};
use err::{NlError, Nlmsgerr};
use genl::Genlmsghdr;
use nl::Nlmsghdr;
use nlattr::Nlattr;
use {Nl, MAX_NL_LENGTH};

/// Iterator over messages returned from a `recv_nl` call
pub struct NlMessageIter<'a, T, P> {
    socket_ref: &'a mut NlSocket,
    data_type: PhantomData<T>,
    data_payload: PhantomData<P>,
}

impl<'a, T, P> NlMessageIter<'a, T, P>
where
    T: Nl + NlType,
    P: Nl,
{
    /// Construct a new iterator that yields `Nlmsghdr` structs from the provided buffer
    pub fn new(socket_ref: &'a mut NlSocket) -> Self {
        NlMessageIter {
            socket_ref,
            data_type: PhantomData,
            data_payload: PhantomData,
        }
    }
}

impl<'a, T, P> Iterator for NlMessageIter<'a, T, P>
where
    T: Nl + NlType,
    P: Nl,
{
    type Item = Result<Nlmsghdr<T, P>, NlError>;

    fn next(&mut self) -> Option<Result<Nlmsghdr<T, P>, NlError>> {
        match self.socket_ref.recv_nl(None) {
            Ok(rn) => Some(Ok(rn)),
            Err(e) => Some(Err(e)),
        }
    }
}

/// Conversion between multicast group IDs and the bitmask representation expected by the kernel
#[inline]
pub fn vec_to_bitmask(groups: Vec<u32>) -> u32 {
    groups.iter().fold(0, |acc, grp| acc | (1 << (grp - 1)))
}

/// Conversion between multicast group IDs and the bitmask expected by the kernel
#[inline]
pub fn bitmask_to_vec(mask: u32) -> Vec<u32> {
    let mut vec = Vec::new();
    // Number of bits in a u32
    for i in 1..=size_of::<u32>() * 8 {
        if (1 << (i - 1)) & mask != 0 {
            vec.push(i as u32);
        }
    }
    vec
}

/// Handle for the socket file descriptor
pub struct NlSocket {
    fd: c_int,
    buffer: Option<StreamReadBuffer<Vec<u8>>>,
}

impl NlSocket {
    /// Wrapper around `socket()` syscall filling in the netlink-specific information
    pub fn new(proto: NlFamily) -> Result<Self, io::Error> {
        let fd =
            match unsafe { libc::socket(AddrFamily::Netlink.into(), libc::SOCK_RAW, proto.into()) }
            {
                i if i >= 0 => Ok(i),
                _ => Err(io::Error::last_os_error()),
            }?;
        Ok(NlSocket { fd, buffer: None })
    }

    /// Set underlying socket file descriptor to be blocking
    pub fn block(&mut self) -> Result<&mut Self, io::Error> {
        match unsafe {
            libc::fcntl(
                self.fd,
                libc::F_SETFL,
                libc::fcntl(self.fd, libc::F_GETFL, 0) & !libc::O_NONBLOCK,
            )
        } {
            i if i < 0 => Err(io::Error::last_os_error()),
            _ => Ok(self),
        }
    }

    /// Set underlying socket file descriptor to be non blocking
    pub fn nonblock(&mut self) -> Result<&mut Self, io::Error> {
        match unsafe {
            libc::fcntl(
                self.fd,
                libc::F_SETFL,
                libc::fcntl(self.fd, libc::F_GETFL, 0) | libc::O_NONBLOCK,
            )
        } {
            i if i < 0 => Err(io::Error::last_os_error()),
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
            libc::bind(
                self.fd,
                &nladdr as *const _ as *const libc::sockaddr,
                size_of::<libc::sockaddr_nl>() as u32,
            )
        } {
            i if i >= 0 => (),
            _ => return Err(io::Error::last_os_error()),
        };
        if let Some(grps) = groups {
            self.add_mcast_membership(grps)?;
        }
        Ok(())
    }

    /// Set multicast groups for socket
    #[deprecated(since = "0.5.0", note = "Use add_multicast_membership instead")]
    pub fn set_mcast_groups(&mut self, groups: Vec<u32>) -> Result<(), io::Error> {
        self.add_mcast_membership(groups)
    }

    /// Join multicast groups for a socket
    pub fn add_mcast_membership(&mut self, groups: Vec<u32>) -> Result<(), io::Error> {
        let grps = vec_to_bitmask(groups);
        match unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_NETLINK,
                libc::NETLINK_ADD_MEMBERSHIP,
                &grps as *const _ as *const libc::c_void,
                size_of::<u32>() as libc::socklen_t,
            )
        } {
            i if i == 0 => Ok(()),
            _ => Err(io::Error::last_os_error()),
        }
    }

    /// Leave multicast groups for a socket
    pub fn drop_mcast_membership(&mut self, groups: Vec<u32>) -> Result<(), io::Error> {
        let grps = vec_to_bitmask(groups);
        match unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_NETLINK,
                libc::NETLINK_DROP_MEMBERSHIP,
                &grps as *const _ as *const libc::c_void,
                size_of::<u32>() as libc::socklen_t,
            )
        } {
            i if i == 0 => Ok(()),
            _ => Err(io::Error::last_os_error()),
        }
    }

    /// List joined groups for a socket
    pub fn list_mcast_membership(&mut self) -> Result<Vec<u32>, io::Error> {
        let mut grps = 0u32;
        let mut len = size_of::<u32>() as libc::socklen_t;
        match unsafe {
            libc::getsockopt(
                self.fd,
                libc::SOL_NETLINK,
                libc::NETLINK_LIST_MEMBERSHIPS,
                &mut grps as *mut _ as *mut libc::c_void,
                &mut len as *mut _ as *mut libc::socklen_t,
            )
        } {
            i if i == 0 => Ok(bitmask_to_vec(grps)),
            _ => Err(io::Error::last_os_error()),
        }
    }

    /// Send message encoded as byte slice to the netlink ID specified in the netlink header
    /// (`neli::nl::Nlmsghdr`)
    pub fn send<B>(&mut self, buf: B, flags: i32) -> Result<libc::ssize_t, io::Error>
    where
        B: AsRef<[u8]>,
    {
        match unsafe {
            libc::send(
                self.fd,
                buf.as_ref() as *const _ as *const c_void,
                buf.as_ref().len(),
                flags,
            )
        } {
            i if i >= 0 => Ok(i),
            _ => Err(io::Error::last_os_error()),
        }
    }

    /// Receive message encoded as byte slice from the netlink socket
    pub fn recv<B>(&mut self, mut buf: B, flags: i32) -> Result<libc::ssize_t, io::Error>
    where
        B: AsMut<[u8]>,
    {
        match unsafe {
            libc::recv(
                self.fd,
                buf.as_mut() as *mut _ as *mut c_void,
                buf.as_mut().len(),
                flags,
            )
        } {
            i if i >= 0 => Ok(i),
            _ => Err(io::Error::last_os_error()),
        }
    }

    /// Equivalent of `socket` and `bind` calls.
    pub fn connect(
        proto: NlFamily,
        pid: Option<u32>,
        groups: Option<Vec<u32>>,
    ) -> Result<Self, io::Error> {
        let mut s = NlSocket::new(proto)?;
        s.bind(pid, groups)?;
        Ok(s)
    }

    fn get_genl_family<T>(
        &mut self,
        family_name: &str,
    ) -> Result<Nlmsghdr<GenlId, Genlmsghdr<CtrlCmd, T>>, NlError>
    where
        T: NlAttrType,
    {
        let attrs = vec![Nlattr::new(None, CtrlAttr::FamilyName, family_name)?];
        let genlhdr = Genlmsghdr::new(CtrlCmd::Getfamily, 2, attrs)?;
        let nlhdr = Nlmsghdr::new(
            None,
            GenlId::Ctrl,
            vec![NlmF::Request, NlmF::Ack],
            None,
            None,
            genlhdr,
        );
        self.send_nl(nlhdr)?;

        let msg = self.recv_nl(None)?;
        self.recv_ack()?;
        Ok(msg)
    }

    /// Convenience function for resolving a `&str` containing the multicast group name to a
    /// numeric netlink ID
    pub fn resolve_genl_family(&mut self, family_name: &str) -> Result<u16, NlError> {
        let nlhdr = self.get_genl_family(family_name)?;
        let handle = nlhdr.nl_payload.get_attr_handle();
        Ok(handle.get_attr_payload_as::<u16>(CtrlAttr::FamilyId)?)
    }

    /// Convenience function for resolving a `&str` containing the multicast group name to a
    /// numeric netlink ID
    pub fn resolve_nl_mcast_group(
        &mut self,
        family_name: &str,
        mcast_name: &str,
    ) -> Result<u32, NlError> {
        let nlhdr = self.get_genl_family(family_name)?;
        let mut handle = nlhdr.nl_payload.get_attr_handle();
        let mcast_groups = handle.get_nested_attributes::<Index>(CtrlAttr::McastGroups)?;
        mcast_groups
            .iter()
            .filter_map(|item| {
                let nested_attrs = item.get_attr_handle::<CtrlAttrMcastGrp>().ok()?;
                let string = nested_attrs
                    .get_attr_payload_as::<String>(CtrlAttrMcastGrp::Name)
                    .ok()?;
                if string.as_str() == mcast_name {
                    nested_attrs
                        .get_attr_payload_as::<u32>(CtrlAttrMcastGrp::Id)
                        .ok()
                } else {
                    None
                }
            })
            .nth(0)
            .ok_or_else(|| NlError::new("Failed to resolve multicast group ID"))
    }

    /// Look up netlink family and multicast group name by ID
    pub fn lookup_id(&mut self, id: u32) -> Result<(String, String), NlError> {
        let attrs = vec![];
        let genlhdr = Genlmsghdr::<CtrlCmd, CtrlAttrMcastGrp>::new(CtrlCmd::Getfamily, 2, attrs)?;
        let nlhdr = Nlmsghdr::new(
            None,
            GenlId::Ctrl,
            vec![NlmF::Request, NlmF::Dump],
            None,
            None,
            genlhdr,
        );

        self.send_nl(nlhdr)?;
        for res_msg in self.iter::<Nlmsg, Genlmsghdr<u8, CtrlAttr>>() {
            let msg = res_msg?;
            if msg.nl_type == Nlmsg::Done {
                break;
            }

            let mut attributes = msg.nl_payload.get_attr_handle();
            let name = attributes.get_attr_payload_as::<String>(CtrlAttr::FamilyName)?;
            let groups = match attributes.get_nested_attributes::<Index>(CtrlAttr::McastGroups) {
                Ok(grps) => grps,
                Err(_) => continue,
            };
            for group_by_index in groups.iter() {
                let attributes = group_by_index.get_attr_handle::<CtrlAttrMcastGrp>()?;
                if let Ok(mcid) = attributes.get_attr_payload_as::<u32>(CtrlAttrMcastGrp::Id) {
                    if mcid == id {
                        let mcast_name =
                            attributes.get_attr_payload_as::<String>(CtrlAttrMcastGrp::Name)?;
                        return Ok((name, mcast_name));
                    }
                }
            }
        }

        Err(NlError::new("ID does not correspond to a multicast group"))
    }

    /// Convenience function to send an `Nlmsghdr` struct
    pub fn send_nl<T, P>(&mut self, msg: Nlmsghdr<T, P>) -> Result<(), NlError>
    where
        T: Nl + NlType,
        P: Nl,
    {
        let mut mem = StreamWriteBuffer::new_growable(Some(msg.asize()));
        msg.serialize(&mut mem)?;
        self.send(mem, 0)?;
        Ok(())
    }

    /// Convenience function to begin receiving a stream of `Nlmsghdr` structs
    pub fn recv_nl<T, P>(&mut self, buf_sz: Option<usize>) -> Result<Nlmsghdr<T, P>, NlError>
    where
        T: Nl + NlType,
        P: Nl,
    {
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
                Ok(())
            } else {
                if let Some(b) = self.buffer.as_mut() {
                    b.rewind()
                }
                Err(NlError::NoAck)
            }
        } else {
            Err(NlError::NoAck)
        }
    }

    /// Return an iterator object
    pub fn iter<T, P>(&mut self) -> NlMessageIter<T, P>
    where
        T: NlType,
        P: Nl,
    {
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

#[cfg(feature = "async")]
pub mod tokio {
    //! Tokio-specific features for neli
    //!
    //! This module contains a struct that wraps `NlSocket` for async IO.
    use super::*;

    use mio::{self, Evented};
    use tokio::prelude::{Async, AsyncRead, Stream};
    use tokio::reactor::PollEvented2;

    /// Tokio-enabled Netlink socket struct
    pub struct NlSocket<T, P> {
        socket: PollEvented2<super::NlSocket>,
        buffer: Option<StreamReadBuffer<Vec<u8>>>,
        type_data: PhantomData<T>,
        payload_data: PhantomData<P>,
    }

    impl<T, P> NlSocket<T, P>
    where
        T: NlType,
    {
        /// Setup NlSocket for use with tokio - set to nonblocking state and wrap in polling mechanism
        pub fn new(mut sock: super::NlSocket) -> io::Result<Self> {
            if sock.is_blocking()? {
                sock.nonblock()?;
            }
            Ok(NlSocket {
                socket: PollEvented2::new(sock),
                buffer: None,
                type_data: PhantomData,
                payload_data: PhantomData,
            })
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

    impl<T, P> Stream for NlSocket<T, P>
    where
        T: NlType,
        P: Nl,
    {
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
                Some(ref mut buf) => Ok(Async::Ready(Some(
                    Nlmsghdr::<T, P>::deserialize(buf).map_err(|_| io::ErrorKind::InvalidData)?,
                ))),
                None => Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
            }
        }
    }

    impl Evented for super::NlSocket {
        fn register(
            &self,
            poll: &mio::Poll,
            token: mio::Token,
            interest: mio::Ready,
            opts: mio::PollOpt,
        ) -> io::Result<()> {
            poll.register(
                &mio::unix::EventedFd(&self.as_raw_fd()),
                token,
                interest,
                opts,
            )
        }

        fn reregister(
            &self,
            poll: &mio::Poll,
            token: mio::Token,
            interest: mio::Ready,
            opts: mio::PollOpt,
        ) -> io::Result<()> {
            poll.reregister(
                &mio::unix::EventedFd(&self.as_raw_fd()),
                token,
                interest,
                opts,
            )
        }

        fn deregister(&self, poll: &mio::Poll) -> io::Result<()> {
            poll.deregister(&mio::unix::EventedFd(&self.as_raw_fd()))
        }
    }
}

impl Drop for NlSocket {
    /// Closes underlying file descriptor to avoid file descriptor leaks.
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use std::io::Read;

    use consts::Nlmsg;

    #[test]
    fn test_socket_nonblock() {
        let mut s = NlSocket::connect(NlFamily::Generic, None, None).unwrap();
        s.nonblock().unwrap();
        assert_eq!(s.is_blocking().unwrap(), false);
        let buf = &mut [0; 4];
        match s.read(buf) {
            Err(e) => {
                if e.kind() != io::ErrorKind::WouldBlock {
                    panic!("Error: {}", e);
                }
            }
            Ok(_) => {
                panic!("Should not return data");
            }
        }
    }

    #[test]
    fn multi_msg_iter() {
        let mut vec = vec![];
        let mut stream = StreamWriteBuffer::new_growable_ref(&mut vec);

        let nl1 = Nlmsghdr::new(
            None,
            Nlmsg::Noop,
            vec![NlmF::Multi],
            None,
            None,
            Genlmsghdr::new(
                CtrlCmd::Unspec,
                2,
                vec![
                    Nlattr::new(None, CtrlAttr::FamilyId, 5u32).unwrap(),
                    Nlattr::new(None, CtrlAttr::FamilyName, "my_family_name").unwrap(),
                ],
            )
            .unwrap(),
        );
        let nl2 = Nlmsghdr::new(
            None,
            Nlmsg::Noop,
            vec![NlmF::Multi],
            None,
            None,
            Genlmsghdr::new(
                CtrlCmd::Unspec,
                2,
                vec![
                    Nlattr::new(None, CtrlAttr::FamilyId, 6u32).unwrap(),
                    Nlattr::new(None, CtrlAttr::FamilyName, "my_other_family_name").unwrap(),
                ],
            )
            .unwrap(),
        );

        nl1.serialize(&mut stream).unwrap();
        nl2.serialize(&mut stream).unwrap();

        let mut s = NlSocket {
            fd: -1,
            buffer: Some(StreamReadBuffer::new(vec)),
        };
        let mut iter = s.iter();
        if let Some(Ok(nl_next)) = iter.next() {
            assert_eq!(nl_next, nl1);
        } else {
            panic!("Expected message not found");
        }
        if let Some(Ok(nl_next)) = iter.next() {
            assert_eq!(nl_next, nl2);
        } else {
            panic!("Expected message not found");
        }
    }
}
