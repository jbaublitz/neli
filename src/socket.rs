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
//! The `stream` feature exposed by `cargo` allows the socket to use Rust's tokio for async IO.
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

use buffering::{StreamReadBuffer, StreamWriteBuffer};
use libc::{self, c_int, c_void};

use consts::{
    self, AddrFamily, CtrlAttr, CtrlAttrMcastGrp, CtrlCmd, GenlId, NlAttrType, NlFamily, NlType,
    NlmF,
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
        let fd =
            match unsafe { libc::socket(AddrFamily::Netlink.into(), libc::SOCK_RAW, proto.into()) }
            {
                i if i >= 0 => Ok(i),
                _ => Err(io::Error::last_os_error()),
            }?;
        Ok(NlSocket {
            fd,
            buffer: None,
            pid: None,
            seq: if track_seq { Some(0) } else { None },
        })
    }

    /// Manually increment sequence number
    pub fn increment_seq(&mut self) {
        self.seq.map(|seq| seq + 1);
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
    ///
    /// The pid parameter sets PID checking.
    /// * `None` means checking is off.
    /// * `Some(0)` turns checking on, but takes the PID from the first received message.
    /// * `Some(pid)` uses the given PID.
    pub fn bind(&mut self, pid: Option<u32>, groups: Option<Vec<u32>>) -> Result<(), io::Error> {
        let mut nladdr = unsafe { zeroed::<libc::sockaddr_nl>() };
        nladdr.nl_family = libc::c_int::from(AddrFamily::Netlink) as u16;
        nladdr.nl_pid = pid.unwrap_or(0);
        self.pid = pid;
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
            self.set_mcast_groups(grps)?;
        }
        Ok(())
    }

    /// Set multicast groups for socket
    pub fn set_mcast_groups(&mut self, groups: Vec<u32>) -> Result<(), io::Error> {
        let grps = groups
            .into_iter()
            .fold(0, |acc, next| acc | (1 << (next - 1)));
        match unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_NETLINK,
                libc::NETLINK_ADD_MEMBERSHIP,
                &grps as *const _ as *const libc::c_void,
                size_of::<u32>() as libc::socklen_t,
            )
        } {
            i if i == 0 => {
                self.pid = None;
                Ok(())
            }
            _ => Err(io::Error::last_os_error()),
        }
    }

    /// Send message encoded as byte slice to the netlink ID specified in the netlink header
    /// (`neli::nl::Nlmsghdr`)
    pub fn send<B>(&self, buf: B, flags: i32) -> Result<libc::size_t, io::Error>
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
            i if i >= 0 => Ok(i as libc::size_t),
            _ => Err(io::Error::last_os_error()),
        }
    }

    /// Receive message encoded as byte slice from the netlink socket
    pub fn recv<B>(&self, mut buf: B, flags: i32) -> Result<libc::size_t, io::Error>
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
            i if i >= 0 => Ok(i as libc::size_t),
            _ => Err(io::Error::last_os_error()),
        }
    }

    /// Equivalent of `socket` and `bind` calls.
    pub fn connect(
        proto: NlFamily,
        pid: Option<u32>,
        groups: Option<Vec<u32>>,
        track_seq: bool,
    ) -> Result<Self, io::Error> {
        let mut s = NlSocket::new(proto, track_seq)?;
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
        let mcast_groups =
            handle.get_nested_attributes::<CtrlAttrMcastGrp>(CtrlAttr::McastGroups)?;
        mcast_groups
            .iter()
            .filter_map(|item| {
                let nested_attrs = item.get_nested_attributes::<CtrlAttrMcastGrp>().ok()?;
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

    /// Convenience function to send an `Nlmsghdr` struct
    pub fn send_nl<T, P>(&mut self, mut msg: Nlmsghdr<T, P>) -> Result<(), NlError>
    where
        T: Nl + NlType,
        P: Nl,
    {
        let mut mem = StreamWriteBuffer::new_growable(Some(msg.asize()));
        if let Some(ref mut seq) = self.seq {
            *seq += 1;
            msg.nl_seq = *seq;
        }
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
        match self.pid {
            // PID checking turned off.
            None => (),
            // No PID set yet, store the current one.
            Some(0) => self.pid = Some(msg.nl_pid),
            // PID check OK
            Some(pid) if pid == msg.nl_pid => (),
            // PID doesn't match
            Some(_) => return Err(NlError::BadPid),
        }
        if let Some(seq) = self.seq.as_mut() {
            *seq += 1;
        }
        if self.buffer.as_ref().map(|b| b.at_end()).unwrap_or(false) {
            self.buffer = None;
        }
        Ok(msg)
    }

    /// Consume an ACK and return an error if an ACK is not found
    pub fn recv_ack(&mut self) -> Result<(), NlError> {
        if let Ok(ack) = self.recv_nl::<consts::Nlmsg, Nlmsgerr<consts::Nlmsg>>(None) {
            if ack.nl_type == consts::Nlmsg::Error && ack.nl_payload.error == 0 {
                // PID check done as part of recv_nl already
                if let Some(seq) = self.seq {
                    if seq != ack.nl_seq {
                        return Err(NlError::BadSeq);
                    }
                }
                Ok(())
            } else {
                if let Some(b) = self.buffer.as_mut() {
                    b.rewind()
                }
                if ack.nl_type == consts::Nlmsg::Error {
                    let err = std::io::Error::from_raw_os_error(-ack.nl_payload.error as _);
                    Err(NlError::Msg(err.to_string()))
                } else {
                    Err(NlError::NoAck)
                }
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

#[cfg(feature = "stream")]
pub mod tokio {
    //! Tokio-specific features for neli
    //!
    //! This module contains a struct that wraps `NlSocket` for async IO.
    use super::*;

    use mio::{self, Evented};
    use pin_project::pin_project;
    use std::io::Write;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::Error;
    use tokio::prelude::{AsyncRead, AsyncWrite, Sink, Stream};
    use tokio_net::util::PollEvented;

    /// Tokio-enabled Netlink socket struct
    #[pin_project]
    pub struct NlSocket<T, P> {
        #[pin]
        socket: PollEvented<super::NlSocket>,
        buffer: Option<StreamReadBuffer<Vec<u8>>>,
        write_buffer: Vec<u8>,
        write_pos: usize,
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
                socket: PollEvented::new(sock),
                buffer: None,
                write_buffer: vec![0u8; MAX_NL_LENGTH],
                write_pos: 0,
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
        type Item = std::io::Result<Nlmsghdr<T, P>>;

        fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
            let empty = self.empty();
            let this = self.project();
            let socket = this.socket;
            let buffer = this.buffer;
            if empty {
                let mut mem = vec![0; MAX_NL_LENGTH];
                let bytes_read = match socket.poll_read(cx, mem.as_mut_slice()) {
                    Poll::Ready(Ok(0)) => return Poll::Ready(None),
                    Poll::Ready(Ok(i)) => i,
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Some(Err(e))),
                };
                mem.truncate(bytes_read);
                *buffer = Some(StreamReadBuffer::new(mem));
            }

            match buffer {
                Some(ref mut buf) => {
                    Poll::Ready(Some(Ok(Nlmsghdr::<T, P>::deserialize(buf)
                        .map_err(|_| io::ErrorKind::InvalidData)?)))
                }
                None => Poll::Ready(Some(Err(io::Error::from(io::ErrorKind::UnexpectedEof)))),
            }
        }
    }

    impl<T, P> Sink<Nlmsghdr<T, P>> for NlSocket<T, P>
    where
        T: NlType,
        P: Nl,
    {
        type Error = io::Error;

        fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            let this = self.project();
            let socket = this.socket;
            match socket.poll_write_ready(cx) {
                Poll::Ready(Ok(_)) => Poll::Ready(Ok(())),
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            }
        }

        fn start_send(mut self: Pin<&mut Self>, item: Nlmsghdr<T, P>) -> Result<(), Self::Error> {
            let write_pos = self.write_pos as u64;
            let mut writer = StreamWriteBuffer::new_sized(self.write_buffer.as_mut_slice());
            writer.set_position(write_pos);
            let len = item.nl_len as usize;
            item.serialize(&mut writer)
                .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
            self.write_pos += len;
            Ok(())
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            let this = self.project();
            let socket = this.socket;
            let buffer = this.write_buffer;
            let write_pos = this.write_pos;
            let buffer: &[u8] = buffer.as_ref();
            match socket.poll_write(cx, &buffer[0..*write_pos]) {
                Poll::Ready(Ok(size)) if size <= *write_pos => {
                    *write_pos -= size;
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(Ok(_)) => unreachable!(),
                Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
                Poll::Pending => Poll::Pending,
            }
        }

        fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            self.poll_flush(cx)
        }
    }

    impl Write for super::NlSocket {
        fn write(&mut self, buf: &[u8]) -> Result<usize, Error> {
            self.send(buf, 0)
        }

        fn flush(&mut self) -> Result<(), Error> {
            // todo
            Ok(())
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
        let mut s = NlSocket::connect(NlFamily::Generic, None, None, true).unwrap();
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
            seq: None,
            pid: None,
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
