//! Module for iteration over netlink responses

use std::{fmt::Debug, io::Cursor, marker::PhantomData};

use crate::{
    consts::nl::{NlType, NlmF, Nlmsg},
    err::NlError,
    nl::{NlPayload, Nlmsghdr},
    socket::NlSocket,
    FromBytes, FromBytesWithInput,
};

/// Define iteration behavior when traversing a stream of netlink
/// messages.
#[derive(PartialEq, Eq)]
pub enum IterationBehavior {
    /// End iteration of multi-part messages when a DONE message is
    /// reached.
    EndMultiOnDone,
    /// Iterate indefinitely. Mostly useful for multicast
    /// subscriptions.
    IterIndefinitely,
}

/// Iterator over messages in an
/// [`NlSocketHandle`][crate::socket::NlSocketHandle] type.
///
/// This iterator has two high-level options:
/// * Iterate indefinitely over messages. This is most
/// useful in the case of subscribing to messages in a
/// multicast group.
/// * Iterate until a message is returned with
/// [`Nlmsg::Done`][crate::consts::nl::Nlmsg::Done] is set.
/// This is most useful in the case of request-response workflows
/// where the iterator will parse and iterate through all of the
/// messages with [`NlmF::MULTI`][crate::consts::nl::NlmF::MULTI] set
/// until a message with
/// [`Nlmsg::Done`][crate::consts::nl::Nlmsg::Done] is
/// received at which point [`None`] will be returned indicating the
/// end of the response.
pub struct NlMessageIter<'a, T, P> {
    needs_ack: &'a mut bool,
    socket: &'a NlSocket,
    buffer: &'a mut Vec<u8>,
    next_is_none: Option<bool>,
    cur_info: Option<(u64, usize)>,
    phantom: PhantomData<(T, P)>,
}

impl<'a, T, P> NlMessageIter<'a, T, P>
where
    T: NlType + Debug,
    P: FromBytesWithInput<'a, Input = usize> + Debug,
{
    /// Construct a new iterator that yields
    /// [`Nlmsghdr`][crate::nl::Nlmsghdr] structs from the provided
    /// buffer. `behavior` set to
    /// [`IterationBehavior::IterIndefinitely`] will treat
    /// messages as a never-ending stream.
    /// [`IterationBehavior::EndMultiOnDone`] will cause
    /// [`NlMessageIter`] to respect the netlink identifiers
    /// [`NlmF::MULTI`][crate::consts::nl::NlmF::MULTI] and
    /// [`Nlmsg::Done`][crate::consts::nl::Nlmsg::Done].
    ///
    /// If `behavior` is [`IterationBehavior::EndMultiOnDone`],
    /// this means that [`NlMessageIter`] will iterate through
    /// either exactly one message if
    /// [`NlmF::MULTI`][crate::consts::nl::NlmF::MULTI] is not
    /// set, or through all consecutive messages with
    /// [`NlmF::MULTI`][crate::consts::nl::NlmF::MULTI] set until
    /// a terminating message with
    /// [`Nlmsg::Done`][crate::consts::nl::Nlmsg::Done] is reached
    /// at which point [`None`] will be returned by the iterator.
    pub fn new(
        needs_ack: &'a mut bool,
        socket: &'a NlSocket,
        buffer: &'a mut Vec<u8>,
        behavior: IterationBehavior,
    ) -> Self {
        NlMessageIter {
            needs_ack,
            socket,
            buffer,
            next_is_none: if behavior == IterationBehavior::IterIndefinitely {
                None
            } else {
                Some(false)
            },
            cur_info: None,
            phantom: PhantomData,
        }
    }

    fn next<TT, PP>(&mut self) -> Option<Result<Nlmsghdr<TT, PP>, NlError<TT, PP>>>
    where
        TT: NlType + Debug + Copy + Into<u16>,
        PP: for<'b> FromBytesWithInput<'b, Input = usize> + Debug,
    {
        if let Some(true) = self.next_is_none {
            return None;
        }

        let mut cursor = match self.cur_info {
            None => {
                let read = match self.socket.recv(&mut *self.buffer, 0) {
                    Ok(r) => r,
                    Err(e) => return Some(Err(NlError::from(e))),
                };
                Cursor::new(&self.buffer[..read])
            }
            Some((pos, len)) => {
                let mut cur = Cursor::new(&self.buffer[..len]);
                cur.set_position(pos);
                cur
            }
        };

        let nlmsghdr_res = Nlmsghdr::<TT, PP>::from_bytes(&mut cursor);

        let pos = cursor.position();
        let len = cursor.get_ref().len();
        if pos == len as u64 {
            self.cur_info = None;
        } else {
            self.cur_info = Some((pos, len));
        }

        let mut next = match nlmsghdr_res {
            Ok(n) => n,
            Err(e) => return Some(Err(NlError::from(e))),
        };

        let nl_type: u16 = (*next.nl_type()).into();
        if let NlPayload::Ack(_) = next.nl_payload() {
            self.next_is_none = self.next_is_none.map(|_| true);
            if *self.needs_ack {
                *self.needs_ack = false;
            } else {
                return Some(Err(NlError::UnexpectedAck));
            }
        } else if let Some(e) = next.get_err() {
            return Some(Err(NlError::Nlmsgerr(e)));
        } else if (!next.nl_flags().contains(NlmF::MULTI) || nl_type == Nlmsg::Done.into())
            && !*self.needs_ack
        {
            self.next_is_none = self.next_is_none.map(|_| true);
        }

        Some(Ok(next))
    }
}

impl<'a, T, P> Iterator for NlMessageIter<'a, T, P>
where
    T: NlType + Debug,
    P: for<'b> FromBytesWithInput<'b, Input = usize> + Debug,
{
    type Item = Result<Nlmsghdr<T, P>, NlError<T, P>>;

    fn next(&mut self) -> Option<Self::Item> {
        NlMessageIter::next::<T, P>(self)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use std::os::unix::io::FromRawFd;

    use crate::{
        consts::{
            genl::{CtrlAttr, CtrlCmd},
            nl::{NlTypeWrapper, NlmF, Nlmsg},
        },
        genl::{AttrTypeBuilder, GenlmsghdrBuilder, NlattrBuilder},
        nl::{NlPayload, NlmsghdrBuilder},
        test::setup,
        types::{GenlBuffer, NlBuffer},
        ToBytes,
    };

    #[test]
    fn multi_msg_iter() {
        setup();

        let attrs = vec![
            NlattrBuilder::default()
                .nla_type(
                    AttrTypeBuilder::default()
                        .nla_type(CtrlAttr::FamilyId)
                        .build()
                        .unwrap(),
                )
                .nla_payload(5u32)
                .build()
                .unwrap(),
            NlattrBuilder::default()
                .nla_type(
                    AttrTypeBuilder::default()
                        .nla_type(CtrlAttr::FamilyName)
                        .build()
                        .unwrap(),
                )
                .nla_payload("my_family_name")
                .build()
                .unwrap(),
        ]
        .into_iter()
        .collect::<GenlBuffer<_, _>>();
        let nl1 = NlmsghdrBuilder::default()
            .nl_type(NlTypeWrapper::Nlmsg(Nlmsg::Noop))
            .nl_flags(NlmF::MULTI)
            .nl_payload(NlPayload::Payload(
                GenlmsghdrBuilder::default()
                    .cmd(CtrlCmd::Unspec)
                    .version(2)
                    .attrs(attrs)
                    .build()
                    .unwrap(),
            ))
            .build()
            .unwrap();

        let nl2 = NlmsghdrBuilder::default()
            .nl_type(NlTypeWrapper::Nlmsg(Nlmsg::Done))
            .nl_flags(NlmF::MULTI)
            .nl_payload(NlPayload::Empty)
            .build()
            .unwrap();

        let attrs = vec![
            NlattrBuilder::default()
                .nla_type(
                    AttrTypeBuilder::default()
                        .nla_type(CtrlAttr::FamilyId)
                        .build()
                        .unwrap(),
                )
                .nla_payload(6u32)
                .build()
                .unwrap(),
            NlattrBuilder::default()
                .nla_type(
                    AttrTypeBuilder::default()
                        .nla_type(CtrlAttr::FamilyName)
                        .build()
                        .unwrap(),
                )
                .nla_payload("my_other_family_name")
                .build()
                .unwrap(),
        ]
        .into_iter()
        .collect::<GenlBuffer<_, _>>();
        let nl3 = NlmsghdrBuilder::default()
            .nl_type(NlTypeWrapper::Nlmsg(Nlmsg::Noop))
            .nl_flags(NlmF::MULTI)
            .nl_payload(NlPayload::Payload(
                GenlmsghdrBuilder::default()
                    .cmd(CtrlCmd::Unspec)
                    .version(2)
                    .attrs(attrs)
                    .build()
                    .unwrap(),
            ))
            .build()
            .unwrap();
        let v = vec![nl1.clone(), nl2.clone(), nl3]
            .into_iter()
            .collect::<NlBuffer<_, _>>();
        let mut buffer = Cursor::new(Vec::new());
        let mut bytes = {
            v.to_bytes(&mut buffer).unwrap();
            buffer.into_inner()
        };

        let mut needs_ack = false;
        let socket = unsafe { NlSocket::from_raw_fd(-1) };
        let len = bytes.len();
        let mut iter = NlMessageIter::new(
            &mut needs_ack,
            &socket,
            &mut bytes,
            IterationBehavior::EndMultiOnDone,
        );
        iter.cur_info = Some((0, len));
        let nl = iter.map(|req| req.unwrap()).collect::<NlBuffer<_, _>>();

        assert_eq!(nl, vec![nl1, nl2].into_iter().collect::<NlBuffer<_, _>>());
    }
}
