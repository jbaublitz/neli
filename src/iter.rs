//! Module for iteration over netlink responses

use std::{fmt::Debug, marker::PhantomData};

use crate::{
    consts::nl::{NlType, NlTypeWrapper, NlmF, Nlmsg},
    err::NlError,
    nl::{NlPayload, Nlmsghdr},
    socket::NlSocketHandle,
    Nl,
};

/// Define iteration behavior when traversing a stream of netlink messages.
#[derive(PartialEq)]
pub enum IterationBehavior {
    /// End iteration of multi-part messages when a DONE message is reached.
    EndMultiOnDone,
    /// End iteration of multi-part messages when a DONE message
    /// is reached and check for an ACK.
    EndMultiOnDoneAndAck,
    /// Iterate indefinitely. Mostly useful for multicast subscriptions.
    IterIndefinitely,
}

/// Iterator over messages in an `NlSocket` type.
///
/// This iterator has two options:
/// * Iterate indefinitely over messages. This is most
/// useful in the case of subscribing to messages in a
/// multicast group.
/// * Iterate until a message is returned with `Nlmsg::Done`
/// is set. This is most useful in the case of request-response
/// workflows where the iterator will parse and iterate through
/// all of the messages with `NlmF::Multi` set until a message
/// with `Nlmsg::Done` is received at which point `None` will
/// be returned indicating the end of the response.
pub struct NlMessageIter<'a, T, P> {
    sock_ref: &'a mut NlSocketHandle,
    needs_ack: Option<bool>,
    next_is_none: Option<bool>,
    type_: PhantomData<T>,
    payload: PhantomData<P>,
}

impl<'a, T, P> NlMessageIter<'a, T, P>
where
    T: Nl + NlType + Debug,
    P: Nl + Debug,
{
    /// Construct a new iterator that yields `Nlmsghdr` structs
    /// from the provided buffer. `iterate_indefinitely` set to
    /// `true` will treat messages as a never-ending stream.
    /// `false` will cause `NlMessageIter` to respect the
    /// netlink identifiers [`NlmF::Multi`] and [`Nlmsg::Done`].
    ///
    /// If `iterate_indefinitely` is `false`, this means that
    /// `NlMessageIter` will iterate through either exactly one
    /// message if [`NlmF::Multi`] is not set, or through all
    /// consecutive messages with [`NlmF::Multi`] set until
    /// a terminating message with [`Nlmsg::Done`] is reached
    /// at which point `None` will be returned by the iterator.
    pub fn new(sock_ref: &'a mut NlSocketHandle, behavior: IterationBehavior) -> Self {
        NlMessageIter {
            sock_ref,
            needs_ack: match behavior {
                IterationBehavior::EndMultiOnDone => Some(false),
                IterationBehavior::EndMultiOnDoneAndAck => Some(true),
                _ => None,
            },
            next_is_none: if behavior == IterationBehavior::IterIndefinitely {
                None
            } else {
                Some(false)
            },
            type_: PhantomData,
            payload: PhantomData,
        }
    }

    fn next<TT, PP>(&mut self) -> Option<Result<Nlmsghdr<TT, PP>, NlError>>
    where
        TT: NlType + Debug,
        PP: Nl + Debug,
    {
        if let Some(true) = self.next_is_none {
            return None;
        }

        let next_res = self.sock_ref.recv::<TT, PP>();
        let next = match next_res {
            Ok(Some(n)) => n,
            Ok(None) => return None,
            Err(e) => return Some(Err(e)),
        };
        if self.next_is_none.is_some() && !next.nl_flags.contains(&NlmF::Multi) {
            self.next_is_none = Some(true);
        }
        if next.nl_type.into() == Nlmsg::Done.into() {
            if let Some(true) = self.needs_ack {
                if let Ok(Some(n)) = self.sock_ref.recv::<TT, PP>() {
                    if let NlPayload::Payload(_) = n.nl_payload {
                        return Some(Err(NlError::NoAck));
                    }
                }
            }
            None
        } else {
            Some(Ok(next))
        }
    }
}

impl<'a, P> Iterator for NlMessageIter<'a, NlTypeWrapper, P>
where
    P: Nl + Debug,
{
    type Item = Result<Nlmsghdr<NlTypeWrapper, P>, NlError>;

    fn next(&mut self) -> Option<Self::Item> {
        NlMessageIter::next::<NlTypeWrapper, P>(self)
    }
}
