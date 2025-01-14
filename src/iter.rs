//! Module for iteration over netlink responses

use std::{fmt::Debug, marker::PhantomData};

use crate::{
    consts::nl::{NlType, NlmF, Nlmsg},
    err::NlError,
    nl::{NlPayload, Nlmsghdr},
    socket::NlSocketHandle,
    FromBytesWithInput,
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
/// [`NlSocketHandle`] type.
///
/// This iterator has two high-level options:
/// * Iterate indefinitely over messages. This is most
///   useful in the case of subscribing to messages in a
///   multicast group.
/// * Iterate until a message is returned with
///   [`Nlmsg::Done`] is set.
///   This is most useful in the case of request-response workflows
///   where the iterator will parse and iterate through all of the
///   messages with [`NlmF::Multi`] set
///   until a message with
///   [`Nlmsg::Done`] is
///   received at which point [`None`] will be returned indicating the
///   end of the response.
pub struct NlMessageIter<'a, T, P> {
    sock_ref: &'a mut NlSocketHandle,
    next_is_none: Option<bool>,
    type_: PhantomData<T>,
    payload: PhantomData<P>,
}

impl<'a, T, P> NlMessageIter<'a, T, P>
where
    T: NlType + Debug,
    P: FromBytesWithInput<'a, Input = usize> + Debug,
{
    /// Construct a new iterator that yields
    /// [`Nlmsghdr`] structs from the provided
    /// buffer. `behavior` set to
    /// [`IterationBehavior::IterIndefinitely`] will treat
    /// messages as a never-ending stream.
    /// [`IterationBehavior::EndMultiOnDone`] will cause
    /// [`NlMessageIter`] to respect the netlink identifiers
    /// [`NlmF::Multi`] and
    /// [`Nlmsg::Done`].
    ///
    /// If `behavior` is [`IterationBehavior::EndMultiOnDone`],
    /// this means that [`NlMessageIter`] will iterate through
    /// either exactly one message if
    /// [`NlmF::Multi`] is not
    /// set, or through all consecutive messages with
    /// [`NlmF::Multi`] set until
    /// a terminating message with
    /// [`Nlmsg::Done`] is reached
    /// at which point [`None`] will be returned by the iterator.
    pub fn new(sock_ref: &'a mut NlSocketHandle, behavior: IterationBehavior) -> Self {
        NlMessageIter {
            sock_ref,
            next_is_none: if behavior == IterationBehavior::IterIndefinitely {
                None
            } else {
                Some(false)
            },
            type_: PhantomData,
            payload: PhantomData,
        }
    }

    fn next<TT, PP>(&mut self) -> Option<Result<Nlmsghdr<TT, PP>, NlError<TT, PP>>>
    where
        TT: NlType + Debug,
        PP: for<'c> FromBytesWithInput<'c, Input = usize> + Debug,
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

        if let NlPayload::Ack(_) = next.nl_payload {
            self.next_is_none = self.next_is_none.map(|_| true);
        } else if (!next.nl_flags.contains(&NlmF::Multi)
            || next.nl_type.into() == Nlmsg::Done.into())
            && !self.sock_ref.needs_ack
        {
            self.next_is_none = self.next_is_none.map(|_| true);
        }

        Some(Ok(next))
    }
}

impl<T, P> Iterator for NlMessageIter<'_, T, P>
where
    T: NlType + Debug,
    P: for<'b> FromBytesWithInput<'b, Input = usize> + Debug,
{
    type Item = Result<Nlmsghdr<T, P>, NlError<T, P>>;

    fn next(&mut self) -> Option<Self::Item> {
        NlMessageIter::next::<T, P>(self)
    }
}
