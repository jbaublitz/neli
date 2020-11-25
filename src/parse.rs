use std::mem;

use byteorder::{ByteOrder, NativeEndian};

use crate::{
    consts::nl::NlType,
    err::{DeError, NlError},
    nl::{NlPayload, Nlmsghdr},
    Nl,
};

/// Get the length of a netlink message from a buffer
pub fn packet_length_u16(buffer: &[u8], position: usize) -> usize {
    let len_buffer = &buffer[position..position + mem::size_of::<u16>()];
    <NativeEndian as ByteOrder>::read_u16(len_buffer) as usize
}

/// Get the length of a netlink message from a buffer
pub fn packet_length_u32(buffer: &[u8], position: usize) -> usize {
    let len_buffer = &buffer[position..position + mem::size_of::<u32>()];
    <NativeEndian as ByteOrder>::read_u32(len_buffer) as usize
}

/// Parse the next packet in the buffer.
///
/// This parsing method will only parse top level
/// [`Nlmsghdr`][crate::nl::Nlmsghdr] packets.
///
/// The buffer that's passed in should be the entire contents
/// from a read from the socket.
///
/// This position should start at 0. The [`usize`] that is returned
/// is the updated position and should be stored as the new position.
pub fn parse_next<T, P>(
    buffer: &[u8],
    mut position: usize,
    expects_ack: bool,
) -> Result<(usize, Nlmsghdr<T, P>), NlError>
where
    T: NlType,
    P: Nl,
{
    let end = buffer.len();
    // Get the next packet length at the current position of the
    // buffer for the next read operation.
    let next_packet_len = packet_length_u32(buffer, position);
    // If the packet extends past the end of the number of bytes
    // read into the buffer, return an error; something
    // has gone wrong.
    if position + next_packet_len > end {
        return Err(NlError::new(DeError::UnexpectedEOB));
    }

    // Deserialize the next Nlmsghdr struct.
    let deserialized_packet_result =
        Nlmsghdr::<T, P>::deserialize(&buffer[position..position + next_packet_len]);

    let packet = deserialized_packet_result
        .map(|packet| {
            // If successful, forward the position of the buffer
            // for the next read.
            position += next_packet_len;

            packet
        })
        .map_err(NlError::new)?;

    if let NlPayload::Err(e) = packet.nl_payload {
        return Err(NlError::Nlmsgerr(e));
    }

    if expects_ack {
        if let NlPayload::Payload(_) = packet.nl_payload {
            return Err(NlError::NoAck);
        }
    }

    Ok((position, packet))
}
