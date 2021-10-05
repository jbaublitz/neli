use std::mem;

use byteorder::{ByteOrder, NativeEndian};

/// Get the length of a netlink message from a buffer
pub fn packet_length_u32(buffer: &[u8], position: usize) -> usize {
    let len_buffer = &buffer[position..position + mem::size_of::<u32>()];
    <NativeEndian as ByteOrder>::read_u32(len_buffer) as usize
}
