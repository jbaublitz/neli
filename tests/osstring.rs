#![cfg(unix)]

use std::{
    ffi::{OsStr, OsString},
    io::Cursor,
    os::unix::ffi::{OsStrExt, OsStringExt},
};

use neli::{
    attr::Attribute, consts::rtnl::Ifla, rtnl::RtattrBuilder, FromBytesWithInput, Size, ToBytes,
};

#[test]
fn interface_names_preserve_bytes_through_attribute_callers() {
    for name in [
        b"eth0".as_slice(),
        b"",
        b"interface-\xff",
        "接口".as_bytes(),
    ] {
        let borrowed = OsStr::from_bytes(name);
        let owned = OsString::from_vec(name.to_vec());
        let attribute = RtattrBuilder::default()
            .rta_type(Ifla::Ifname)
            .rta_payload(borrowed)
            .build()
            .unwrap();
        let owned_attribute = RtattrBuilder::default()
            .rta_type(Ifla::Ifname)
            .rta_payload(owned.clone())
            .build()
            .unwrap();
        let expected = [name, &[0]].concat();
        assert_eq!(attribute.payload().as_ref(), expected);
        assert_eq!(owned_attribute.payload(), attribute.payload());
        assert_eq!(borrowed.unpadded_size(), expected.len());
        assert_eq!(owned.unpadded_size(), expected.len());
        assert_eq!(
            attribute.get_payload_as_with_len::<OsString>().unwrap(),
            owned
        );
        if let Ok(utf8) = std::str::from_utf8(name) {
            let utf8_attribute = RtattrBuilder::default()
                .rta_type(Ifla::Ifname)
                .rta_payload(utf8)
                .build()
                .unwrap();
            assert_eq!(utf8_attribute.payload(), attribute.payload());
        }
    }
}

#[test]
fn os_strings_observe_cursor_bounds() {
    let mut input = Cursor::new([b'!', b'e', 0xff, 0, b'?']);
    input.set_position(1);
    let name = OsString::from_bytes_with_input(&mut input, 3).unwrap();
    assert_eq!(name.as_bytes(), b"e\xff");
    assert_eq!(input.position(), 4);
    let mut output = Cursor::new(vec![b'!']);
    output.set_position(1);
    name.to_bytes(&mut output).unwrap();
    assert_eq!(output.into_inner(), vec![b'!', b'e', 0xff, 0]);
}

#[test]
fn malformed_os_strings_return_errors_without_consuming_input() {
    for (bytes, position, length) in [
        (b"x\0".as_slice(), 0, 0),
        (b"name".as_slice(), 0, 4),
        (b"x\0".as_slice(), 0, 3),
        (b"x\0".as_slice(), 1, usize::MAX),
        (b"x\0".as_slice(), 3, 1),
    ] {
        let mut input = Cursor::new(bytes);
        input.set_position(position);
        assert!(OsString::from_bytes_with_input(&mut input, length).is_err());
        assert_eq!(input.position(), position);
    }
}
