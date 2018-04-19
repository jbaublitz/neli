#[macro_export]
macro_rules! attr_cmd_to_nl {
    ( $name:ident, $( $cmd:ident ),* ) => {
        #[derive(Clone,Debug,PartialEq)]
        pub enum $name {
            $( $cmd, )*
            UnrecognizedVariant,
        }

        impl Into<u8> for $name {
            fn into(self) -> u8 {
                self as u8
            }
        }

        impl From<u8> for $name {
            fn from(v: u8) -> Self {
                match v {
                    $(
                        i if i == $name::$cmd as u8 => $name::$cmd,
                    )*
                    _ => $name::UnrecognizedVariant,
                }
            }
        }

        impl Nl for $name {
            type SerIn = ();
            type DeIn = ();

            fn serialize(&self, mem: &mut MemWrite) -> Result<(), SerError> {
                let val = self.clone() as u8;
                val.serialize(mem)?;
                Ok(())
            }

            fn deserialize(mem: &mut MemRead) -> Result<Self, DeError> {
                let cmd = u8::deserialize(mem)?;
                Ok(Self::from(cmd))
            }

            fn size(&self) -> usize {
                0u8.size()
            }
        }
    }
}

#[cfg(test)]
mod test {
    use {Nl,MemRead,MemWrite};
    use err::{SerError,DeError};

    #[test]
    fn test_attr_cmd_to_nl_macro() {
        attr_cmd_to_nl!(TestCmd, Cmd0, Cmd1, Cmd2, Cmd3);

        let slice = &mut [0u8; 1];
        let mut ser_mem = MemWrite::new_slice(slice);
        TestCmd::Cmd1.serialize(&mut ser_mem).unwrap();
        assert_eq!(ser_mem.as_slice(), &[1]);
        let mut de_mem = ser_mem.into();
        assert_eq!(TestCmd::Cmd1, TestCmd::deserialize(&mut de_mem).unwrap());
    }
}
