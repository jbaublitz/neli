#[macro_export]

macro_rules! enum_to_nl {
    ( $name:ident, $type:tt, $( $cmd:ident ),* ) => {
        #[derive(Clone,Debug,PartialEq)]
        pub enum $name {
            $( $cmd, )*
            UnrecognizedVariant,
        }

        impl Into<$type> for $name {
            fn into(self) -> $type {
                self as $type
            }
        }

        impl From<$type> for $name {
            fn from(v: $type) -> Self {
                match v {
                    $(
                        i if i == $name::$cmd as $type => $name::$cmd,
                    )*
                    _ => $name::UnrecognizedVariant,
                }
            }
        }

        impl Nl for $name {
            type SerIn = ();
            type DeIn = ();

            fn serialize(&self, mem: &mut MemWrite) -> Result<(), SerError> {
                let val = self.clone() as $type;
                val.serialize(mem)?;
                Ok(())
            }

            fn deserialize(mem: &mut MemRead) -> Result<Self, DeError> {
                let cmd = $type::deserialize(mem)?;
                Ok(Self::from(cmd))
            }

            fn size(&self) -> usize {
                ::std::mem::size_of::<$type>()
            }
        }
    };
    ( $name:ident, $type:tt, $( $cmd:ident = $num:tt ),* ) => {
        #[derive(Clone,Debug,PartialEq)]
        pub enum $name {
            $( $cmd = $num, )*
            UnrecognizedVariant,
        }

        impl Into<$type> for $name {
            fn into(self) -> $type {
                self as $type
            }
        }

        impl From<$type> for $name {
            fn from(v: $type) -> Self {
                match v {
                    $(
                        i if i == $name::$cmd as $type => $name::$cmd,
                    )*
                    _ => $name::UnrecognizedVariant,
                }
            }
        }

        impl Nl for $name {
            type SerIn = ();
            type DeIn = ();

            fn serialize(&self, mem: &mut MemWrite) -> Result<(), SerError> {
                let val = self.clone() as $type;
                val.serialize(mem)?;
                Ok(())
            }

            fn deserialize(mem: &mut MemRead) -> Result<Self, DeError> {
                let cmd = $type::deserialize(mem)?;
                Ok(Self::from(cmd))
            }

            fn size(&self) -> usize {
                ::std::mem::size_of::<$type>()
            }
        }
    };
}

#[macro_export]
macro_rules! cmd_to_nl {
    ( $name:ident, $( $cmd:ident ),* ) => {
        enum_to_nl!($name, u8, $( $cmd ),*);
    };
    ( $name:ident, $( $cmd:ident = $num:tt ),* ) => {
        enum_to_nl!($name, u8, $( $cmd = $num ),*);
    };
}

#[cfg(test)]
mod test {
    use {Nl,MemRead,MemWrite};
    use err::{SerError,DeError};

    #[test]
    fn test_attr_cmd_to_nl_macro() {
        cmd_to_nl!(TestCmd, Cmd0, Cmd1, Cmd2, Cmd3);

        let slice = &mut [0u8; 1];
        let mut ser_mem = MemWrite::new_slice(slice);
        TestCmd::Cmd1.serialize(&mut ser_mem).unwrap();
        assert_eq!(ser_mem.as_slice(), &[1]);
        let mut de_mem = ser_mem.into();
        assert_eq!(TestCmd::Cmd1, TestCmd::deserialize(&mut de_mem).unwrap());
    }
}
