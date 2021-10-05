use neli_proc_macros::neli_enum;

#[neli_enum(serialized_type = "u16")]
pub enum TestEnum {
    VarOne = 1,
    VarTwo = 10,
}

fn main() {
    assert_eq!(TestEnum::from(1), TestEnum::VarOne);
    assert_eq!(u16::from(TestEnum::VarOne), 1);
    assert_eq!(TestEnum::from(10), TestEnum::VarTwo);
    assert_eq!(u16::from(TestEnum::VarTwo), 10);
    assert_eq!(TestEnum::from(60), TestEnum::UnrecognizedConst(60));
}
