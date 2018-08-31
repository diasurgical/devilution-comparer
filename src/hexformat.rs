use std::fmt::{Formatter, Result as FmtResult, UpperHex};
use std::ops::Neg;

use num_traits::Signed;

#[derive(Debug)]
pub struct CustomUpperHexFormat<T: UpperHex + Signed + Copy>(pub T);

impl<T> UpperHex for CustomUpperHexFormat<T>
where
    T: UpperHex + Signed + Copy,
    <T as Neg>::Output: UpperHex,
{
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        if self.0.is_positive() {
            if f.sign_plus() {
                write!(f, "+");
            }
            if f.alternate() {
                write!(f, "0x");
            }
            write!(f, "{:X}", self.0)
        } else {
            write!(f, "-");
            if f.alternate() {
                write!(f, "0x");
            }
            write!(f, "{:X}", -self.0)
        }
    }
}

impl<T: UpperHex + Signed + Copy> From<T> for CustomUpperHexFormat<T> {
    fn from(v: T) -> Self {
        CustomUpperHexFormat(v)
    }
}
