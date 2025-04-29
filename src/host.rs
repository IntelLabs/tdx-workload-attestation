use crate::error::Result;

pub trait TeeHost {
    fn verify_launch_endorsement(&self) -> Result<bool>;
}
