#![feature(register_tool)]
#![register_tool(rr)]
#![feature(custom_inner_attributes)]
#![rr::package("refinedrust_trait_reproducer")]

#[derive(Clone, Copy)]
pub enum CompleteError {
    UnexpectedCompletion,
}

pub trait Complete {
    #[rr::verify]
    fn complete(&mut self) -> Result<(), CompleteError>;
}

pub struct Adapter<P> {
    port: P,
    in_flight: u8,
}

#[rr::verify]
impl<P> Complete for Adapter<P> {
    #[rr::verify]
    fn complete(&mut self) -> Result<(), CompleteError> {
        if self.in_flight == 0 {
            return Err(CompleteError::UnexpectedCompletion);
        }
        self.in_flight -= 1;
        Ok(())
    }
}
