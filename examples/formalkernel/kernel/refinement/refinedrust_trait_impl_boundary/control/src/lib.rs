#![feature(register_tool)]
#![register_tool(rr)]
#![feature(custom_inner_attributes)]
#![rr::package("refinedrust_trait_control")]

#[derive(Clone, Copy)]
pub enum CompleteError {
    UnexpectedCompletion,
}

pub struct Adapter {
    in_flight: u8,
}

impl Adapter {
    #[rr::verify]
    pub fn complete(&mut self) -> Result<(), CompleteError> {
        if self.in_flight == 0 {
            return Err(CompleteError::UnexpectedCompletion);
        }
        self.in_flight -= 1;
        Ok(())
    }
}
