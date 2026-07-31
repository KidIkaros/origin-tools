use crate::cli::VerifyArgs;
use crate::error::Error;

pub fn cmd_verify(_args: VerifyArgs) -> Result<(), Error> {
    Err(Error::NotImplemented("verify".to_string()))
}