use crate::cli::RecoverArgs;
use crate::error::Error;

pub fn cmd_recover(_args: RecoverArgs) -> Result<(), Error> {
    Err(Error::NotImplemented("recover".to_string()))
}