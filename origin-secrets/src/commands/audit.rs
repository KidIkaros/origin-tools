use crate::cli::AuditArgs;
use crate::error::Error;

pub fn cmd_audit(_args: AuditArgs) -> Result<(), Error> {
    Err(Error::NotImplemented("audit".to_string()))
}