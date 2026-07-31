use crate::cli::ExportArgs;
use crate::error::Error;

pub fn cmd_export_share(_args: ExportArgs) -> Result<(), Error> {
    Err(Error::NotImplemented("export-share".to_string()))
}