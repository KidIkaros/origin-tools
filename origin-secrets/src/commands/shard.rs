use crate::cli::ShardArgs;
use crate::error::Error;

pub fn cmd_shard(_args: ShardArgs) -> Result<(), Error> {
    Err(Error::NotImplemented("shard".to_string()))
}