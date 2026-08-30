use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "origin-vcs",
    version,
    about = "Git-like file versioning — signed commits, encrypted-at-rest objects, MMR audit"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Initialize an encrypted object store for the current directory
    Init(InitArgs),
    /// Stage files into the index
    Add(AddArgs),
    /// Remove paths from the index
    Rm(RmArgs),
    /// Show working tree / index status
    Status(StatusArgs),
    /// Create a signed commit from the staged index
    Commit(CommitArgs),
    /// Show commit history
    Log(LogArgs),
    /// Show a commit or a file at a revision
    Show(ShowArgs),
    /// List / create / delete branches
    Branch(BranchArgs),
    /// Switch the working tree to a branch or commit
    Checkout(CheckoutArgs),
    /// Tag a commit
    Tag(TagArgs),
    /// Tree-to-tree diff
    Diff(DiffArgs),
    /// Merge another branch into HEAD
    Merge(MergeArgs),
    /// Re-apply commits from another branch onto HEAD (linearize history)
    Rebase(RebaseArgs),
    /// Apply a single commit's changes onto HEAD
    CherryPick(CherryPickArgs),
    /// Shelve/restore uncommitted working-tree changes
    Stash(StashArgs),
    /// Show per-line authorship of a file across history
    Blame(BlameArgs),
    /// Clone a remote repository into a new directory
    Clone(CloneArgs),
    /// Verify signatures, object hashes, refs, and MMR
    Verify(VerifyArgs),
    /// Print the MMR root of the commit log
    Mmr(MmrArgs),
    /// Reset HEAD to a commit (soft clears index, hard restores tree)
    Reset(ResetArgs),
    /// Garbage-collect unreachable objects
    Gc(GcArgs),
    /// Manage remotes and push/pull object packs
    Remote(RemoteArgs),
    /// Create / import / verify a single-file bundle
    Bundle(BundleArgs),
    /// Binary search for the commit that introduced a regression
    Bisect(BisectArgs),
}

#[derive(Parser, Clone, Debug)]
pub struct InitArgs {
    /// Store directory (default: <cwd>/.origin-vcs)
    #[arg(long)]
    pub store: Option<String>,
    /// Default branch name (default: main)
    #[arg(long, default_value = "main")]
    pub branch: String,
    /// Force re-initialize
    #[arg(long)]
    pub force: bool,
    /// At-rest encryption mode for objects: "identity" (key derived from the
    /// suite identity) or "passphrase" (Argon2id over a passphrase; default
    /// identity)
    #[arg(long, default_value = "identity")]
    pub encrypt: String,
    /// Argon2id memory tier for passphrase mode: nano | standard | sovereign
    /// (default nano)
    #[arg(long, default_value = "nano")]
    pub tier: String,
    /// Seed hex for signing (optional; default derived from suite identity)
    #[arg(long)]
    pub seed: Option<String>,
    /// Load identity from ~/.origin/identity.seed
    #[arg(long)]
    pub identity: bool,
    /// Passphrase file
    #[arg(short, long)]
    pub passphrase_file: Option<String>,
}

#[derive(Parser, Clone, Debug)]
pub struct AddArgs {
    /// Paths to stage (default: .)
    #[arg(default_value = ".")]
    pub paths: Vec<String>,
    /// Explicit store path (else auto-discovered)
    #[arg(long)]
    pub store: Option<String>,
    /// Identity bindings
    #[arg(long)]
    pub identity: bool,
    #[arg(long)]
    pub seed: Option<String>,
    #[arg(short, long)]
    pub passphrase_file: Option<String>,
    /// Stream large files through chunked encryption (bounded memory)
    #[arg(long)]
    pub stream: bool,
    /// Chunk size for --stream (default 64 KiB)
    #[arg(long, default_value = "65536")]
    pub chunk_size: usize,
}

#[derive(Parser, Clone, Debug)]
pub struct RmArgs {
    /// Paths to unstage
    pub paths: Vec<String>,
    #[arg(long)]
    pub store: Option<String>,
    #[arg(long)]
    pub identity: bool,
    #[arg(long)]
    pub seed: Option<String>,
    #[arg(short, long)]
    pub passphrase_file: Option<String>,
}

#[derive(Parser, Clone, Debug)]
pub struct StatusArgs {
    #[arg(long)]
    pub json: bool,
    #[arg(long)]
    pub store: Option<String>,
    /// Working directory to scan (default: cwd)
    #[arg(long)]
    pub dir: Option<String>,
    #[arg(long)]
    pub identity: bool,
    #[arg(long)]
    pub seed: Option<String>,
    #[arg(short, long)]
    pub passphrase_file: Option<String>,
}

#[derive(Parser, Clone, Debug)]
pub struct CommitArgs {
    /// Commit message
    #[arg(short, long)]
    pub message: String,
    /// Author string ("Name <email>")
    #[arg(long)]
    pub author: Option<String>,
    /// Commit timestamp override (unix epoch seconds; default now)
    #[arg(long)]
    pub date: Option<u64>,
    /// Seed hex
    #[arg(long)]
    pub seed: Option<String>,
    /// Use suite identity
    #[arg(long)]
    pub identity: bool,
    #[arg(short, long)]
    pub passphrase_file: Option<String>,
    #[arg(long)]
    pub store: Option<String>,
    /// Allow commit when there are unstaged changes not in the index
    #[arg(long)]
    pub all: bool,
    /// Amend the last commit: reuse its parent(s) but take the staged index
    /// as the new tree (and the -m message, when given).
    #[arg(long)]
    pub amend: bool,
}

#[derive(Parser, Clone, Debug)]
pub struct LogArgs {
    /// Limit to N most recent commits
    #[arg(short, long)]
    pub max: Option<usize>,
    #[arg(long)]
    pub oneline: bool,
    #[arg(long)]
    pub json: bool,
    #[arg(long)]
    pub store: Option<String>,
    /// Branch or commit to start from (default HEAD)
    #[arg(long)]
    pub from: Option<String>,
    #[arg(long)]
    pub identity: bool,
    #[arg(long)]
    pub seed: Option<String>,
    #[arg(short, long)]
    pub passphrase_file: Option<String>,
}

#[derive(Parser, Clone, Debug)]
pub struct ShowArgs {
    /// Commit id or ref
    pub id: String,
    /// Show a file at this revision (path rel. to repo tree)
    #[arg(long)]
    pub path: Option<String>,
    #[arg(long)]
    pub store: Option<String>,
    #[arg(long)]
    pub identity: bool,
    #[arg(long)]
    pub seed: Option<String>,
    #[arg(short, long)]
    pub passphrase_file: Option<String>,
}

#[derive(Parser, Clone, Debug)]
pub struct BranchArgs {
    /// Branch name (create)
    pub name: Option<String>,
    /// Delete a branch
    #[arg(short, long)]
    pub delete: Option<String>,
    /// Rename a branch: `-m <old> <new>`
    #[arg(short = 'm', long = "move", num_args = 2, value_names = ["old", "new"])]
    pub mv: Option<Vec<String>>,
    /// Pivot point for a new branch (default HEAD)
    #[arg(long)]
    pub from: Option<String>,
    #[arg(long)]
    pub store: Option<String>,
    #[arg(long)]
    pub identity: bool,
    #[arg(long)]
    pub seed: Option<String>,
    #[arg(short, long)]
    pub passphrase_file: Option<String>,
}

#[derive(Parser, Clone, Debug)]
pub struct CheckoutArgs {
    /// Branch name or commit id
    pub target: String,
    /// Store path
    #[arg(long)]
    pub store: Option<String>,
    /// Working directory
    #[arg(long)]
    pub dir: Option<String>,
    /// Stream blob decryption when writing the working tree (bounded memory)
    #[arg(long)]
    pub stream: bool,
    /// Sparse checkout: materialize only these paths (repeatable); with no
    /// value, clears the sparse set and restores the full tree
    #[arg(long)]
    pub path: Vec<String>,
    #[arg(long)]
    pub identity: bool,
    #[arg(long)]
    pub seed: Option<String>,
    #[arg(short, long)]
    pub passphrase_file: Option<String>,
}

#[derive(Parser, Clone, Debug)]
pub struct TagArgs {
    /// List tags if no name
    pub name: Option<String>,
    /// Target commit/ref (default HEAD)
    pub target: Option<String>,
    /// Tag message
    #[arg(short, long)]
    pub message: Option<String>,
    /// Delete a tag
    #[arg(short, long)]
    pub delete: Option<String>,
    #[arg(long)]
    pub seed: Option<String>,
    #[arg(long)]
    pub identity: bool,
    #[arg(short, long)]
    pub passphrase_file: Option<String>,
    #[arg(long)]
    pub store: Option<String>,
}

#[derive(Parser, Clone, Debug)]
pub struct DiffArgs {
    /// First tree (ref or commit). Default: HEAD
    pub a: Option<String>,
    /// Second tree (ref or commit). Default: working tree
    pub b: Option<String>,
    /// Restrict diff to a path
    #[arg(long)]
    pub path: Option<String>,
    #[arg(long)]
    pub store: Option<String>,
    /// Working dir
    #[arg(long)]
    pub dir: Option<String>,
    #[arg(long)]
    pub identity: bool,
    #[arg(long)]
    pub seed: Option<String>,
    #[arg(short, long)]
    pub passphrase_file: Option<String>,
}

#[derive(Parser, Clone, Debug)]
pub struct MergeArgs {
    /// Branch to merge into HEAD
    pub branch: String,
    #[arg(long)]
    pub seed: Option<String>,
    #[arg(long)]
    pub identity: bool,
    #[arg(short, long)]
    pub passphrase_file: Option<String>,
    #[arg(long)]
    pub store: Option<String>,
    /// Merge message
    #[arg(short, long, default_value = "merge")]
    pub message: String,
    /// File-level resolution strategy for changed blobs: "union" (v1, whole
    /// file wins) or "textual" (Phase 11 line-diff auto-merge + conflict
    /// markers)
    #[arg(long, default_value = "union")]
    pub strategy: String,
    /// Abort an in-progress merge, restoring HEAD, index, and working tree
    /// to the pre-merge state
    #[arg(long)]
    pub abort: bool,
}

#[derive(Parser, Clone, Debug)]
pub struct RebaseArgs {
    /// Branch whose commits are replayed onto HEAD
    pub branch: String,
    #[arg(long)]
    pub seed: Option<String>,
    #[arg(long)]
    pub identity: bool,
    #[arg(short, long)]
    pub passphrase_file: Option<String>,
    #[arg(long)]
    pub store: Option<String>,
    /// File-level resolution strategy for conflicting replayed commits:
    /// "union" (whole-file wins) or "textual" (line merge + conflict markers).
    #[arg(long, default_value = "union")]
    pub strategy: String,
    /// Interactive rebase: edit the todo plan (pick/squash/reword/drop/edit)
    #[arg(short = 'i', long)]
    pub interactive: bool,
    /// Todo file for interactive rebase (default: $EDITOR on a generated plan)
    #[arg(long)]
    pub todo: Option<String>,
    /// Continue an interactive rebase paused at an `edit` stop
    #[arg(long)]
    pub cont: bool,
    /// Abort an in-progress interactive rebase, restoring the original HEAD
    #[arg(long)]
    pub abort: bool,
    /// Auto-detect fixup!/squash! prefixes and reorder the todo plan
    #[arg(long)]
    pub autosquash: bool,
    /// Preserve merge commits during rebase (instead of dropping them)
    #[arg(long)]
    pub rebase_merges: bool,
}

#[derive(Parser, Clone, Debug)]
pub struct CherryPickArgs {
    /// Commit / ref to apply onto HEAD
    pub commit: String,
    #[arg(long)]
    pub seed: Option<String>,
    #[arg(long)]
    pub identity: bool,
    #[arg(short, long)]
    pub passphrase_file: Option<String>,
    #[arg(long)]
    pub store: Option<String>,
    /// File-level resolution strategy for a conflicting apply: "union" or
    /// "textual".
    #[arg(long, default_value = "union")]
    pub strategy: String,
}

#[derive(Parser, Clone, Debug)]
pub struct StashArgs {
    /// Subcommand: push | apply | pop | list | drop
    #[command(subcommand)]
    pub action: StashAction,
    #[arg(long, global = true)]
    pub seed: Option<String>,
    #[arg(long, global = true)]
    pub identity: bool,
    #[arg(short, long, global = true)]
    pub passphrase_file: Option<String>,
    #[arg(long, global = true)]
    pub store: Option<String>,
}

#[derive(Subcommand, Clone, Debug)]
pub enum StashAction {
    /// Shelve working-tree + index changes (with an optional message)
    Push { message: Option<String> },
    /// Apply the newest (or nth) stash to the working tree, keeping it
    Apply { index: Option<usize> },
    /// Apply and drop the newest (or nth) stash
    Pop { index: Option<usize> },
    /// List stash entries
    List {},
    /// Drop the newest (or nth) stash entry
    Drop { index: Option<usize> },
}

#[derive(Parser, Clone, Debug)]
pub struct BlameArgs {
    /// File path to attribute per line
    pub path: String,
    /// Revision to start from (default HEAD)
    #[arg(long)]
    pub from: Option<String>,
    #[arg(long)]
    pub store: Option<String>,
    #[arg(long)]
    pub identity: bool,
    #[arg(long)]
    pub seed: Option<String>,
    #[arg(short, long)]
    pub passphrase_file: Option<String>,
    /// Emit JSON (array of {line, id, author, message})
    #[arg(long)]
    pub json: bool,
}

#[derive(Parser, Clone, Debug)]
pub struct CloneArgs {
    /// Remote target: a directory snapshot, tcp://host:port, or
    /// relay://host:port/<relay-fp>/<relay-pk>/<peer-fp>
    pub target: String,
    /// Destination directory (created if missing)
    pub dir: String,
    /// Remote name (default: origin)
    #[arg(long, default_value = "origin")]
    pub name: String,
    /// Branch to check out (default: the remote's main, else its first branch)
    #[arg(long)]
    pub branch: Option<String>,
    /// At-rest encryption mode for the new store: "identity" (default) or
    /// "passphrase". Passphrase clones must use the same passphrase AND
    /// storage config as the source to decrypt its envelopes.
    #[arg(long, default_value = "identity")]
    pub encrypt: String,
    /// Argon2id tier for passphrase mode
    #[arg(long, default_value = "nano")]
    pub tier: String,
    /// Seed hex for the new store's signing + storage key
    #[arg(long)]
    pub seed: Option<String>,
    /// Use suite identity
    #[arg(long)]
    pub identity: bool,
    /// Passphrase file
    #[arg(short, long)]
    pub passphrase_file: Option<String>,
    /// Network identity seed for relay connections (defaults to the repo seed)
    #[arg(long)]
    pub net_seed: Option<String>,
    /// STUN server (host:port) for NAT-punched relay remotes
    #[arg(long)]
    pub stun: Option<String>,
    /// Shallow clone: fetch only the tip commits + their trees/blobs (no
    /// ancestor history). The clone's store is marked shallow.
    #[arg(long)]
    pub shallow: bool,
    /// Depth for a shallow clone: fetch at most this many ancestor
    /// generations from each branch/tag tip (1 = tips only, same as
    /// `--shallow`). Implies `--shallow`.
    #[arg(long)]
    pub depth: Option<usize>,
    /// Sparse clone: after checking out, materialize only these paths
    /// (repeatable; the full history + objects are still fetched)
    #[arg(long)]
    pub path: Vec<String>,
}

#[derive(Parser, Clone, Debug)]
pub struct VerifyArgs {
    /// Ref / commit / tag to verify (default: verify whole history)
    #[arg(long)]
    pub target: Option<String>,
    /// Also check the working tree matches HEAD (no drift)
    #[arg(long)]
    pub tree: bool,
    #[arg(long)]
    pub store: Option<String>,
    #[arg(long)]
    pub identity: bool,
    #[arg(long)]
    pub seed: Option<String>,
    #[arg(short, long)]
    pub passphrase_file: Option<String>,
}

#[derive(Parser, Clone, Debug)]
pub struct MmrArgs {
    /// Print the MMR root (no argument)
    #[arg(long)]
    pub root: bool,
    #[arg(long)]
    pub store: Option<String>,
    #[arg(long)]
    pub identity: bool,
    #[arg(long)]
    pub seed: Option<String>,
    #[arg(short, long)]
    pub passphrase_file: Option<String>,
}

#[derive(Parser, Clone, Debug)]
pub struct GcArgs {
    #[arg(long)]
    pub store: Option<String>,
    #[arg(long)]
    pub identity: bool,
    #[arg(long)]
    pub seed: Option<String>,
    #[arg(short, long)]
    pub passphrase_file: Option<String>,
    /// Also delete stale tracking refs (refs/remotes/...) whose tip is no
    /// longer reachable from any local branch or tag
    #[arg(long)]
    pub prune_remotes: bool,
}

#[derive(Parser, Clone, Debug)]
pub struct RemoteArgs {
    /// Subcommand: add | remove | list | push | fetch | pull | prune | serve
    #[command(subcommand)]
    pub action: RemoteAction,
    #[arg(long)]
    pub store: Option<String>,
    #[arg(long)]
    pub identity: bool,
    #[arg(long)]
    pub seed: Option<String>,
    #[arg(short, long)]
    pub passphrase_file: Option<String>,
    /// Network identity seed for relay connections (defaults to the repo seed)
    #[arg(long)]
    pub net_seed: Option<String>,
    /// STUN server (host:port) used to discover our public address for
    /// NAT-punched relay remotes (server advert + client decision tree)
    #[arg(long)]
    pub stun: Option<String>,
}

#[derive(Subcommand, Clone, Debug)]
pub enum RemoteAction {
    /// Add a remote (name -> local directory holding a store snapshot)
    Add(RemoteAddArgs),
    /// Remove a remote
    Remove(RemoteRemoveArgs),
    /// List configured remotes
    List(RemoteListArgs),
    /// Push the current branch (and objects) to a remote
    Push(RemotePushArgs),
    /// Fetch objects + refs from a remote (no merge)
    Fetch(RemoteFetchArgs),
    /// Pull = fetch + fast-forward current branch on top of fetched ref
    Pull(RemotePullArgs),
    /// Prune stale tracking refs for a remote (branches it no longer advertises)
    Prune(RemotePruneArgs),
    /// List a remote's branches/tags without needing a local store
    LsRemote(RemoteLsArgs),
    /// Scheduled bidirectional sync with a remote (interval loop)
    Sync(RemoteSyncArgs),
    /// Serve this store over origin-network TCP (accepts fetch/push)
    Serve(RemoteServeArgs),
}

#[derive(Parser, Clone, Debug)]
pub struct RemoteAddArgs {
    /// Remote name
    pub name: String,
    /// Target: a directory that holds a store snapshot, or later an
    /// origin-network address.
    pub target: String,
}

#[derive(Parser, Clone, Debug)]
pub struct RemoteRemoveArgs {
    /// Remote name
    pub name: String,
}

#[derive(Parser, Clone, Debug)]
pub struct RemoteListArgs {}

#[derive(Parser, Clone, Debug)]
pub struct RemotePushArgs {
    /// Remote name
    pub name: String,
    /// Branch to push (default: current HEAD branch)
    #[arg(long)]
    pub branch: Option<String>,
    /// Allow overwriting a remote branch tip that is not a fast-forward
    /// (rejected by default; the remote must already carry the tip being
    /// replaced).
    #[arg(long)]
    pub force: bool,
}

#[derive(Parser, Clone, Debug)]
pub struct RemoteFetchArgs {
    /// Remote name
    pub name: String,
    /// Fetch branch/ref into origin/<remote>/<branch> tracking refs
    #[arg(long)]
    pub branch: Option<String>,
    /// Depth for a shallow fetch: fetch at most this many ancestor generations
    /// (1 = tips only, same as --shallow). Omit for full history.
    #[arg(long)]
    pub depth: Option<usize>,
    /// Sparse fetch: after importing, check out only these paths (repeatable)
    #[arg(long)]
    pub path: Vec<String>,
}

#[derive(Parser, Clone, Debug)]
pub struct RemoteLsArgs {
    /// Remote target: a directory snapshot, tcp://, quic://, session://, or
    /// relay:// address (no local store needed)
    pub target: String,
}

#[derive(Parser, Clone, Debug)]
pub struct RemoteSyncArgs {
    /// Remote name (must already be configured in this store)
    pub name: String,
    /// Branch to sync (default: current HEAD branch)
    #[arg(long)]
    pub branch: Option<String>,
    /// Sync interval in seconds (default 60); the loop runs until stopped
    #[arg(long, default_value = "60")]
    pub interval: u64,
    /// Sync once and exit (no loop)
    #[arg(long)]
    pub once: bool,
    /// Run the sync loop as a detached background daemon
    #[arg(long)]
    pub daemon: bool,
    /// Stop a sync daemon started with --daemon (reads the pid file,
    /// SIGTERMs the pid, waits for exit, removes the pid file)
    #[arg(long)]
    pub stop: bool,
    /// Hidden marker: this process IS the daemon child (re-exec path)
    #[arg(long, hide = true)]
    pub serve_child: bool,
    /// Pid file for the daemon (records pid + remote)
    #[arg(long)]
    pub pid_file: Option<String>,
    /// Log file for the daemon's output
    #[arg(long)]
    pub log_file: Option<String>,
}

#[derive(Parser, Clone, Debug)]
pub struct RemoteServeArgs {
    /// Listen address (default 127.0.0.1:7332)
    #[arg(long, default_value = "127.0.0.1:7332")]
    pub listen: String,
    /// Serve through an origin-network relay instead of a direct listener:
    /// relay://host:port/<relay-fp>/<relay-pk> (the peer fingerprint is our
    /// own; clients dial relay://.../<relay-fp>/<relay-pk>/<our-fp>)
    #[arg(long)]
    pub relay: Option<String>,
    /// Serve over the QUIC transport (quinn): quic://host:port client
    /// targets. Same pack protocol as tcp://; QUIC adds stream multiplexing
    /// and migration support. Self-signed TLS is obfuscation only — identity
    /// auth, when required, is a session:// target.
    #[arg(long)]
    pub quic: Option<String>,
    /// Serve AUTHENTICATED sessions instead: accept origin-network endpoint
    /// handshakes on this address (mutually exclusive with --relay). Only
    /// identities in the allowlist pass; clients dial
    /// session://host:port/<our-fp>/<our-transport-pk>
    #[arg(long)]
    pub session: Option<String>,
    /// Allowlist for --session: a hex identity seed whose PeerKeys record
    /// may authenticate (repeatable)
    #[arg(long)]
    pub allow: Vec<String>,
    /// Allowlist file for --session: JSONL of PeerKeys records (one per
    /// line, as serialized by origin-network)
    #[arg(long)]
    pub allow_file: Option<String>,
    /// Run the serve loop as a background daemon: re-exec this binary with a
    /// hidden --serve-child marker, redirect output to the log file, and
    /// record the child pid + bound address in the pid file.
    #[arg(long)]
    pub daemon: bool,
    /// Stop a daemon started with --daemon (reads the pid file, SIGTERMs the
    /// pid, waits for exit, removes the pid file).
    #[arg(long)]
    pub stop: bool,
    /// Pid file for --daemon/--stop (default <store>/serve.pid)
    #[arg(long)]
    pub pid_file: Option<String>,
    /// Log file for --daemon (default <store>/serve.log)
    #[arg(long)]
    pub log_file: Option<String>,
    /// Internal: set by --daemon's re-exec to mark the background child
    #[arg(long, hide = true)]
    pub serve_child: bool,
}

#[derive(Parser, Clone, Debug)]
pub struct RemotePruneArgs {
    /// Remote name
    pub name: String,
}

#[derive(Parser, Clone, Debug)]
pub struct RemotePullArgs {
    /// Remote name
    pub name: String,
    /// Branch to pull (default: current HEAD branch)
    #[arg(long)]
    pub branch: Option<String>,
    /// Sparse pull: check out only these paths (repeatable)
    #[arg(long)]
    pub path: Vec<String>,
}

#[derive(Parser, Clone, Debug)]
pub struct BundleArgs {
    #[command(subcommand)]
    pub action: BundleAction,
    #[arg(long)]
    pub store: Option<String>,
    #[arg(long)]
    pub identity: bool,
    #[arg(long)]
    pub seed: Option<String>,
    #[arg(short, long)]
    pub passphrase_file: Option<String>,
}

#[derive(Subcommand, Clone, Debug)]
pub enum BundleAction {
    /// Write a portable bundle file of the reachable objects + refs
    Create(BundleCreateArgs),
    /// Import a bundle's objects + refs into this store
    Import(BundleImportArgs),
    /// Verify a bundle's objects are present and decryptable
    Verify(BundleVerifyArgs),
}

#[derive(Parser, Clone, Debug)]
pub struct BundleCreateArgs {
    /// Output bundle file path
    pub file: String,
}

#[derive(Parser, Clone, Debug)]
pub struct BundleImportArgs {
    /// Bundle file path
    pub file: String,
    /// Name under which to record the bundle's refs (refs/remotes/<name>/...)
    #[arg(long, default_value = "bundle")]
    pub name: String,
}

#[derive(Parser, Clone, Debug)]
pub struct BundleVerifyArgs {
    /// Bundle file path
    pub file: String,
}

#[derive(Parser, Clone, Debug)]
pub struct ResetArgs {
    /// Target commit/ref
    #[arg(long)]
    pub id: String,
    /// soft: move HEAD only; hard: also restore tree
    #[arg(long)]
    pub mode: Option<String>,
    #[arg(long)]
    pub store: Option<String>,
    /// Working dir
    #[arg(long)]
    pub dir: Option<String>,
    #[arg(long)]
    pub identity: bool,
    #[arg(long)]
    pub seed: Option<String>,
    #[arg(short, long)]
    pub passphrase_file: Option<String>,
}

#[derive(Parser, Clone, Debug)]
pub struct BisectArgs {
    /// Bisect subcommand: start | good | bad | skip | reset | run
    #[command(subcommand)]
    pub action: BisectAction,
    #[arg(long, global = true)]
    pub seed: Option<String>,
    #[arg(long, global = true)]
    pub identity: bool,
    #[arg(short, long, global = true)]
    pub passphrase_file: Option<String>,
    #[arg(long, global = true)]
    pub store: Option<String>,
}

#[derive(Subcommand, Clone, Debug)]
pub enum BisectAction {
    /// Start a bisect session with a good and bad commit
    Start {
        /// Known good commit/ref
        good: String,
        /// Known bad commit/ref (default: HEAD)
        #[arg(long)]
        bad: Option<String>,
    },
    /// Mark a commit as good (passing)
    Good {
        /// Commit/ref to mark good
        commit: String,
    },
    /// Mark a commit as bad (failing)
    Bad {
        /// Commit/ref to mark bad
        commit: String,
    },
    /// Skip the current commit (not buildable)
    Skip,
    /// Reset bisect state
    Reset,
    /// Run a test script and auto-bisect
    Run {
        /// Shell command to run (exit 0 = good, non-zero = bad)
        script: String,
    },
}
