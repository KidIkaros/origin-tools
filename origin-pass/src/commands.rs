// SPDX-License-Identifier: Apache-2.0

//! Stub command implementations for `origin-pass`.
//!
//! Each `cmd_*` function returns `Result<(), String>`. The v0.1.0 scaffold
//! marks every command as `todo!()` so `cargo check` resolves cleanly while
//! the real implementations are landed in subsequent commits (see
//! `origin-tools/DESIGN.md` §6 for the implementation sequence).

use crate::cli::{
    AddArgs, ChangePassphraseArgs, CodeArgs, ExportQrArgs, GetArgs, ImportQrArgs,
    InitArgs, ListArgs, LockArgs, RmArgs, UnlockArgs,
};

pub fn cmd_init(_args: InitArgs) -> Result<(), String> {
    todo!("origin-pass init — see DESIGN.md §6 step 2")
}

pub fn cmd_unlock(_args: UnlockArgs) -> Result<(), String> {
    todo!("origin-pass unlock — see DESIGN.md §6 step 3")
}

pub fn cmd_lock(_args: LockArgs) -> Result<(), String> {
    todo!("origin-pass lock — see DESIGN.md §6 step 3")
}

pub fn cmd_add(_args: AddArgs) -> Result<(), String> {
    todo!("origin-pass add — see DESIGN.md §6 step 3")
}

pub fn cmd_get(_args: GetArgs) -> Result<(), String> {
    todo!("origin-pass get — see DESIGN.md §6 step 3")
}

pub fn cmd_list(_args: ListArgs) -> Result<(), String> {
    todo!("origin-pass list — see DESIGN.md §6 step 3")
}

pub fn cmd_rm(_args: RmArgs) -> Result<(), String> {
    todo!("origin-pass rm — see DESIGN.md §6 step 3")
}

pub fn cmd_code(_args: CodeArgs) -> Result<(), String> {
    todo!("origin-pass code — see DESIGN.md §6 step 4 (OTP)")
}

pub fn cmd_export_qr(_args: ExportQrArgs) -> Result<(), String> {
    todo!("origin-pass export-qr — see DESIGN.md §6 step 4 (OTP)")
}

pub fn cmd_import_qr(_args: ImportQrArgs) -> Result<(), String> {
    todo!("origin-pass import-qr — see DESIGN.md §6 step 4 (OTP)")
}

pub fn cmd_change_passphrase(_args: ChangePassphraseArgs) -> Result<(), String> {
    todo!("origin-pass change-passphrase — see DESIGN.md §6 step 3")
}
