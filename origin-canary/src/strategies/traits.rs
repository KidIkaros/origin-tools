// SPDX-License-Identifier: OPL-1.4
//
// Copyright (c) 2026 Origin Contributors

//! Canary embedding strategies — trait + RNG.

use crate::manifest::CanaryToken;
use std::collections::HashSet;
use std::path::PathBuf;

/// A strategy that embeds canary tokens into source files.
pub trait EmbedStrategy: Send + Sync {
    /// Human-readable strategy name (also the manifest key).
    fn name(&self) -> &'static str;
    /// File extensions this strategy can embed into.
    fn extensions(&self) -> &'static [&'static str];
    /// Embed `token` into a file under `source_dir`, returning the
    /// modified file's path relative to `source_dir`, or `None` if no
    /// suitable target was found.
    ///
    /// `used_files` tracks files already carrying a token from a previous
    /// call in this run; the strategy prefers an unused file so tokens
    /// spread across the tree (better coverage density). It may reuse a
    /// file only when every eligible file is already taken.
    fn embed(
        &self,
        source_dir: &std::path::Path,
        token: &CanaryToken,
        rng: &mut dyn Rng,
        used_files: &mut HashSet<PathBuf>,
    ) -> Option<String>;
}

/// Minimal RNG interface for strategy implementations.
///
/// Object-safe: only non-generic methods. Random selection from slices is
/// provided as a helper on `SeededRng` (the only implementor).
pub trait Rng {
    /// Advance the generator and return the next 32 bits of output.
    fn next_u32(&mut self) -> u32;
}

/// A simple seeded PRNG backed by a u64 state.
pub struct SeededRng {
    state: u64,
}

impl SeededRng {
    /// Create a generator from a 64-bit seed. The xorshift sequence is
    /// deterministic for a given seed.
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Pick a random index into `slice`, returning `None` if empty.
    pub fn choose_index(&mut self, len: usize) -> Option<usize> {
        if len == 0 {
            return None;
        }
        let idx = self.next_u32() as usize % len;
        Some(idx)
    }
}

impl Rng for SeededRng {
    fn next_u32(&mut self) -> u32 {
        self.state ^= self.state << 13;
        self.state ^= self.state >> 7;
        self.state ^= self.state << 17;
        (self.state >> 32) as u32
    }
}

/// Pick a random element from a slice via a trait-object RNG.
///
/// Free function (not a trait method) so `Rng` stays object-safe.
pub fn choose<'a, T>(rng: &mut dyn Rng, slice: &'a [T]) -> Option<&'a T> {
    if slice.is_empty() {
        return None;
    }
    let idx = rng.next_u32() as usize % slice.len();
    Some(&slice[idx])
}
