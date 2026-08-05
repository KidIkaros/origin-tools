// SPDX-License-Identifier: Apache-2.0

//! Dump PeerKeys records as JSONL for relay allowlist testing.

use origin_network::identity::PeerKeys;

fn main() {
    for i in 0..3u8 {
        let seed = [0x40u8 + i; 32];
        let rec = PeerKeys::from_seed(&seed, 0).unwrap();
        println!("{}", serde_json::to_string(&rec).unwrap());
    }
}
