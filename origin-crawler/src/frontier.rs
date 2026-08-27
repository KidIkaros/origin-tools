// SPDX-License-Identifier: Apache-2.0

//! URL frontier — priority queue + seen-set + politeness bookkeeping.
//!
//! The classic frontier design (system-design notes ch. 9) splits URLs into
//! priority and back queues; this crate collapses that into a single
//! min-heap keyed by `(depth, foreign-host, arrival-seq)`:
//!
//! - **Shallowest first** — BFS semantics preserved: a page's children are
//!   never processed before shallower work.
//! - **Same-site bonus** — at equal depth, URLs on a seed host precede
//!   foreign ones, keeping crawls focused before wandering off-site.
//! - **FIFO tiebreak** — equal (depth, host-class) entries pop in discovery
//!   order, so behavior degrades gracefully to plain BFS.
//!
//! A seen-set (`url seen?` in the classic design) prevents revisits, while
//! per-host reservation tables enforce politeness: each host receives at
//! most one request every `delay`, regardless of worker concurrency. A
//! per-host page quota and a maximum URL length bound spider traps.

use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::time::{Duration, Instant};

use url::Url;

/// A queued crawl target.
#[derive(Debug, Clone)]
pub struct QueuedUrl {
    pub url: Url,
    pub depth: usize,
}

/// Internal heap entry. `Ord` is reversed so `BinaryHeap` acts as a min-heap
/// over `(depth, foreign, seq)`.
#[derive(Debug)]
struct Entry {
    key: (usize, bool, u64),
    item: QueuedUrl,
}

impl PartialEq for Entry {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
    }
}
impl Eq for Entry {}
impl Ord for Entry {
    fn cmp(&self, other: &Self) -> Ordering {
        other.key.cmp(&self.key)
    }
}
impl PartialOrd for Entry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// URL frontier shared by all crawler workers.
pub struct Frontier {
    heap: BinaryHeap<Entry>,
    seq: u64,
    seen: HashSet<String>,
    /// Hosts of the seed URLs — same-site bonus class for prioritization.
    seed_hosts: HashSet<String>,
    /// Host -> earliest instant the next fetch may start (politeness).
    host_next_ok: HashMap<String, Instant>,
    /// Host -> pages fetched so far (spider-trap quota).
    host_pages: HashMap<String, usize>,
    max_url_len: usize,
}

impl Frontier {
    /// Create a frontier; `seed_hosts` determines which queued URLs get the
    /// same-site priority bonus.
    pub fn new<I: IntoIterator<Item = String>>(max_url_len: usize, seed_hosts: I) -> Self {
        Self {
            heap: BinaryHeap::new(),
            seq: 0,
            seen: HashSet::new(),
            seed_hosts: seed_hosts.into_iter().collect(),
            host_next_ok: HashMap::new(),
            host_pages: HashMap::new(),
            max_url_len,
        }
    }

    /// Enqueue a URL if it has not been seen before and fits the length cap.
    ///
    /// Fragments are stripped defensively (they never carry crawl identity),
    /// so `page` and `page#section` dedupe to one frontier entry even if a
    /// caller skips [`crate::parser::resolve`] normalization.
    /// Returns `true` when the URL was newly added.
    pub fn push(&mut self, mut url: Url, depth: usize) -> bool {
        url.set_fragment(None);
        if url.as_str().len() > self.max_url_len {
            return false;
        }
        // Url normalizes its serialization; fragments were stripped upstream.
        if !self.seen.insert(url.as_str().to_string()) {
            return false;
        }
        let foreign = !url.host_str().is_some_and(|h| self.seed_hosts.contains(h));
        let key = (depth, foreign, self.seq);
        self.seq += 1;
        self.heap.push(Entry {
            key,
            item: QueuedUrl { url, depth },
        });
        true
    }

    /// Pop the highest-priority target: shallowest depth first, then seed
    /// hosts over foreign ones, then FIFO within the same class.
    pub fn pop(&mut self) -> Option<QueuedUrl> {
        self.heap.pop().map(|e| e.item)
    }

    /// Reserve this host's next politeness slot atomically.
    ///
    /// Returns the instant at which the caller may begin fetching: either
    /// "now" for an idle host or the previous slot boundary. The host's next
    /// allowed time is advanced by `delay`, so concurrent workers serialize
    /// on the same host instead of stampeding it.
    pub fn reserve_slot(&mut self, host: &str, delay: Duration) -> Instant {
        let now = Instant::now();
        let start = self.host_next_ok.get(host).copied().unwrap_or(now);
        let next = start.max(now) + delay;
        self.host_next_ok.insert(host.to_string(), next);
        start
    }

    /// Consume one unit of the host's page quota.
    ///
    /// Returns `true` when the quota is exhausted (spider-trap guard).
    pub fn host_quota_exhausted(&mut self, host: &str, max_pages_per_host: usize) -> bool {
        let count = self.host_pages.entry(host.to_string()).or_insert(0);
        if *count >= max_pages_per_host {
            true
        } else {
            *count += 1;
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    fn frontier_with_seed(seed_host: &str) -> Frontier {
        Frontier::new(2048, [seed_host.to_string()])
    }

    #[test]
    fn fifo_order_within_same_class_and_seen_dedup() {
        let mut f = frontier_with_seed("h");
        assert!(f.push(u("http://h/a"), 0));
        assert!(f.push(u("http://h/b"), 0));
        // Duplicate (same normalized URL) is rejected.
        assert!(!f.push(u("http://h/a"), 1));

        let first = f.pop().unwrap();
        let second = f.pop().unwrap();
        assert_eq!(first.url.as_str(), "http://h/a");
        assert_eq!(second.url.as_str(), "http://h/b");
        assert_eq!(first.depth, 0);
        assert!(f.pop().is_none());
    }

    #[test]
    fn fragment_stripped_urls_dedup() {
        let mut f = frontier_with_seed("h");
        assert!(f.push(u("http://h/page"), 0));
        // "#section" normalizes to the same URL -> rejected as a duplicate.
        assert!(!f.push(u("http://h/page#section"), 0));
        assert_eq!(
            f.pop().map(|q| q.url.as_str().to_string()),
            Some("http://h/page".into())
        );
        assert!(f.pop().is_none());
    }

    #[test]
    fn url_length_guard() {
        let mut f = frontier_with_seed("h");
        f.max_url_len = 16;
        assert!(f.push(u("http://h/short"), 0));
        assert!(!f.push(u("http://h/an-extremely-long-path-that-exceeds-the-cap"), 0));
        assert!(f.pop().is_some());
        assert!(f.pop().is_none());
    }

    #[test]
    fn shallower_depth_pops_first_regardless_of_insertion_order() {
        let mut f = frontier_with_seed("h");
        assert!(f.push(u("http://h/deep"), 3));
        assert!(f.push(u("http://h/mid"), 1));
        assert!(f.push(u("http://h/shallow"), 0));
        // Priority beats arrival order.
        assert_eq!(f.pop().unwrap().url.as_str(), "http://h/shallow");
        assert_eq!(f.pop().unwrap().url.as_str(), "http://h/mid");
        assert_eq!(f.pop().unwrap().url.as_str(), "http://h/deep");
    }

    #[test]
    fn seed_hosts_win_ties_over_foreign_ones() {
        let mut f = frontier_with_seed("home");
        assert!(f.push(u("http://foreign.example/x"), 0));
        assert!(f.push(u("http://home/y"), 0));
        assert!(f.push(u("http://other.example/z"), 0));
        assert_eq!(f.pop().unwrap().url.as_str(), "http://home/y");
        // Foreign hosts keep FIFO order among themselves.
        assert_eq!(f.pop().unwrap().url.as_str(), "http://foreign.example/x");
        assert_eq!(f.pop().unwrap().url.as_str(), "http://other.example/z");
    }

    #[test]
    fn depth_dominates_the_same_site_bonus() {
        let mut f = frontier_with_seed("home");
        assert!(f.push(u("http://home/deep"), 2));
        assert!(f.push(u("http://foreign.example/shallow"), 0));
        assert_eq!(
            f.pop().unwrap().url.as_str(),
            "http://foreign.example/shallow"
        );
    }

    #[test]
    fn politeness_slots_serialize_per_host() {
        let mut f = frontier_with_seed("h");
        let d = Duration::from_millis(50);

        // First reservation on an idle host starts immediately...
        let t1 = f.reserve_slot("h", d);
        assert!(t1 <= Instant::now());

        // ...but the second must wait at least one full delay past it.
        let t2 = f.reserve_slot("h", d);
        assert!(t2 >= t1 + d);
    }

    #[test]
    fn politeness_slots_are_independent_across_hosts() {
        let mut f = frontier_with_seed("h");
        let d = Duration::from_millis(50_000); // long enough to never elapse mid-test
        let _ = f.reserve_slot("a", d);
        let t_b = f.reserve_slot("b", d);
        // A different host is unaffected by host a's slot.
        assert!(t_b <= Instant::now());
    }

    #[test]
    fn host_quota_exhaustion() {
        let mut f = frontier_with_seed("h");
        assert!(!f.host_quota_exhausted("h", 2));
        assert!(!f.host_quota_exhausted("h", 2));
        assert!(f.host_quota_exhausted("h", 2));
        // Other hosts keep their own budget.
        assert!(!f.host_quota_exhausted("other", 2));
    }
}
