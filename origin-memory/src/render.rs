// SPDX-License-Identifier: Apache-2.0

//! render — text-based visualization of the memory graph.
//!
//! Two views, matching the visual-thinker design:
//!
//! 1. **Tree view** — the recursive coarse hierarchy as an ASCII tree. Each
//!    node shows its evidence badge ( Doc / Assert / Sum / Ficn ) and tier.
//!    Revoked nodes are struck through: ~~id~~.
//!
//! 2. **Star chart** — nodes plotted along a temporal axis, grouped by wing.
//!    This is the "conspiracy map" view — you scan the timeline and see where
//!    evidence clusters.
//!
//! Both are pure text so they render in any terminal, markdown, or log.

use crate::memory::Memory;
use crate::node::Evidence;

fn evidence_badge(e: &Evidence) -> &'static str {
    match e {
        Evidence::Documented => "Doc",
        Evidence::Assertion => "Asrt",
        Evidence::Summary => "Sum",
        Evidence::Fiction => "Ficn",
    }
}

impl Memory {
    /// Render the hierarchy rooted at `summary_id` as an ASCII tree.
    /// Leaves show their evidence badge; revoked nodes are marked ✗.
    pub fn render_tree(&self, summary_id: &str) -> String {
        let mut out = String::new();
        self.render_tree_inner(summary_id, "", true, &mut out);
        out
    }

    fn render_tree_inner(&self, id: &str, prefix: &str, is_last: bool, out: &mut String) {
        let connector = if is_last { "└── " } else { "├── " };
        let node = match self.node(id) {
            Some(n) => n,
            None => {
                out.push_str(&format!("{}{}[missing: {}]\n", prefix, connector, id));
                return;
            }
        };

        let revoked = self.is_revoked(id);
        let badge = evidence_badge(&node.evidence);
        let marker = if revoked { " ✗" } else { "" };
        let title = if node.title.is_empty() {
            id
        } else {
            &node.title
        };

        out.push_str(&format!(
            "{}{}{} ({}){}",
            prefix, connector, title, badge, marker
        ));
        if !node.topics.is_empty() {
            out.push_str(&format!("  [{}]", node.topics.join(", ")));
        }
        out.push('\n');

        let children = match self.children(id) {
            Some(c) if !c.is_empty() => c,
            _ => return,
        };
        let extension = if is_last { "    " } else { "│   " };
        let child_prefix = format!("{}{}", prefix, extension);
        for (i, child) in children.iter().enumerate() {
            let last = i == children.len() - 1;
            self.render_tree_inner(child, &child_prefix, last, out);
        }
    }

    /// Render a temporal star chart — all non-revoked nodes sorted by time,
    /// grouped by topic "wing." Each node shows its date, evidence badge, and
    /// a positional marker on a rough timeline.
    pub fn render_star_chart(&self) -> String {
        let mut chart_ids: Vec<String> = self
            .node_ids()
            .into_iter()
            .filter(|id| !self.is_revoked(id))
            .collect();
        // Sort by time via re-lookup.
        chart_ids.sort_by_key(|id| self.node(id).map(|n| n.time).unwrap_or_default());

        if chart_ids.is_empty() {
            return "(empty memory — no nodes to chart)\n".to_string();
        }

        // Build a wing→nodes map (only non-revoked nodes).
        let mut wings: std::collections::BTreeMap<String, Vec<String>> =
            std::collections::BTreeMap::new();
        for id in &chart_ids {
            let n = match self.node(id) {
                Some(n) => n,
                None => continue,
            };
            for t in &n.topics {
                wings.entry(t.clone()).or_default().push(id.clone());
            }
        }

        let mut out = String::new();
        out.push_str("★ Star Chart — temporal evidence map\n");
        out.push_str(&format!(
            "  {} nodes across {} wings\n\n",
            chart_ids.len(),
            wings.len()
        ));

        for (wing, ids) in &wings {
            out.push_str(&format!("◆ Wing: {}\n", wing));
            for id in ids {
                let n = self.node(id).unwrap();
                let badge = evidence_badge(&n.evidence);
                let date = n.time.format("%Y-%m-%d");
                out.push_str(&format!(
                    "  {} [{}] {}{}\n",
                    date,
                    badge,
                    id,
                    if n.links.is_empty() { "" } else { " ◆" }
                ));
            }
            out.push('\n');
        }

        out
    }
}
