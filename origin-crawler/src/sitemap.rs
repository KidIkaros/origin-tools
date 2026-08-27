// SPDX-License-Identifier: Apache-2.0

//! sitemap.xml discovery — dependency-light `<loc>` extraction.
//!
//! A host's `/sitemap.xml` is a machine-readable list of URLs that often
//! includes pages reachable by no other path. Before BFS starts, each seed
//! origin's sitemap is fetched (when enabled) and its entries are injected
//! as extra depth-0 seeds; they then pass through the normal crawl
//! pipeline — robots gating, politeness, quota, dedup — like any other URL.
//!
//! Like `parser`, this deliberately avoids a real XML parser: the sitemap
//! protocol is a fixed shape (`<urlset>/<sitemapindex>` with `<loc>`
//! elements), so scanning suffices and malformed documents degrade to "fewer
//! or no URLs" rather than errors.

/// Extract every `<loc>…</loc>` payload from a sitemap document.
///
/// Handles namespace-qualified urlsets, surrounding whitespace, and CDATA
/// wrappers. Duplicates are *not* removed here — the frontier's seen-set
/// dedups on enqueue.
pub fn extract_locations(xml: &str) -> Vec<String> {
    let lower = xml.to_ascii_lowercase();
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while let Some(rel) = lower[cursor..].find("<loc>") {
        let start = cursor + rel + "<loc>".len();
        let Some(end_rel) = lower[start..].find("</loc>") else {
            break;
        };
        let end = start + end_rel;
        if let Some(loc) = clean(xml[start..end].trim()) {
            out.push(loc);
        }
        cursor = end + "</loc>".len();
    }
    out
}

/// Strip a CDATA wrapper, if present, from a raw `<loc>` payload.
fn clean(raw: &str) -> Option<String> {
    let inner = raw.trim();
    if let Some(rest) = inner.strip_prefix("<![CDATA[") {
        return Some(rest.strip_suffix("]]>")?.trim().to_string());
    }
    if inner.is_empty() {
        None
    } else {
        Some(inner.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_locs_from_namespaced_urlset() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://example.com/</loc></url>
  <url>
    <loc>
      https://example.com/about
    </loc>
  </url>
</urlset>"#;
        assert_eq!(
            extract_locations(xml),
            vec!["https://example.com/", "https://example.com/about"]
        );
    }

    #[test]
    fn handles_sitemapindex_and_cdata() {
        let xml = "<sitemapindex><sitemap><loc><![CDATA[ https://e.com/sm.xml ]]></loc>\
                   </sitemap></sitemapindex>";
        assert_eq!(extract_locations(xml), vec!["https://e.com/sm.xml"]);
    }

    #[test]
    fn empty_and_malformed_documents_yield_nothing() {
        assert!(extract_locations("").is_empty());
        assert!(extract_locations("not xml at all").is_empty());
        // Unterminated <loc> degrades to zero rather than panicking.
        assert!(extract_locations("<urlset><loc>oops</urlset>").is_empty());
        assert_eq!(extract_locations("<loc></loc>").len(), 0);
    }

    #[test]
    fn duplicate_locs_are_kept_for_the_frontier_to_dedup() {
        let xml = "<a><loc>/x</loc></a><b><loc>/x</loc></b>";
        assert_eq!(extract_locations(xml), vec!["/x", "/x"]);
    }

    #[test]
    fn case_insensitive_tags_match_uppercase_documents() {
        let xml = "<URLSET><URL><LOC>https://e.com/p</LOC></URL></URLSET>";
        assert_eq!(extract_locations(xml), vec!["https://e.com/p"]);
    }
}
