// SPDX-License-Identifier: Apache-2.0

//! Content parser — dependency-light HTML scanning.
//!
//! Extracts the page title and anchor hrefs without a full HTML parser:
//! sufficient for a foundational crawler, and deliberately forgiving of
//! malformed markup (bad HTML is expected in the wild).

use url::Url;

/// Metadata extracted from one fetched page.
#[derive(Debug, Default, Clone)]
pub struct PageMeta {
    pub title: Option<String>,
    pub links: Vec<String>,
}

/// Scan an HTML document for its title and anchor hrefs.
///
/// Matching runs on a lowercase copy while attribute values are sliced from
/// the original text (ASCII lowercasing preserves byte offsets, including
/// inside multi-byte UTF-8).
pub fn parse(html: &str) -> PageMeta {
    let lower = html.to_ascii_lowercase();
    PageMeta {
        title: extract_between(&lower, html, "<title>", "</title>").map(|t| collapse_ws(&t)),
        links: extract_hrefs(html, &lower),
    }
}

/// Resolve a raw href against the page URL.
///
/// Rejects non-http(s) schemes, empty and fragment-only references, strips
/// fragments (so `page#section` and `page` dedupe to one frontier entry),
/// and decodes the `&amp;` entity that shows up in hand-authored markup.
/// Returns `None` for URLs exceeding `max_len`.
pub fn resolve(raw: &str, base: &Url) -> Option<Url> {
    let cleaned = raw.trim();
    if cleaned.is_empty() || cleaned.starts_with('#') {
        return None;
    }
    let low = cleaned.to_ascii_lowercase();
    if low.starts_with("javascript:")
        || low.starts_with("mailto:")
        || low.starts_with("data:")
        || low.starts_with("tel:")
    {
        return None;
    }
    let decoded = cleaned.replace("&amp;", "&");
    let mut url = base.join(&decoded).ok()?;
    if !matches!(url.scheme(), "http" | "https") {
        return None;
    }
    url.set_fragment(None);
    Some(url)
}

fn extract_between(lower: &str, orig: &str, open: &str, close: &str) -> Option<String> {
    let start = lower.find(open)? + open.len();
    let end = start + lower[start..].find(close)?;
    Some(orig[start..end].to_string())
}

fn collapse_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn extract_hrefs(orig: &str, lower: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = lower.as_bytes();
    let mut i = 0;
    while let Some(pos) = lower[i..].find("<a") {
        let tag_start = i + pos;
        let Some(rel_end) = lower[tag_start..].find('>') else {
            break;
        };
        let tag_end = tag_start + rel_end; // index of '>'
                                           // Must be an anchor tag: "<a", "<a ", "<a\n", ... not "<abbr".
        let after = bytes[tag_start + 2];
        if matches!(after, b' ' | b'\t' | b'\n' | b'\r' | b'/' | b'>') {
            let tag_lower = &lower[tag_start..=tag_end];
            let tag_orig = &orig[tag_start..=tag_end];
            if let Some(v) = attr_value(tag_orig, tag_lower, "href") {
                out.push(v);
            }
        }
        i = tag_end + 1;
    }
    out
}

/// Pull an attribute value from one tag, honoring double quotes, single
/// quotes, and unquoted values. Locating happens on `tag_lower`, slicing on
/// `tag_orig` so value casing survives.
fn attr_value(tag_orig: &str, tag_lower: &str, name: &str) -> Option<String> {
    let mut search_from = 0;
    loop {
        let at = tag_lower[search_from..].find(name)? + search_from;
        let after_name = at + name.len();
        let rest = &tag_lower[after_name..];
        let eq_rel = rest.find('=')?;
        // Attribute name must be followed by '=' with only whitespace between.
        if !rest[..eq_rel].trim().is_empty() {
            search_from = after_name + 1;
            continue;
        }
        let val_start = after_name + eq_rel + 1;
        let val_rest = &tag_lower[val_start..];
        let trimmed = val_rest.trim_start();
        let lead = val_rest.len() - trimmed.len();
        let abs = val_start + lead;

        if trimmed.starts_with('"') || trimmed.starts_with('\'') {
            let quote = trimmed.as_bytes()[0];
            let body_start = abs + 1;
            let close_rel = tag_lower[body_start..].find(quote as char)?;
            return Some(tag_orig[body_start..body_start + close_rel].to_string());
        }
        // Unquoted value: ends at whitespace or '>'.
        let end_rel = trimmed
            .find(|c: char| c.is_whitespace() || c == '>')
            .unwrap_or(trimmed.len());
        return Some(tag_orig[abs..abs + end_rel].to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Url {
        Url::parse("http://h/dir/page.html").unwrap()
    }

    #[test]
    fn extracts_title_and_links_mixed_quotes() {
        let html = r#"<html><head><TITLE>Hello   World</title></head>
            <body>
              <a HREF="/one">one</a>
              <a href='/two'>two</a>
              <a href=three>three</a>
              <a href="https://other.example/x">abs</a>
            </body></html>"#;
        let meta = parse(html);
        assert_eq!(meta.title.as_deref(), Some("Hello World"));
        assert_eq!(meta.links.len(), 4);
        assert_eq!(meta.links[0], "/one");
        assert_eq!(meta.links[2], "three");
    }

    #[test]
    fn ignores_non_anchor_tags_and_hrefless_anchors() {
        let html = r#"<abbr href="/nope">x</abbr><a name="anchor">y</a><p>z</p>"#;
        let meta = parse(html);
        assert!(meta.links.is_empty());
    }

    #[test]
    fn resolve_relative_absolute_and_entities() {
        let b = base();
        assert_eq!(
            resolve("sub/x.html", &b).unwrap().as_str(),
            "http://h/dir/sub/x.html"
        );
        assert_eq!(resolve("/root", &b).unwrap().as_str(), "http://h/root");
        assert_eq!(
            resolve("http://other.example/p?a=1&amp;b=2", &b)
                .unwrap()
                .as_str(),
            "http://other.example/p?a=1&b=2"
        );
    }

    #[test]
    fn resolve_strips_fragments_for_dedup() {
        let b = Url::parse("http://h/a").unwrap();
        assert_eq!(resolve("/a#section", &b).unwrap().as_str(), "http://h/a");
        assert!(resolve("#local", &b).is_none());
        assert!(resolve("", &b).is_none());
    }

    #[test]
    fn resolve_rejects_bad_schemes() {
        let b = base();
        assert!(resolve("javascript:void(0)", &b).is_none());
        assert!(resolve("mailto:a@b.c", &b).is_none());
        assert!(resolve("ftp://h/f", &b).is_none());
    }

    #[test]
    fn utf8_offsets_survive_lowercase_copy() {
        let html = r#"<a title="héllo wörld" href="/ünïcode">link</a>"#;
        let meta = parse(html);
        assert_eq!(meta.links, vec!["/ünïcode"]);
    }
}
