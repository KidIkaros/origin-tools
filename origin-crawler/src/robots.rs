// SPDX-License-Identifier: Apache-2.0

//! Minimal robots.txt compliance.
//!
//! Parses the `User-agent` / `Disallow` / `Allow` record structure well
//! enough for a polite foundational crawler: groups of consecutive
//! `User-agent` lines share rules, the wildcard group (`*`) always applies,
//! named product tokens apply when they appear (case-insensitively) in our
//! user agent, and Allow/Disallow conflicts resolve by longest match.
//!
//! `Sitemap:` directives are also harvested. Per the sitemap protocol they
//! are global — valid outside any user-agent group — so they are collected
//! regardless of which group is active.

/// Parsed robots.txt rules applicable to this crawler's user agent.
#[derive(Debug, Default, Clone)]
pub struct Robots {
    allow: Vec<String>,
    disallow: Vec<String>,
    /// Globally-declared `Sitemap:` URLs (outside any user-agent group).
    sitemaps: Vec<String>,
}

impl Robots {
    /// Parse robots.txt text, keeping only the rules that apply to
    /// `user_agent` (the `*` group plus any group whose token is contained
    /// in the agent string).
    pub fn parse(txt: &str, user_agent: &str) -> Self {
        let ua = user_agent.to_ascii_lowercase();
        let mut robots = Robots::default();
        let mut group_applies = false;
        let mut in_agent_block = false;

        for raw in txt.lines() {
            // Strip comments and surrounding whitespace.
            let line = raw.split('#').next().unwrap_or("").trim().to_string();
            if line.is_empty() {
                group_applies = false;
                in_agent_block = false;
                continue;
            }
            let Some((key, val)) = line.split_once(':') else {
                continue;
            };
            let key = key.trim().to_ascii_lowercase();
            let val = val.trim().to_string();
            match key.as_str() {
                "user-agent" => {
                    if !in_agent_block {
                        group_applies = false;
                        in_agent_block = true;
                    }
                    let token = val.to_ascii_lowercase();
                    if token == "*" || (!token.is_empty() && ua.contains(&token)) {
                        group_applies = true;
                    }
                }
                "disallow" | "allow" if group_applies => {
                    // An empty `Disallow:` value is pushed as "" and treated
                    // as allow-all by [`Robots::allows`].
                    if key == "disallow" {
                        robots.disallow.push(val);
                    } else {
                        robots.allow.push(val);
                    }
                }
                // Global directive: collected wherever it appears.
                "sitemap" if !val.is_empty() => {
                    robots.sitemaps.push(val);
                }
                _ => {} // crawl-delay, etc. — ignored by this minimal parser
            }
        }
        robots
    }

    /// Whether `path` (the URL path, e.g. `/private/secret`) may be fetched.
    ///
    /// Uses longest-prefix-match: an explicit Allow wins ties against an
    /// equal-length Disallow. An empty `Disallow:` value means "allow all".
    pub fn allows(&self, path: &str) -> bool {
        let mut best_allow = 0usize;
        let mut best_disallow = 0usize;
        for p in &self.allow {
            if path.starts_with(p.as_str()) && p.len() > best_allow {
                best_allow = p.len();
            }
        }
        for p in &self.disallow {
            if p.is_empty() {
                // Empty Disallow matches nothing — it grants everything.
                continue;
            }
            if path.starts_with(p.as_str()) && p.len() > best_disallow {
                best_disallow = p.len();
            }
        }
        best_allow >= best_disallow
    }

    /// True when no rules were recorded for this agent.
    pub fn is_empty(&self) -> bool {
        self.allow.is_empty() && self.disallow.is_empty()
    }

    /// Sitemap URLs declared via global `Sitemap:` directives, in file order.
    pub fn sitemaps(&self) -> &[String] {
        &self.sitemaps
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_disallow_blocks_prefix() {
        let r = Robots::parse("User-agent: *\nDisallow: /private/\n", "origin-crawler/0.4");
        assert!(r.allows("/public/page"));
        assert!(!r.allows("/private/secret"));
        assert!(r.allows("/private")); // prefix must include the trailing slash
    }

    #[test]
    fn named_group_applies_by_token_substring() {
        let txt =
            "User-agent: Googlebot\nDisallow: /g/\n\nUser-agent: origin-crawler\nDisallow: /o/\n";
        let r = Robots::parse(txt, "origin-crawler/0.4");
        assert!(r.allows("/g/anything"));
        assert!(!r.allows("/o/anything"));
    }

    #[test]
    fn unrelated_group_is_ignored() {
        let r = Robots::parse("User-agent: Bingbot\nDisallow: /\n", "origin-crawler/0.4");
        assert!(r.is_empty());
        assert!(r.allows("/anything"));
    }

    #[test]
    fn empty_disallow_means_allow_all() {
        let r = Robots::parse("User-agent: *\nDisallow:\n", "origin-crawler/0.4");
        assert!(r.allows("/everything"));
    }

    #[test]
    fn longest_match_wins_and_allow_wins_ties() {
        let txt = "User-agent: *\nDisallow: /tmp\nAllow: /tmp/keep\n";
        let r = Robots::parse(txt, "origin-crawler/0.4");
        assert!(!r.allows("/tmp/junk"));
        assert!(r.allows("/tmp/keep/file")); // longer Allow beats Disallow
                                             // Classic quirk: rules are plain string prefixes, so "/tmpkeep"
                                             // matches Disallow "/tmp" even though it is not a path prefix.
        assert!(!r.allows("/tmpkeep"));
    }

    #[test]
    fn comments_and_blank_lines_split_groups() {
        let txt = "# comment\nUser-agent: * # wildcard\nDisallow: /a # block a\n\nDisallow: /b\n";
        let r = Robots::parse(txt, "origin-crawler/0.4");
        assert!(!r.allows("/a/x"));
        assert!(r.allows("/b/x")); // rule after blank line has no active group
    }

    #[test]
    fn consecutive_agent_lines_share_a_group() {
        let txt = "User-agent: foo\nUser-agent: origin-crawler\nDisallow: /x/\n";
        let r = Robots::parse(txt, "origin-crawler/0.4");
        assert!(!r.allows("/x/y"));
    }

    #[test]
    fn sitemap_directives_are_collected_globally() {
        // Sitemap lines are valid outside any user-agent group (and after a
        // blank line that would end one).
        let txt = "Sitemap: https://e.com/a.xml\n\nUser-agent: *\nDisallow: /p/\nSitemap: https://e.com/b.xml\nSitemap:\n";
        let r = Robots::parse(txt, "origin-crawler/0.4");
        assert_eq!(r.sitemaps(), ["https://e.com/a.xml", "https://e.com/b.xml"]);
        assert!(!r.allows("/p/x"));
        // Empty values and case-insensitive keys are handled.
        let r2 = Robots::parse("sitemap: https://e.com/c.xml", "x");
        assert_eq!(r2.sitemaps(), ["https://e.com/c.xml"]);
    }
}
