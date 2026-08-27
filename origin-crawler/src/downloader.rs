// SPDX-License-Identifier: Apache-2.0

//! HTML downloader — reqwest client with timeout, user agent, a
//! content-type gate so binary payloads are rejected before parsing, HTTP
//! conditional-request support (`ETag` / `Last-Modified` validators) for
//! cheap `--resume` revalidation, and bounded retry with exponential
//! backoff honoring `Retry-After` for transient failures.

use std::time::Duration;

use url::Url;

use crate::robots::Robots;

/// A successfully fetched page body.
#[derive(Debug, Clone)]
pub struct FetchedPage {
    pub status: u16,
    pub content_type: String,
    pub body: String,
    /// Raw `ETag` header, when present (used for resume revalidation).
    pub etag: Option<String>,
    /// Raw `Last-Modified` header, when present.
    pub last_modified: Option<String>,
}

/// Validators for a conditional request, keyed by URL in the sidecar store.
#[derive(Debug, Clone, Default)]
pub struct Validators {
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}

impl Validators {
    pub fn is_usable(&self) -> bool {
        self.etag.is_some() || self.last_modified.is_some()
    }
}

/// Outcome of a fetch that may be answered by a `304 Not Modified`.
#[derive(Debug)]
pub enum FetchOutcome {
    /// The server confirmed our cached copy is current.
    NotModified,
    Page(FetchedPage),
}

/// Structured fetch failure — lets the retry loop distinguish transient
/// conditions from deterministic ones without re-parsing strings.
#[derive(Debug)]
pub enum FetchError {
    /// Connection/DNS/timeout failures — usually worth retrying.
    Transport(String),
    /// Non-success HTTP status; `retry_after` carries the parsed
    /// `Retry-After` header in seconds when present.
    Status {
        status: u16,
        retry_after: Option<u64>,
    },
    /// Content-type gate rejection — deterministic, never retried.
    UnsupportedType(String),
    BodyRead(String),
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FetchError::Transport(e) => write!(f, "request failed: {e}"),
            FetchError::Status { status, .. } => write!(f, "HTTP {status}"),
            FetchError::UnsupportedType(ct) => write!(f, "unsupported content-type: {ct}"),
            FetchError::BodyRead(e) => write!(f, "body read failed: {e}"),
        }
    }
}

/// Statuses worth another attempt: rate limiting plus the classic
/// transient server errors.
fn is_retryable_status(status: u16) -> bool {
    matches!(status, 429 | 500 | 502 | 503 | 504)
}

/// How long to wait before retry `attempt` (1-based).
///
/// An explicit `Retry-After` (seconds form) wins, capped at 60s;
/// otherwise exponential backoff off `base_backoff_ms`.
fn retry_delay(retry_after: Option<u64>, attempt: u32, base_backoff_ms: u64) -> Duration {
    const MAX_SECS: u64 = 60;
    let ms = match retry_after {
        Some(secs) => secs.min(MAX_SECS) * 1_000,
        None => base_backoff_ms << attempt.saturating_sub(1),
    };
    Duration::from_millis(ms)
}

/// Thin wrapper around a configured reqwest client.
#[derive(Clone)]
pub struct Downloader {
    client: reqwest::Client,
}

impl Downloader {
    pub fn new(timeout_ms: u64, user_agent: &str) -> Result<Self, String> {
        let client = reqwest::Client::builder()
            .user_agent(user_agent)
            .timeout(Duration::from_millis(timeout_ms))
            .build()
            .map_err(|e| format!("http client build failed: {e}"))?;
        Ok(Self { client })
    }

    /// Fetch a page as text, rejecting non-HTML payloads.
    pub async fn fetch_text(&self, url: &Url) -> Result<FetchedPage, String> {
        match self.fetch(url, None).await? {
            FetchOutcome::NotModified => {
                unreachable!("unconditional request cannot yield 304")
            }
            FetchOutcome::Page(p) => Ok(p),
        }
    }

    /// Fetch a page, optionally as a conditional request.
    ///
    /// Single attempt; see [`Downloader::fetch_with_retries`] for the
    /// retrying variant.
    pub async fn fetch(
        &self,
        url: &Url,
        validators: Option<&Validators>,
    ) -> Result<FetchOutcome, String> {
        self.fetch_once(url, validators)
            .await
            .map_err(|e| e.to_string())
    }

    /// Fetch with bounded retries for transient failures.
    ///
    /// Retries transport errors and `429`/`5xx`-server statuses up to
    /// `max_retries` extra attempts, waiting per [`retry_delay`] (an
    /// explicit `Retry-After` header wins over exponential backoff).
    /// Deterministic failures (404s, content-type gates, `304`s) are never
    /// retried. Returns the outcome and how many retries were consumed.
    pub async fn fetch_with_retries(
        &self,
        url: &Url,
        validators: Option<&Validators>,
        max_retries: u32,
        base_backoff_ms: u64,
    ) -> Result<(FetchOutcome, u32), String> {
        let mut retries_used = 0u32;
        loop {
            match self.fetch_once(url, validators).await {
                Ok(outcome) => return Ok((outcome, retries_used)),
                Err(FetchError::Status {
                    status,
                    retry_after,
                }) if is_retryable_status(status) && retries_used < max_retries => {
                    tokio::time::sleep(retry_delay(retry_after, retries_used + 1, base_backoff_ms))
                        .await;
                    retries_used += 1;
                }
                Err(FetchError::Transport(_)) if retries_used < max_retries => {
                    tokio::time::sleep(retry_delay(None, retries_used + 1, base_backoff_ms)).await;
                    retries_used += 1;
                }
                Err(err) => return Err(err.to_string()),
            }
        }
    }

    async fn fetch_once(
        &self,
        url: &Url,
        validators: Option<&Validators>,
    ) -> Result<FetchOutcome, FetchError> {
        let mut req = self.client.get(url.clone());
        if let Some(v) = validators {
            if let Some(etag) = &v.etag {
                req = req.header(reqwest::header::IF_NONE_MATCH, etag);
            }
            if let Some(lm) = &v.last_modified {
                req = req.header(reqwest::header::IF_MODIFIED_SINCE, lm);
            }
        }

        let resp = req
            .send()
            .await
            .map_err(|e| FetchError::Transport(e.to_string()))?;

        let status = resp.status().as_u16();
        if status == 304 {
            return Ok(FetchOutcome::NotModified);
        }
        if !resp.status().is_success() {
            let retry_after = resp
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.trim().parse::<u64>().ok());
            return Err(FetchError::Status {
                status,
                retry_after,
            });
        }

        let content_type = content_type_of(&resp);
        if !content_type.is_empty()
            && !content_type.starts_with("text/html")
            && !content_type.starts_with("application/xhtml")
        {
            return Err(FetchError::UnsupportedType(content_type));
        }

        let etag = header(&resp, reqwest::header::ETAG);
        let last_modified = header(&resp, reqwest::header::LAST_MODIFIED);
        let body = resp
            .text()
            .await
            .map_err(|e| FetchError::BodyRead(e.to_string()))?;
        Ok(FetchOutcome::Page(FetchedPage {
            status,
            content_type,
            body,
            etag,
            last_modified,
        }))
    }

    /// Fetch and parse `/robots.txt` for a URL origin.
    ///
    /// Returns `None` on any transport error or missing/unreachable file —
    /// the standard interpretation is that crawling is then unrestricted.
    pub async fn fetch_robots(&self, origin: &str, user_agent: &str) -> Option<Robots> {
        let url = format!("{origin}/robots.txt");
        let resp = self.client.get(&url).send().await.ok()?;
        if !resp.status().is_success() {
            return None;
        }
        let txt = resp.text().await.ok()?;
        Some(Robots::parse(&txt, user_agent))
    }

    /// Fetch a sitemap document (any URL — robots.txt may declare sitemaps
    /// outside the probed host or at non-standard paths).
    ///
    /// Returns `None` when the document is missing, unreachable, or not
    /// plausibly XML — hosts without sitemaps are entirely normal.
    pub async fn fetch_sitemap(&self, url: &Url) -> Option<String> {
        let resp = self.client.get(url.clone()).send().await.ok()?;
        if !resp.status().is_success() {
            return None;
        }
        // Lenient gate: XML per spec, but tolerate text/* or absent headers.
        let ctype = content_type_of(&resp);
        if !ctype.is_empty() && !ctype.contains("xml") && !ctype.starts_with("text/") {
            return None;
        }
        resp.text().await.ok()
    }
}

fn content_type_of(resp: &reqwest::Response) -> String {
    resp.headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
}

fn header(resp: &reqwest::Response, name: reqwest::header::HeaderName) -> Option<String> {
    resp.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn client_builds_with_defaults() {
        let d = Downloader::new(5_000, "test-agent").unwrap();
        // Unroutable address fails fast without hanging past the timeout.
        let u = Url::parse("http://127.0.0.1:1/nope").unwrap();
        assert!(d.fetch_text(&u).await.is_err());
    }

    #[test]
    fn default_user_agent_matches_robots_wildcard_group() {
        // The wildcard group (`*`) always applies regardless of agent string.
        let r = Robots::parse("User-agent: *\nDisallow: /x/\n", "anything");
        assert!(!r.allows("/x/y"));
    }

    #[test]
    fn validator_usability() {
        assert!(!Validators::default().is_usable());
        assert!(Validators {
            etag: Some("\"v\"".into()),
            last_modified: None,
        }
        .is_usable());
    }
}
