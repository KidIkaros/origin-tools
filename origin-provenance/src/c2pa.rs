// SPDX-License-Identifier: Apache-2.0

//! Hand-rolled minimal C2PA reader (spec S5; design D1/E/F) — annotation
//! channel only, NEVER a trust signal.
//!
//! Read scope (design E/F, verbatim): v1 ships readers for JPEG APP11, PNG
//! iTXt, and sidecar JUMBF (`.jumbf`); other containers yield the explicit
//! line "C2PA parse not attempted (no reader for this container)" — never
//! silent. Parsed reports are verbatim-minimal: claim generator, actions,
//! whether the signature parses — always suffixed "C2PA claim present — not
//! Origin-verified."
//!
//! Interop honesty: this is a *minimal* JUMBF walk (ISO 19566-5 superboxes:
//! `jumb` containing a leading `jumd` description with a label), not a full
//! conformance implementation — C2PA parse depth is OQ6, and a broken or
//! exotic structure degrades the annotation, never the Origin verdict (F).

use std::path::Path;

/// Result of container detection: either a JUMBF byte store, an explicit
/// unsupported-container note, or absence (no C2PA data found).
pub enum C2paStore {
    /// JUMBF bytes + container name.
    Detected(Vec<u8>, &'static str),
    /// Known asset type, but no reader for its C2PA container (or none found).
    Unsupported(&'static str),
    /// Asset type with no C2PA container convention we recognize.
    Absent,
}

/// The C2PA annotation (design F — orthogonal to the three-state verdict).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C2paAnnotation {
    pub container: Option<&'static str>,
    pub present: bool,
    pub claim_generator: Option<String>,
    pub action_count: Option<usize>,
    pub signature_parses: Option<bool>,
    /// Honest note for degraded/unsupported reads (design: never silent).
    pub note: Option<String>,
}

impl C2paAnnotation {
    /// The annotation lines for verifier output — every parsed report ends
    /// with the mandated suffix; unsupported containers get the explicit
    /// no-reader line; absence prints nothing (no C2PA data is not an event).
    pub fn render(&self) -> Vec<String> {
        match (self.present, &self.note) {
            (false, Some(note)) => vec![note.clone()],
            (false, None) => vec![],
            (true, _) => {
                let mut lines = vec![];
                let mut facts: Vec<String> = vec![];
                if let Some(gen) = &self.claim_generator {
                    facts.push(format!("claim generator: {gen}"));
                }
                if let Some(n) = self.action_count {
                    facts.push(format!("{n} action(s)"));
                }
                if let Some(p) = self.signature_parses {
                    facts.push(format!(
                        "signature structure {}",
                        if p { "parses" } else { "does NOT parse" }
                    ));
                }
                let detail = if facts.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", facts.join("; "))
                };
                lines.push(format!(
                    "c2pa: {} manifest{}{}",
                    self.container.unwrap_or("unknown"),
                    detail,
                    " — C2PA claim present — not Origin-verified."
                ));
                if let Some(note) = &self.note {
                    lines.push(format!("c2pa note: {note}"));
                }
                lines
            }
        }
    }
}

/// Detect the container and extract the JUMBF store from asset bytes.
pub fn extract_store(data: &[u8], path_hint: Option<&Path>) -> C2paStore {
    // JPEG: 0xFF 0xD8 ... APP11 (0xFF 0xEB) segments carry "JP"-prefixed
    // JUMBF fragments that concatenate to the full store.
    if data.len() > 3 && data[0] == 0xFF && data[1] == 0xD8 {
        return match jpeg_app11_store(data) {
            Some(bytes) if !bytes.is_empty() => C2paStore::Detected(bytes, "jpeg-app11"),
            _ => C2paStore::Unsupported("jpeg"),
        };
    }
    // PNG: iTXt chunk keyed "c2pa" carries the store (uncompressed in v1).
    if data.len() > 8 && data[..8] == [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A] {
        return match png_itxt_store(data) {
            Some(bytes) if !bytes.is_empty() => C2paStore::Detected(bytes, "png-itxt"),
            _ => C2paStore::Unsupported("png"),
        };
    }
    // Sidecar .jumbf file: raw store.
    if let Some(p) = path_hint {
        if p.extension().map(|e| e == "jumbf").unwrap_or(false) {
            return C2paStore::Detected(data.to_vec(), "jumbf-sidecar");
        }
    }
    C2paStore::Absent
}

/// Walk JPEG markers and concatenate all APP11 payloads.
fn jpeg_app11_store(data: &[u8]) -> Option<Vec<u8>> {
    let mut i = 2usize; // past SOI
    let mut out = Vec::new();
    while i + 1 < data.len() {
        if data[i] != 0xFF {
            return None; // not walking entropy-coded data in v1
        }
        while i < data.len() && data[i] == 0xFF {
            i += 1; // fill bytes
        }
        if i >= data.len() {
            break;
        }
        let marker = data[i];
        i += 1;
        let standalone = marker == 0xD8 || (0xD0..=0xD7).contains(&marker) || marker == 0x01;
        if standalone || marker == 0xD9 {
            continue;
        }
        if i + 2 > data.len() {
            break;
        }
        let seg_len = u16::from_be_bytes([data[i], data[i + 1]]) as usize;
        if seg_len < 2 || i + seg_len > data.len() {
            return None; // malformed segment: stop the walk honestly
        }
        let payload = &data[i + 2..i + seg_len];
        if marker == 0xEB {
            // APP11: JUMBF fragments are prefixed "JP" (2 bytes).
            if payload.len() > 2 && &payload[..2] == b"JP" {
                out.extend_from_slice(&payload[2..]);
            }
        }
        i += seg_len;
        if marker == 0xDA {
            break; // SOS: scan data follows; v1 stops here
        }
    }
    Some(out)
}

/// Walk PNG chunks; return the first uncompressed iTXt keyed "c2pa".
fn png_itxt_store(data: &[u8]) -> Option<Vec<u8>> {
    let mut i = 8usize;
    while i + 8 <= data.len() {
        let len = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]) as usize;
        let ctype = &data[i + 4..i + 8];
        if i + 8 + len + 4 > data.len() {
            return None; // truncated chunk
        }
        if ctype == b"iTXt" {
            let body = &data[i + 8..i + 8 + len];
            // keyword\0 compression_flag compression_method language\0
            // translated\0 text
            let mut pos = body.iter().position(|&b| b == 0)? + 1;
            if pos >= body.len() {
                return None;
            }
            let compressed = body[pos] == 1;
            pos += 2; // flag + method
                      // two more null terminators (language, translated keyword)
            for _ in 0..2 {
                pos += body[pos..].iter().position(|&b| b == 0)? + 1;
            }
            let text = &body[pos..];
            if compressed {
                // zlib text: honest scope note rather than a wrong parse.
                return None;
            }
            return Some(text.to_vec());
        }
        i += 8 + len + 4; // header + data + CRC
    }
    None
}

/// Walk JUMBF superboxes; collect the c2pa facts from labeled payloads.
pub fn annotate(store: C2paStore) -> C2paAnnotation {
    let (bytes, container) = match store {
        C2paStore::Detected(b, c) => (b, c),
        C2paStore::Unsupported(c) => {
            return C2paAnnotation {
                container: None,
                present: false,
                claim_generator: None,
                action_count: None,
                signature_parses: None,
                note: Some(format!(
                    "C2PA parse not attempted (no reader for this container: {c})"
                )),
            };
        }
        C2paStore::Absent => {
            return C2paAnnotation {
                container: None,
                present: false,
                claim_generator: None,
                action_count: None,
                signature_parses: None,
                note: None,
            };
        }
    };

    let mut claim: Option<&[u8]> = None;
    let mut actions: Option<&[u8]> = None;
    let mut signature: Option<&[u8]> = None;

    let mut i = 0usize;
    while i + 8 <= bytes.len() {
        let len = u32::from_be_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]) as usize;
        let btype = &bytes[i + 4..i + 8];
        if len < 8 || i + len > bytes.len() {
            break; // malformed tail: degrade honestly
        }
        if btype == b"jumb" {
            let content = &bytes[i + 8..i + len];
            if let Some(label) = jumb_label(content) {
                let payload = &content[jumb_header_len(content)..];
                match label {
                    "c2pa.claim.v2" | "c2pa.claim.v1" | "c2pa.claim" => claim = Some(payload),
                    l if l.starts_with("c2pa.actions") => actions = Some(payload),
                    l if l.starts_with("c2pa.signature") => signature = Some(payload),
                    _ => {}
                }
            }
        }
        i += len;
    }

    let present = claim.is_some() || actions.is_some() || signature.is_some();
    let claim_generator = claim.and_then(cbor_get_text_claim_generator);
    let action_count = actions.and_then(cbor_count_actions);
    let signature_parses = signature.map(cbor_signature_parses);

    C2paAnnotation {
        container: Some(container),
        present,
        claim_generator,
        action_count,
        signature_parses,
        note: if present {
            None
        } else {
            Some("JUMBF store found but no c2pa.* labels recognized".into())
        },
    }
}

/// The `jumd` description box is the first child of a `jumb` superbox:
/// 16-byte UUID, 1-byte toggles (bit 0 = label), then the label (null-
/// terminated UTF-8 per the JUMBF convention; minimal-reader assumption,
/// interop depth tracked as OQ6). Returns the label if parseable.
fn jumb_label(content: &[u8]) -> Option<&str> {
    // Minimum to safely read: size(4) + type(4) + uuid(16) + toggles(1).
    if content.len() < 8 + 16 + 1 || &content[4..8] != b"jumd" {
        return None;
    }
    let toggles = content[8 + 16];
    if toggles & 1 == 0 {
        return None; // no label
    }
    let label_start = 8 + 16 + 1;
    let rest = &content[label_start..];
    let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
    std::str::from_utf8(&rest[..end]).ok()
}

/// Byte offset where the `jumb` payload begins (past the `jumd` box).
fn jumb_header_len(content: &[u8]) -> usize {
    if content.len() >= 8 {
        let dlen = u32::from_be_bytes([content[0], content[1], content[2], content[3]]) as usize;
        if content[4..8] == *b"jumd" && dlen >= 8 && dlen <= content.len() {
            return dlen;
        }
    }
    0
}

// ---- minimal CBOR (RFC 8949) scanning — top-level claims only ----

fn cbor_header(bytes: &[u8], pos: usize) -> Option<(u8, u64, usize)> {
    if pos >= bytes.len() {
        return None;
    }
    let ib = bytes[pos];
    let major = ib >> 5;
    let info = ib & 0x1f;
    // Header length per additional-info; refuse truncated headers.
    let hdr_len = match info {
        0..=23 => 1,
        24 => 2,
        25 => 3,
        26 => 5,
        27 => 9,
        _ => return None, // indefinite lengths: out of minimal scope
    };
    if pos + hdr_len > bytes.len() {
        return None;
    }
    let (val, hdr) = match info {
        0..=23 => (info as u64, 1),
        24 => (u64::from(bytes[pos + 1]), 2),
        25 => (
            u64::from(u16::from_be_bytes([bytes[pos + 1], bytes[pos + 2]])),
            3,
        ),
        26 => (
            u64::from(u32::from_be_bytes([
                bytes[pos + 1],
                bytes[pos + 2],
                bytes[pos + 3],
                bytes[pos + 4],
            ])),
            5,
        ),
        27 => (
            u64::from_be_bytes([
                bytes[pos + 1],
                bytes[pos + 2],
                bytes[pos + 3],
                bytes[pos + 4],
                bytes[pos + 5],
                bytes[pos + 6],
                bytes[pos + 7],
                bytes[pos + 8],
            ]),
            9,
        ),
        _ => unreachable!("hdr_len match above returns None for other infos"),
    };
    Some((major, val, hdr))
}

/// Skip one CBOR item at `pos`, returning the next position. Depth-capped:
/// claim payloads are attacker-controlled bytes and the minimal reader must
/// degrade, never crash (stack overflow via pathological nesting).
fn cbor_skip(bytes: &[u8], pos: usize) -> Option<usize> {
    cbor_skip_capped(bytes, pos, 0)
}

const CBOR_MAX_DEPTH: usize = 64;

fn cbor_skip_capped(bytes: &[u8], pos: usize, depth: usize) -> Option<usize> {
    if depth > CBOR_MAX_DEPTH {
        return None;
    }
    let (major, n, hdr) = cbor_header(bytes, pos)?;
    let mut next = pos + hdr;
    match major {
        0 | 1 | 7 => Some(next),
        2 | 3 => {
            next += n as usize;
            if next <= bytes.len() {
                Some(next)
            } else {
                None
            }
        }
        4 => {
            for _ in 0..n {
                next = cbor_skip_capped(bytes, next, depth + 1)?;
            }
            Some(next)
        }
        5 => {
            for _ in 0..n {
                next = cbor_skip_capped(bytes, next, depth + 1)?; // key
                next = cbor_skip_capped(bytes, next, depth + 1)?; // value
            }
            Some(next)
        }
        _ => None,
    }
}

/// Read `claim_generator` (top-level text field) from a claim CBOR map.
fn cbor_get_text_claim_generator(payload: &[u8]) -> Option<String> {
    let (major, pairs, hdr) = cbor_header(payload, 0)?;
    if major != 5 {
        return None;
    }
    let mut pos = hdr;
    for _ in 0..pairs {
        let (kmaj, _, khdr) = cbor_header(payload, pos)?;
        if kmaj != 3 {
            // Non-text key: skip the key item, then its value.
            let after_key = cbor_skip(payload, pos)?;
            pos = cbor_skip(payload, after_key)?;
            continue;
        }
        let (_, klen, _) = cbor_header(payload, pos)?;
        let key = payload.get(pos + khdr..pos + khdr + klen as usize)?;
        let key = std::str::from_utf8(key).ok()?;
        let val_pos = pos + khdr + klen as usize;
        let (vmaj, vlen, vhdr) = cbor_header(payload, val_pos)?;
        if key == "claim_generator" && vmaj == 3 {
            let val = payload.get(val_pos + vhdr..val_pos + vhdr + vlen as usize)?;
            return std::str::from_utf8(val).ok().map(str::to_string);
        }
        pos = cbor_skip(payload, val_pos)?;
    }
    None
}

/// Count entries of the `actions` array in an actions-assertion CBOR map.
fn cbor_count_actions(payload: &[u8]) -> Option<usize> {
    let (major, pairs, hdr) = cbor_header(payload, 0)?;
    if major != 5 {
        return None;
    }
    let mut pos = hdr;
    for _ in 0..pairs {
        let (kmaj, klen, khdr) = cbor_header(payload, pos)?;
        if kmaj != 3 {
            return None;
        }
        let key = payload.get(pos + khdr..pos + khdr + klen as usize)?;
        let key = std::str::from_utf8(key).ok()?;
        let val_pos = pos + khdr + klen as usize;
        if key == "actions" {
            let (vmaj, count, _) = cbor_header(payload, val_pos)?;
            return if vmaj == 4 {
                Some(count as usize)
            } else {
                None
            };
        }
        pos = cbor_skip(payload, val_pos)?;
    }
    None
}

/// COSE signature structure is a CBOR array; minimal "parses" = well-formed
/// array header with the Sig_structure arity. NOT a verification — the
/// output suffix says exactly that.
fn cbor_signature_parses(payload: &[u8]) -> bool {
    matches!(cbor_header(payload, 0), Some((4, n, _)) if n >= 4)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-build a JUMBF store: jumb(jumd("c2pa.<name>"), payload).
    pub(crate) fn build_store(boxes: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut out = Vec::new();
        for (label, payload) in boxes {
            // description box
            let mut jumd = Vec::new();
            jumd.extend_from_slice(b"jumd");
            jumd.extend_from_slice(&[0u8; 16]); // UUID
            jumd.push(0x01); // toggles: label present
            jumd.extend_from_slice(label.as_bytes());
            jumd.push(0x00); // null-terminated label
                             // ISOBMFF: the size field counts itself. `jumd` here holds
                             // [type(4)][uuid(16)][toggles(1)][label][nul], i.e. size - 4.
            let dlen = (jumd.len() as u32 + 4).to_be_bytes();

            let mut jumb = Vec::new();
            jumb.extend_from_slice(b"jumb");
            jumb.extend_from_slice(&dlen);
            jumb.extend_from_slice(&jumd);
            jumb.extend_from_slice(payload);
            // Outer size also counts its own 4-byte size field — same
            // ISOBMFF rule as the inner box (multi-box stores misalign
            // otherwise: the walk would land inside the prior payload).
            let jlen = (jumb.len() as u32 + 4).to_be_bytes();

            out.extend_from_slice(&jlen);
            out.extend_from_slice(&jumb);
        }
        out
    }

    /// CBOR map with a single text key/value.
    fn cbor_map_one(key: &str, val: &str) -> Vec<u8> {
        // Text strings are major 3: header byte 0x60 | len (short lengths).
        let mut out = vec![0xA1, 0x60 | key.len() as u8];
        out.extend_from_slice(key.as_bytes());
        out.push(0x60 | val.len() as u8);
        out.extend_from_slice(val.as_bytes());
        out
    }

    pub(crate) fn claim_store(generator: &str) -> Vec<u8> {
        build_store(&[("c2pa.claim.v2", cbor_map_one("claim_generator", generator))])
    }

    fn sig_store() -> Vec<u8> {
        // COSE-ish: array of 4
        build_store(&[("c2pa.signature", vec![0x84, 0x01, 0x02, 0x03, 0x04])])
    }

    #[allow(dead_code)]
    fn unused_but_documents_shape() {
        let _ = sig_store();
    }

    fn wrap_jpeg(store: &[u8]) -> Vec<u8> {
        let mut out = vec![0xFF, 0xD8];
        // one APP11 segment: payload = "JP" + store
        let seg_len = (2 + 2 + store.len()) as u16;
        out.extend_from_slice(&[0xFF, 0xEB]);
        out.extend_from_slice(&seg_len.to_be_bytes());
        out.extend_from_slice(b"JP");
        out.extend_from_slice(store);
        out.extend_from_slice(&[0xFF, 0xD9]);
        out
    }

    fn wrap_png(store: &[u8]) -> Vec<u8> {
        let mut out = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        let mut itxt = Vec::new();
        itxt.extend_from_slice(b"c2pa\0");
        itxt.push(0); // compression flag: uncompressed
        itxt.push(0); // compression method
        itxt.extend_from_slice(b"\0"); // language
        itxt.extend_from_slice(b"\0"); // translated keyword
        itxt.extend_from_slice(store);
        out.extend_from_slice(&(itxt.len() as u32).to_be_bytes());
        out.extend_from_slice(b"iTXt");
        out.extend_from_slice(&itxt);
        out.extend_from_slice(&[0, 0, 0, 0]); // CRC placeholder
        out.extend_from_slice(b"IEND");
        out.extend_from_slice(&[0, 0, 0, 0]);
        out
    }

    #[test]
    fn jpeg_container_parses_claim_facts() {
        let store = build_store(&[
            (
                "c2pa.claim.v2",
                cbor_map_one("claim_generator", "TestGen/1.0"),
            ),
            ("c2pa.actions", {
                let mut body = vec![0xA1, 0x67];
                body.extend_from_slice(b"actions");
                body.push(0x83); // array of 3
                body.extend(std::iter::repeat_n(0xA0, 3));
                body
            }),
            ("c2pa.signature", vec![0x84, 0x01, 0x02, 0x03, 0x04]),
        ]);
        let ann = annotate(C2paStore::Detected(store, "jpeg-app11"));
        assert!(ann.present);
        assert_eq!(ann.claim_generator.as_deref(), Some("TestGen/1.0"));
        assert_eq!(ann.action_count, Some(3));
        assert_eq!(ann.signature_parses, Some(true));
        let lines = ann.render();
        assert!(lines[0].ends_with("C2PA claim present — not Origin-verified."));
    }

    #[test]
    fn png_and_sidecar_yield_same_facts() {
        let store = claim_store("Gen/2.0");
        let ann_png = annotate(extract_store(&wrap_png(&store), None));
        assert_eq!(ann_png.container, Some("png-itxt"));
        assert_eq!(ann_png.claim_generator.as_deref(), Some("Gen/2.0"));

        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("manifest.jumbf");
        std::fs::write(&p, &store).unwrap();
        let ann_raw = annotate(extract_store(&store, Some(&p)));
        assert_eq!(ann_raw.container, Some("jumbf-sidecar"));
        assert_eq!(ann_raw.claim_generator.as_deref(), Some("Gen/2.0"));
    }

    #[test]
    fn unsupported_container_is_explicit_never_silent() {
        let ann = annotate(C2paStore::Unsupported("mp4"));
        assert!(!ann.present);
        let lines = ann.render();
        assert_eq!(
            lines[0],
            "C2PA parse not attempted (no reader for this container: mp4)"
        );
    }

    #[test]
    fn absent_c2pa_renders_nothing() {
        let ann = annotate(C2paStore::Absent);
        assert!(ann.render().is_empty());
    }

    #[test]
    fn malformed_store_degrades_honestly() {
        // Truncated box header
        let ann = annotate(C2paStore::Detected(
            vec![0x00, 0x00, 0x00, b'j'],
            "jpeg-app11",
        ));
        assert!(!ann.present);
        // Box length lying beyond the buffer
        let mut lying = Vec::new();
        lying.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
        lying.extend_from_slice(b"jumb");
        let ann = annotate(C2paStore::Detected(lying, "jpeg-app11"));
        assert!(!ann.present);
        // Broken signature structure still annotated, flagged as not parsing
        let broken = build_store(&[("c2pa.signature", vec![0x41, 0x01])]);
        let ann = annotate(C2paStore::Detected(broken, "jpeg-app11"));
        assert_eq!(ann.signature_parses, Some(false));
        assert!(ann.present);
    }

    #[test]
    fn jpeg_walk_tolerates_garbage_without_panic() {
        let data = vec![0xFF, 0xD8, 0xFF, 0xEB, 0x00, 0x02, 0xFF, 0x00];
        let ann = annotate(extract_store(&data, None));
        assert!(!ann.present);
    }

    #[test]
    fn deeply_nested_cbor_is_rejected_not_crashed() {
        // 200 nested one-element arrays: beyond the depth cap, the minimal
        // reader degrades (no facts extracted), never overflows the stack.
        let mut payload = vec![0x81u8; 200];
        payload.push(0x01); // terminal unsigned int
        let broken = build_store(&[("c2pa.claim.v2", payload)]);
        let ann = annotate(C2paStore::Detected(broken, "jumbf-sidecar"));
        assert!(ann.present);
        assert_eq!(ann.claim_generator, None);
    }

    #[test]
    fn truncated_cbor_header_is_rejected_not_panicked() {
        // Map header claims 1 pair; the text key header claims 3 bytes but
        // only 2 are present.
        let payload = vec![0xA1, 0x63, b'a', b'b'];
        let broken = build_store(&[("c2pa.claim.v2", payload)]);
        let ann = annotate(C2paStore::Detected(broken, "jumbf-sidecar"));
        assert_eq!(ann.claim_generator, None);

        // Truncated 8-byte integer header inside an actions payload.
        let payload = vec![
            0xA1, 0x67, b'a', b'c', b't', b'i', b'o', b'n', b's', 0x1B, 0x01,
        ];
        let broken = build_store(&[("c2pa.actions", payload)]);
        let ann = annotate(C2paStore::Detected(broken, "jumbf-sidecar"));
        assert_eq!(ann.action_count, None);
    }

    #[test]
    fn both_containers_detected_correctly() {
        let store = claim_store("X/1");
        assert!(matches!(
            extract_store(&wrap_jpeg(&store), None),
            C2paStore::Detected(_, "jpeg-app11")
        ));
        assert!(matches!(
            extract_store(&wrap_png(&store), None),
            C2paStore::Detected(_, "png-itxt")
        ));
        // Plain text asset: absent.
        assert!(matches!(extract_store(b"hello", None), C2paStore::Absent));
    }
}

/// Test-support re-exports: verify.rs tests build C2PA fixtures without
/// duplicating the byte-format builders. Not part of the public API.
#[cfg(test)]
pub(crate) mod tests_support {
    use super::tests::claim_store as claim_store_pub;

    pub(crate) fn claim_store(generator: &str) -> Vec<u8> {
        claim_store_pub(generator)
    }
}
