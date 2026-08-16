// SPDX-License-Identifier: OPL-1.4
//
// Copyright (c) 2026 Origin Contributors

//! Concrete embedding strategy implementations.

use super::traits::{choose, EmbedStrategy};
use crate::manifest::CanaryToken;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Pick a target file for a token, preferring files not yet carrying one.
///
/// Returns an absolute path. When every eligible file already holds a token,
/// falls back to a random eligible file (so dense embedding is still possible,
/// just with reduced per-file isolation).
fn pick_target(
    files: &[PathBuf],
    used_files: &HashSet<PathBuf>,
    rng: &mut dyn super::traits::Rng,
) -> Option<PathBuf> {
    let unused: Vec<PathBuf> = files
        .iter()
        .filter(|f| !used_files.contains(*f))
        .cloned()
        .collect();
    let pool: &[PathBuf] = if unused.is_empty() { files } else { &unused };
    choose(rng, pool).map(|p| p.clone())
}

// ── Variable injection ────────────────────────────────────────────────────

/// Python: inject a module-level `_canary_<id>` constant after imports.
pub struct VariableInjectPython;

impl EmbedStrategy for VariableInjectPython {
    fn name(&self) -> &'static str {
        "variable.python"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["py"]
    }
    fn embed(
        &self,
        source_dir: &Path,
        token: &CanaryToken,
        rng: &mut dyn super::traits::Rng,
        used_files: &mut HashSet<PathBuf>,
    ) -> Option<String> {
        let files = find_files_by_ext(source_dir, &["py"])?;
        let target = pick_target(&files, used_files, rng)?;
        let relative = target.strip_prefix(source_dir).unwrap_or(&target);
        let content = fs::read_to_string(&target).ok()?;
        let mut lines: Vec<String> = content.lines().map(String::from).collect();
        let insert_at = find_python_insertion_point(&lines);
        let var_name = format!("_canary_{}", token.token_id);
        let var_value = format!("\"{}\"", token.secret);
        let injected = format!(
            "{} = {}  # Internal validation marker\n",
            var_name, var_value
        );
        lines.insert(insert_at, injected);
        write_lines_preserving(&target, &lines, &content)?;
        used_files.insert(target.clone());
        Some(relative.to_string_lossy().to_string())
    }
}

fn find_python_insertion_point(lines: &[String]) -> usize {
    let mut insert_at = 0;
    let mut in_imports = false;
    for (i, line) in lines.iter().enumerate() {
        let s = line.trim();
        if s.starts_with("import ") || s.starts_with("from ") {
            in_imports = true;
            insert_at = i + 1;
        } else if in_imports && !s.is_empty() && !s.starts_with('#') {
            in_imports = false;
            insert_at = insert_at.max(i);
        }
    }
    for (i, line) in lines.iter().enumerate().take(5) {
        if line.starts_with("#!") || line.contains("Copyright") || line.contains("SPDX") {
            insert_at = insert_at.max(i + 1);
        }
    }
    insert_at.min(lines.len())
}

/// JavaScript/TypeScript: inject a `const _canary_<id>` after imports/requires.
pub struct VariableInjectJavaScript;

impl EmbedStrategy for VariableInjectJavaScript {
    fn name(&self) -> &'static str {
        "variable.javascript"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["js", "jsx", "ts", "tsx"]
    }
    fn embed(
        &self,
        source_dir: &Path,
        token: &CanaryToken,
        rng: &mut dyn super::traits::Rng,
        used_files: &mut HashSet<PathBuf>,
    ) -> Option<String> {
        let files = find_files_by_ext(source_dir, &["js", "jsx", "ts", "tsx"])?;
        let target = pick_target(&files, used_files, rng)?;
        let relative = target.strip_prefix(source_dir).unwrap_or(&target);
        let content = fs::read_to_string(&target).ok()?;
        let mut lines: Vec<String> = content.lines().map(String::from).collect();
        let insert_at = find_js_insertion_point(&lines);
        let var_name = format!("_canary_{}", token.token_id);
        let var_value = format!("\"{}\"", token.secret);
        let suffix = target
            .extension()
            .map(|e| e.to_string_lossy().to_string())
            .unwrap_or_default();
        let injected = if suffix == "ts" || suffix == "tsx" {
            format!(
                "const {} = {} as string; // Internal validation marker\n",
                var_name, var_value
            )
        } else {
            format!(
                "const {} = {}; // Internal validation marker\n",
                var_name, var_value
            )
        };
        lines.insert(insert_at, injected);
        write_lines_preserving(&target, &lines, &content)?;
        used_files.insert(target.clone());
        Some(relative.to_string_lossy().to_string())
    }
}

fn find_js_insertion_point(lines: &[String]) -> usize {
    let mut insert_at = 0;
    for (i, line) in lines.iter().enumerate() {
        let s = line.trim();
        if s.starts_with("import ") || s.starts_with("export ") || s.starts_with("require(") {
            insert_at = i + 1;
        }
    }
    for (i, line) in lines.iter().enumerate().take(5) {
        if line.starts_with("#!") {
            insert_at = insert_at.max(i + 1);
        }
    }
    insert_at.min(lines.len())
}

/// Rust: inject a `const CANARY_<id>` after `use` / `mod` declarations.
pub struct VariableInjectRust;

impl EmbedStrategy for VariableInjectRust {
    fn name(&self) -> &'static str {
        "variable.rust"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["rs"]
    }
    fn embed(
        &self,
        source_dir: &Path,
        token: &CanaryToken,
        rng: &mut dyn super::traits::Rng,
        used_files: &mut HashSet<PathBuf>,
    ) -> Option<String> {
        let files = find_files_by_ext(source_dir, &["rs"])?;
        let target = pick_target(&files, used_files, rng)?;
        let relative = target.strip_prefix(source_dir).unwrap_or(&target);
        let content = fs::read_to_string(&target).ok()?;
        let mut lines: Vec<String> = content.lines().map(String::from).collect();
        let insert_at = find_rust_insertion_point(&lines);
        let const_name = format!("CANARY_{}", token.token_id);
        let const_value = format!("\"{}\"", token.secret);
        let injected = format!(
            "const {}: &str = {}; // Internal validation marker\n",
            const_name, const_value
        );
        lines.insert(insert_at, injected);
        write_lines_preserving(&target, &lines, &content)?;
        used_files.insert(target.clone());
        Some(relative.to_string_lossy().to_string())
    }
}

fn find_rust_insertion_point(lines: &[String]) -> usize {
    let mut insert_at = 0;
    for (i, line) in lines.iter().enumerate() {
        let s = line.trim();
        if s.starts_with("use ") || s.starts_with("extern crate") {
            insert_at = i + 1;
        }
    }
    for (i, line) in lines.iter().enumerate() {
        let s = line.trim();
        if s.starts_with("mod ") {
            insert_at = insert_at.max(i + 1);
        }
    }
    insert_at.min(lines.len())
}

/// Solidity: inject a `string constant canary_<id>` after pragma/import.
pub struct VariableInjectSolidity;

impl EmbedStrategy for VariableInjectSolidity {
    fn name(&self) -> &'static str {
        "variable.solidity"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["sol"]
    }
    fn embed(
        &self,
        source_dir: &Path,
        token: &CanaryToken,
        rng: &mut dyn super::traits::Rng,
        used_files: &mut HashSet<PathBuf>,
    ) -> Option<String> {
        let files = find_files_by_ext(source_dir, &["sol"])?;
        let target = pick_target(&files, used_files, rng)?;
        let relative = target.strip_prefix(source_dir).unwrap_or(&target);
        let content = fs::read_to_string(&target).ok()?;
        let mut lines: Vec<String> = content.lines().map(String::from).collect();
        let insert_at = find_solidity_insertion_point(&lines);
        let const_name = format!("canary_{}", token.token_id);
        let const_value = format!("\"{}\"", token.secret);
        let injected = format!(
            "string constant {} = {}; // Internal marker\n",
            const_name, const_value
        );
        lines.insert(insert_at, injected);
        write_lines_preserving(&target, &lines, &content)?;
        used_files.insert(target.clone());
        Some(relative.to_string_lossy().to_string())
    }
}

fn find_solidity_insertion_point(lines: &[String]) -> usize {
    let mut insert_at = 0;
    for (i, line) in lines.iter().enumerate() {
        let t = line.trim();
        if t.starts_with("pragma ") || t.starts_with("import ") {
            insert_at = i + 1;
        }
        if t.starts_with("contract ") || t.starts_with("interface ") || t.starts_with("library ") {
            break;
        }
    }
    insert_at.min(lines.len())
}

// ── Watermark ─────────────────────────────────────────────────────────────

/// Watermark: append `[ref:canary_...]` to an existing long comment, or add
/// a `# Module reference: canary_...` near the top of the file.
///
/// Unlike variable injection (which uses a derived value), the watermark
/// embeds the literal canary secret in a comment — making it directly
/// grep-able for verification. This is intentional: the watermark is the
/// "easy to verify" strategy, while variable injection is the "harder to
/// detect" strategy.
pub struct WatermarkStrategy;

impl EmbedStrategy for WatermarkStrategy {
    fn name(&self) -> &'static str {
        "watermark"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &[
            "py", "js", "jsx", "ts", "tsx", "rs", "sol", "c", "cpp", "h", "hpp", "go", "java", "kt",
        ]
    }
    fn embed(
        &self,
        source_dir: &Path,
        token: &CanaryToken,
        rng: &mut dyn super::traits::Rng,
        used_files: &mut HashSet<PathBuf>,
    ) -> Option<String> {
        let files = find_files_by_ext(
            source_dir,
            &[
                "py", "js", "jsx", "ts", "tsx", "rs", "sol", "c", "cpp", "h", "hpp", "go", "java",
                "kt",
            ],
        )?;
        if files.is_empty() {
            return None;
        }
        let target = pick_target(&files, used_files, rng)?;
        let relative = target.strip_prefix(source_dir).unwrap_or(&target);
        let relative_str = relative.to_string_lossy().to_string();
        let watermark = format!("[ref:{}]", token.secret);
        let content = fs::read_to_string(&target).ok()?;
        let mut lines: Vec<String> = content.lines().map(String::from).collect();

        // Try appending to an existing long comment.
        for line in lines.iter_mut() {
            let t = line.trim();
            if (t.starts_with('#')
                || t.starts_with("//")
                || t.starts_with("/*")
                || t.starts_with('*'))
                && t.len() > 15
            {
                line.push_str(&watermark);
                write_lines_preserving(&target, &lines, &content)?;
                return Some(relative_str);
            }
        }

        // Add a module-level reference near the top.
        let mut inserted = false;
        for (i, line) in lines.iter().enumerate().take(10) {
            let t = line.trim();
            if t.starts_with("#!")
                || t.starts_with("package ")
                || t.starts_with("use ")
                || t.starts_with("import ")
                || t.starts_with("extern ")
            {
                let ref_line = format!("# Module reference: {}", watermark);
                lines.insert(i + 1, ref_line);
                inserted = true;
                break;
            }
        }
        if !inserted {
            let ref_line = format!("# Module reference: {}\n", watermark);
            lines.insert(0, ref_line);
        }
        write_lines_preserving(&target, &lines, &content)?;
        used_files.insert(target.clone());
        Some(relative_str)
    }
}

// ── Dead code (Python) ────────────────────────────────────────────────────

/// Dead code: inject a functionally inert `_validate_<magic>()` helper inside
/// an existing function. No side effects, no reachable external calls.
pub struct DeadCodePython;

impl EmbedStrategy for DeadCodePython {
    fn name(&self) -> &'static str {
        "deadcode.python"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["py"]
    }
    fn embed(
        &self,
        source_dir: &Path,
        token: &CanaryToken,
        rng: &mut dyn super::traits::Rng,
        used_files: &mut HashSet<PathBuf>,
    ) -> Option<String> {
        let files = find_files_by_ext(source_dir, &["py"])?;
        if files.is_empty() {
            return None;
        }
        let target = pick_target(&files, used_files, rng)?;
        let relative = target.strip_prefix(source_dir).unwrap_or(&target);
        let relative_str = relative.to_string_lossy().to_string();
        let content = fs::read_to_string(&target).ok()?;
        let mut lines: Vec<String> = content.lines().map(String::from).collect();

        let func_lines: Vec<usize> = lines
            .iter()
            .enumerate()
            .filter(|(_, l)| l.trim().starts_with("def ") || l.trim().starts_with("async def "))
            .map(|(i, _)| i)
            .collect();
        if func_lines.is_empty() {
            return None;
        }

        let func_idx = choose(rng, &func_lines).unwrap();
        let indent = find_indent(&lines[*func_idx]);

        // Deterministic magic from the token secret (naming only — the
        // secret itself is embedded below so verification stays robust
        // across Rust releases; DefaultHasher output is not stable).
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        token.secret.hash(&mut hasher);
        let magic = format!("{:08x}", hasher.finish());
        let magic_short = if magic.len() >= 4 {
            &magic[..4]
        } else {
            &magic
        };

        let dead_code = vec![
            format!("{}# Internal validation helper", indent),
            format!("{}def _validate_{}():", indent, magic_short),
            format!(
                "{}    if isinstance(globals().get(\"_config\"), dict):",
                indent
            ),
            format!("{}        return True", indent),
            format!(
                "{}    _marker_{} = \"{}\"",
                indent, magic_short, token.secret
            ),
            format!("{}    return False", indent),
            format!("{}", indent),
        ];

        let insert_at = *func_idx + 2;
        if insert_at < lines.len() {
            for (i, line) in dead_code.iter().enumerate() {
                lines.insert(insert_at + i, line.clone());
            }
        } else {
            for line in dead_code {
                lines.push(line);
            }
        }

        write_lines_preserving(&target, &lines, &content)?;
        used_files.insert(target.clone());
        Some(relative_str)
    }
}

// ── Helpers ────────────────────────────────────────────────────────────────

/// Join lines and write them back, preserving the original file's trailing
/// newline (a plain `lines.join("\n")` silently strips it).
fn write_lines_preserving(target: &Path, lines: &[String], original: &str) -> Option<()> {
    let mut out = lines.join("\n");
    if original.ends_with('\n') {
        out.push('\n');
    }
    fs::write(target, out).ok()
}

fn find_files_by_ext(source_dir: &Path, exts: &[&str]) -> Option<Vec<PathBuf>> {
    let mut files = Vec::new();
    let exclusions = [
        "test",
        "tests",
        "__pycache__",
        "node_modules",
        ".git",
        "venv",
        ".venv",
        "build",
        "dist",
        "target",
        ".tox",
        ".nox",
        ".eggs",
    ];
    scan_for_ext(source_dir, exts, &exclusions, &mut files);
    if files.is_empty() {
        None
    } else {
        Some(files)
    }
}

fn scan_for_ext(dir: &Path, exts: &[&str], exclusions: &[&str], files: &mut Vec<PathBuf>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            if !exclusions.contains(&name.as_str()) {
                scan_for_ext(&path, exts, exclusions, files);
            }
        } else if path.is_file() {
            // Skip very large files (matches the embed.rs scan_files limit).
            if let Ok(meta) = path.metadata() {
                if meta.len() >= 500_000 {
                    continue;
                }
            }
            if let Some(ext) = path.extension() {
                if let Some(ext_str) = ext.to_str() {
                    if exts.contains(&ext_str) {
                        files.push(path);
                    }
                }
            }
        }
    }
}

fn find_indent(line: &str) -> String {
    let mut indent = String::new();
    for ch in line.chars() {
        if ch == ' ' || ch == '\t' {
            indent.push(ch);
        } else {
            break;
        }
    }
    if indent.is_empty() {
        // Top-level code: Python's canonical 4-space block indent.
        indent.push_str("    ");
    }
    indent
}
