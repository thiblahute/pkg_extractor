//! Integration tests that download real GStreamer `.pkg` installers and
//! compare the extraction result against a committed reference fixture.
//! They are `#[ignore]`d so `cargo test` only runs the lightweight unit
//! tests. Two entry points:
//!
//! ```sh
//! # Verify our extractor still matches every committed fixture.
//! cargo test --test real_pkgs extraction_matches_fixture -- --ignored
//!
//! # Regenerate fixture(s), e.g. after a new upstream `.pkg` release.
//! cargo test --test real_pkgs regenerate_fixture -- --ignored
//! ```
//!
//! Each fixture in `tests/fixtures/<name>.txt` is a sorted, one-line-per-
//! entry dump of every file and symlink the extraction should produce:
//!
//! ```text
//! <mode_oct>\tfile\t<size>\t<fnv1a64_hex>\t<path>
//! <mode_oct>\tsymlink\t<target>\t<path>
//! ```
//!
//! Directories are implicit (they're created by the files inside them).
//! The `regenerate_fixture` test downloads a fresh installer, runs the
//! current extractor on it, and writes the resulting summary back as the
//! new fixture — no shell tools or manual steps needed.

use std::{
    error::Error,
    fs,
    io::Cursor,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use bytes::Bytes;
use pkg_extractor::PkgExtractor;
use reqwest::blocking;
use rstest::rstest;

const GSTREAMER_MIRROR: &str = "https://gstreamer.freedesktop.org/data/pkg/osx";

fn download_gstreamer_devel(version: &str) -> reqwest::Result<Bytes> {
    let url = format!("{GSTREAMER_MIRROR}/{version}/gstreamer-1.0-devel-{version}-universal.pkg");
    blocking::Client::builder()
        // The freedesktop mirror's CDN 403s the default `reqwest/…` UA.
        .user_agent(concat!("pkg-extractor/", env!("CARGO_PKG_VERSION")))
        .timeout(std::time::Duration::from_secs(600))
        .build()?
        .get(url)
        .send()?
        .error_for_status()?
        .bytes()
}

/// Walk `root` and produce a sorted, one-line-per-entry textual summary of
/// every file and symlink under it. Directories are implicit.
fn tree_summary(root: &Path) -> Result<String, Box<dyn Error>> {
    fn walk(root: &Path, dir: &Path, out: &mut Vec<String>) -> Result<(), Box<dyn Error>> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let rel = path.strip_prefix(root)?.to_string_lossy().into_owned();
            let ft = entry.file_type()?;
            let meta = fs::symlink_metadata(&path)?;
            let perm = meta.permissions().mode() & 0o7777;
            if ft.is_symlink() {
                let target = fs::read_link(&path)?;
                out.push(format!("{perm:04o}\tsymlink\t{}\t{rel}", target.display()));
            } else if ft.is_dir() {
                walk(root, &path, out)?;
            } else if ft.is_file() {
                let bytes = fs::read(&path)?;
                // FNV-1a 64-bit: no extra dep, collision-resistant enough
                // for equality of thousands of files.
                let mut h: u64 = 0xcbf29ce484222325;
                for b in &bytes {
                    h ^= *b as u64;
                    h = h.wrapping_mul(0x00000100000001B3);
                }
                out.push(format!(
                    "{perm:04o}\tfile\t{}\t{h:016x}\t{rel}",
                    bytes.len()
                ));
            }
        }
        Ok(())
    }

    let mut lines = Vec::new();
    walk(root, root, &mut lines)?;
    lines.sort();
    lines.push(String::new()); // trailing newline
    Ok(lines.join("\n"))
}

fn fixture_path(version: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(format!("gstreamer-{version}-devel.txt"))
}

/// Download `version`, extract it with `PkgExtractor`, and hand back the
/// tree summary alongside the tempdir guard (so callers can still inspect
/// the extraction on failure).
fn extract_and_summarise(version: &str) -> Result<(String, tempfile::TempDir), Box<dyn Error>> {
    let bytes = download_gstreamer_devel(version)?;
    let tmp = tempfile::tempdir()?;
    PkgExtractor::new(Cursor::new(bytes.to_vec()), Some(tmp.path().to_path_buf())).extract()?;
    let summary = tree_summary(tmp.path())?;
    Ok((summary, tmp))
}

/// Build a short sorted diff of `expected` vs `actual` for the failure
/// message. Up to 40 lines; `-` = expected, `+` = actual.
fn short_diff(expected: &str, actual: &str) -> String {
    let exp: Vec<&str> = expected.lines().collect();
    let act: Vec<&str> = actual.lines().collect();
    let mut diff = Vec::new();
    let (mut i, mut j) = (0, 0);
    while (i < exp.len() || j < act.len()) && diff.len() < 40 {
        match (exp.get(i), act.get(j)) {
            (Some(a), Some(b)) if a == b => {
                i += 1;
                j += 1;
            }
            (Some(a), Some(b)) if a < b => {
                diff.push(format!("- {a}"));
                i += 1;
            }
            (Some(a), Some(b)) if a > b => {
                diff.push(format!("+ {b}"));
                j += 1;
            }
            (Some(a), Some(b)) => {
                diff.push(format!("- {a}"));
                diff.push(format!("+ {b}"));
                i += 1;
                j += 1;
            }
            (Some(a), None) => {
                diff.push(format!("- {a}"));
                i += 1;
            }
            (None, Some(b)) => {
                diff.push(format!("+ {b}"));
                j += 1;
            }
            (None, None) => break,
        }
    }
    diff.join("\n")
}

/// Verifies the current extractor reproduces every byte, permission bit,
/// and symlink target the fixture claims. Fails with a readable diff on
/// mismatch and points at the regeneration command.
#[rstest]
#[ignore = "downloads a ~700 MiB installer"]
fn extraction_matches_fixture(#[values("1.28.2")] version: &str) -> Result<(), Box<dyn Error>> {
    let (summary, _tmp) = extract_and_summarise(version)?;
    let fixture = fixture_path(version);
    let expected = fs::read_to_string(&fixture).map_err(|e| {
        format!(
            "missing fixture {}: {e}. Generate it with: \
             cargo test --test real_pkgs regenerate_fixture -- --ignored",
            fixture.display()
        )
    })?;
    if expected == summary {
        return Ok(());
    }
    Err(format!(
        "extraction does not match {}\n\
         first differences (- expected, + actual):\n{}\n\n\
         regenerate with: cargo test --test real_pkgs regenerate_fixture -- --ignored",
        fixture.display(),
        short_diff(&expected, &summary),
    )
    .into())
}

/// Downloads and re-extracts every tracked version, writing each tree
/// summary back to its fixture. Run this after genuine output changes
/// (new upstream release, extractor behaviour change) and commit the
/// resulting diffs. Always succeeds if the downloads and extractions do;
/// does not compare against the old fixture.
#[rstest]
#[ignore = "downloads installers and overwrites committed fixtures"]
fn regenerate_fixture(#[values("1.28.2")] version: &str) -> Result<(), Box<dyn Error>> {
    let (summary, _tmp) = extract_and_summarise(version)?;
    let fixture = fixture_path(version);
    fs::create_dir_all(fixture.parent().unwrap())?;
    fs::write(&fixture, summary)?;
    eprintln!("wrote {}", fixture.display());
    Ok(())
}
