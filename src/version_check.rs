//! Background version check — queries GitHub releases for newer versions.
//!
//! Checks are non-blocking, cached for 24 hours, and configurable via
//! `check_for_updates` in settings.json.

use std::path::{Path, PathBuf};

/// Current crate version (from Cargo.toml).
pub const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// How long to cache the version check result (24 hours).
const CACHE_TTL_SECS: u64 = 24 * 60 * 60;

/// Result of a version check.
#[derive(Debug, Clone)]
pub enum VersionCheckResult {
    /// A newer version is available.
    UpdateAvailable { latest: String },
    /// Already on the latest (or newer) version.
    UpToDate,
    /// Check failed (network error, parse error, etc.) — fail silently.
    Failed,
}

/// Compare two semver-like version strings (e.g. "0.1.0" vs "0.2.0").
///
/// Returns `true` if `latest` is strictly newer than `current`.
#[must_use]
pub fn is_newer(current: &str, latest: &str) -> bool {
    let parse = |v: &str| -> Option<(u32, u32, u32)> {
        let v = v.strip_prefix('v').unwrap_or(v);
        // Strip pre-release suffix (e.g. "1.2.3-dev")
        let v = v.split('-').next()?;
        let mut parts = v.splitn(3, '.');
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next()?.parse().ok()?;
        let patch = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
        Some((major, minor, patch))
    };

    match (parse(current), parse(latest)) {
        (Some(c), Some(l)) => l > c,
        _ => false,
    }
}

/// Path to the version check cache file.
fn cache_path() -> PathBuf {
    let config_dir = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
    config_dir.join("pi").join(".version_check_cache")
}

/// Read a cached version if the cache is fresh (within TTL).
#[must_use]
pub fn read_cached_version() -> Option<String> {
    read_cached_version_at(&cache_path())
}

fn read_cached_version_at(path: &Path) -> Option<String> {
    let metadata = std::fs::metadata(path).ok()?;
    let modified = metadata.modified().ok()?;
    let age = modified.elapsed().ok()?;
    if age.as_secs() > CACHE_TTL_SECS {
        return None;
    }
    let content = std::fs::read_to_string(path).ok()?;
    let version = content.trim().to_string();
    if version.is_empty() {
        return None;
    }
    Some(version)
}

/// Write a version to the cache file.
pub fn write_cached_version(version: &str) {
    write_cached_version_at(&cache_path(), version);
}

fn write_cached_version_at(path: &Path, version: &str) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(path, version);
}

/// Check the latest version from cache or return None if cache is stale/missing.
///
/// The actual HTTP check is performed separately (by the caller spawning
/// a background task with the HTTP client).
#[must_use]
pub fn check_cached() -> VersionCheckResult {
    read_cached_version().map_or(VersionCheckResult::Failed, |latest| {
        if is_newer(CURRENT_VERSION, &latest) {
            VersionCheckResult::UpdateAvailable { latest }
        } else {
            VersionCheckResult::UpToDate
        }
    })
}

/// Parse the latest version from a GitHub releases API JSON response.
///
/// Expects the response from `https://api.github.com/repos/OWNER/REPO/releases/latest`.
#[must_use]
pub fn parse_github_release_version(json: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(json).ok()?;
    let tag = value.get("tag_name")?.as_str()?;
    // Strip leading 'v' if present
    let version = tag.strip_prefix('v').unwrap_or(tag);
    Some(version.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_newer_basic() {
        assert!(is_newer("0.1.0", "0.2.0"));
        assert!(is_newer("0.1.0", "1.0.0"));
        assert!(is_newer("1.0.0", "1.0.1"));
    }

    #[test]
    fn is_newer_same_version() {
        assert!(!is_newer("1.0.0", "1.0.0"));
    }

    #[test]
    fn is_newer_current_is_newer() {
        assert!(!is_newer("2.0.0", "1.0.0"));
    }

    #[test]
    fn is_newer_with_v_prefix() {
        assert!(is_newer("v0.1.0", "v0.2.0"));
        assert!(is_newer("0.1.0", "v0.2.0"));
        assert!(is_newer("v0.1.0", "0.2.0"));
    }

    #[test]
    fn is_newer_with_prerelease() {
        // Pre-release suffix is stripped for comparison
        assert!(!is_newer("1.2.3-dev", "1.2.3"));
        assert!(is_newer("1.2.3-dev", "1.3.0"));
    }

    #[test]
    fn is_newer_invalid_versions() {
        assert!(!is_newer("not-a-version", "1.0.0"));
        assert!(!is_newer("1.0.0", "not-a-version"));
        assert!(!is_newer("", ""));
    }

    #[test]
    fn parse_github_release_version_valid() {
        let json = r#"{"tag_name": "v0.2.0", "name": "Release 0.2.0"}"#;
        assert_eq!(
            parse_github_release_version(json),
            Some("0.2.0".to_string())
        );
    }

    #[test]
    fn parse_github_release_version_no_v_prefix() {
        let json = r#"{"tag_name": "0.2.0"}"#;
        assert_eq!(
            parse_github_release_version(json),
            Some("0.2.0".to_string())
        );
    }

    #[test]
    fn parse_github_release_version_invalid_json() {
        assert_eq!(parse_github_release_version("not json"), None);
    }

    #[test]
    fn parse_github_release_version_missing_tag() {
        let json = r#"{"name": "Release"}"#;
        assert_eq!(parse_github_release_version(json), None);
    }

    #[test]
    fn cache_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache");

        write_cached_version_at(&path, "1.2.3");
        assert_eq!(read_cached_version_at(&path), Some("1.2.3".to_string()));
    }

    #[test]
    fn cache_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonexistent");
        assert_eq!(read_cached_version_at(&path), None);
    }

    #[test]
    fn cache_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache");
        std::fs::write(&path, "").unwrap();
        assert_eq!(read_cached_version_at(&path), None);
    }
}
