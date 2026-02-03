//! Unit tests for error type conversions and display invariants.
//!
//! Covers:
//! - All error constructors (config/session/provider/auth/tool/validation/extension/api)
//! - From conversions (`io::Error`, `serde_json::Error`, `sqlmodel_core::Error`, `LockError`)
//! - Display formatting (ensures context appears in error messages)

mod common;

use pi::error::{Error, Result};
use std::fs;
use std::io::{self, ErrorKind};

use common::logging::TestLogger;

/// Helper to assert an error message contains expected substring.
fn assert_display_contains(err: &Error, expected: &str) {
    let display = err.to_string();
    assert!(
        display.contains(expected),
        "Error display '{display}' should contain '{expected}'"
    );
}

/// Helper to assert an error message is non-empty and has expected prefix.
fn assert_display_prefix(err: &Error, prefix: &str) {
    let display = err.to_string();
    assert!(!display.is_empty(), "Error display should not be empty");
    assert!(
        display.starts_with(prefix),
        "Error display '{display}' should start with '{prefix}'"
    );
}

// =============================================================================
// Constructor tests
// =============================================================================

#[test]
fn test_config_error_constructor() {
    let logger = TestLogger::new();
    logger.info("setup", "Testing Error::config constructor");

    let err = Error::config("invalid model ID");

    logger.info_ctx("verify", "Checking display output", |ctx| {
        ctx.push(("error".into(), err.to_string()));
    });

    assert_display_prefix(&err, "Configuration error:");
    assert_display_contains(&err, "invalid model ID");
}

#[test]
fn test_config_error_with_empty_message() {
    let err = Error::config("");
    // Empty messages are allowed but display still has prefix
    assert_display_prefix(&err, "Configuration error:");
}

#[test]
fn test_session_error_constructor() {
    let logger = TestLogger::new();
    logger.info("setup", "Testing Error::session constructor");

    let err = Error::session("corrupt JSONL at line 42");

    logger.info_ctx("verify", "Checking display output", |ctx| {
        ctx.push(("error".into(), err.to_string()));
    });

    assert_display_prefix(&err, "Session error:");
    assert_display_contains(&err, "corrupt JSONL at line 42");
}

#[test]
fn test_session_not_found_variant() {
    let err = Error::SessionNotFound {
        path: "/home/user/.pi/sessions/test.jsonl".to_string(),
    };

    assert_display_contains(&err, "Session not found");
    assert_display_contains(&err, "/home/user/.pi/sessions/test.jsonl");
}

#[test]
fn test_provider_error_constructor() {
    let logger = TestLogger::new();
    logger.info("setup", "Testing Error::provider constructor");

    let err = Error::provider("anthropic", "rate limit exceeded");

    logger.info_ctx("verify", "Checking display output", |ctx| {
        ctx.push(("error".into(), err.to_string()));
    });

    assert_display_prefix(&err, "Provider error:");
    assert_display_contains(&err, "anthropic");
    assert_display_contains(&err, "rate limit exceeded");
}

#[test]
fn test_auth_error_constructor() {
    let logger = TestLogger::new();
    logger.info("setup", "Testing Error::auth constructor");

    let err = Error::auth("invalid API key format");

    logger.info_ctx("verify", "Checking display output", |ctx| {
        ctx.push(("error".into(), err.to_string()));
    });

    assert_display_prefix(&err, "Authentication error:");
    assert_display_contains(&err, "invalid API key format");
}

#[test]
fn test_tool_error_constructor() {
    let logger = TestLogger::new();
    logger.info("setup", "Testing Error::tool constructor");

    let err = Error::tool("bash", "command not found: rg");

    logger.info_ctx("verify", "Checking display output", |ctx| {
        ctx.push(("error".into(), err.to_string()));
    });

    assert_display_prefix(&err, "Tool error:");
    assert_display_contains(&err, "bash");
    assert_display_contains(&err, "command not found: rg");
}

#[test]
fn test_validation_error_constructor() {
    let logger = TestLogger::new();
    logger.info("setup", "Testing Error::validation constructor");

    let err = Error::validation("oldText not found in file");

    logger.info_ctx("verify", "Checking display output", |ctx| {
        ctx.push(("error".into(), err.to_string()));
    });

    assert_display_prefix(&err, "Validation error:");
    assert_display_contains(&err, "oldText not found in file");
}

#[test]
fn test_extension_error_constructor() {
    let logger = TestLogger::new();
    logger.info("setup", "Testing Error::extension constructor");

    let err = Error::extension("extension manifest missing name field");

    logger.info_ctx("verify", "Checking display output", |ctx| {
        ctx.push(("error".into(), err.to_string()));
    });

    assert_display_prefix(&err, "Extension error:");
    assert_display_contains(&err, "extension manifest missing name field");
}

#[test]
fn test_api_error_constructor() {
    let logger = TestLogger::new();
    logger.info("setup", "Testing Error::api constructor");

    let err = Error::api("unexpected HTTP 503");

    logger.info_ctx("verify", "Checking display output", |ctx| {
        ctx.push(("error".into(), err.to_string()));
    });

    assert_display_prefix(&err, "API error:");
    assert_display_contains(&err, "unexpected HTTP 503");
}

#[test]
fn test_aborted_error() {
    let err = Error::Aborted;

    let display = err.to_string();
    assert_eq!(display, "Operation aborted");
}

// =============================================================================
// From conversion tests
// =============================================================================

#[test]
fn test_from_io_error() {
    let logger = TestLogger::new();
    logger.info("setup", "Testing From<std::io::Error> conversion");

    // Create a real io::Error by accessing a non-existent file
    let io_err = fs::read("/nonexistent/path/that/does/not/exist").unwrap_err();

    let err: Error = io_err.into();

    logger.info_ctx("verify", "Checking display output", |ctx| {
        ctx.push(("error".into(), err.to_string()));
    });

    assert_display_prefix(&err, "IO error:");
}

#[test]
fn test_from_io_error_not_found() {
    // Specific io::Error variant
    let io_err = io::Error::new(ErrorKind::NotFound, "file not found");
    let err: Error = io_err.into();

    assert_display_prefix(&err, "IO error:");
    assert_display_contains(&err, "file not found");
}

#[test]
fn test_from_io_error_permission_denied() {
    let io_err = io::Error::new(ErrorKind::PermissionDenied, "access denied");
    let err: Error = io_err.into();

    assert_display_prefix(&err, "IO error:");
    assert_display_contains(&err, "access denied");
}

#[test]
fn test_from_serde_json_error() {
    let logger = TestLogger::new();
    logger.info("setup", "Testing From<serde_json::Error> conversion");

    // Create a real serde_json::Error by parsing malformed JSON
    let json_err: serde_json::Error =
        serde_json::from_str::<serde_json::Value>("{ invalid }").unwrap_err();

    let err: Error = json_err.into();

    logger.info_ctx("verify", "Checking display output", |ctx| {
        ctx.push(("error".into(), err.to_string()));
    });

    assert_display_prefix(&err, "JSON error:");
}

#[test]
fn test_from_serde_json_eof_error() {
    // Unexpected end of input
    let json_err: serde_json::Error = serde_json::from_str::<serde_json::Value>("{").unwrap_err();
    let err: Error = json_err.into();

    assert_display_prefix(&err, "JSON error:");
    // The error message should indicate EOF or missing something
    let display = err.to_string();
    assert!(display.len() > 12); // More than just "JSON error: "
}

#[test]
fn test_from_lock_error_cancelled() {
    let logger = TestLogger::new();
    logger.info(
        "setup",
        "Testing LockError::Cancelled -> Error::Aborted mapping",
    );

    let lock_err = asupersync::sync::LockError::Cancelled;
    let err: Error = lock_err.into();

    logger.info_ctx("verify", "Checking display output", |ctx| {
        ctx.push(("error".into(), err.to_string()));
    });

    // Cancelled should map to Aborted
    assert!(matches!(err, Error::Aborted));
    assert_eq!(err.to_string(), "Operation aborted");
}

#[test]
fn test_from_lock_error_poisoned() {
    let logger = TestLogger::new();
    logger.info(
        "setup",
        "Testing LockError::Poisoned -> Session error mapping",
    );

    let lock_err = asupersync::sync::LockError::Poisoned;
    let err: Error = lock_err.into();

    logger.info_ctx("verify", "Checking display output", |ctx| {
        ctx.push(("error".into(), err.to_string()));
    });

    // Poisoned should map to Session error
    assert_display_prefix(&err, "Session error:");
}

// =============================================================================
// Display format stability tests (for snapshot comparisons)
// =============================================================================

#[test]
fn test_display_format_stability_config() {
    let err = Error::config("test message");
    assert_eq!(err.to_string(), "Configuration error: test message");
}

#[test]
fn test_display_format_stability_session() {
    let err = Error::session("test message");
    assert_eq!(err.to_string(), "Session error: test message");
}

#[test]
fn test_display_format_stability_provider() {
    let err = Error::provider("test_provider", "test message");
    assert_eq!(
        err.to_string(),
        "Provider error: test_provider: test message"
    );
}

#[test]
fn test_display_format_stability_auth() {
    let err = Error::auth("test message");
    assert_eq!(err.to_string(), "Authentication error: test message");
}

#[test]
fn test_display_format_stability_tool() {
    let err = Error::tool("test_tool", "test message");
    assert_eq!(err.to_string(), "Tool error: test_tool: test message");
}

#[test]
fn test_display_format_stability_validation() {
    let err = Error::validation("test message");
    assert_eq!(err.to_string(), "Validation error: test message");
}

#[test]
fn test_display_format_stability_extension() {
    let err = Error::extension("test message");
    assert_eq!(err.to_string(), "Extension error: test message");
}

#[test]
fn test_display_format_stability_api() {
    let err = Error::api("test message");
    assert_eq!(err.to_string(), "API error: test message");
}

#[test]
fn test_display_format_stability_session_not_found() {
    let err = Error::SessionNotFound {
        path: "/test/path".to_string(),
    };
    assert_eq!(err.to_string(), "Session not found: /test/path");
}

#[test]
fn test_display_format_stability_aborted() {
    let err = Error::Aborted;
    assert_eq!(err.to_string(), "Operation aborted");
}

// =============================================================================
// Debug formatting tests
// =============================================================================

#[test]
fn test_debug_format_includes_variant() {
    let err = Error::config("test");
    let debug = format!("{err:?}");
    assert!(debug.contains("Config"));
}

#[test]
fn test_debug_format_provider_includes_both_fields() {
    let err = Error::provider("openai", "timeout");
    let debug = format!("{err:?}");
    assert!(debug.contains("Provider"));
    assert!(debug.contains("openai"));
    assert!(debug.contains("timeout"));
}

#[test]
fn test_debug_format_tool_includes_both_fields() {
    let err = Error::tool("grep", "invalid regex");
    let debug = format!("{err:?}");
    assert!(debug.contains("Tool"));
    assert!(debug.contains("grep"));
    assert!(debug.contains("invalid regex"));
}

// =============================================================================
// Result type tests
// =============================================================================

#[test]
fn test_result_type_alias() {
    fn returning_ok() -> Result<i32> {
        let value = "42"
            .parse::<i32>()
            .map_err(|e| Error::config(format!("parse error: {e}")))?;
        Ok(value)
    }

    fn returning_err() -> Result<i32> {
        Err(Error::config("test"))
    }

    assert!(returning_ok().is_ok());
    assert!(returning_err().is_err());
}

#[test]
fn test_result_with_question_mark() {
    fn inner() -> Result<()> {
        Err(Error::validation("failed"))
    }

    fn outer() -> Result<()> {
        inner()?;
        Ok(())
    }

    let result = outer();
    assert!(result.is_err());
    if let Err(e) = result {
        assert_display_prefix(&e, "Validation error:");
    }
}

// =============================================================================
// Error context preservation tests
// =============================================================================

#[test]
fn test_provider_error_preserves_provider_name() {
    for provider in ["anthropic", "openai", "gemini", "azure", "bedrock"] {
        let err = Error::provider(provider, "test");
        assert_display_contains(&err, provider);
    }
}

#[test]
fn test_tool_error_preserves_tool_name() {
    for tool in ["read", "write", "edit", "bash", "grep", "find", "ls"] {
        let err = Error::tool(tool, "test");
        assert_display_contains(&err, tool);
    }
}

#[test]
fn test_session_not_found_preserves_path() {
    let paths = [
        "/home/user/.pi/sessions/test.jsonl",
        "./relative/path.jsonl",
        "~/.pi/sessions/session.jsonl",
    ];

    for path in paths {
        let err = Error::SessionNotFound {
            path: path.to_string(),
        };
        assert_display_contains(&err, path);
    }
}

// =============================================================================
// Unicode and special character handling
// =============================================================================

#[test]
fn test_error_with_unicode_message() {
    let err = Error::config("配置错误: 无效的模型ID");
    let display = err.to_string();
    assert!(display.contains("配置错误"));
}

#[test]
fn test_error_with_newlines_in_message() {
    let err = Error::validation("line 1\nline 2\nline 3");
    let display = err.to_string();
    assert!(display.contains('\n'));
}

#[test]
fn test_error_with_special_characters() {
    let err = Error::tool("bash", "command failed: `echo \"hello\" | grep 'world'`");
    let display = err.to_string();
    assert!(display.contains('`'));
    assert!(display.contains('"'));
    assert!(display.contains('\''));
}
