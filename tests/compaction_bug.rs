use pi::compaction::{ResolvedCompactionSettings, prepare_compaction};
use pi::model::{
    AssistantMessage, ContentBlock, Cost, StopReason, TextContent, Usage, UserContent,
};
use pi::session::{EntryBase, MessageEntry, SessionEntry, SessionMessage};

#[test]
fn test_compaction_usage_double_counting_bug() {
    // Create an assistant message with specific usage
    let usage = Usage {
        input: 100, // Total input tokens (includes cached)
        output: 10,
        cache_read: 20,
        cache_write: 30,
        total_tokens: 0, // Simulate missing/default total_tokens
        cost: Cost::default(),
    };

    let message = SessionMessage::Assistant {
        message: AssistantMessage {
            content: vec![ContentBlock::Text(TextContent::new("test"))],
            api: "test".to_string(),
            provider: "test".to_string(),
            model: "test".to_string(),
            usage,
            stop_reason: StopReason::Stop,
            error_message: None,
            timestamp: 0,
        },
    };

    let user1 = SessionEntry::Message(MessageEntry {
        base: EntryBase::new(None, "u1".to_string()),
        message: SessionMessage::User {
            content: UserContent::Text("hi".to_string()),
            timestamp: None,
        },
    });

    let assistant_entry = SessionEntry::Message(MessageEntry {
        base: EntryBase::new(None, "msg1".to_string()),
        message,
    });

    // Add a trailing user message so `estimate_context_tokens` considers it "after" the last
    // assistant usage entry, but keep it empty so its token estimate is 0.
    let user2 = SessionEntry::Message(MessageEntry {
        base: EntryBase::new(None, "u2".to_string()),
        message: SessionMessage::User {
            content: UserContent::Text(String::new()),
            timestamp: None,
        },
    });

    let entries = vec![user1, assistant_entry, user2];
    // Force a non-empty `messages_to_summarize` so `prepare_compaction` returns `Some(...)`.
    let settings = ResolvedCompactionSettings {
        keep_recent_tokens: 0,
        ..Default::default()
    };

    // prepare_compaction calculates tokens_before using estimate_context_tokens
    // which uses calculate_context_tokens
    let prep = prepare_compaction(&entries, settings);

    assert!(prep.is_some());
    let prep = prep.unwrap();

    // Correct behavior (assuming `input` includes cached tokens): 100 + 10 = 110.
    assert_eq!(
        prep.tokens_before, 110,
        "Expected 110 tokens (100 input + 10 output), got double-counted tokens"
    );
}
