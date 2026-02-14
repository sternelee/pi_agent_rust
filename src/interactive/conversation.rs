use crate::model::{
    ContentBlock, ImageContent, Message as ModelMessage, TextContent, Usage, UserContent,
};
use crate::models::ModelEntry;
use crate::session::{Session, SessionEntry, SessionMessage, bash_execution_to_text};
use serde_json::{Value, json};

use super::text_utils::push_line;
use super::{ConversationMessage, MessageRole};

pub(super) fn user_content_to_text(content: &UserContent) -> String {
    match content {
        UserContent::Text(text) => text.clone(),
        UserContent::Blocks(blocks) => content_blocks_to_text(blocks),
    }
}

pub(super) fn assistant_content_to_text(content: &[ContentBlock]) -> (String, Option<String>) {
    let mut text = String::new();
    let mut thinking = String::new();

    for block in content {
        match block {
            ContentBlock::Text(t) => text.push_str(&t.text),
            ContentBlock::Thinking(t) => thinking.push_str(&t.thinking),
            _ => {}
        }
    }

    let thinking = if thinking.trim().is_empty() {
        None
    } else {
        Some(thinking)
    };

    (text, thinking)
}

pub(super) fn content_blocks_to_text(blocks: &[ContentBlock]) -> String {
    let mut output = String::new();
    for block in blocks {
        match block {
            ContentBlock::Text(text_block) => push_line(&mut output, &text_block.text),
            ContentBlock::Image(image) => {
                let rendered =
                    crate::terminal_images::render_inline(&image.data, &image.mime_type, 72);
                push_line(&mut output, &rendered);
            }
            ContentBlock::Thinking(thinking_block) => {
                push_line(&mut output, &thinking_block.thinking);
            }
            ContentBlock::ToolCall(call) => {
                push_line(&mut output, &format!("[tool call: {}]", call.name));
            }
        }
    }
    output
}

pub(super) fn split_content_blocks_for_input(
    blocks: &[ContentBlock],
) -> (String, Vec<ImageContent>) {
    let mut text = String::new();
    let mut images = Vec::new();
    for block in blocks {
        match block {
            ContentBlock::Text(text_block) => push_line(&mut text, &text_block.text),
            ContentBlock::Image(image) => images.push(image.clone()),
            _ => {}
        }
    }
    (text, images)
}

pub(super) fn build_content_blocks_for_input(
    text: &str,
    images: &[ImageContent],
) -> Vec<ContentBlock> {
    let mut content = Vec::new();
    if !text.trim().is_empty() {
        content.push(ContentBlock::Text(TextContent::new(text.to_string())));
    }
    for image in images {
        content.push(ContentBlock::Image(image.clone()));
    }
    content
}

pub(super) fn tool_content_blocks_to_text(blocks: &[ContentBlock], show_images: bool) -> String {
    let mut output = String::new();
    let mut hidden_images = 0usize;

    for block in blocks {
        match block {
            ContentBlock::Text(text_block) => push_line(&mut output, &text_block.text),
            ContentBlock::Image(image) => {
                if show_images {
                    let rendered =
                        crate::terminal_images::render_inline(&image.data, &image.mime_type, 72);
                    push_line(&mut output, &rendered);
                } else {
                    hidden_images = hidden_images.saturating_add(1);
                }
            }
            ContentBlock::Thinking(thinking_block) => {
                push_line(&mut output, &thinking_block.thinking);
            }
            ContentBlock::ToolCall(call) => {
                push_line(&mut output, &format!("[tool call: {}]", call.name));
            }
        }
    }

    if !show_images && hidden_images > 0 {
        push_line(&mut output, &format!("[{hidden_images} image(s) hidden]"));
    }

    output
}

pub fn conversation_from_session(session: &Session) -> (Vec<ConversationMessage>, Usage) {
    let mut messages = Vec::new();
    let mut usage = Usage::default();

    for entry in session.entries_for_current_path() {
        let SessionEntry::Message(message_entry) = entry else {
            continue;
        };

        match &message_entry.message {
            SessionMessage::User { content, .. } => {
                messages.push(ConversationMessage::new(
                    MessageRole::User,
                    user_content_to_text(content),
                    None,
                ));
            }
            SessionMessage::Assistant { message } => {
                let (text, thinking) = assistant_content_to_text(&message.content);
                add_usage(&mut usage, &message.usage);
                messages.push(ConversationMessage::new(
                    MessageRole::Assistant,
                    text,
                    thinking,
                ));
            }
            SessionMessage::ToolResult {
                tool_name,
                content,
                details,
                is_error,
                ..
            } => {
                let (mut text, _) = assistant_content_to_text(content);
                if let Some(diff) = details
                    .as_ref()
                    .and_then(|d: &Value| d.get("diff"))
                    .and_then(Value::as_str)
                {
                    let diff = diff.trim();
                    if !diff.is_empty() {
                        if !text.trim().is_empty() {
                            text.push_str("\n\n");
                        }
                        text.push_str("Diff:\n");
                        text.push_str(diff);
                    }
                }
                let prefix = if *is_error {
                    "Tool error"
                } else {
                    "Tool result"
                };
                messages.push(ConversationMessage::tool(format!(
                    "{prefix} ({tool_name}): {text}"
                )));
            }
            SessionMessage::BashExecution {
                command,
                output,
                extra,
                ..
            } => {
                let mut text = bash_execution_to_text(command, output, 0, false, false, None);
                if extra
                    .get("excludeFromContext")
                    .and_then(Value::as_bool)
                    .is_some_and(|v| v)
                {
                    text.push_str("\n\n[Output excluded from model context]");
                }
                messages.push(ConversationMessage::tool(text));
            }
            SessionMessage::Custom {
                content, display, ..
            } => {
                if *display {
                    messages.push(ConversationMessage::new(
                        MessageRole::System,
                        content.clone(),
                        None,
                    ));
                }
            }
            _ => {}
        }
    }

    (messages, usage)
}

pub(super) fn extension_model_from_entry(entry: &ModelEntry) -> Value {
    json!({
        "provider": entry.model.provider.as_str(),
        "id": entry.model.id.as_str(),
        "name": entry.model.name.as_str(),
        "api": entry.model.api.as_str(),
        "baseUrl": entry.model.base_url.as_str(),
        "reasoning": entry.model.reasoning,
        "contextWindow": entry.model.context_window,
        "maxTokens": entry.model.max_tokens,
        "apiKeyPresent": entry.api_key.is_some(),
    })
}

pub(super) fn last_assistant_message(
    messages: &[ModelMessage],
) -> Option<&crate::model::AssistantMessage> {
    messages.iter().rev().find_map(|msg| match msg {
        ModelMessage::Assistant(assistant) => Some(assistant),
        _ => None,
    })
}

pub(super) fn add_usage(total: &mut Usage, delta: &Usage) {
    total.input = total.input.saturating_add(delta.input);
    total.output = total.output.saturating_add(delta.output);
    total.cache_read = total.cache_read.saturating_add(delta.cache_read);
    total.cache_write = total.cache_write.saturating_add(delta.cache_write);
    total.total_tokens = total.total_tokens.saturating_add(delta.total_tokens);
    total.cost.input += delta.cost.input;
    total.cost.output += delta.cost.output;
    total.cost.cache_read += delta.cost.cache_read;
    total.cost.cache_write += delta.cost.cache_write;
    total.cost.total += delta.cost.total;
}
