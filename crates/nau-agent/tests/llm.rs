//! LLM port tests: integer-only budgets, honest heuristics, fallible providers,
//! and provider metadata as data.
//!
//! upstream v2.5.6 fix set covered here:
//! * adapters that `.unwrap()`ed the client result and indexed `choices[0]`
//!   unchecked, so any provider error was an unconditional panic;
//! * `temperature: f64`;
//! * `truncate_history` silently degrading to "system prompt only".

use nau_agent::{
    context_window_for, digest_request_sequence, known_profiles, model_context_windows,
    provider_names, request_digest, ChatMessage, ChatRequest, ChatResponse, ChatRole, LlmProvider,
    ProviderOutcome, ProviderProfile, ScriptedProvider, TokenBudget,
};
use nau_core::NauError;
use serde_json::Value;

fn scripted(replies: &[&str]) -> ScriptedProvider {
    ScriptedProvider::new(
        "scripted-test-double",
        8_000,
        replies.iter().map(|r| (*r).to_string()).collect(),
    )
}

/// Walk a JSON value looking for any float. `serde_json` represents a float as
/// `Value::Number` with `is_f64()` true.
fn contains_f64(value: &Value) -> bool {
    match value {
        Value::Number(number) => number.is_f64(),
        Value::Array(items) => items.iter().any(contains_f64),
        Value::Object(map) => map.values().any(contains_f64),
        _ => false,
    }
}

#[test]
fn a_chat_request_round_trips_without_a_single_float() {
    let request = ChatRequest {
        model: "deepseek-flash".into(),
        messages: vec![
            ChatMessage::system("You are a careful agent."),
            ChatMessage::user("Summarise the ledger."),
            ChatMessage::assistant("Which ledger?"),
            ChatMessage::user("The escrow one."),
        ],
        max_tokens: 512,
        // 0.7 expressed as milli-units: the whole point of the field.
        temperature_milli: 700,
    };

    let value = serde_json::to_value(&request).expect("serializes");
    assert!(
        !contains_f64(&value),
        "a signed-payload-safe request must contain no f64 at all: {value}"
    );

    // Spot-check the shape, so the test cannot pass on a serialization failure.
    assert_eq!(value["temperature_milli"], Value::from(700));
    assert_eq!(value["model"], Value::from("deepseek-flash"));
    assert_eq!(value["messages"][0]["role"], Value::from("system"));
    assert_eq!(
        value["messages"][3]["content"],
        Value::from("The escrow one.")
    );

    // The rendered JSON text must contain no float *number*. Checking for a bare
    // '.' or 'e' in the text is wrong: this very fixture contains "deepseek-flash"
    // (an 'e') and prose ending in a period ("You are a careful agent."). The check
    // must look for the *shape* of a number, so scan for digit '.' digit and
    // digit ('e'|'E') [digit|sign].
    let text = serde_json::to_string(&request).expect("serializes");
    let bytes = text.as_bytes();
    let float_syntax = bytes
        .windows(3)
        .any(|w| w[0].is_ascii_digit() && w[1] == b'.' && w[2].is_ascii_digit());
    assert!(!float_syntax, "no float number may appear: {text}");
    let exponent_syntax = bytes.windows(3).any(|w| {
        w[0].is_ascii_digit()
            && (w[1] == b'e' || w[1] == b'E')
            && (w[2].is_ascii_digit() || w[2] == b'+' || w[2] == b'-')
    });
    assert!(!exponent_syntax, "no exponent number may appear: {text}");
    // The prose really does contain the characters a naive scan would trip on.
    assert!(text.contains("deepseek-flash") && text.contains("agent."));

    let decoded: ChatRequest = serde_json::from_value(value).expect("deserializes");
    assert_eq!(decoded, request, "the round trip must be lossless");

    // A response is likewise float-free.
    let response = ChatResponse {
        model: decoded.model.clone(),
        content: "Done.".into(),
        prompt_tokens: 21,
        completion_tokens: 3,
        finish_reason: "stop".into(),
    };
    let response_value = serde_json::to_value(&response).expect("serializes");
    assert!(!contains_f64(&response_value));
    assert_eq!(response_value["finish_reason"], Value::from("stop"));
}

#[test]
fn a_chat_request_can_be_signed_because_it_is_integer_only() {
    // The canonical-payload layer rejects floats outright, so a request that
    // survives canonicalization is proof of integer-only encoding.
    let request = ChatRequest {
        model: "qwen3.8-max".into(),
        messages: vec![ChatMessage::user("你好，请总结")],
        max_tokens: 1_024,
        temperature_milli: 1_000,
    };
    let canonical = nau_core::identity::canonical::canonical_payload(&request)
        .expect("integer-only payload canonicalizes");
    let text = String::from_utf8(canonical).expect("canonical payloads are UTF-8");
    assert!(text.contains("temperature_milli"));
    assert!(text.contains("1000"));

    // A float is refused by the same layer, which is what makes the field type
    // matter rather than being a style choice.
    let floaty = serde_json::json!({ "temperature": 0.7 });
    assert!(nau_core::identity::canonical::canonical_string(&floaty).is_err());
}

#[test]
fn the_token_budget_reserves_output_tokens() {
    let budget = TokenBudget::new(64_000, 4_096).expect("a valid budget");
    assert_eq!(budget.context_window(), 64_000);
    assert_eq!(budget.reserve_output(), 4_096);
    assert_eq!(
        budget.input_budget(),
        64_000 - 4_096,
        "input budget must exclude the reservation"
    );

    // A reservation that leaves no room is refused at construction.
    assert!(TokenBudget::new(4_096, 4_096).is_err());
    assert!(TokenBudget::new(4_096, 5_000).is_err());
    assert!(TokenBudget::new(0, 0).is_err());
    assert!(TokenBudget::new(1, 0).is_ok());
}

#[test]
fn the_estimate_is_labelled_a_heuristic_and_behaves_like_one() {
    let budget = TokenBudget::new(100_000, 0).expect("a valid budget");
    assert_eq!(budget.estimate(&[]), 0, "no messages cost nothing");

    let small = budget.estimate(&[ChatMessage::user("hello world")]);
    let large = budget.estimate(&[ChatMessage::user("hello world".repeat(100))]);
    assert!(small > 0 && large > small, "more text must cost more");

    // CJK is denser per byte than ASCII, so the same byte count costs more.
    let ascii = budget.estimate(&[ChatMessage::user("a".repeat(60))]);
    let cjk = budget.estimate(&[ChatMessage::user("汉".repeat(60))]);
    assert!(
        cjk > ascii,
        "a heuristic that ignores CJK would under-count it: ascii={ascii} cjk={cjk}"
    );

    // It is deterministic and never overflows, even for absurd input.
    assert_eq!(small, budget.estimate(&[ChatMessage::user("hello world")]));
    let huge = budget.estimate(&[ChatMessage::user("x".repeat(4_000_000))]);
    assert!(huge > 0);
    let _ = budget.estimate(&[ChatMessage::user("\u{0}".repeat(10_000))]);
}

#[test]
fn fits_accounts_for_both_the_prompt_and_the_completion() {
    let budget = TokenBudget::new(1_000, 0).expect("a valid budget");
    let messages = vec![ChatMessage::user("x".repeat(400))]; // ~100 tokens + overhead
    assert!(budget.fits(&messages, 500));
    assert!(
        !budget.fits(&messages, 10_000),
        "the completion must be counted"
    );
    assert!(!budget.fits(&[], 1), "an empty conversation fails closed");
}

#[test]
fn truncate_history_drops_the_oldest_non_system_messages_first() {
    let budget = TokenBudget::new(1_000, 0).expect("a valid budget");
    let mut messages = vec![
        ChatMessage::system("system rules"),
        ChatMessage::user("oldest"),
        ChatMessage::user("middle"),
        ChatMessage::user("newest"),
    ];
    // Room for everything.
    assert!(budget.fits(&messages, 0));
    let dropped = budget
        .truncate_history(&mut messages, 0)
        .expect("fits already");
    assert_eq!(dropped, 0);

    // Now make it exactly tight enough for the system prompt plus the newest
    // message, so both older messages have to go. A window of `newest_only + 10`
    // would leave room for one short message and only drop one.
    let newest_only = budget.estimate(&[messages[0].clone(), ChatMessage::user("newest")]);
    let mut messages = vec![
        ChatMessage::system("system rules"),
        ChatMessage::user("oldest"),
        ChatMessage::user("middle"),
        ChatMessage::user("newest"),
    ];
    let budget = TokenBudget::new(newest_only, 0).expect("a valid budget");
    let dropped = budget
        .truncate_history(&mut messages, 0)
        .expect("truncation succeeds");
    assert_eq!(dropped, 2, "both older messages are dropped");
    assert_eq!(messages.len(), 2);
    assert_eq!(
        messages[0].role,
        ChatRole::System,
        "system is never dropped"
    );
    assert_eq!(messages[1].content, "newest", "order is preserved");
    assert!(budget.fits(&messages, 0));
}

#[test]
fn truncate_history_errors_when_a_single_message_cannot_fit() {
    // upstream v2.5.6 fix: upstream broke out of its loop and returned the
    // system prompt alone, sending it as if it were the request. That must be an
    // error instead.
    let budget = TokenBudget::new(2_000, 0).expect("a valid budget");
    let mut messages = vec![
        ChatMessage::system("system rules"),
        ChatMessage::user("x".repeat(100_000)),
    ];
    let err = budget
        .truncate_history(&mut messages, 0)
        .expect_err("an unfittable newest message must be an error");
    assert!(matches!(err, NauError::Validation(_)), "got {err:?}");
    assert!(
        err.to_string().contains("no non-system message"),
        "the error must explain why nothing could be dropped: {err}"
    );

    // A request whose *system prompt* alone is too large is also an error, and
    // the message is left untouched rather than silently emptied.
    let mut system_only = vec![ChatMessage::system("s".repeat(100_000))];
    let before = system_only.clone();
    assert!(budget.truncate_history(&mut system_only, 0).is_err());
    assert_eq!(
        system_only, before,
        "a failed truncation must not mutate input"
    );
}

#[test]
fn truncate_history_respects_the_completion_reservation() {
    // The cap the caller passes and the reservation both count against the
    // window, so a larger `max_tokens` must force more dropping.
    let budget = TokenBudget::new(4_096, 1_024).expect("a valid budget");
    let build = || {
        vec![
            ChatMessage::system("rules"),
            ChatMessage::user("a".repeat(2_000)),
            ChatMessage::user("b".repeat(2_000)),
            ChatMessage::user("c".repeat(2_000)),
        ]
    };
    let mut generous = build();
    let dropped_generous = budget
        .truncate_history(&mut generous, 100)
        .expect("succeeds");
    let mut tight = build();
    let dropped_tight = budget
        .truncate_history(&mut tight, 3_000)
        .expect("succeeds");
    assert!(
        dropped_tight > dropped_generous,
        "a larger completion must force more history drops: {dropped_tight} vs {dropped_generous}"
    );
    assert!(budget.fits(&generous, 100));
    assert!(budget.fits(&tight, 3_000));
}

#[tokio::test]
async fn a_scripted_provider_is_usable_through_dyn_llm_provider() {
    let provider = scripted(&["first answer", "second answer"]);
    // The port must be object-safe: a consumer holds `dyn LlmProvider`.
    let dynamic: &dyn LlmProvider = &provider;
    assert_eq!(dynamic.name(), "scripted-test-double");
    assert_eq!(dynamic.context_window(), 8_000);

    let request = ChatRequest {
        model: "any".into(),
        messages: vec![ChatMessage::user("question one")],
        max_tokens: 64,
        temperature_milli: 0,
    };
    let first = dynamic
        .chat(request.clone())
        .await
        .expect("a scripted reply");
    assert_eq!(first.content, "first answer");
    assert_eq!(first.model, "any");
    assert_eq!(first.finish_reason, "stop");
    assert!(first.prompt_tokens > 0);
    assert!(first.completion_tokens > 0);

    let second = dynamic
        .chat(request.clone())
        .await
        .expect("a second scripted reply");
    assert_eq!(second.content, "second answer");
    assert_eq!(provider.calls(), 2);
    assert_eq!(provider.remaining(), 0);

    // Running out of script is a typed error, never a panic.
    let err = dynamic.chat(request).await.unwrap_err();
    assert!(matches!(err, NauError::Validation(_)), "got {err:?}");
    assert_eq!(provider.calls(), 3, "a failed call is still counted");

    // The same request digests identically every time (determinism).
    let request = ChatRequest {
        model: "m".into(),
        messages: vec![ChatMessage::user("same")],
        max_tokens: 8,
        temperature_milli: 250,
    };
    assert_eq!(
        request_digest(&request).expect("digests"),
        request_digest(&request).expect("digests")
    );
}

#[tokio::test]
async fn a_provider_error_is_observed_as_a_result_not_a_panic() {
    // upstream v2.5.6 fix: the adapter `.unwrap()`ed the client result, so this
    // path used to abort the process.
    let provider = scripted(&[]);
    let request = ChatRequest {
        model: "m".into(),
        messages: vec![ChatMessage::user("hello")],
        max_tokens: 16,
        temperature_milli: 0,
    };
    let outcome = match provider.chat(request).await {
        Ok(response) => ProviderOutcome::Answered(response),
        Err(error) => ProviderOutcome::Failed(error.to_string()),
    };
    match outcome {
        ProviderOutcome::Failed(message) => assert!(message.contains("no reply left"), "{message}"),
        ProviderOutcome::Answered(_) => panic!("a provider with no script must fail"),
    }
}

#[tokio::test]
async fn a_request_that_cannot_fit_is_refused_by_the_provider() {
    let provider = scripted(&["never reached"]);
    let request = ChatRequest {
        model: "m".into(),
        messages: vec![ChatMessage::user("x".repeat(1_000_000))],
        max_tokens: 64,
        temperature_milli: 0,
    };
    let err = provider.chat(request).await.unwrap_err();
    assert!(err.to_string().contains("does not fit"), "got {err}");
    assert_eq!(provider.remaining(), 1, "the script was not consumed");
}

#[test]
fn every_profile_is_coherent_and_needs_no_secret_in_the_struct() {
    let profiles = known_profiles();
    assert!(
        profiles.len() >= 7,
        "deepseek, openai, anthropic, gemini + Chinese vendors"
    );

    let names = provider_names();
    for required in ["deepseek", "openai", "anthropic", "gemini"] {
        assert!(
            names.contains(&required),
            "`{required}` must be in the catalog"
        );
    }
    // At least two Chinese vendors.
    let chinese = ["qwen", "zhipu", "kimi"];
    assert!(
        chinese.iter().filter(|name| names.contains(name)).count() >= 2,
        "at least two Chinese vendors are required, got {names:?}"
    );

    for profile in &profiles {
        assert!(!profile.name.is_empty());
        assert!(
            profile.base_url.starts_with("https://"),
            "`{}` must use https, got `{}`",
            profile.name,
            profile.base_url
        );
        assert!(
            !profile.models.is_empty(),
            "`{}` lists no models",
            profile.name
        );
        assert!(
            profile.context_window > 0,
            "`{}` has no context window",
            profile.name
        );
        // The profile's window is the primary model's window.
        let primary = profile.models[0].clone();
        assert_eq!(
            context_window_for(&primary),
            Some(profile.context_window),
            "the profile window must match the primary model's window for `{primary}`"
        );
        // Every listed model must be resolvable.
        for model in &profile.models {
            assert!(
                context_window_for(model).is_some(),
                "`{model}` is listed by `{}` but has no window",
                profile.name
            );
        }
        // The key is named, never held.
        let env = profile.api_key_env.clone().expect("a key env var name");
        assert!(env.ends_with("_API_KEY"), "got `{env}`");
        let encoded = serde_json::to_string(profile).expect("serializes");
        for forbidden in ["sk-", "Bearer ", "secret", "token\""] {
            assert!(
                !encoded.contains(forbidden),
                "a profile must not carry a secret: found `{forbidden}` in {encoded}"
            );
        }
    }

    // Windows are per model, not one flat constant. Check the differences this
    // catalog actually relies on, across three different vendors.
    let pairs = [
        ("deepseek-flash", "deepseek-chat"),
        ("gpt-5.2", "gpt-4o"),
        ("gemini-3-pro", "gemini-3-flash"),
        ("qwen3.8-max", "qwen-max"),
        ("glm-5", "glm-4-flash"),
        ("kimi-k3", "moonshot-v1-8k"),
    ];
    for (big, small) in pairs {
        let big_window = context_window_for(big).expect("resolvable");
        let small_window = context_window_for(small).expect("resolvable");
        assert!(
            big_window > small_window,
            "`{big}` ({big_window}) must have a larger window than `{small}` ({small_window}); \
             a single flat constant for every model is the defect this table avoids"
        );
    }
}

#[test]
fn model_and_profile_lookups_are_consistent_and_deterministic() {
    let flat = model_context_windows();
    assert!(!flat.is_empty());
    // Ordered and duplicate-free, so the flat view is a usable table.
    let mut sorted = flat.clone();
    sorted.sort();
    let mut deduped = sorted.clone();
    deduped.dedup();
    assert_eq!(sorted, deduped, "no model id may appear twice");
    for (model, window) in &flat {
        assert_eq!(context_window_for(model), Some(*window));
    }

    // Case-insensitive fallback, and a hard `None` for an unknown model.
    assert_eq!(
        context_window_for("GPT-4O"),
        context_window_for("gpt-4o"),
        "lookup must be case-insensitive"
    );
    assert_eq!(
        context_window_for("  gpt-4o  "),
        context_window_for("gpt-4o")
    );
    assert_eq!(context_window_for("no-such-model"), None);
    assert_eq!(context_window_for(""), None);

    // Repeated calls are stable (no set-iteration-order leakage).
    assert_eq!(model_context_windows(), flat);
    assert_eq!(known_profiles(), known_profiles());
}

#[test]
fn a_provider_profile_round_trips_through_json() {
    let profile = ProviderProfile {
        name: "example".into(),
        base_url: "https://example.invalid/v1".into(),
        models: vec!["model-a".into(), "model-b".into()],
        context_window: 32_768,
        api_key_env: None,
    };
    let value = serde_json::to_value(&profile).expect("serializes");
    assert!(!contains_f64(&value));
    assert_eq!(value["context_window"], Value::from(32_768));
    assert!(value["api_key_env"].is_null());
    let decoded: ProviderProfile = serde_json::from_value(value).expect("deserializes");
    assert_eq!(decoded, profile);
}

#[test]
fn a_request_sequence_is_hash_chained() {
    let requests: Vec<ChatRequest> = (0..4)
        .map(|index| ChatRequest {
            model: "deepseek-flash".into(),
            messages: vec![ChatMessage::user(format!("turn {index}"))],
            max_tokens: 32,
            temperature_milli: 500,
        })
        .collect();
    let digests = digest_request_sequence(&requests).expect("digests");
    assert_eq!(digests.len(), 4);
    for digest in &digests {
        assert_eq!(digest.len(), 64, "SHA-256 hex");
    }
    // Distinct requests produce distinct links, and the chain is deterministic.
    assert_ne!(digests[0], digests[1]);
    assert_eq!(
        digests,
        digest_request_sequence(&requests).expect("digests")
    );

    // Re-running with one request changed changes the links from that point on.
    let mut tampered = requests.clone();
    tampered[2].messages = vec![ChatMessage::user("tampered")];
    let other = digest_request_sequence(&tampered).expect("digests");
    assert_eq!(digests[0], other[0]);
    assert_eq!(digests[1], other[1]);
    assert_ne!(digests[2], other[2]);
    assert_ne!(
        digests[3], other[3],
        "a change must propagate down the chain"
    );

    assert!(digest_request_sequence(&[]).expect("digests").is_empty());
}

#[test]
fn chat_roles_are_snake_case_on_the_wire() {
    for (role, expected) in [
        (ChatRole::System, "system"),
        (ChatRole::User, "user"),
        (ChatRole::Assistant, "assistant"),
    ] {
        assert_eq!(
            serde_json::to_string(&role).expect("serializes"),
            format!("\"{expected}\"")
        );
    }
    // The constructors agree with the roles.
    assert_eq!(ChatMessage::system("x").role, ChatRole::System);
    assert_eq!(ChatMessage::user("x").role, ChatRole::User);
    assert_eq!(ChatMessage::assistant("x").role, ChatRole::Assistant);
}
