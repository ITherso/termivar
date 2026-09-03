//! Downstream contract tests for runtime-owned scan context construction.

#![cfg(feature = "legacy-scanner")]

use std::sync::Arc;

use reqwest::Client;
use termivar_core::{EntityId, EntityKind, KnowledgeEntity};
use termivar_scanner::{EventBus, ScanContext};
use tokio_util::sync::CancellationToken;
use url::Url;

fn inputs() -> (Url, Client, tokio::sync::mpsc::UnboundedSender<String>) {
    let target = Url::parse("https://example.test").expect("fixture URL must be valid");
    let (telemetry_tx, _telemetry_rx) = tokio::sync::mpsc::unbounded_channel();
    (target, Client::new(), telemetry_tx)
}

#[test]
fn named_constructors_preserve_runtime_policy() {
    let (target, client, telemetry_tx) = inputs();
    let default_context = ScanContext::new(target, client, telemetry_tx);
    assert_eq!(default_context.phase_timeout_secs, 300);

    let (target, client, telemetry_tx) = inputs();
    let timeout_context = ScanContext::with_timeout(target, client, telemetry_tx, 17);
    assert_eq!(timeout_context.phase_timeout_secs, 17);

    let cancellation = CancellationToken::new();
    let (target, client, telemetry_tx) = inputs();
    let cancellable_context =
        ScanContext::with_cancellation(target, client, telemetry_tx, 23, cancellation.clone());
    cancellation.cancel();
    assert!(cancellable_context.cancel_token.is_cancelled());

    let event_bus = Arc::new(EventBus::new());
    let (target, client, telemetry_tx) = inputs();
    let event_context = ScanContext::with_event_bus(
        target,
        client,
        telemetry_tx,
        29,
        CancellationToken::new(),
        event_bus.clone(),
    );
    assert!(Arc::ptr_eq(&event_context.event_bus, &event_bus));
}

#[test]
fn cloned_contexts_share_one_knowledge_identity() {
    let (target, client, telemetry_tx) = inputs();
    let context = ScanContext::new(target, client, telemetry_tx);
    let cloned = context.clone();
    let entity = KnowledgeEntity::new(
        EntityId::new("host:example.test").expect("fixture ID must be valid"),
        EntityKind::Host,
        "example.test",
    )
    .expect("fixture entity must be valid");

    context
        .knowledge()
        .insert_entity(entity)
        .expect("knowledge write must succeed");

    assert_eq!(cloned.knowledge().stats().entities, 1);
}
