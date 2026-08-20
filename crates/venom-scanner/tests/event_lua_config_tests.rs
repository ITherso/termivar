#![cfg(all(
    feature = "legacy-scanner",
    feature = "lua",
    feature = "platform-models"
))]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use venom_scanner::{
    ConfigLoader, Event, EventBus, EventType, LuaContext, LuaScript, LuaScriptRegistry,
};

#[tokio::test]
async fn registered_lua_source_execution_fails_closed_without_echoing_context() {
    let root = tempfile::tempdir().expect("temporary script root");
    let source = root.path().join("fixture.lua");
    std::fs::write(&source, "return 'this source must not run'").expect("fixture source");

    let script = LuaScript::new_safe("fixture", &source, root.path()).expect("validated script");
    let script_id = script.id.to_string();
    let registry = LuaScriptRegistry::new();
    registry.register(script.clone());

    let result = script
        .execute(
            LuaContext::new("https://private.example.invalid/path")
                .with_payload("private-payload")
                .with_parameter("token", "private-value"),
        )
        .await;

    assert!(!result.success);
    assert!(result.output.is_empty());
    assert!(result.return_value.is_none());
    assert_eq!(
        result.error.as_deref(),
        Some("Lua execution is unavailable: registered script source loading is not implemented")
    );
    let diagnostic = result
        .error
        .as_deref()
        .expect("fixed unavailable diagnostic");
    assert!(!diagnostic.contains("private.example.invalid"));
    assert!(!diagnostic.contains("private-payload"));
    assert!(!diagnostic.contains("private-value"));
    assert!(registry.get(&script_id).is_some());
}

#[test]
fn built_in_profiles_do_not_enable_unwired_lua_scripts() {
    let loader = ConfigLoader::new();

    for profile_name in ["enterprise", "cloud", "aggressive", "passive"] {
        let profile = loader.get_profile(profile_name).expect("built-in profile");
        assert!(profile.lua_scripts_enabled.is_empty());
    }
}

#[test]
fn event_bus_remains_an_explicit_legacy_host_contract() {
    let bus = EventBus::new();
    let observed = Arc::new(AtomicUsize::new(0));
    let observed_by_handler = Arc::clone(&observed);

    bus.subscribe(
        EventType::ConfigReloaded,
        "active-fixture",
        Arc::new(move |_| {
            observed_by_handler.fetch_add(1, Ordering::SeqCst);
        }),
    );
    bus.publish(Event::new(EventType::ConfigReloaded, "active-fixture"));

    assert_eq!(observed.load(Ordering::SeqCst), 1);
    assert_eq!(bus.total_events(), 1);
}
