#![cfg(all(
    feature = "legacy-scanner",
    feature = "lua",
    feature = "platform-models"
))]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use venom_scanner::{
    ConfigLoader, Event, EventBus, EventType, LuaContext, LuaExecutionStatus, LuaReturnValue,
    LuaScript, LuaScriptRegistry,
};

#[tokio::test]
async fn registry_executes_only_the_registered_source_snapshot() {
    let root = tempfile::tempdir().expect("temporary script root");
    let source = root.path().join("fixture.lua");
    std::fs::write(
        &source,
        "emit(context.target); return context.parameter('mode')",
    )
    .expect("fixture source");

    let script = LuaScript::new_safe("fixture", &source, root.path()).expect("validated script");
    let script_id = script.id();
    std::fs::write(&source, "return 'replacement must not run'").expect("replacement source");
    let registry = LuaScriptRegistry::new().expect("registry");
    registry.register(script).expect("registration");

    let result = registry
        .execute(
            &script_id,
            LuaContext::new("approved-target").with_parameter("mode", "snapshot"),
        )
        .await;
    let result = result.expect("execution");

    assert_eq!(result.status(), LuaExecutionStatus::Completed);
    assert_eq!(result.output(), "approved-target");
    assert_eq!(
        result.return_value(),
        Some(&LuaReturnValue::String("snapshot".to_owned()))
    );
    assert!(registry.get(&script_id).expect("registry lookup").is_some());
    assert_eq!(registry.get_history(&script_id).expect("history").len(), 1);
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
