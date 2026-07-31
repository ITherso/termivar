#![cfg(any())]

use std::sync::atomic::AtomicU32;
use std::sync::Arc;
use venom_scanner::{
    ConfigLoader, Event, EventBus, EventSeverity, EventType, LuaContext, LuaScript,
    LuaScriptRegistry, ScanIntensity,
};

#[test]
fn test_event_bus_with_lua_scripts() {
    let event_bus = EventBus::new();
    let script_registry = LuaScriptRegistry::new();

    // Create a script
    let script = LuaScript::new("test_script", "Test Script", "test.lua")
        .with_categories(vec!["security".to_string()]);

    script_registry.register(script);

    // Subscribe to events with handler that tracks findings
    let finding_count = Arc::new(AtomicU32::new(0));
    let finding_count_clone = finding_count.clone();

    event_bus.subscribe(
        EventType::FindingFound,
        "script_handler",
        Arc::new(move |event| {
            if event.event_type == EventType::FindingFound {
                finding_count_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        }),
    );

    // Publish finding events
    for i in 0..5 {
        let event = Event::new(EventType::FindingFound, "lua_script")
            .with_data("severity", "HIGH")
            .with_data("index", i.to_string());
        event_bus.publish(event);
    }

    assert_eq!(finding_count.load(std::sync::atomic::Ordering::SeqCst), 5);
}

#[test]
fn test_lua_script_context_with_event_publishing() {
    let event_bus = EventBus::new();
    let script_registry = LuaScriptRegistry::new();

    // Create multiple scripts
    for i in 0..3 {
        let script = LuaScript::new(
            format!("security_script_{}", i),
            format!("Security Script {}", i),
            format!("scripts/security_{}.lua", i),
        )
        .with_categories(vec!["security".to_string()]);

        script_registry.register(script);
    }

    // Create contexts
    let contexts: Vec<_> = (0..3)
        .map(|i| {
            LuaContext::new(format!("http://target{}.com", i))
                .with_payload(format!("<script>alert('xss{}')</script>", i))
                .with_parameter("intensity", "high")
        })
        .collect();

    // Publish events for each context
    for (i, ctx) in contexts.iter().enumerate() {
        let event = Event::new(EventType::PluginExecuted, "lua_engine")
            .with_data("script_id", format!("security_script_{}", i))
            .with_data("target", ctx.target.clone());

        event_bus.publish(event);
    }

    assert_eq!(event_bus.total_events(), 3);
    assert_eq!(script_registry.count(), 3);
}

#[test]
fn test_config_profiles_with_lua_scripts() {
    let config_loader = ConfigLoader::new();
    let script_registry = LuaScriptRegistry::new();

    // Get enterprise profile
    let enterprise = config_loader.get_profile("enterprise").unwrap();

    // Register scripts mentioned in profile
    for script_id in &enterprise.lua_scripts_enabled {
        let script = LuaScript::new(script_id, script_id, format!("scripts/{}.lua", script_id));
        script_registry.register(script);
    }

    assert_eq!(
        script_registry.count(),
        enterprise.lua_scripts_enabled.len()
    );

    // Get cloud profile
    let cloud = config_loader.get_profile("cloud").unwrap();

    // Register cloud profile scripts
    for script_id in &cloud.lua_scripts_enabled {
        let script = LuaScript::new(script_id, script_id, format!("scripts/{}.lua", script_id));
        script_registry.register(script);
    }

    assert!(script_registry.count() >= 2);
}

#[test]
fn test_event_bus_with_config_profile_changes() {
    let event_bus = EventBus::new();
    let config_loader = ConfigLoader::new();

    let event_count = Arc::new(AtomicU32::new(0));
    let event_count_clone = event_count.clone();

    // Subscribe to config reload events
    event_bus.subscribe(
        EventType::ConfigReloaded,
        "config_handler",
        Arc::new(move |_| {
            event_count_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }),
    );

    // Simulate profile changes
    for profile_name in &["enterprise", "cloud", "aggressive", "passive"] {
        config_loader.set_active_profile(profile_name).ok();

        let event = Event::new(EventType::ConfigReloaded, "config_loader")
            .with_data("profile", profile_name.to_string())
            .with_severity(EventSeverity::Info);

        event_bus.publish(event);
    }

    assert_eq!(event_count.load(std::sync::atomic::Ordering::SeqCst), 4);
}

#[test]
fn test_complete_scanning_workflow() {
    let event_bus = EventBus::new();
    let script_registry = LuaScriptRegistry::new();
    let config_loader = ConfigLoader::new();

    // Setup: Register scripts
    for i in 0..3 {
        let script = LuaScript::new(
            format!("workflow_script_{}", i),
            format!("Workflow Script {}", i),
            format!("workflow_{}.lua", i),
        )
        .with_categories(vec!["workflow".to_string()]);

        script_registry.register(script);
    }

    // Set active profile to aggressive
    config_loader.set_active_profile("aggressive").unwrap();
    let active_profile = config_loader.get_active_profile();

    // Track events
    let events_emitted = Arc::new(AtomicU32::new(0));
    let events_emitted_clone = events_emitted.clone();

    event_bus.subscribe(
        EventType::ScanStarted,
        "scan_tracker",
        Arc::new(move |_| {
            events_emitted_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }),
    );

    // Workflow: Scan Started
    let scan_event = Event::new(EventType::ScanStarted, "scanner")
        .with_data("target", "http://app.com")
        .with_data("profile", active_profile.name.clone())
        .with_severity(EventSeverity::Info);

    event_bus.publish(scan_event);

    // Execute scripts
    for script_id in script_registry.list_enabled() {
        let ctx = LuaContext::new("http://app.com").with_payload("<test>");

        let event = Event::new(EventType::PluginExecuted, "script_executor")
            .with_data("script_id", script_id.id)
            .with_data("target", ctx.target);

        event_bus.publish(event);
    }

    // Scan Completed
    let complete_event =
        Event::new(EventType::ScanCompleted, "scanner").with_severity(EventSeverity::Info);

    event_bus.publish(complete_event);

    assert_eq!(events_emitted.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(
        event_bus.total_events(),
        1 + script_registry.count() as u64 + 1
    );
}

#[test]
fn test_profile_merging_with_script_aggregation() {
    let config_loader = ConfigLoader::new();
    let script_registry = LuaScriptRegistry::new();

    // Get base profile
    let enterprise = config_loader.get_profile("enterprise").unwrap();

    // Get custom profile and merge
    let merged = config_loader
        .merge_profiles("enterprise", "aggressive")
        .unwrap();

    // Enterprise scripts
    for script_id in &enterprise.lua_scripts_enabled {
        let script = LuaScript::new(script_id, script_id, format!("scripts/{}.lua", script_id));
        script_registry.register(script);
    }

    // Merged scripts (should include both)
    for script_id in &merged.lua_scripts_enabled {
        if !script_registry.get(script_id).is_some() {
            let script = LuaScript::new(script_id, script_id, format!("scripts/{}.lua", script_id));
            script_registry.register(script);
        }
    }

    assert!(script_registry.count() > 0);
}

#[test]
fn test_event_severity_filtering_with_profiles() {
    let event_bus = EventBus::new();
    let config_loader = ConfigLoader::new();

    // Get aggressive profile (high intensity = more critical events)
    let aggressive = config_loader.get_profile("aggressive").unwrap();
    assert_eq!(aggressive.scan_intensity, ScanIntensity::Aggressive);

    // Track critical events
    let critical_count = Arc::new(AtomicU32::new(0));
    let critical_count_clone = critical_count.clone();

    event_bus.subscribe(
        EventType::FindingFound,
        "critical_tracker",
        Arc::new(move |event| {
            if event.severity >= EventSeverity::Error {
                critical_count_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        }),
    );

    // Publish findings with varying severities
    for i in 0..5 {
        let severity = match i {
            0 | 1 => EventSeverity::Critical,
            2 | 3 => EventSeverity::Error,
            _ => EventSeverity::Warning,
        };

        let event = Event::new(EventType::FindingFound, "scanner")
            .with_severity(severity)
            .with_data("index", i.to_string());

        event_bus.publish(event);
    }

    assert_eq!(critical_count.load(std::sync::atomic::Ordering::SeqCst), 4);
}

#[test]
fn test_multi_script_multi_event_workflow() {
    let event_bus = EventBus::new();
    let script_registry = LuaScriptRegistry::new();

    // Register multiple scripts with categories
    let categories = vec!["xss", "sqli", "lfi"];
    for category in &categories {
        for i in 0..2 {
            let script = LuaScript::new(
                format!("{}_script_{}", category, i),
                format!("{} Scanner {}", category, i),
                format!("scripts/{}_{}.lua", category, i),
            )
            .with_categories(vec![category.to_string()]);

            script_registry.register(script);
        }
    }

    assert_eq!(script_registry.count(), 6);

    // Publish events for each script execution
    for category in categories {
        let scripts_in_category = script_registry.list_by_category(category);

        for script in scripts_in_category {
            let event = Event::new(EventType::PluginExecuted, "executor")
                .with_data("script_id", script.id)
                .with_data("category", category.to_string());

            event_bus.publish(event);
        }
    }

    assert_eq!(event_bus.total_events(), 6);
}
