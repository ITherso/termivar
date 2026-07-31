use std::sync::Arc;
use venom_scanner::{
    LFIPlugin, Plugin, PluginCategory, PluginConfig, PluginError, PluginRegistry, SQLiPlugin,
    SSRFPlugin, SSTIPlugin, XSSPlugin, XXEPlugin,
};

#[tokio::test]
async fn test_plugin_registry_multi_plugin_loading() {
    let registry = PluginRegistry::new();

    let xss = Arc::new(XSSPlugin);
    let sqli = Arc::new(SQLiPlugin);
    let lfi = Arc::new(LFIPlugin);

    registry.register(xss).unwrap();
    registry.register(sqli).unwrap();
    registry.register(lfi).unwrap();

    assert_eq!(registry.count(), 3);
}

#[tokio::test]
async fn test_plugin_execution_workflow() {
    let registry = PluginRegistry::new();

    let xss = Arc::new(XSSPlugin);
    registry.register(xss).unwrap();

    let result = registry
        .execute(
            "xss_plugin",
            "http://target.com",
            "<script>alert('xss')</script>",
        )
        .await
        .unwrap();

    assert!(result.success);
    assert_eq!(result.findings.len(), 1);
}

#[tokio::test]
async fn test_plugin_category_filtering() {
    let registry = PluginRegistry::new();

    let plugins: Vec<Arc<dyn Plugin>> = vec![
        Arc::new(XSSPlugin),
        Arc::new(SQLiPlugin),
        Arc::new(LFIPlugin),
        Arc::new(XXEPlugin),
        Arc::new(SSRFPlugin),
        Arc::new(SSTIPlugin),
    ];

    for plugin in plugins {
        registry.register(plugin).unwrap();
    }

    let xss_plugins = registry.list_by_category(PluginCategory::XSS);
    assert_eq!(xss_plugins.len(), 1);

    let sqli_plugins = registry.list_by_category(PluginCategory::SQLi);
    assert_eq!(sqli_plugins.len(), 1);

    let ssti_plugins = registry.list_by_category(PluginCategory::SSTI);
    assert_eq!(ssti_plugins.len(), 1);
}

#[tokio::test]
async fn test_plugin_config_customization() {
    let registry = PluginRegistry::new();
    let xss = Arc::new(XSSPlugin);

    registry.register(xss).unwrap();

    let mut custom_config = PluginConfig::default();
    custom_config.timeout_ms = 10000;
    custom_config.max_payload_size = 20480;

    registry.update_config("xss_plugin", custom_config).unwrap();

    let retrieved = registry.get_config("xss_plugin").unwrap();
    assert_eq!(retrieved.timeout_ms, 10000);
    assert_eq!(retrieved.max_payload_size, 20480);
}

#[tokio::test]
async fn test_plugin_metadata_tracking() {
    let registry = PluginRegistry::new();
    let sqli = Arc::new(SQLiPlugin);

    registry.register(sqli).unwrap();

    // Execute multiple times
    for i in 0..5 {
        let payload = if i % 2 == 0 {
            "' OR '1'='1"
        } else {
            "normal_input"
        };

        registry
            .execute("sqli_plugin", "http://target.com", payload)
            .await
            .ok();
    }

    let meta = registry.get_metadata("sqli_plugin").unwrap();
    assert_eq!(meta.execution_count, 5);
    assert!(meta.success_count > 0);
}

#[tokio::test]
async fn test_comprehensive_vulnerability_scanning() {
    let registry = PluginRegistry::new();

    // Register all plugins
    let plugins: Vec<(&str, Arc<dyn Plugin>)> = vec![
        ("XSS", Arc::new(XSSPlugin)),
        ("SQLi", Arc::new(SQLiPlugin)),
        ("LFI", Arc::new(LFIPlugin)),
        ("XXE", Arc::new(XXEPlugin)),
        ("SSRF", Arc::new(SSRFPlugin)),
        ("SSTI", Arc::new(SSTIPlugin)),
    ];

    for (name, plugin) in &plugins {
        println!("Registering {} plugin", name);
        registry.register(plugin.clone()).unwrap();
    }

    assert_eq!(registry.count(), 6);

    // List all plugins
    let all_plugins = registry.list_all();
    assert_eq!(all_plugins.len(), 6);

    println!("Available Plugins:");
    for meta in &all_plugins {
        println!("  - {} ({})", meta.name, meta.category);
    }

    // Execute each plugin with vulnerable payloads
    let test_cases = vec![
        (
            "xss_plugin",
            "http://target.com",
            "<script>alert('xss')</script>",
        ),
        ("sqli_plugin", "http://target.com", "' OR '1'='1"),
        (
            "lfi_plugin",
            "http://target.com?file=",
            "../../../etc/passwd",
        ),
        (
            "xxe_plugin",
            "http://target.com",
            "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>",
        ),
        ("ssrf_plugin", "http://target.com", "http://localhost/admin"),
        ("ssti_plugin", "http://target.com", "{{7*7}}"),
    ];

    let mut total_findings = 0;

    for (plugin_id, target, payload) in test_cases {
        let result = registry.execute(plugin_id, target, payload).await.unwrap();

        println!("Plugin {}: {} findings", plugin_id, result.findings.len());

        total_findings += result.findings.len();
    }

    assert!(total_findings > 0);
}

#[tokio::test]
async fn test_plugin_unregister_and_reregister() {
    let registry = PluginRegistry::new();
    let lfi = Arc::new(LFIPlugin);

    registry.register(lfi.clone()).unwrap();
    assert_eq!(registry.count(), 1);

    registry.unregister("lfi_plugin").unwrap();
    assert_eq!(registry.count(), 0);

    registry.register(lfi).unwrap();
    assert_eq!(registry.count(), 1);
}

#[tokio::test]
async fn test_plugin_not_found_error() {
    let registry = PluginRegistry::new();

    let result = registry
        .execute("nonexistent_plugin", "target", "payload")
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        PluginError::NotFound(_) => {},
        _ => panic!("Expected NotFound error"),
    }
}

#[tokio::test]
async fn test_all_plugins_enabled() {
    let registry = PluginRegistry::new();

    let plugins: Vec<Arc<dyn Plugin>> = vec![
        Arc::new(XSSPlugin),
        Arc::new(SQLiPlugin),
        Arc::new(LFIPlugin),
        Arc::new(XXEPlugin),
        Arc::new(SSRFPlugin),
        Arc::new(SSTIPlugin),
    ];

    for plugin in plugins {
        registry.register(plugin).unwrap();
    }

    let all_plugins = registry.list_all();
    assert!(all_plugins.iter().all(|p| p.enabled));
}

#[tokio::test]
async fn test_plugin_performance_tracking() {
    let registry = PluginRegistry::new();
    let ssrf = Arc::new(SSRFPlugin);

    registry.register(ssrf).unwrap();

    let result = registry
        .execute(
            "ssrf_plugin",
            "http://target.com",
            "http://169.254.169.254/",
        )
        .await
        .unwrap();

    println!("Plugin execution time: {} ms", result.execution_time_ms);
}
