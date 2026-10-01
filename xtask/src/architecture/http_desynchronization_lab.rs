//! Exact isolation contract for the HTTP desynchronization parser-boundary
//! laboratory. This is test code only: it must never become a Cargo feature,
//! CLI surface, product module, report producer, or live-target raw sender.

use std::{
    error::Error,
    fs, io,
    path::{Path, PathBuf},
};

use syn::{visit::Visit, Item, Visibility};

const SCANNER_LIBRARY: &str = "crates/termivar-scanner/src/lib.rs";
const LAB_SOURCE: &str = "crates/termivar-scanner/tests/support/http_desynchronization_lab.rs";
const LAB_MODULE_PATH: &str = "../tests/support/http_desynchronization_lab.rs";
const CRATES_ROOT: &str = "crates";
const MODULE: &str = "http_desynchronization_lab";
const PRODUCT_SURFACE_PATHS: &[&str] = &[
    "crates/termivar-scanner/Cargo.toml",
    "crates/termivar-cli/Cargo.toml",
    "crates/termivar-cli/src/main.rs",
    "crates/termivar-cli/src/capabilities.rs",
    "crates/termivar-scanner/src/reporting.rs",
    ".github/workflows/release.yml",
];
const EXACT_TEST: &str = "owned_loopback_matrix_is_bounded_and_reports_only_parser_boundaries";
const EXACT_GUARD: &str = "all(test,feature=\"scanning\")";

const REQUIRED_COMPACT_FRAGMENTS: &[&str] = &[
    "constMAX_CASE_REQUEST_BYTES:usize=2*1024;",
    "constMAX_MATRIX_REQUEST_BYTES:usize=8*1024;",
    "constCASE_TIMEOUT:Duration=Duration::from_secs(1);",
    "constMATRIX_TIMEOUT:Duration=Duration::from_secs(5);",
    "constMATRIX_CASE_LIMIT:u32=4;",
    "TcpListener::bind((std::net::Ipv4Addr::LOCALHOST,0))",
    "TcpStream::connect(front_address)",
    "TcpStream::connect(back_address)",
    ".ip().is_loopback()",
    "RequestAccountingBroker",
    "try_begin_with_request_body_bytes(",
    "DecisionExecutionStage::Active",
    "validate_case_bounds(spec.request.len(),matrix_bytes)?;",
    "fnbounded_parser_boundary(boundary:usize)->Result<usize,LabError>",
    "ifboundary>MAX_CASE_REQUEST_BYTES",
    "assert_eq!(http_request_line_marker_count(spec.request),1);",
    "tokio::select!{biased;",
    "_=cancellation.cancelled()=>None",
    "result=timeout(CASE_TIMEOUT,execute_network_case(spec,totals))=>Some(result)",
    "implDropforClientTaskGuard",
    "handle.abort();",
    ".with_max_total_requests(MATRIX_CASE_LIMIT)",
    ".with_max_wall_time(MATRIX_TIMEOUT)",
    "Some(RuntimeBudgetDimension::TotalRequests)",
    "assert_eq!(totals.front_request_bytes,328);",
    "assert_eq!(totals.back_request_bytes,266);",
    "assert_eq!(snapshot.response_bytes(),0);",
    "parser_boundary_disagreement",
    "inconclusive_timeout",
    "agreement",
];

const FORBIDDEN_LAB_FRAGMENTS: &[&str] = &[
    "0.0.0.0",
    "::0",
    "Ipv4Addr::UNSPECIFIED",
    "Ipv6Addr::UNSPECIFIED",
    "std::env",
    "std::fs",
    "std::process",
    "unsafe",
    "libc",
    "socket2",
    "windows_sys",
    "Command::",
    "stdin(",
    "args(",
    "args_os(",
    "reqwest",
    "hyper::",
    "serde",
    "termivar_cli",
    "AssessmentRunReport",
    "RunReport",
    "ScanFinding",
    "WebAssessmentRuntime",
    "TcpSocket",
    "UdpSocket",
    "UnixStream",
    "UnixDatagram",
    "std::net::TcpStream",
    "connect_timeout",
    "ToSocketAddrs",
    "to_socket_addrs",
    "lookup_host",
    "#[no_mangle]",
    "#[export_name",
    "#[macro_export]",
    "include!(",
    "println!(",
    "eprintln!(",
    "print!(",
    "dbg!(",
];

pub(super) fn check(workspace_root: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    let library = fs::read_to_string(workspace_root.join(SCANNER_LIBRARY))?;
    let lab = match fs::read_to_string(workspace_root.join(LAB_SOURCE)) {
        Ok(source) => source,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(vec![format!(
                "{LAB_SOURCE}: private HTTP desynchronization laboratory source is missing"
            )]);
        },
        Err(error) => return Err(error.into()),
    };
    let product_sources = product_rust_sources(workspace_root)?;
    let mut violations = contract_violations(&library, &lab, &product_sources)?;
    if !lab_source_is_nested_test_support(LAB_SOURCE) {
        violations.push(format!(
            "{LAB_SOURCE}: laboratory source must remain a nested non-target support file below `tests/`"
        ));
    }
    let product_surfaces = PRODUCT_SURFACE_PATHS
        .iter()
        .map(|path| {
            Ok((
                (*path).to_owned(),
                fs::read_to_string(workspace_root.join(path))?,
            ))
        })
        .collect::<Result<Vec<_>, io::Error>>()?;
    violations.extend(product_surface_violations(&product_surfaces));
    Ok(violations)
}

fn product_surface_violations(sources: &[(String, String)]) -> Vec<String> {
    let mut violations = Vec::new();
    for (path, source) in sources {
        if source.contains(MODULE) || source.contains("http-desynchronization") {
            violations.push(format!(
                "{path}: HTTP desynchronization laboratory must not become a Cargo feature, CLI/capability/report surface, or release-package path"
            ));
        }
    }
    violations
}

fn lab_source_is_nested_test_support(source: &str) -> bool {
    let path = Path::new(source);
    path.parent().and_then(Path::file_name) == Some(std::ffi::OsStr::new("support"))
        && path
            .parent()
            .and_then(Path::parent)
            .and_then(Path::file_name)
            == Some(std::ffi::OsStr::new("tests"))
}

fn contract_violations(
    library: &str,
    lab: &str,
    product_sources: &[(String, String)],
) -> Result<Vec<String>, syn::Error> {
    let mut violations = module_declaration_violations(library)?;
    let lab_syntax = syn::parse_file(lab)?;

    let mut visibility = NonPrivateVisibility::default();
    visibility.visit_file(&lab_syntax);
    if visibility.count != 0 {
        violations.push(format!(
            "{LAB_SOURCE}: laboratory items must remain private; found {} non-private visibility declarations",
            visibility.count
        ));
    }

    let mut writes = ReviewedWriteAllVisitor::default();
    writes.visit_file(&lab_syntax);
    if writes.total != 2
        || writes.client_request != 1
        || writes.forwarded_received != 1
        || writes.unreviewed != 0
    {
        violations.push(format!(
            "{LAB_SOURCE}: laboratory must contain exactly the two reviewed fixed-byte `write_all` calls and no alternate socket writes; found total={}, client_request={}, forwarded_received={}, unreviewed={}",
            writes.total, writes.client_request, writes.forwarded_received, writes.unreviewed
        ));
    }

    let exact_tests = lab_syntax
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Mod(module) if module.ident == "tests" => module.content.as_ref(),
            _ => None,
        })
        .flat_map(|(_, items)| items)
        .filter_map(|item| match item {
            Item::Fn(function) if function.sig.ident == EXACT_TEST => Some(function),
            _ => None,
        })
        .collect::<Vec<_>>();
    let exact_test_is_runnable = matches!(exact_tests.as_slice(), [function]
    if function.sig.asyncness.is_some()
        && function.attrs.iter().any(|attribute| {
            let mut segments = attribute.path().segments.iter();
            matches!(segments.next(), Some(segment) if segment.ident == "tokio")
                && matches!(segments.next(), Some(segment) if segment.ident == "test")
                && segments.next().is_none()
        }));
    if !exact_test_is_runnable {
        violations.push(format!(
            "{LAB_SOURCE}: expected exactly one private async `#[tokio::test]` named `{EXACT_TEST}`"
        ));
    }

    let compact = compact_whitespace(lab);
    for required in REQUIRED_COMPACT_FRAGMENTS {
        if !compact.contains(required) {
            violations.push(format!(
                "{LAB_SOURCE}: bounded loopback laboratory contract is missing `{required}`"
            ));
        }
    }
    for forbidden in FORBIDDEN_LAB_FRAGMENTS {
        if compact.contains(forbidden) {
            violations.push(format!(
                "{LAB_SOURCE}: laboratory must not contain externally reachable, dynamic-input, product-report, or raw-output fragment `{forbidden}`"
            ));
        }
    }

    let loopback_bind_calls = compact
        .matches("TcpListener::bind((std::net::Ipv4Addr::LOCALHOST,0))")
        .count();
    let listener_bind_calls = compact.matches("TcpListener::bind(").count();
    if loopback_bind_calls != 1 || listener_bind_calls != 1 {
        violations.push(format!(
            "{LAB_SOURCE}: laboratory must have exactly one reviewed numeric-loopback listener binding helper; found reviewed={loopback_bind_calls}, total={listener_bind_calls}"
        ));
    }
    let connect_calls = compact.matches("TcpStream::connect(").count();
    if connect_calls != 2 {
        violations.push(format!(
            "{LAB_SOURCE}: laboratory must have exactly the reviewed front-address and back-address connection calls; found {connect_calls}"
        ));
    }

    for (path, source) in product_sources {
        if source.contains(MODULE) {
            violations.push(format!(
                "{path}: product source must not reference private HTTP desynchronization laboratory module `{MODULE}`"
            ));
        }
    }
    Ok(violations)
}

fn module_declaration_violations(library: &str) -> Result<Vec<String>, syn::Error> {
    let syntax = syn::parse_file(library)?;
    let modules = syntax
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Mod(module) if module.ident == MODULE => Some(module),
            _ => None,
        })
        .collect::<Vec<_>>();
    let [module] = modules.as_slice() else {
        return Ok(vec![format!(
            "{SCANNER_LIBRARY}: expected exactly one private test-and-scanning-only `{MODULE}` module declaration"
        )]);
    };

    let guard_is_exact = module.attrs.iter().any(|attribute| {
        attribute.path().is_ident("cfg")
            && attribute
                .meta
                .require_list()
                .is_ok_and(|list| compact_whitespace(&list.tokens.to_string()) == EXACT_GUARD)
    });
    let path_is_exact = module.attrs.iter().any(|attribute| {
        if !attribute.path().is_ident("path") {
            return false;
        }
        let syn::Meta::NameValue(name_value) = &attribute.meta else {
            return false;
        };
        let syn::Expr::Lit(expression) = &name_value.value else {
            return false;
        };
        matches!(&expression.lit, syn::Lit::Str(value) if value.value() == LAB_MODULE_PATH)
    });
    let declaration_is_private_external = matches!(module.vis, Visibility::Inherited)
        && module.content.is_none()
        && module.semi.is_some();
    let references = library.matches(MODULE).count();
    if module.attrs.len() == 2
        && guard_is_exact
        && path_is_exact
        && declaration_is_private_external
        && references == 2
    {
        Ok(Vec::new())
    } else {
        Ok(vec![format!(
            "{SCANNER_LIBRARY}: `{MODULE}` must appear once as exact `#[cfg(all(test, feature = \"scanning\"))] #[path = \"{LAB_MODULE_PATH}\"] mod {MODULE};` and remain private"
        )])
    }
}

#[derive(Default)]
struct NonPrivateVisibility {
    count: usize,
}

impl<'ast> Visit<'ast> for NonPrivateVisibility {
    fn visit_visibility(&mut self, visibility: &'ast Visibility) {
        if !matches!(visibility, Visibility::Inherited) {
            self.count += 1;
        }
        syn::visit::visit_visibility(self, visibility);
    }
}

#[derive(Default)]
struct ReviewedWriteAllVisitor {
    total: usize,
    client_request: usize,
    forwarded_received: usize,
    unreviewed: usize,
}

impl<'ast> Visit<'ast> for ReviewedWriteAllVisitor {
    fn visit_expr_method_call(&mut self, expression: &'ast syn::ExprMethodCall) {
        if expression.method == "write_all" {
            self.total += 1;
            if expression.args.len() == 1
                && expression_is_path(&expression.receiver, "client")
                && expression_is_path(&expression.args[0], "client_request")
            {
                self.client_request += 1;
            }
            if expression.args.len() == 1
                && expression_is_path(&expression.receiver, "forward")
                && expression_is_reference_to_path(&expression.args[0], "received")
            {
                self.forwarded_received += 1;
            }
        } else if is_unreviewed_write_identifier(&expression.method.to_string()) {
            self.unreviewed += 1;
        }
        syn::visit::visit_expr_method_call(self, expression);
    }

    fn visit_expr_call(&mut self, expression: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = expression.func.as_ref() {
            if path
                .path
                .segments
                .last()
                .is_some_and(|segment| segment.ident == "write_all")
            {
                self.total += 1;
            } else if path
                .path
                .segments
                .last()
                .is_some_and(|segment| is_unreviewed_write_identifier(&segment.ident.to_string()))
            {
                self.unreviewed += 1;
            }
        }
        syn::visit::visit_expr_call(self, expression);
    }

    fn visit_macro(&mut self, expression: &'ast syn::Macro) {
        if expression
            .path
            .segments
            .last()
            .is_some_and(|segment| is_unreviewed_write_identifier(&segment.ident.to_string()))
        {
            self.unreviewed += 1;
        }
        syn::visit::visit_macro(self, expression);
    }
}

fn is_unreviewed_write_identifier(identifier: &str) -> bool {
    identifier.starts_with("write")
        || identifier.starts_with("try_write")
        || identifier.starts_with("poll_write")
        || identifier.starts_with("copy")
}

fn expression_is_path(expression: &syn::Expr, expected: &str) -> bool {
    matches!(expression, syn::Expr::Path(path)
        if path.qself.is_none()
            && path.path.segments.len() == 1
            && path.path.segments[0].ident == expected)
}

fn expression_is_reference_to_path(expression: &syn::Expr, expected: &str) -> bool {
    matches!(expression, syn::Expr::Reference(reference)
        if reference.mutability.is_none()
            && expression_is_path(&reference.expr, expected))
}

fn product_rust_sources(workspace_root: &Path) -> Result<Vec<(String, String)>, io::Error> {
    let mut paths = Vec::new();
    collect_rust_sources(&workspace_root.join(CRATES_ROOT), &mut paths)?;
    paths.sort();
    let scanner_library = workspace_root.join(SCANNER_LIBRARY);
    let lab_source = workspace_root.join(LAB_SOURCE);
    paths
        .into_iter()
        .filter(|path| path != &scanner_library && path != &lab_source)
        .map(|path| {
            let relative = path
                .strip_prefix(workspace_root)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
                .to_string_lossy()
                .replace('\\', "/");
            Ok((relative, fs::read_to_string(path)?))
        })
        .collect()
}

fn collect_rust_sources(root: &Path, paths: &mut Vec<PathBuf>) -> Result<(), io::Error> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = entry.metadata()?;
        if metadata.is_dir() {
            collect_rust_sources(&path, paths)?;
        } else if metadata.is_file() && path.extension().is_some_and(|extension| extension == "rs")
        {
            paths.push(path);
        }
    }
    Ok(())
}

fn compact_whitespace(source: &str) -> String {
    source
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_LIBRARY: &str = r#"
        #[cfg(all(test, feature = "scanning"))]
        #[path = "../tests/support/http_desynchronization_lab.rs"]
        mod http_desynchronization_lab;
    "#;

    const VALID_LAB: &str = r#"
        use std::{net::Ipv4Addr, time::Duration};
        use tokio::{io::AsyncWriteExt, net::{TcpListener, TcpStream}};
        use crate::web_runtime::{DecisionExecutionStage, RequestAccountingBroker};

        const MAX_CASE_REQUEST_BYTES: usize = 2 * 1024;
        const MAX_MATRIX_REQUEST_BYTES: usize = 8 * 1024;
        const CASE_TIMEOUT: Duration = Duration::from_secs(1);
        const MATRIX_TIMEOUT: Duration = Duration::from_secs(5);
        const MATRIX_CASE_LIMIT: u32 = 4;
        const AGREEMENT: &str = "agreement";
        const DISAGREEMENT: &str = "parser_boundary_disagreement";
        const TIMEOUT: &str = "inconclusive_timeout";

        fn bounded_parser_boundary(boundary: usize) -> Result<usize, LabError> {
            if boundary > MAX_CASE_REQUEST_BYTES {
                Err(LabError::CaseTooLarge)
            } else {
                Ok(boundary)
            }
        }

        struct ClientTaskGuard {
            handle: FakeHandle,
        }

        impl Drop for ClientTaskGuard {
            fn drop(&mut self) {
                self.handle.abort();
            }
        }

        async fn bind() {
            let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let front_address = listener.local_addr().unwrap();
            let back_address = front_address;
            let mut client = TcpStream::connect(front_address).await.unwrap();
            let client_request = b"request";
            client.write_all(client_request).await.unwrap();
            let mut forward = TcpStream::connect(back_address).await.unwrap();
            let received = [0_u8; 1];
            forward.write_all(&received).await.unwrap();
            let (_, peer) = listener.accept().await.unwrap();
            assert!(peer.ip().is_loopback());
        }

        fn account(broker: &RequestAccountingBroker) {
            assert_eq!(http_request_line_marker_count(spec.request), 1);
            validate_case_bounds(spec.request.len(), matrix_bytes)?;
            let _ = broker.try_begin_with_request_body_bytes(
                "case",
                DecisionExecutionStage::Active,
                None,
                MAX_CASE_REQUEST_BYTES,
            );
            let _ = tokio::select! {
                biased;
                _ = cancellation.cancelled() => None,
                result = timeout(CASE_TIMEOUT, execute_network_case(spec, totals)) => Some(result),
            };
            let budget = RuntimeBudget::default()
                .with_max_total_requests(MATRIX_CASE_LIMIT)
                .with_max_wall_time(MATRIX_TIMEOUT);
            let _ = Some(RuntimeBudgetDimension::TotalRequests);
            assert_eq!(totals.front_request_bytes, 328);
            assert_eq!(totals.back_request_bytes, 266);
            assert_eq!(snapshot.response_bytes(), 0);
        }

        mod tests {
            #[tokio::test]
            async fn owned_loopback_matrix_is_bounded_and_reports_only_parser_boundaries() {}
        }
    "#;

    #[test]
    fn exact_private_test_and_scanning_guard_is_required() {
        assert!(module_declaration_violations(VALID_LIBRARY)
            .unwrap()
            .is_empty());

        for mutation in [
            VALID_LIBRARY.replace(
                "all(test, feature = \"scanning\")",
                "any(test, feature = \"scanning\")",
            ),
            VALID_LIBRARY.replace(
                "all(test, feature = \"scanning\")",
                "feature = \"scanning\"",
            ),
            VALID_LIBRARY.replace(
                "mod http_desynchronization_lab",
                "pub mod http_desynchronization_lab",
            ),
            VALID_LIBRARY.replace(
                "#[path = \"../tests/support/http_desynchronization_lab.rs\"]",
                "",
            ),
            VALID_LIBRARY.replace(
                "../tests/support/http_desynchronization_lab.rs",
                "../tests/http_desynchronization_lab.rs",
            ),
            VALID_LIBRARY.replace(
                "#[path = \"../tests/support/http_desynchronization_lab.rs\"]",
                "#[path = \"../tests/support/http_desynchronization_lab.rs\"]\n#[allow(dead_code)]",
            ),
            format!("{VALID_LIBRARY}\npub use crate::http_desynchronization_lab::*;"),
        ] {
            assert_ne!(mutation, VALID_LIBRARY);
            assert!(!module_declaration_violations(&mutation).unwrap().is_empty());
        }
    }

    #[test]
    fn laboratory_source_is_nested_below_tests_without_becoming_an_auto_target() {
        assert!(lab_source_is_nested_test_support(LAB_SOURCE));
        assert!(!lab_source_is_nested_test_support(
            "crates/termivar-scanner/tests/http_desynchronization_lab.rs"
        ));
        assert!(!lab_source_is_nested_test_support(
            "crates/termivar-scanner/src/http_desynchronization_lab.rs"
        ));
    }

    #[test]
    fn bounded_private_loopback_contract_accepts_the_reviewed_shape() {
        let violations = contract_violations(VALID_LIBRARY, VALID_LAB, &[]).unwrap();
        assert!(violations.is_empty(), "{violations:?}");
    }

    #[test]
    fn laboratory_contract_rejects_product_reachability_and_widened_inputs() {
        let product_source = vec![(
            "crates/termivar-cli/src/main.rs".to_owned(),
            "use termivar_scanner::http_desynchronization_lab;".to_owned(),
        )];
        assert!(
            contract_violations(VALID_LIBRARY, VALID_LAB, &product_source)
                .unwrap()
                .iter()
                .any(|violation| violation.contains("product source"))
        );

        for mutation in [
            VALID_LAB.replace("async fn bind()", "pub async fn bind()"),
            VALID_LAB.replace("#[tokio::test]", "#[test]"),
            VALID_LAB.replace(
                "std::net::Ipv4Addr::LOCALHOST",
                "std::net::Ipv4Addr::UNSPECIFIED",
            ),
            VALID_LAB.replace(
                "let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await.unwrap();",
                "let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await.unwrap();\nlet _extra = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await;",
            ),
            VALID_LAB.replace(
                "TcpStream::connect(front_address)",
                "TcpStream::connect(\"198.51.100.1:80\")",
            ),
            VALID_LAB.replace(
                "let mut forward = TcpStream::connect(back_address).await.unwrap();",
                "let mut forward = TcpStream::connect(back_address).await.unwrap();\nlet _ = TcpStream::connect(\"198.51.100.1:80\").await;",
            ),
            VALID_LAB.replace(
                "const MATRIX_CASE_LIMIT: u32 = 4;",
                "const MATRIX_CASE_LIMIT: u32 = 40;",
            ),
            VALID_LAB.replace(
                "if boundary > MAX_CASE_REQUEST_BYTES",
                "if boundary > usize::MAX",
            ),
            VALID_LAB.replace(
                ".with_max_total_requests(MATRIX_CASE_LIMIT)",
                ".with_max_total_requests(40)",
            ),
            VALID_LAB.replace("self.handle.abort();", "drop(self.handle);"),
            VALID_LAB.replace(
                "_ = cancellation.cancelled() => None,",
                "_ = std::future::pending::<()>() => None,",
            ),
            VALID_LAB.replace(
                "assert_eq!(totals.back_request_bytes, 266);",
                "assert_eq!(totals.back_request_bytes, 0);",
            ),
            VALID_LAB.replace(
                "assert_eq!(http_request_line_marker_count(spec.request), 1);",
                "assert_eq!(http_request_line_marker_count(spec.request), 2);",
            ),
            VALID_LAB.replace(
                "client.write_all(client_request).await.unwrap();",
                "client.write_all(client_request).await.unwrap();\nclient.write_all(b\"GET /second HTTP/1.1\\r\\n\\r\\n\").await.unwrap();",
            ),
            VALID_LAB.replace(
                "client.write_all(client_request).await.unwrap();",
                "client.write_all(client_request).await.unwrap();\nlet _ = client.write(b\"GET /second HTTP/1.1\\r\\n\\r\\n\").await;",
            ),
            VALID_LAB.replace(
                "client.write_all(client_request).await.unwrap();",
                "client.write_all(client_request).await.unwrap();\nclient.write_u8(b'X').await.unwrap();",
            ),
            VALID_LAB.replace(
                "client.write_all(client_request).await.unwrap();",
                "client.write_all(client_request).await.unwrap();\nlet _ = client.try_write_vectored(&[]);",
            ),
            VALID_LAB.replace(
                "client.write_all(client_request).await.unwrap();",
                "client.write_all(client_request).await.unwrap();\nlet _ = tokio::io::copy_buf(&mut client_request, &mut client).await;",
            ),
            VALID_LAB.replace(
                "client.write_all(client_request).await.unwrap();",
                "client.write_all(client_request).await.unwrap();\nwrite!(&mut client, \"second\").unwrap();",
            ),
            format!("{VALID_LAB}\nfn input() {{ let _ = std::env::args_os(); }}"),
            format!("{VALID_LAB}\nfn output() {{ println!(\"{{:?}}\", b\"raw\"); }}"),
            format!(
                "{VALID_LAB}\nasync fn udp() {{ let socket = tokio::net::UdpSocket::bind(\"127.0.0.1:0\").await.unwrap(); let _ = socket.send_to(b\"x\", \"127.0.0.1:9\").await; }}"
            ),
            format!(
                "{VALID_LAB}\nasync fn socket() {{ let _ = tokio::net::TcpSocket::new_v4(); }}"
            ),
            format!(
                "{VALID_LAB}\nfn external_tcp() {{ let address = \"198.51.100.1:80\".parse().unwrap(); let _ = std::net::TcpStream::connect_timeout(&address, Duration::from_millis(1)); }}"
            ),
            format!(
                "{VALID_LAB}\nfn external_dns() {{ use std::net::ToSocketAddrs as _; let _ = (\"example.invalid\", 80).to_socket_addrs(); }}"
            ),
            format!("{VALID_LAB}\nunsafe fn raw_socket_escape() {{}}"),
        ] {
            assert_ne!(mutation, VALID_LAB);
            assert!(!contract_violations(VALID_LIBRARY, &mutation, &[])
                .unwrap()
                .is_empty());
        }

        let product_surface = vec![(
            "crates/termivar-scanner/Cargo.toml".to_owned(),
            "[features]\nhttp-desynchronization-lab = [\"scanning\"]".to_owned(),
        )];
        assert_eq!(product_surface_violations(&product_surface).len(), 1);
    }
}
