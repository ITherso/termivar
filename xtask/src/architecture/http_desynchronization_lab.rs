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
const LAB_SOURCE: &str = "crates/termivar-scanner/src/http_desynchronization_lab.rs";
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
    if loopback_bind_calls != 1 {
        violations.push(format!(
            "{LAB_SOURCE}: laboratory must have exactly one reviewed numeric-loopback listener binding helper; found {loopback_bind_calls}"
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

    let guard_is_exact = module.attrs.len() == 1
        && module.attrs[0].path().is_ident("cfg")
        && module.attrs[0]
            .meta
            .require_list()
            .is_ok_and(|list| compact_whitespace(&list.tokens.to_string()) == EXACT_GUARD);
    let declaration_is_private_external = matches!(module.vis, Visibility::Inherited)
        && module.content.is_none()
        && module.semi.is_some();
    let references = library.matches(MODULE).count();
    if guard_is_exact && declaration_is_private_external && references == 1 {
        Ok(Vec::new())
    } else {
        Ok(vec![format!(
            "{SCANNER_LIBRARY}: `{MODULE}` must appear once as exact `#[cfg(all(test, feature = \"scanning\"))] mod {MODULE};` and remain private"
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
        mod http_desynchronization_lab;
    "#;

    const VALID_LAB: &str = r#"
        use std::{net::Ipv4Addr, time::Duration};
        use tokio::net::{TcpListener, TcpStream};
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
            let _ = TcpStream::connect(front_address).await;
            let _ = TcpStream::connect(back_address).await;
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
            format!("{VALID_LIBRARY}\npub use crate::http_desynchronization_lab::*;"),
        ] {
            assert_ne!(mutation, VALID_LIBRARY);
            assert!(!module_declaration_violations(&mutation).unwrap().is_empty());
        }
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
                "TcpStream::connect(front_address)",
                "TcpStream::connect(\"198.51.100.1:80\")",
            ),
            VALID_LAB.replace(
                "let _ = TcpStream::connect(back_address).await;",
                "let _ = TcpStream::connect(back_address).await;\nlet _ = TcpStream::connect(\"198.51.100.1:80\").await;",
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
            format!("{VALID_LAB}\nfn input() {{ let _ = std::env::args_os(); }}"),
            format!("{VALID_LAB}\nfn output() {{ println!(\"{{:?}}\", b\"raw\"); }}"),
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
