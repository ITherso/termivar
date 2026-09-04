//! Shared authority for every subject executed by one bounded web runtime.
//!
//! The authority is intentionally crate-private. Product runtimes may clone its
//! handles, but cannot mint a second request budget, transport broker, knowledge
//! store, cancellation domain, or wall-clock origin for another subject in the
//! same assessment.

use std::sync::{Arc, OnceLock};

use tokio_util::sync::CancellationToken;
use url::Url;

use crate::{
    http_evidence::HttpRequestBroker, runtime_budget::RequestAccountingBroker, HttpEvidenceError,
    HttpEvidencePolicy, KnowledgeBase, RuntimeBudget,
};

#[cfg(feature = "oast-native-provider")]
use crate::native_oast_provider::{
    NativeOastProviderAdapter, NativeOastProviderConfiguration, NativeOastProviderError,
};

#[cfg(feature = "oast-native-provider")]
struct NativeOastProviderMintSeal;

/// Move-only proof that a native-provider adapter was minted by the one
/// shared web-runtime authority.
///
/// The private seal deliberately has no constructor or trait implementations.
/// Sibling scanner modules may name this crate-private type through the
/// `web_runtime` re-export, but only this module can construct it.
#[cfg(feature = "oast-native-provider")]
pub(crate) struct NativeOastProviderMintToken(NativeOastProviderMintSeal);

/// Returns whether credentials may be dispatched to this exact target.
///
/// Authenticated transport requires HTTPS except for numeric-IP loopback HTTP
/// fixtures. Hostname-based localhost and every other cleartext origin fail
/// closed before secret material reaches transport.
pub(crate) fn authenticated_transport_is_allowed(target: &Url) -> bool {
    target.scheme() == "https"
        || (target.scheme() == "http"
            && target.host().is_some_and(|host| {
                matches!(host, url::Host::Ipv4(ip) if ip.is_loopback())
                    || matches!(host, url::Host::Ipv6(ip) if ip.is_loopback())
            }))
}

/// One immutable wall-clock origin and absolute deadline shared by all subjects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SharedWebRuntimeTiming {
    started_at: tokio::time::Instant,
    deadline: Option<tokio::time::Instant>,
}

impl SharedWebRuntimeTiming {
    pub(crate) const fn started_at(self) -> tokio::time::Instant {
        self.started_at
    }

    pub(crate) const fn deadline(self) -> Option<tokio::time::Instant> {
        self.deadline
    }
}

/// Singleton capability bundle for one exact-origin web run.
///
/// Cloning this type clones shared handles only. The request counters, transport
/// audit, knowledge base, cancellation state, and lazily established absolute
/// deadline remain common to every clone.
#[derive(Clone)]
pub(crate) struct SharedWebRuntimeAuthority {
    policy: HttpEvidencePolicy,
    budget: RuntimeBudget,
    knowledge: KnowledgeBase,
    requests: HttpRequestBroker,
    request_accounting: RequestAccountingBroker,
    cancellation: CancellationToken,
    timing: Arc<OnceLock<SharedWebRuntimeTiming>>,
    #[cfg(feature = "oast-native-provider")]
    native_oast_provider_minted: Arc<std::sync::Mutex<bool>>,
}

impl SharedWebRuntimeAuthority {
    /// Creates the sole metered transport authority for an exact origin.
    ///
    /// A custom policy may carry broader host authorization for another API, but
    /// this runtime narrows its private broker to `target`'s exact origin after
    /// proving that the supplied policy already authorized that target.
    pub(crate) fn new_exact_origin(
        target: &Url,
        policy: HttpEvidencePolicy,
        budget: RuntimeBudget,
        cancellation: CancellationToken,
    ) -> Result<Self, HttpEvidenceError> {
        let policy = policy.restricted_to_exact_origin(target)?;
        let request_accounting = RequestAccountingBroker::new(budget);
        let requests = HttpRequestBroker::new_metered(policy.clone(), request_accounting.clone())?;

        Ok(Self {
            policy,
            budget,
            knowledge: KnowledgeBase::new(),
            requests,
            request_accounting,
            cancellation,
            timing: Arc::new(OnceLock::new()),
            #[cfg(feature = "oast-native-provider")]
            native_oast_provider_minted: Arc::new(std::sync::Mutex::new(false)),
        })
    }

    /// Fails closed unless `target` belongs to this authority's exact origin.
    pub(crate) fn authorize_target(&self, target: &Url) -> Result<(), HttpEvidenceError> {
        self.policy.require_permitted_target(target)
    }

    pub(crate) const fn budget(&self) -> RuntimeBudget {
        self.budget
    }

    pub(crate) const fn knowledge(&self) -> &KnowledgeBase {
        &self.knowledge
    }

    pub(crate) const fn requests(&self) -> &HttpRequestBroker {
        &self.requests
    }

    pub(crate) const fn request_accounting(&self) -> &RequestAccountingBroker {
        &self.request_accounting
    }

    pub(crate) fn cancellation_token(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    pub(crate) const fn cancellation(&self) -> &CancellationToken {
        &self.cancellation
    }

    /// Starts the shared monotonic clock once and returns the same timing on replay.
    ///
    /// Lazy start preserves the standalone runtime contract: time between
    /// `build()` and the first execution attempt is not charged. An assessment
    /// starts the authority before discovery, so every later subject inherits
    /// that already-established absolute deadline.
    pub(crate) fn start(&self) -> SharedWebRuntimeTiming {
        *self.timing.get_or_init(|| {
            let started_at = tokio::time::Instant::now();
            SharedWebRuntimeTiming {
                started_at,
                deadline: started_at.checked_add(self.budget.max_wall_time()),
            }
        })
    }

    /// Mints the single narrowing native-provider authority from the same
    /// broker, budget, cancellation domain, exact target origin, and absolute
    /// deadline already owned by this assessment.
    #[cfg(feature = "oast-native-provider")]
    #[cfg_attr(
        all(not(test), not(feature = "ssrf-oast-review")),
        expect(
            dead_code,
            reason = "sealed PR B authority is consumed only by the separately gated ssrf-oast-review capability"
        )
    )]
    pub(crate) fn mint_native_oast_provider(
        &self,
        configuration: NativeOastProviderConfiguration,
    ) -> Result<NativeOastProviderAdapter, NativeOastProviderError> {
        let mut minted = self
            .native_oast_provider_minted
            .lock()
            .map_err(|_| NativeOastProviderError::internal_invariant())?;
        if *minted {
            return Err(NativeOastProviderError::authority_already_minted());
        }
        let target_origin = self
            .policy
            .allowed_origins()
            .iter()
            .next()
            .filter(|_| self.policy.allowed_origins().len() == 1)
            .ok_or_else(NativeOastProviderError::internal_invariant)?;
        let timing = self.start();
        let adapter = NativeOastProviderAdapter::mint(
            NativeOastProviderMintToken(NativeOastProviderMintSeal),
            configuration,
            target_origin,
            self.request_accounting.clone(),
            self.budget,
            self.cancellation.clone(),
            timing.deadline(),
        )?;
        *minted = true;
        Ok(adapter)
    }
}

#[cfg(test)]
mod tests {
    use termivar_core::{
        ConfidenceScore, EntityId, Evidence, EvidenceKind, EvidenceSource, EvidenceValue,
        HttpEvidencePredicate,
    };

    use super::*;
    use crate::{DecisionExecutionStage, RuntimeBudgetDimension, TransportDispatchOutcome};

    fn target(path: &str) -> Url {
        Url::parse(&format!("https://example.test{path}")).unwrap()
    }

    #[test]
    fn authority_narrows_a_broader_policy_to_one_exact_origin() {
        let root = target("/root");
        let policy = HttpEvidencePolicy::new(
            [root.clone(), Url::parse("https://other.test/").unwrap()],
            std::time::Duration::from_secs(2),
            1024,
        )
        .unwrap();
        let authority = SharedWebRuntimeAuthority::new_exact_origin(
            &root,
            policy,
            RuntimeBudget::default(),
            CancellationToken::new(),
        )
        .unwrap();

        assert_eq!(
            authority.requests().policy().allowed_origins(),
            &std::collections::BTreeSet::from(["https://example.test".to_owned()])
        );
        authority.authorize_target(&target("/next")).unwrap();
        assert!(matches!(
            authority.authorize_target(&Url::parse("https://other.test/").unwrap()),
            Err(HttpEvidenceError::TargetOutsidePolicy { .. })
        ));
    }

    #[test]
    fn authority_revalidates_same_origin_credentials_and_unsupported_schemes() {
        let root = target("/root");
        let authority = SharedWebRuntimeAuthority::new_exact_origin(
            &root,
            HttpEvidencePolicy::for_origin(root.clone()).unwrap(),
            RuntimeBudget::default(),
            CancellationToken::new(),
        )
        .unwrap();

        assert!(matches!(
            authority.authorize_target(
                &Url::parse("https://embedded:secret@example.test/private").unwrap()
            ),
            Err(HttpEvidenceError::EmbeddedCredentials)
        ));
        assert!(matches!(
            authority.authorize_target(&Url::parse("ftp://example.test/archive").unwrap()),
            Err(HttpEvidenceError::UnsupportedScheme { .. })
        ));
    }

    #[test]
    fn clones_share_budget_knowledge_cancellation_and_absolute_deadline() {
        let target = target("/one");
        let authority = SharedWebRuntimeAuthority::new_exact_origin(
            &target,
            HttpEvidencePolicy::for_origin(target.clone()).unwrap(),
            RuntimeBudget::default().with_max_total_requests(1),
            CancellationToken::new(),
        )
        .unwrap();
        let clone = authority.clone();

        let timing = authority.start();
        assert_eq!(clone.start(), timing);
        assert_eq!(
            timing.deadline(),
            timing
                .started_at()
                .checked_add(RuntimeBudget::default().max_wall_time())
        );

        let subject = EntityId::new(format!("endpoint:{target}")).unwrap();
        let evidence = Evidence::new(
            subject.clone(),
            EvidenceKind::Http,
            HttpEvidencePredicate::RESPONSE_STATUS.into(),
            EvidenceValue::Unsigned(200),
            EvidenceSource::new("authority-test", "status").unwrap(),
            ConfidenceScore::MAX,
        );
        authority.knowledge().insert_evidence(evidence).unwrap();
        assert_eq!(clone.knowledge().evidence_for_subject(&subject).len(), 1);

        let mut lease = authority
            .request_accounting()
            .try_begin("action.one", DecisionExecutionStage::Passive, None)
            .unwrap();
        lease.finish(TransportDispatchOutcome::Completed);
        drop(lease);
        let limit = clone
            .request_accounting()
            .try_begin("action.two", DecisionExecutionStage::Passive, None)
            .unwrap_err();
        assert_eq!(limit.dimension(), RuntimeBudgetDimension::TotalRequests);

        clone.cancellation_token().cancel();
        assert!(authority.cancellation().is_cancelled());
    }

    #[cfg(feature = "oast-native-provider")]
    #[test]
    fn native_oast_mint_narrows_the_shared_broker_and_separates_provider_from_target() {
        use crate::native_oast_provider::{
            NativeOastProviderConfiguration, NativeOastProviderErrorKind,
            NativeOastProviderLifecycle, NativeOastProviderLimits,
        };

        let root = target("/root");
        let authority = SharedWebRuntimeAuthority::new_exact_origin(
            &root,
            HttpEvidencePolicy::for_origin(root.clone()).unwrap(),
            RuntimeBudget::default(),
            CancellationToken::new(),
        )
        .unwrap();
        let clone = authority.clone();
        let limits = NativeOastProviderLimits::new(1, 1, 4, 1, 16_384, 65_536, 5_000).unwrap();

        let overlap = clone
            .mint_native_oast_provider(
                NativeOastProviderConfiguration::new(
                    "https://example.test/",
                    "assessment:native-oast-overlap",
                    [72; 32],
                    b"NATIVE-OAST-OVERLAP-MUST-NOT-LEAK-83B4".to_vec(),
                    limits,
                )
                .unwrap(),
            )
            .unwrap_err();
        assert_eq!(
            overlap.kind(),
            NativeOastProviderErrorKind::ProviderTargetOriginOverlap
        );

        let adapter = authority
            .mint_native_oast_provider(
                NativeOastProviderConfiguration::new(
                    "https://oast.example.test/",
                    "assessment:native-oast-authority",
                    [71; 32],
                    b"NATIVE-OAST-AUTHORITY-MUST-NOT-LEAK-91A7".to_vec(),
                    limits,
                )
                .unwrap(),
            )
            .unwrap();
        assert_eq!(adapter.lifecycle(), NativeOastProviderLifecycle::Configured);
        assert!(authority
            .authorize_target(&Url::parse("https://oast.example.test/v1/sessions").unwrap())
            .is_err());

        let second = clone
            .mint_native_oast_provider(
                NativeOastProviderConfiguration::new(
                    "https://other-oast.example.test/",
                    "assessment:native-oast-second",
                    [73; 32],
                    b"NATIVE-OAST-SECOND-MUST-NOT-LEAK-68C2".to_vec(),
                    limits,
                )
                .unwrap(),
            )
            .unwrap_err();
        assert_eq!(
            second.kind(),
            NativeOastProviderErrorKind::AuthorityAlreadyMinted
        );
        assert_eq!(
            second.to_string(),
            "native OAST provider authority was already minted"
        );
    }
}
