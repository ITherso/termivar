use crate::{CallbackId, CallbackTarget, ProviderError, SessionId};
use std::{fmt, net::SocketAddr, str::FromStr};
use url::{Host, Url};

/// Maximum externally visible provider-origin bytes.
pub const MAX_PUBLIC_ORIGIN_BYTES: usize = 2_048;
/// Hard global live-session ceiling.
pub const HARD_MAX_ACTIVE_SESSIONS: u16 = 256;
/// Hard per-session callback ceiling.
pub const HARD_MAX_CALLBACKS_PER_SESSION: u16 = 8;
/// Hard per-session accepted-event ceiling.
pub const HARD_MAX_EVENTS_PER_SESSION: u16 = 64;
/// Hard per-session poll ceiling.
pub const HARD_MAX_POLLS_PER_SESSION: u16 = 32;
/// Hard page-size ceiling for one poll.
pub const HARD_MAX_POLL_EVENTS_PER_RESPONSE: u16 = 32;
/// Hard session-lifetime ceiling.
pub const HARD_MAX_SESSION_LIFETIME_MILLIS: u64 = 120_000;
/// Hard concurrent HTTP request ceiling.
pub const HARD_MAX_CONCURRENT_REQUESTS: u16 = 256;
/// Fixed maximum management request body size.
pub const MAX_MANAGEMENT_BODY_BYTES: usize = 64 * 1_024;
/// Fixed maximum management response body size.
pub const MAX_MANAGEMENT_RESPONSE_BYTES: usize = 256 * 1_024;

/// Exact loopback socket on which the provider may listen.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct LoopbackBind(SocketAddr);

impl LoopbackBind {
    /// Accepts only IPv4 or IPv6 loopback sockets.
    pub fn new(address: SocketAddr) -> Result<Self, ProviderError> {
        if !address.ip().is_loopback() {
            return Err(ProviderError::NonLoopbackBindRejected);
        }
        Ok(Self(address))
    }

    /// Returns the checked socket address.
    pub const fn socket_addr(self) -> SocketAddr {
        self.0
    }
}

impl fmt::Debug for LoopbackBind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LoopbackBind(<loopback>)")
    }
}

impl FromStr for LoopbackBind {
    type Err = ProviderError;

    fn from_str(source: &str) -> Result<Self, Self::Err> {
        let address = source
            .parse::<SocketAddr>()
            .map_err(|_| ProviderError::NonLoopbackBindRejected)?;
        Self::new(address)
    }
}

/// Canonical, externally visible HTTPS origin of one self-hosted provider.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PublicOrigin {
    canonical: String,
}

impl PublicOrigin {
    /// Returns the canonical origin, always ending in `/`.
    pub fn as_str(&self) -> &str {
        &self.canonical
    }

    pub(crate) fn callback_target(
        &self,
        session_id: &SessionId,
        callback_id: &CallbackId,
    ) -> Result<CallbackTarget, ProviderError> {
        let value = format!(
            "{}c/{}/{}",
            self.canonical,
            session_id.as_str(),
            callback_id.as_str()
        );
        CallbackTarget::from_provider(value)
    }

    #[cfg(test)]
    pub(crate) fn test_http_loopback(source: &str) -> Result<Self, ProviderError> {
        let mut parsed = parse_origin(source, true)?;
        match parsed.host() {
            Some(Host::Ipv4(address)) if address.is_loopback() => {},
            Some(Host::Ipv6(address)) if address.is_loopback() => {},
            _ => return Err(ProviderError::InvalidPublicOrigin),
        }
        normalize_origin(&mut parsed)
    }
}

impl FromStr for PublicOrigin {
    type Err = ProviderError;

    fn from_str(source: &str) -> Result<Self, Self::Err> {
        let mut parsed = parse_origin(source, false)?;
        if parsed.scheme() != "https" {
            return Err(ProviderError::InvalidPublicOrigin);
        }
        match parsed.host() {
            Some(Host::Domain(host)) if valid_dns_host(host) => {},
            _ => return Err(ProviderError::InvalidPublicOrigin),
        }
        if parsed.port_or_known_default() != Some(443) {
            return Err(ProviderError::InvalidPublicOrigin);
        }
        normalize_origin(&mut parsed)
    }
}

impl fmt::Debug for PublicOrigin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PublicOrigin(<configured>)")
    }
}

fn parse_origin(source: &str, allow_test_http: bool) -> Result<Url, ProviderError> {
    validate_raw_origin(source, allow_test_http)?;
    let parsed = Url::parse(source).map_err(|_| ProviderError::InvalidPublicOrigin)?;
    if (!allow_test_http && parsed.scheme() != "https")
        || (allow_test_http && !matches!(parsed.scheme(), "http" | "https"))
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.path() != "/"
    {
        return Err(ProviderError::InvalidPublicOrigin);
    }
    Ok(parsed)
}

fn validate_raw_origin(source: &str, allow_test_http: bool) -> Result<(), ProviderError> {
    if source.is_empty()
        || source.len() > MAX_PUBLIC_ORIGIN_BYTES
        || !source.is_ascii()
        || source.chars().any(|character| {
            character.is_control()
                || character.is_whitespace()
                || matches!(character, ',' | '*' | '%' | '@' | '?' | '#' | '\\')
        })
    {
        return Err(ProviderError::InvalidPublicOrigin);
    }

    let (scheme, authority_and_path) = source
        .split_once("://")
        .ok_or(ProviderError::InvalidPublicOrigin)?;
    let scheme_allowed = if allow_test_http {
        scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https")
    } else {
        scheme.eq_ignore_ascii_case("https")
    };
    if !scheme_allowed || authority_and_path.is_empty() {
        return Err(ProviderError::InvalidPublicOrigin);
    }

    let (authority, raw_path) = authority_and_path
        .split_once('/')
        .map_or((authority_and_path, ""), |(authority, path)| {
            (authority, path)
        });
    if authority.is_empty() || authority.ends_with(':') || !raw_path.is_empty() {
        return Err(ProviderError::InvalidPublicOrigin);
    }
    Ok(())
}

fn normalize_origin(parsed: &mut Url) -> Result<PublicOrigin, ProviderError> {
    let explicit_default_port = matches!(
        (parsed.scheme(), parsed.port()),
        ("http", Some(80)) | ("https", Some(443))
    );
    if explicit_default_port {
        parsed
            .set_port(None)
            .map_err(|()| ProviderError::InvalidPublicOrigin)?;
    }
    parsed.set_path("/");
    Ok(PublicOrigin {
        canonical: parsed.as_str().to_owned(),
    })
}

fn valid_dns_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost")
        || host.ends_with(".localhost")
        || host.len() > 253
        || host.is_empty()
    {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

/// Explicit checked provider resource ceilings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderLimits {
    max_active_sessions: u16,
    max_callbacks_per_session: u16,
    max_events_per_session: u16,
    max_polls_per_session: u16,
    max_poll_events_per_response: u16,
    max_session_lifetime_millis: u64,
    max_concurrent_requests: u16,
}

impl ProviderLimits {
    /// Validates every operational limit against its hard ceiling.
    pub fn new(
        max_active_sessions: u16,
        max_callbacks_per_session: u16,
        max_events_per_session: u16,
        max_polls_per_session: u16,
        max_poll_events_per_response: u16,
        max_session_lifetime_millis: u64,
        max_concurrent_requests: u16,
    ) -> Result<Self, ProviderError> {
        if max_active_sessions == 0
            || max_callbacks_per_session == 0
            || max_events_per_session == 0
            || max_polls_per_session == 0
            || max_poll_events_per_response == 0
            || max_session_lifetime_millis == 0
            || max_concurrent_requests == 0
            || max_active_sessions > HARD_MAX_ACTIVE_SESSIONS
            || max_callbacks_per_session > HARD_MAX_CALLBACKS_PER_SESSION
            || max_events_per_session > HARD_MAX_EVENTS_PER_SESSION
            || max_polls_per_session > HARD_MAX_POLLS_PER_SESSION
            || max_poll_events_per_response > HARD_MAX_POLL_EVENTS_PER_RESPONSE
            || max_poll_events_per_response > max_events_per_session
            || max_session_lifetime_millis > HARD_MAX_SESSION_LIFETIME_MILLIS
            || max_concurrent_requests > HARD_MAX_CONCURRENT_REQUESTS
        {
            return Err(ProviderError::InvalidConfiguration);
        }
        Ok(Self {
            max_active_sessions,
            max_callbacks_per_session,
            max_events_per_session,
            max_polls_per_session,
            max_poll_events_per_response,
            max_session_lifetime_millis,
            max_concurrent_requests,
        })
    }

    /// Maximum simultaneously retained sessions.
    pub const fn max_active_sessions(self) -> u16 {
        self.max_active_sessions
    }
    /// Maximum callbacks in one session.
    pub const fn max_callbacks_per_session(self) -> u16 {
        self.max_callbacks_per_session
    }
    /// Maximum unique events in one session.
    pub const fn max_events_per_session(self) -> u16 {
        self.max_events_per_session
    }
    /// Maximum polls in one session.
    pub const fn max_polls_per_session(self) -> u16 {
        self.max_polls_per_session
    }
    /// Maximum events emitted in one poll page.
    pub const fn max_poll_events_per_response(self) -> u16 {
        self.max_poll_events_per_response
    }
    /// Maximum session lifetime.
    pub const fn max_session_lifetime_millis(self) -> u64 {
        self.max_session_lifetime_millis
    }
    /// Maximum concurrently admitted HTTP requests.
    pub const fn max_concurrent_requests(self) -> u16 {
        self.max_concurrent_requests
    }
}

/// Immutable configuration for one in-memory provider instance.
#[derive(Clone, PartialEq, Eq)]
pub struct ProviderConfig {
    bind: LoopbackBind,
    public_origin: PublicOrigin,
    limits: ProviderLimits,
}

impl fmt::Debug for ProviderConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProviderConfig(<configured>)")
    }
}

impl ProviderConfig {
    /// Creates an exact provider configuration from fully checked components.
    pub const fn new(
        bind: LoopbackBind,
        public_origin: PublicOrigin,
        limits: ProviderLimits,
    ) -> Self {
        Self {
            bind,
            public_origin,
            limits,
        }
    }

    /// Returns the loopback listen socket.
    pub const fn bind(&self) -> LoopbackBind {
        self.bind
    }
    /// Returns the exact external origin.
    pub const fn public_origin(&self) -> &PublicOrigin {
        &self.public_origin
    }
    /// Returns all checked ceilings.
    pub const fn limits(&self) -> ProviderLimits {
        self.limits
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_origins_are_exact_https_dns_origins() {
        let origin: PublicOrigin = "https://oast.example.test:443/".parse().unwrap();
        assert_eq!(origin.as_str(), "https://oast.example.test/");
        assert_eq!(
            "https://oast.example.test"
                .parse::<PublicOrigin>()
                .unwrap()
                .as_str(),
            "https://oast.example.test/"
        );
        for invalid in [
            "http://oast.example.test/",
            "https://127.0.0.1/",
            "https://localhost/",
            "https://user@oast.example.test/",
            "https://oast.example.test/path",
            "https://oast.example.test/?query=1",
            "https://oast.example.test/#fragment",
            "https://*.example.test/",
            "https://one.test/,https://two.test/",
            "https://oast.example.test:8443/",
            "https://oast.example.test:/",
            "https://@oast.example.test/",
            "https://:@oast.example.test/",
            "https://oast.example.test/./",
            "https://oast.example.test/foo/..",
            "https://oast.example.test/%2e",
            "https://%6fast.example.test/",
            "https://oast.exämple.test/",
            "https:\\oast.example.test\\",
            "https://oast.exam\tple.test/",
            "https://oast.example.test/\n",
        ] {
            assert_eq!(
                invalid.parse::<PublicOrigin>(),
                Err(ProviderError::InvalidPublicOrigin)
            );
        }
        assert_eq!(
            format!(
                "https://{}.example.test/",
                "a".repeat(MAX_PUBLIC_ORIGIN_BYTES)
            )
            .parse::<PublicOrigin>(),
            Err(ProviderError::InvalidPublicOrigin)
        );
    }

    #[test]
    fn only_loopback_binds_and_test_http_loopback_are_accepted() {
        assert!("127.0.0.1:8080".parse::<LoopbackBind>().is_ok());
        assert!("[::1]:8080".parse::<LoopbackBind>().is_ok());
        for invalid in ["0.0.0.0:8080", "[::]:8080", "192.0.2.1:8080"] {
            assert_eq!(
                invalid.parse::<LoopbackBind>(),
                Err(ProviderError::NonLoopbackBindRejected)
            );
        }
        assert!(PublicOrigin::test_http_loopback("http://127.0.0.1:8080/").is_ok());
        assert!(PublicOrigin::test_http_loopback("http://example.test/").is_err());
    }

    #[test]
    fn limits_reject_zero_and_cross_limit_pages() {
        assert!(ProviderLimits::new(1, 2, 3, 4, 3, 5_000, 6).is_ok());
        assert_eq!(
            ProviderLimits::new(1, 2, 3, 4, 4, 5_000, 6),
            Err(ProviderError::InvalidConfiguration)
        );
        assert_eq!(
            ProviderLimits::new(0, 2, 3, 4, 3, 5_000, 6),
            Err(ProviderError::InvalidConfiguration)
        );
    }
}
