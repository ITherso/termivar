//! Bounded in-memory cache.
//!
//! ## Runtime scope
//!
//! - **Build:** opt-in via `platform-models`.
//! - **Execution:** host/library only; no repository runtime caller.
//! - **Default `termivar scan`:** no.
//! - **Support:** experimental/scaffold.
//!
//! See `docs/internals/runtime-map.md`.
//!
//! [`LruCache`] provides process-local TTL storage with true access-recency
//! eviction. TTL uses a monotonic clock; recency uses a sequence allocated
//! while the cache lock is held. This module does
//! not cache HTTP responses because a URL alone cannot identify authorization,
//! cookies, headers, request body, or other response-varying context safely.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

trait Clock: Send + Sync {
    fn now(&self) -> Duration;
}

struct SystemClock {
    origin: Instant,
}

impl SystemClock {
    fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Clock for SystemClock {
    fn now(&self) -> Duration {
        self.origin.elapsed()
    }
}

struct CacheEntry<T> {
    value: T,
    created_at: Duration,
    last_access_sequence: u128,
    ttl: Duration,
}

impl<T> CacheEntry<T> {
    fn new(value: T, ttl: Duration, now: Duration, access_sequence: u128) -> Self {
        Self {
            value,
            created_at: now,
            last_access_sequence: access_sequence,
            ttl,
        }
    }

    fn is_expired_at(&self, now: Duration) -> bool {
        now.saturating_sub(self.created_at) >= self.ttl
    }
}

struct CacheState<K, V> {
    entries: HashMap<K, CacheEntry<V>>,
    next_access_sequence: u128,
}

impl<K, V> Default for CacheState<K, V> {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            next_access_sequence: 0,
        }
    }
}

impl<K, V> CacheState<K, V> {
    fn allocate_access_sequence(&mut self) -> u128 {
        if self.next_access_sequence == u128::MAX {
            let mut entries: Vec<_> = self.entries.values_mut().collect();
            entries.sort_by_key(|entry| entry.last_access_sequence);
            for (sequence, entry) in entries.into_iter().enumerate() {
                entry.last_access_sequence = sequence as u128;
            }
            self.next_access_sequence = self.entries.len() as u128;
        }
        let sequence = self.next_access_sequence;
        self.next_access_sequence += 1;
        sequence
    }
}

/// A process-local, bounded least-recently-used cache with TTL expiration.
pub struct LruCache<K, V> {
    cache: Mutex<CacheState<K, V>>,
    max_size: usize,
    hits: AtomicU64,
    misses: AtomicU64,
    clock: Arc<dyn Clock>,
}

impl<K: Eq + Hash + Clone, V: Clone> LruCache<K, V> {
    /// Creates an empty cache using a monotonic process clock.
    #[must_use]
    pub fn new(max_size: usize) -> Self {
        Self::with_clock(max_size, Arc::new(SystemClock::new()))
    }

    fn with_clock(max_size: usize, clock: Arc<dyn Clock>) -> Self {
        Self {
            cache: Mutex::new(CacheState::default()),
            max_size,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            clock,
        }
    }

    /// Inserts or replaces a value with a TTL measured from this call.
    pub fn insert(&self, key: K, value: V, ttl_secs: u64) {
        if self.max_size == 0 {
            return;
        }

        let mut state = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        let now = self.clock.now();
        if !state.entries.contains_key(&key) && state.entries.len() >= self.max_size {
            let eviction_key = state
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_access_sequence)
                .map(|(key, _)| key.clone());
            if let Some(eviction_key) = eviction_key {
                state.entries.remove(&eviction_key);
            }
        }

        let access_sequence = state.allocate_access_sequence();
        state.entries.insert(
            key,
            CacheEntry::new(value, Duration::from_secs(ttl_secs), now, access_sequence),
        );
    }

    /// Returns an unexpired value and records this lookup as the latest access.
    pub fn get(&self, key: &K) -> Option<V> {
        let mut state = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        let now = self.clock.now();

        let expired = state
            .entries
            .get(key)
            .is_some_and(|entry| entry.is_expired_at(now));
        if expired {
            state.entries.remove(key);
            increment(&self.misses);
            return None;
        }

        if let Some(value) = state.entries.get(key).map(|entry| entry.value.clone()) {
            let access_sequence = state.allocate_access_sequence();
            if let Some(entry) = state.entries.get_mut(key) {
                entry.last_access_sequence = access_sequence;
            }
            increment(&self.hits);
            Some(value)
        } else {
            increment(&self.misses);
            None
        }
    }

    /// Removes a key.
    pub fn remove(&self, key: &K) -> bool {
        self.cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entries
            .remove(key)
            .is_some()
    }

    /// Clears all entries without changing accumulated statistics.
    pub fn clear(&self) {
        self.cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entries
            .clear();
    }

    /// Returns a point-in-time statistics snapshot.
    #[must_use]
    pub fn stats(&self) -> CacheStats {
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        let total = hits.saturating_add(misses);
        let size = self
            .cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entries
            .len();

        CacheStats {
            hits,
            misses,
            hit_rate: if total == 0 {
                0.0
            } else {
                (hits as f64 / total as f64) * 100.0
            },
            size,
            max_size: self.max_size,
        }
    }
}

fn increment(counter: &AtomicU64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_add(1))
    });
}

/// Cache statistics snapshot.
#[derive(Debug, Clone, PartialEq)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub hit_rate: f64,
    pub size: usize,
    pub max_size: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct TestClock {
        seconds: AtomicU64,
    }

    impl TestClock {
        fn set(&self, seconds: u64) {
            self.seconds.store(seconds, Ordering::Relaxed);
        }

        fn advance(&self, seconds: u64) {
            self.seconds.fetch_add(seconds, Ordering::Relaxed);
        }
    }

    impl Clock for TestClock {
        fn now(&self) -> Duration {
            Duration::from_secs(self.seconds.load(Ordering::Relaxed))
        }
    }

    fn cache_with_clock<K: Eq + Hash + Clone, V: Clone>(
        max_size: usize,
        clock: Arc<TestClock>,
    ) -> LruCache<K, V> {
        LruCache::with_clock(max_size, clock)
    }

    #[test]
    fn ttl_expiration_uses_the_injected_monotonic_clock() {
        let clock = Arc::new(TestClock::default());
        let cache = cache_with_clock(1, Arc::clone(&clock));
        cache.insert("key", "value", 10);

        clock.advance(9);
        assert_eq!(cache.get(&"key"), Some("value"));
        clock.advance(1);
        assert_eq!(cache.get(&"key"), None);
    }

    #[test]
    fn backward_clock_values_do_not_underflow_or_expire_entries() {
        let clock = Arc::new(TestClock::default());
        clock.set(10);
        let cache = cache_with_clock(1, Arc::clone(&clock));
        cache.insert("key", "value", 5);

        clock.set(1);
        assert_eq!(cache.get(&"key"), Some("value"));
    }

    #[test]
    fn successful_get_refreshes_lru_recency() {
        let clock = Arc::new(TestClock::default());
        let cache = cache_with_clock(2, Arc::clone(&clock));
        cache.insert("first", "one", 100);
        clock.advance(1);
        cache.insert("second", "two", 100);
        clock.advance(1);
        assert_eq!(cache.get(&"first"), Some("one"));
        clock.advance(1);
        cache.insert("third", "three", 100);

        assert_eq!(cache.get(&"second"), None);
        assert_eq!(cache.get(&"first"), Some("one"));
        assert_eq!(cache.get(&"third"), Some("three"));
    }

    #[test]
    fn equal_clock_values_still_evict_by_serialized_access_order() {
        let clock = Arc::new(TestClock::default());
        let cache = cache_with_clock(2, clock);
        cache.insert("first", "one", 100);
        cache.insert("second", "two", 100);
        assert_eq!(cache.get(&"first"), Some("one"));
        cache.insert("third", "three", 100);

        assert_eq!(cache.get(&"second"), None);
        assert_eq!(cache.get(&"first"), Some("one"));
        assert_eq!(cache.get(&"third"), Some("three"));
    }

    #[test]
    fn replacing_an_existing_key_does_not_evict_another_entry() {
        let clock = Arc::new(TestClock::default());
        let cache = cache_with_clock(2, Arc::clone(&clock));
        cache.insert("first", "one", 100);
        clock.advance(1);
        cache.insert("second", "two", 100);
        clock.advance(1);
        cache.insert("first", "updated", 100);

        assert_eq!(cache.stats().size, 2);
        assert_eq!(cache.get(&"first"), Some("updated"));
        assert_eq!(cache.get(&"second"), Some("two"));
    }

    #[test]
    fn zero_size_cache_stores_nothing_and_counts_a_miss() {
        let cache = LruCache::new(0);
        cache.insert(1, "value", 100);

        assert_eq!(cache.get(&1), None);
        assert_eq!(
            cache.stats(),
            CacheStats {
                hits: 0,
                misses: 1,
                hit_rate: 0.0,
                size: 0,
                max_size: 0,
            }
        );
    }

    #[test]
    fn remove_clear_and_stats_report_real_operations() {
        let cache = LruCache::new(2);
        cache.insert("first", "one", 100);
        cache.insert("second", "two", 100);
        assert_eq!(cache.get(&"first"), Some("one"));
        assert!(cache.remove(&"second"));
        assert!(!cache.remove(&"missing"));
        cache.clear();

        let stats = cache.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 0);
        assert_eq!(stats.hit_rate, 100.0);
        assert_eq!(stats.size, 0);
    }
}
