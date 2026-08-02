//! Caching Layer for Performance Optimization
//!
//! LRU cache for responses, patterns, and scan results.

use dashmap::DashMap;
use std::sync::Arc;

/// Cache entry with TTL
#[derive(Debug, Clone)]
pub struct CacheEntry<T> {
    pub value: T,
    pub created_at: u64,
    pub ttl_secs: u64,
}

impl<T> CacheEntry<T> {
    pub fn new(value: T, ttl_secs: u64) -> Self {
        Self {
            value,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            ttl_secs,
        }
    }

    pub fn is_expired(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now - self.created_at > self.ttl_secs
    }
}

/// LRU Cache with TTL support
pub struct LruCache<K, V> {
    cache: Arc<DashMap<K, CacheEntry<V>>>,
    max_size: usize,
    hits: Arc<std::sync::atomic::AtomicU64>,
    misses: Arc<std::sync::atomic::AtomicU64>,
}

impl<K: Eq + std::hash::Hash + Clone, V: Clone> LruCache<K, V> {
    /// Creates a new LRU cache
    pub fn new(max_size: usize) -> Self {
        Self {
            cache: Arc::new(DashMap::new()),
            max_size,
            hits: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            misses: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    /// Inserts a value with TTL
    pub fn insert(&self, key: K, value: V, ttl_secs: u64) {
        if self.max_size == 0 {
            return;
        }

        if self.cache.len() >= self.max_size {
            // Clone the eviction key while the iterator holds DashMap's shard
            // lock, then drop the iterator before mutating the same map.
            let eviction_key = self
                .cache
                .iter()
                .min_by_key(|entry| entry.created_at)
                .map(|entry| entry.key().clone());

            if let Some(eviction_key) = eviction_key {
                self.cache.remove(&eviction_key);
            }
        }
        self.cache.insert(key, CacheEntry::new(value, ttl_secs));
    }

    /// Gets a value if not expired
    pub fn get(&self, key: &K) -> Option<V> {
        if let Some(entry) = self.cache.get(key) {
            if entry.is_expired() {
                drop(entry);
                self.cache.remove(key);
                self.misses
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                None
            } else {
                let value = entry.value.clone();
                self.hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Some(value)
            }
        } else {
            self.misses
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            None
        }
    }

    /// Removes a key
    pub fn remove(&self, key: &K) -> bool {
        self.cache.remove(key).is_some()
    }

    /// Clears entire cache
    pub fn clear(&self) {
        self.cache.clear();
    }

    /// Gets cache statistics
    pub fn stats(&self) -> CacheStats {
        let hits = self.hits.load(std::sync::atomic::Ordering::Relaxed);
        let misses = self.misses.load(std::sync::atomic::Ordering::Relaxed);
        let total = hits + misses;

        CacheStats {
            hits,
            misses,
            hit_rate: if total > 0 {
                (hits as f64 / total as f64) * 100.0
            } else {
                0.0
            },
            size: self.cache.len(),
            max_size: self.max_size,
        }
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub hit_rate: f64,
    pub size: usize,
    pub max_size: usize,
}

/// Response cache for HTTP results
pub struct ResponseCache {
    cache: LruCache<String, Vec<u8>>,
}

impl ResponseCache {
    /// Creates a new response cache
    pub fn new(max_size: usize) -> Self {
        Self {
            cache: LruCache::new(max_size),
        }
    }

    /// Caches a response
    pub fn cache_response(&self, url: &str, response: Vec<u8>, ttl_secs: u64) {
        self.cache.insert(url.to_string(), response, ttl_secs);
    }

    /// Gets a cached response
    pub fn get_response(&self, url: &str) -> Option<Vec<u8>> {
        self.cache.get(&url.to_string())
    }

    /// Gets cache stats
    pub fn stats(&self) -> CacheStats {
        self.cache.stats()
    }
}

impl Default for ResponseCache {
    fn default() -> Self {
        Self::new(1000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_entry_creation() {
        let entry = CacheEntry::new("value".to_string(), 3600);
        assert_eq!(entry.value, "value");
        assert!(!entry.is_expired());
    }

    #[test]
    fn test_cache_entry_expiration() {
        let mut entry = CacheEntry::new("value".to_string(), 3600);
        // Manually set to past
        entry.created_at -= 7200;
        assert!(entry.is_expired());
    }

    #[test]
    fn test_lru_cache_insert_get() {
        let cache: LruCache<String, String> = LruCache::new(100);
        cache.insert("key1".to_string(), "value1".to_string(), 3600);

        let value = cache.get(&"key1".to_string());
        assert_eq!(value, Some("value1".to_string()));
    }

    #[test]
    fn test_cache_miss() {
        let cache: LruCache<String, String> = LruCache::new(100);
        let value = cache.get(&"nonexistent".to_string());
        assert!(value.is_none());
    }

    #[test]
    fn test_cache_stats() {
        let cache: LruCache<String, String> = LruCache::new(100);
        cache.insert("key1".to_string(), "value1".to_string(), 3600);

        let _ = cache.get(&"key1".to_string());
        let _ = cache.get(&"key2".to_string());

        let stats = cache.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
    }

    #[test]
    fn test_cache_remove() {
        let cache: LruCache<String, String> = LruCache::new(100);
        cache.insert("key1".to_string(), "value1".to_string(), 3600);

        assert!(cache.remove(&"key1".to_string()));
        assert!(cache.get(&"key1".to_string()).is_none());
    }

    #[test]
    fn test_cache_clear() {
        let cache: LruCache<String, String> = LruCache::new(100);
        cache.insert("key1".to_string(), "value1".to_string(), 3600);
        cache.insert("key2".to_string(), "value2".to_string(), 3600);

        cache.clear();
        assert!(cache.get(&"key1".to_string()).is_none());
    }

    #[test]
    fn test_response_cache() {
        let cache = ResponseCache::new(100);
        let response = vec![1, 2, 3, 4, 5];

        cache.cache_response("https://example.com", response.clone(), 3600);
        let cached = cache.get_response("https://example.com");

        assert_eq!(cached, Some(response));
    }

    #[test]
    fn test_cache_max_size() {
        let cache: LruCache<usize, String> = LruCache::new(2);
        cache.insert(1, "value1".to_string(), 3600);
        cache.insert(2, "value2".to_string(), 3600);
        cache.insert(3, "value3".to_string(), 3600);

        assert!(cache.stats().size <= 2);
    }

    #[test]
    fn test_zero_size_cache_does_not_store_entries() {
        let cache: LruCache<usize, String> = LruCache::new(0);
        cache.insert(1, "value1".to_string(), 3600);

        assert_eq!(cache.stats().size, 0);
        assert!(cache.get(&1).is_none());
    }

    #[test]
    fn test_hit_rate_calculation() {
        let cache: LruCache<String, String> = LruCache::new(100);
        cache.insert("key1".to_string(), "value1".to_string(), 3600);

        for _ in 0..2 {
            let _ = cache.get(&"key1".to_string());
        }
        let _ = cache.get(&"key2".to_string());

        let stats = cache.stats();
        assert!(stats.hit_rate > 0.0 && stats.hit_rate < 100.0);
    }
}
