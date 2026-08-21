// Copyright (c) the go-browserhttp/gitcorsproxy authors.
// SPDX-License-Identifier: BSD-3-Clause

package gitcorsproxy

import (
	"math"
	"sync"
	"time"
)

// rateLimiter is a concurrency-safe, per-key token-bucket limiter. Each key
// (a client IP) gets its own bucket that refills at rate tokens/second up to a
// burst ceiling. It is a tiny internal implementation so the package keeps its
// zero-dependency, standard-library-only posture (golang.org/x/time/rate would
// otherwise be the obvious choice, but it is not worth a module dependency for
// a bucket this small).
//
// Memory is bounded two ways: buckets idle longer than idleAfter are swept
// lazily, and if the live set still exceeds maxKeys the least-recently-seen
// bucket is evicted. Both keep an abusive spray of distinct forged IPs from
// growing the map without limit.
type rateLimiter struct {
	mu        sync.Mutex
	buckets   map[string]*bucket
	rate      float64       // tokens per second
	burst     float64       // bucket ceiling
	maxKeys   int           // hard cap on tracked buckets
	idleAfter time.Duration // sweep buckets unseen for longer than this
	now       func() time.Time
}

// bucket is one client's token state. last is both the refill instant and the
// last-seen instant used for idle eviction.
type bucket struct {
	tokens float64
	last   time.Time
}

// newRateLimiter builds a limiter. ratePerMinute and burst come from config;
// maxKeys, idleAfter and now carry their resolved defaults from New.
func newRateLimiter(ratePerMinute, burst, maxKeys int, idleAfter time.Duration, now func() time.Time) *rateLimiter {
	return &rateLimiter{
		buckets:   make(map[string]*bucket),
		rate:      float64(ratePerMinute) / 60.0,
		burst:     float64(burst),
		maxKeys:   maxKeys,
		idleAfter: idleAfter,
		now:       now,
	}
}

// allow consumes one token for key. It reports whether the request may proceed
// and, when it may not, the duration the caller should wait before one token
// is available (for the Retry-After header).
func (l *rateLimiter) allow(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	b := l.buckets[key]
	if b == nil {
		// A new key. Sweep idle buckets first, and if the set is still at the
		// cap drop the least-recently-seen one so the map stays bounded.
		if len(l.buckets) >= l.maxKeys {
			l.sweep(now)
		}
		if len(l.buckets) >= l.maxKeys {
			l.evictOldest()
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}

	// Refill according to elapsed time, capped at the burst ceiling.
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens = math.Min(l.burst, b.tokens+elapsed*l.rate)
	}
	b.last = now

	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	// Time until the bucket regains one whole token.
	retry := time.Duration((1 - b.tokens) / l.rate * float64(time.Second))
	return false, retry
}

// sweep removes buckets not seen within idleAfter. The caller holds the lock.
func (l *rateLimiter) sweep(now time.Time) {
	for k, b := range l.buckets {
		if now.Sub(b.last) > l.idleAfter {
			delete(l.buckets, k)
		}
	}
}

// evictOldest removes the single least-recently-seen bucket. The caller holds
// the lock and has already established that the map is at capacity.
func (l *rateLimiter) evictOldest() {
	var oldestKey string
	var oldest time.Time
	first := true
	for k, b := range l.buckets {
		if first || b.last.Before(oldest) {
			oldestKey, oldest, first = k, b.last, false
		}
	}
	delete(l.buckets, oldestKey)
}
