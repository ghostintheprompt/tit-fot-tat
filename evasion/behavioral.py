"""
Behavioral Analysis & Entropy Scoring
======================================
Modern bot detection systems analyze request timing patterns, navigation sequences,
and inter-page behavior to distinguish humans from automated tools. A script that
makes requests at precise 500ms intervals has a timing entropy score near zero —
trivially detectable.

This module implements:
  - Gaussian jitter: human-like inter-request delays with realistic variance
  - Non-linear navigation: randomized visit ordering and occasional backtracking
  - Entropy scoring: quantifies behavioral randomness (higher = more human-like)
  - Stealth mode wrapper: applies all evasion techniques to a request sequence

Entropy formula:
  H(X) = -Σ p_i * log2(p_i)
  Applied to binned inter-request timing intervals.
  Perfect bot (constant interval): H ≈ 0 bits
  Human browsing:                  H ≈ 3.5–5.0 bits
  Maximum (uniform distribution): H = log2(n) bits

References:
  - DistilNetworks bot taxonomy (2019)
  - Cloudflare Bot Fight Mode whitepaper
  - "Bot or Not?" — USENIX Security 2012
"""

import time
import math
import random
import statistics
from typing import List, Optional, Callable, Any


# ── Jitter Engine ─────────────────────────────────────────────────────────────

class JitterEngine:
    """
    Produces human-like inter-request delays using Gaussian sampling.

    Human reading and navigation times follow a log-normal distribution with
    occasional long pauses (reading, distraction). This engine models:
      - Base reading time: 2–8 seconds per page
      - Navigation time: 0.5–2 seconds between clicks
      - Distraction pauses: 10–30 seconds, occurring ~15% of the time
      - Burst reading: <0.5 seconds for asset/media requests
    """

    def __init__(
        self,
        base_mean: float = 3.0,
        base_std: float = 1.5,
        min_delay: float = 0.3,
        max_delay: float = 25.0,
        distraction_prob: float = 0.12,
        distraction_mean: float = 18.0,
        distraction_std: float = 6.0,
    ):
        self.base_mean = base_mean
        self.base_std = base_std
        self.min_delay = min_delay
        self.max_delay = max_delay
        self.distraction_prob = distraction_prob
        self.distraction_mean = distraction_mean
        self.distraction_std = distraction_std
        self._history: List[float] = []

    def next_delay(self) -> float:
        """Sample the next inter-request delay."""
        if random.random() < self.distraction_prob:
            # Distraction pause: log-normal around distraction_mean
            delay = random.gauss(self.distraction_mean, self.distraction_std)
        else:
            delay = random.gauss(self.base_mean, self.base_std)

        delay = max(self.min_delay, min(self.max_delay, delay))
        self._history.append(delay)
        return delay

    def sleep(self) -> float:
        """Sleep for the next sampled delay. Returns actual delay used."""
        delay = self.next_delay()
        time.sleep(delay)
        return delay

    def compute_entropy(self, intervals: Optional[List[float]] = None) -> float:
        """
        Compute Shannon entropy of timing intervals.

        Bins intervals into 0.5-second buckets and computes the entropy
        of the resulting probability distribution.

        Returns: entropy in bits. Higher = more human-like.
          < 1.0  — highly regular (bot-like)
          1.0-2.5 — semi-regular (detectable)
          2.5-4.0 — human-like
          > 4.0  — chaotic (may look synthetic)
        """
        intervals = intervals or self._history
        if len(intervals) < 3:
            return 0.0

        # Bin into 0.5-second buckets
        bin_size = 0.5
        max_val = max(intervals)
        bins = [0] * (int(max_val / bin_size) + 2)
        for v in intervals:
            bucket = int(v / bin_size)
            bins[bucket] += 1

        n = len(intervals)
        entropy = 0.0
        for count in bins:
            if count > 0:
                p = count / n
                entropy -= p * math.log2(p)

        return entropy

    def entropy_report(self) -> dict:
        """Full behavioral entropy report for logging/portfolio evidence."""
        if not self._history:
            return {"error": "No timing data recorded yet"}

        ent = self.compute_entropy()
        return {
            "request_count": len(self._history),
            "mean_delay_s": round(statistics.mean(self._history), 3),
            "std_delay_s": round(statistics.stdev(self._history) if len(self._history) > 1 else 0, 3),
            "min_delay_s": round(min(self._history), 3),
            "max_delay_s": round(max(self._history), 3),
            "entropy_bits": round(ent, 3),
            "human_likeness": _classify_entropy(ent),
            "detection_risk": _entropy_to_risk(ent),
        }


def _classify_entropy(h: float) -> str:
    if h < 1.0:
        return "BOT_LIKE"
    if h < 2.5:
        return "SEMI_REGULAR"
    if h < 4.0:
        return "HUMAN_LIKE"
    return "CHAOTIC"


def _entropy_to_risk(h: float) -> str:
    if h < 1.0:
        return "HIGH — timing pattern trivially detectable"
    if h < 2.0:
        return "MEDIUM — pattern detectable with ML classifiers"
    if h < 3.5:
        return "LOW — within normal human variance"
    return "VERY_LOW — exceeds average human entropy (suspicious in opposite direction)"


# ── Navigation Pattern Randomizer ─────────────────────────────────────────────

class NavigationRandomizer:
    """
    Introduces non-linear navigation patterns to simulate human browsing.

    Bots typically traverse pages in a predictable sequential order:
    index → page_1 → page_2 → page_3 → ...

    Humans: skip pages, re-visit, follow tangents, abandon paths.
    This class models those patterns.
    """

    def __init__(self, pages: List[str], revisit_prob: float = 0.08,
                 skip_prob: float = 0.15, abandon_prob: float = 0.05):
        self.pages = list(pages)
        self.revisit_prob = revisit_prob
        self.skip_prob = skip_prob
        self.abandon_prob = abandon_prob
        self._visited: List[str] = []
        self._sequence: List[str] = []

    def generate_sequence(self) -> List[str]:
        """
        Generate a non-linear page visit sequence from the page list.
        """
        remaining = self.pages.copy()
        sequence = []

        while remaining:
            # Abandon with small probability
            if len(sequence) > 3 and random.random() < self.abandon_prob:
                break

            # Skip next page with some probability
            if len(remaining) > 2 and random.random() < self.skip_prob:
                remaining.pop(0)
                continue

            # Revisit a previously seen page
            if self._visited and random.random() < self.revisit_prob:
                sequence.append(random.choice(self._visited[-5:]))
                continue

            page = remaining.pop(0)
            sequence.append(page)
            self._visited.append(page)

        self._sequence = sequence
        return sequence

    def shuffled_subset(self, n: int = None) -> List[str]:
        """
        Return a randomly shuffled subset of pages.
        If n is None, uses a random subset size.
        """
        n = n or random.randint(max(1, len(self.pages) // 3), len(self.pages))
        subset = random.sample(self.pages, min(n, len(self.pages)))
        return subset


# ── Stealth Mode Wrapper ──────────────────────────────────────────────────────

class StealthRequestor:
    """
    Wraps a request function with full behavioral evasion.

    Applies:
      1. JitterEngine delays between requests
      2. NavigationRandomizer for non-linear traversal
      3. Session rotation via fingerprint.py profiles
      4. Entropy tracking and reporting
    """

    def __init__(
        self,
        request_fn: Callable,
        jitter: Optional[JitterEngine] = None,
        profile_rotation: bool = True,
    ):
        self.request_fn = request_fn
        self.jitter = jitter or JitterEngine()
        self.profile_rotation = profile_rotation
        self._request_count = 0
        self._start_time: Optional[float] = None

    def get(self, url: str, **kwargs) -> Any:
        """Make a single request with behavioral evasion applied."""
        if self._start_time is None:
            self._start_time = time.time()
        else:
            # Apply jitter before every request after the first
            delay = self.jitter.sleep()

        self._request_count += 1
        result = self.request_fn(url, **kwargs)
        return result

    def get_many(self, urls: List[str], **kwargs) -> List[Any]:
        """
        Fetch multiple URLs in a behaviorally randomized sequence.
        Returns responses in the order they were requested (non-sequential may differ).
        """
        randomizer = NavigationRandomizer(urls)
        sequence = randomizer.generate_sequence()

        responses = {}
        for url in sequence:
            response = self.get(url, **kwargs)
            responses[url] = response

        # Return in original URL order
        return [responses.get(u) for u in urls if u in responses]

    def entropy_report(self) -> dict:
        elapsed = (time.time() - self._start_time) if self._start_time else 0
        report = self.jitter.entropy_report()
        report["total_requests"] = self._request_count
        report["session_duration_s"] = round(elapsed, 1)
        if self._request_count > 0 and elapsed > 0:
            report["requests_per_minute"] = round(self._request_count / elapsed * 60, 2)
        return report


# ── Convenience Functions ─────────────────────────────────────────────────────

def quick_jitter(min_s: float = 1.0, max_s: float = 5.0) -> float:
    """Simple random delay without tracking. Use in basic stealth loops."""
    delay = random.uniform(min_s, max_s)
    time.sleep(delay)
    return delay


def score_timing_list(intervals: List[float]) -> dict:
    """
    Score an externally provided list of timing intervals.
    Useful for analyzing logs from existing scripts.
    """
    engine = JitterEngine()
    engine._history = intervals
    return engine.entropy_report()
