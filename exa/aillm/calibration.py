"""Confidence calibration for a future scoring / LLM-assist tier.

The deterministic rule-based classifier (``exa/aillm/learn.py``) emits discrete
verdicts, not probabilities, so it needs no calibration and stays auditable. This
module is the calibration layer for the moment a *continuous* confidence appears
-- an LLM-assist backend scoring "how generic-AI is this value, 0..1", or a
learned scorer. Raw model confidences are typically mis-calibrated, so we:

1. **Calibrate** raw scores -> P(safe) with **isotonic regression** (PAVA, L2,
   non-parametric, monotone -- preserves the ranker's order without assuming a
   sigmoid link).
2. **Threshold on a precision floor, not 0.5**: pick the lowest score whose
   Wilson lower-bound of promote-precision >= target, so a small calibration
   sample cannot let a leak through -- the interval width *is* the safety margin.

Pure Python, no sklearn dependency. NOT wired into the classifier yet; it is
staged behind the scoring tier and validated on the golden corpus.
"""

from __future__ import annotations

import bisect
import math


def isotonic_regression(y: list[float], w: list[float] | None = None) -> list[float]:
    """Pool-Adjacent-Violators: monotone non-decreasing L2 fit of ``y`` (in order).

    Returns fitted values aligned to the input order. ``y`` should already be
    ordered by the covariate (e.g. ascending score). O(n).
    """
    n = len(y)
    if n == 0:
        return []
    if w is None:
        w = [1.0] * n
    # Each block: [weighted_sum, weight, count]; merge while the previous block's
    # mean exceeds the current block's mean (a monotonicity violation).
    blocks: list[list[float]] = []
    for yi, wi in zip(y, w, strict=True):
        blocks.append([yi * wi, wi, 1])
        while len(blocks) >= 2 and (
            blocks[-2][0] / blocks[-2][1] > blocks[-1][0] / blocks[-1][1]
        ):
            b2 = blocks.pop()
            b1 = blocks.pop()
            blocks.append([b1[0] + b2[0], b1[1] + b2[1], b1[2] + b2[2]])
    out: list[float] = []
    for wsum, weight, count in blocks:
        out.extend([wsum / weight] * int(count))
    return out


def wilson_lower_bound(k: int, n: int, z: float = 1.96) -> float:
    """Lower bound of the Wilson score interval for a binomial proportion k/n."""
    if n == 0:
        return 0.0
    phat = k / n
    denom = 1.0 + z * z / n
    center = phat + z * z / (2 * n)
    margin = z * math.sqrt(phat * (1 - phat) / n + z * z / (4 * n * n))
    return max(0.0, (center - margin) / denom)


class IsotonicCalibrator:
    """Map a raw score to a calibrated P(safe) via isotonic regression."""

    def __init__(self) -> None:
        self._x: list[float] = []
        self._y: list[float] = []

    def fit(self, scores: list[float], labels: list[int]) -> IsotonicCalibrator:
        if not scores:
            return self
        pairs = sorted(zip(scores, labels, strict=True))
        xs = [float(s) for s, _ in pairs]
        ys = [float(y) for _, y in pairs]
        self._x = xs
        self._y = isotonic_regression(ys)
        return self

    def predict(self, score: float) -> float:
        """Calibrated probability at ``score`` (clipped, linearly interpolated)."""
        x, y = self._x, self._y
        if not x:
            return 0.5
        if score <= x[0]:
            return y[0]
        if score >= x[-1]:
            return y[-1]
        i = bisect.bisect_right(x, score)
        x0, x1, y0, y1 = x[i - 1], x[i], y[i - 1], y[i]
        if x1 == x0:
            return y1
        return y0 + (y1 - y0) * (score - x0) / (x1 - x0)


def choose_threshold(
    scores: list[float], labels: list[int], *, target: float = 0.99, z: float = 1.96
) -> float | None:
    """Lowest score T where the Wilson LB of precision on {score >= T} >= target.

    Maximises recall subject to a precision floor. Returns None if no threshold
    meets the floor. Assumes a roughly monotone score->label relationship (the
    point of calibrating a decent ranker); non-monotonicity is why the LB, not
    the point estimate, is the gate.
    """
    if not scores:
        return None
    pairs = sorted(zip(scores, labels, strict=True), reverse=True)  # highest first
    # Evaluate the floor only at DISTINCT score boundaries, where the accumulated
    # set is exactly {score >= s}; tied scores are all in-or-all-out, so a partial
    # tie prefix can't spuriously satisfy the floor.
    k = n = 0
    i = 0
    m = len(pairs)
    best: float | None = None
    while i < m:
        s = pairs[i][0]
        while i < m and pairs[i][0] == s:
            n += 1
            k += int(pairs[i][1])
            i += 1
        if wilson_lower_bound(k, n, z) >= target:
            best = float(s)  # {score >= s} clears the floor -> accept this lower T
    return best
