"""Isotonic calibration, Wilson lower bound, and precision-floor thresholding."""

from __future__ import annotations

from exa.aillm.calibration import (
    IsotonicCalibrator,
    choose_threshold,
    isotonic_regression,
    wilson_lower_bound,
)


def _monotone(xs):
    return all(b >= a - 1e-9 for a, b in zip(xs, xs[1:]))


def test_isotonic_already_monotone_unchanged():
    assert isotonic_regression([1.0, 2.0, 3.0]) == [1.0, 2.0, 3.0]


def test_isotonic_pools_violators():
    # 3,1,2 -> all pooled to the mean 2.0
    out = isotonic_regression([3.0, 1.0, 2.0])
    assert out == [2.0, 2.0, 2.0]
    assert _monotone(out)


def test_isotonic_partial_pool_and_mean_preserving():
    out = isotonic_regression([0.0, 0.0, 1.0, 0.0, 1.0, 1.0])
    assert _monotone(out)
    # PAVA preserves the total sum (weighted mean)
    assert abs(sum(out) - 3.0) < 1e-9


def test_wilson_lower_bound_bounds():
    assert wilson_lower_bound(0, 0) == 0.0
    assert wilson_lower_bound(0, 10) == 0.0
    # more successes -> higher lower bound
    assert wilson_lower_bound(9, 10) > wilson_lower_bound(5, 10)
    # a perfect small sample is still uncertain (not 1.0)
    assert 0.0 < wilson_lower_bound(1, 1) < 0.5


def test_calibrator_is_monotone_and_clipped():
    scores = [i / 10 for i in range(1, 10)]
    labels = [0, 0, 0, 1, 0, 1, 1, 1, 1]
    cal = IsotonicCalibrator().fit(scores, labels)
    grid = [i / 100 for i in range(0, 101)]
    preds = [cal.predict(x) for x in grid]
    assert _monotone(preds)
    assert cal.predict(-1.0) == preds[0] == cal.predict(0.0)
    assert cal.predict(2.0) == preds[-1]


def test_choose_threshold_meets_precision_floor():
    scores = [0.9] * 20 + [0.1] * 5
    labels = [1] * 20 + [0] * 5
    t = choose_threshold(scores, labels, target=0.7)
    assert t == 0.9  # the clean high-score band clears the floor; the negatives don't


def test_choose_threshold_none_when_floor_unreachable():
    # tiny sample can't guarantee a 0.99 precision floor
    assert choose_threshold([0.9, 0.8], [1, 1], target=0.99) is None
