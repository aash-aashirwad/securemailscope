"""Performance benchmark (SIH upgrade #7). Excluded from the default
`pytest` run via the `benchmark` marker (see pytest.ini's addopts) since
it's meaningfully slower than a unit test — run explicitly with:
    pytest -m benchmark -q -s
"""
import pytest
from scripts.benchmark import run_benchmark


@pytest.mark.benchmark
def test_analysis_pipeline_scales_and_completes_within_budget():
    """Not a strict perf-regression gate (CI hardware varies too much for
    a tight threshold to be meaningful) -- asserts the pipeline actually
    completes and recovers every session at each size, and prints real
    timing/memory numbers so a human can eyeball scaling behavior."""
    results = run_benchmark(session_counts=(10, 100))
    for r in results:
        assert r["sessions_recovered"] == r["sessions_requested"]
        assert r["elapsed_seconds"] < 30, f"analysis took too long: {r}"
        print(r)
