"""Regression corpus (#17): results on labelled samples must not change without review.

If this fails after a deliberate change, look at the diff, then accept it with
`python scripts/corpus.py --snapshot` and commit the updated case.json files.
"""

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("corpus", ROOT / "scripts" / "corpus.py")
corpus = importlib.util.module_from_spec(_spec)
sys.modules["corpus"] = corpus   # dataclasses look the module up while the class is created
_spec.loader.exec_module(corpus)

CASES = corpus.cases(corpus.DEFAULT_CORPUS)


def test_corpus_has_cases():
    assert len(CASES) >= 10


@pytest.mark.parametrize("case_dir", CASES, ids=[c.name for c in CASES])
def test_case_matches_its_snapshot(case_dir, tmp_path):
    meta = json.loads((case_dir / "case.json").read_text(encoding="utf-8"))
    result = corpus.run_case(case_dir, tmp_path)
    assert result.leaks == [], f"secrets leaked: {result.leaks}"
    assert "snapshot" in meta, "new case: run `python scripts/corpus.py --snapshot`"
    assert result.snapshot() == meta["snapshot"], (
        "results changed on the corpus; review, then run `python scripts/corpus.py --snapshot`")


@pytest.mark.parametrize("case_dir", CASES, ids=[c.name for c in CASES])
def test_labels_use_known_patterns(case_dir):
    from firstsignal.patterns import resolve_packs

    keys = {p.key for p in resolve_packs(["all"])}
    truth = json.loads((case_dir / "case.json").read_text(encoding="utf-8"))["truth"]
    assert set(truth["findings"]) <= keys
    assert truth["first"] is None or truth["first"] in truth["findings"]
