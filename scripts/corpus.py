"""Score firstsignal against the labelled regression corpus.

    python scripts/corpus.py                 # score tests/corpus, compare with stored snapshots
    python scripts/corpus.py --snapshot      # store current results as the snapshots (review the diff!)
    python scripts/corpus.py --dir PATH      # score a held-out corpus kept outside the repo

Each case is a folder with case.json and logs/. "truth" is what a careful engineer concludes from the
logs; it is never generated from firstsignal's output. "snapshot" is what firstsignal reports today.
Accuracy compares the two; the regression test fails whenever the snapshot changes.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import sys
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CORPUS = ROOT / "tests" / "corpus"
sys.path.insert(0, str(ROOT))

from firstsignal import cli  # noqa: E402


@dataclass
class Result:
    name: str
    truth: set[str]
    truth_first: str | None
    found: dict[str, int]
    first: str | None
    severity: str
    leaks: list[str] = field(default_factory=list)

    @property
    def true_positives(self) -> set[str]:
        return self.truth & set(self.found)

    @property
    def false_positives(self) -> set[str]:
        return set(self.found) - self.truth

    @property
    def misses(self) -> set[str]:
        return self.truth - set(self.found)

    @property
    def first_ok(self) -> bool:
        return self.first == self.truth_first

    def snapshot(self) -> dict:
        return {"findings": dict(sorted(self.found.items())), "first": self.first, "severity": self.severity}


def cases(corpus: Path) -> list[Path]:
    return sorted(p.parent for p in corpus.glob("*/case.json"))


def run_case(case_dir: Path, workdir: Path) -> Result:
    meta = json.loads((case_dir / "case.json").read_text(encoding="utf-8"))
    logs = case_dir / "logs"
    common = ["--json", "--no-write", "--no-history", "--packs", ",".join(meta.get("packs", ["all"]))]
    if meta.get("mode") == "archive":
        bundle = workdir / f"{case_dir.name}.zip"
        with zipfile.ZipFile(bundle, "w", zipfile.ZIP_DEFLATED) as z:
            for f in sorted(p for p in logs.rglob("*") if p.is_file()):
                z.write(f, f.relative_to(logs).as_posix())
        argv = ["archive", str(bundle), *common]
    else:
        (only,) = [p for p in logs.iterdir() if p.is_file()]
        argv = ["file", "--path", str(only), *common]
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        code = cli.run(argv)
    if code not in (cli.EXIT_OK, cli.EXIT_THRESHOLD):
        raise RuntimeError(f"{case_dir.name}: firstsignal exited {code}")
    text = out.getvalue()
    report = json.loads(text)
    order = report["order_of_first_appearance"]
    return Result(
        name=case_dir.name,
        truth=set(meta["truth"]["findings"]),
        truth_first=meta["truth"]["first"],
        found={k: v["count"] for k, v in report["findings"].items()},
        first=order[0] if order else None,
        severity=report["severity"],
        leaks=[s for s in meta.get("must_not_leak", []) if s in text],
    )


def run_all(corpus: Path) -> list[Result]:
    with tempfile.TemporaryDirectory() as tmp:
        return [run_case(c, Path(tmp)) for c in cases(corpus)]


def summary(results: list[Result]) -> dict:
    tp = sum(len(r.true_positives) for r in results)
    fp = sum(len(r.false_positives) for r in results)
    fn = sum(len(r.misses) for r in results)
    return {
        "cases": len(results),
        "precision": tp / (tp + fp) if tp + fp else 1.0,
        "recall": tp / (tp + fn) if tp + fn else 1.0,
        "first_correct": sum(r.first_ok for r in results),
        "false_positives": fp,
        "misses": fn,
        "leaks": sum(len(r.leaks) for r in results),
    }


def report(results: list[Result]) -> str:
    lines = ["| Case | Expected | Found | False positives | Missed | First finding |", "|---|---:|---:|---|---|---|"]
    for r in results:
        first = "✓" if r.first_ok else f"✗ `{r.first}` (expected `{r.truth_first}`)"
        lines.append(f"| {r.name} | {len(r.truth)} | {len(r.true_positives)} "
                     f"| {', '.join(f'`{k}`' for k in sorted(r.false_positives)) or '–'} "
                     f"| {', '.join(f'`{k}`' for k in sorted(r.misses)) or '–'} | {first} |")
    s = summary(results)
    lines += ["", f"Precision {s['precision']:.0%}, recall {s['recall']:.0%}, first finding right in "
                  f"{s['first_correct']} of {s['cases']} cases, {s['leaks']} secret leaks."]
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--dir", type=Path, default=DEFAULT_CORPUS, help="corpus folder (default: tests/corpus)")
    ap.add_argument("--snapshot", action="store_true", help="store current results as each case's snapshot")
    args = ap.parse_args(argv)
    results = run_all(args.dir)
    if args.snapshot:
        for r in results:
            path = args.dir / r.name / "case.json"
            meta = json.loads(path.read_text(encoding="utf-8"))
            meta["snapshot"] = r.snapshot()
            path.write_text(json.dumps(meta, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(report(results))
    return 1 if summary(results)["leaks"] else 0


if __name__ == "__main__":
    sys.exit(main())
