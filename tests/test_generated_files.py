"""The committed samples, captures, queries and coverage document match what the code builds."""

from detlab import build
from detlab.rules import ROOT


def test_generated_files_are_current():
    problems = build.stale(build.generated_files())
    assert not problems, "run `python -m detlab build`:\n" + "\n".join(problems)


def test_a_changed_file_is_reported(tmp_path, monkeypatch):
    target = tmp_path / "converted" / "eql" / "demo.eql"
    files = {target: b"any where true\n"}
    monkeypatch.setattr(build, "ROOT", tmp_path)
    monkeypatch.setattr(build, "GENERATED_DIRS", {target.parent: ".eql"})
    assert build.stale(files) == ["converted/eql/demo.eql: missing"]
    assert build.write(files) == [target]
    assert build.stale(files) == []
    target.write_bytes(b"something else\n")
    assert build.stale(files) == ["converted/eql/demo.eql: out of date"]
    (target.parent / "old.eql").write_bytes(b"left over\n")
    assert "converted/eql/old.eql: no longer generated" in build.stale(files)
    build.write(files)
    assert build.stale(files) == []
    assert not (target.parent / "old.eql").exists()


def test_events_are_one_json_document_per_line():
    for name in ("attack.ndjson", "benign.ndjson"):
        lines = (build.EVENTS_DIR / name).read_text(encoding="utf-8").splitlines()
        assert lines and all(line.startswith('{"@timestamp"') for line in lines)


def test_generated_paths_stay_inside_the_repository():
    for path in build.generated_files():
        assert ROOT in path.parents
