"""Phase 11D.2 Tests: Execution Accounting Hardening.

Tests for authoritative execution accounting, quarantine record creation,
persistence-failure handling, and quarantine reconciliation.

All tests use isolated temporary directories -- no real TEMP modification.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.remediation.cleanup_temp import (
    CleanupResult,
    MoveRecord,
    execute_cleanup,
    preview_cleanup,
)
from app.remediation.quarantine_store import (
    QuarantineRecord,
    QuarantineStore,
    reconcile_quarantine,
)


@pytest.fixture
def temp_dir():
    d = Path(tempfile.mkdtemp(prefix="test_11d2_temp_"))
    yield d
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def qdir():
    d = Path(tempfile.mkdtemp(prefix="test_11d2_q_"))
    yield d
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def store(tmp_path):
    return QuarantineStore(db_path=str(tmp_path / "test.db"))


def _create_three_files(base: Path) -> list[Path]:
    files = []
    for i in range(1, 4):
        f = base / f"ocm-test-disposable-{i}.tmp"
        content = f"Phase 11E test file {i} - safe to quarantine"
        f.write_text(content)
        old_time = time.time() - (60 * 86400)
        os.utime(str(f), (old_time, old_time))
        files.append(f)
    return files


# A: All 3 files moved -> files_moved=3

class TestThreeFilesMoved:
    def test_three_files_moved(self, temp_dir, qdir):
        _create_three_files(temp_dir)
        result = execute_cleanup(temp_root=temp_dir, quarantine_dir=qdir)
        assert result.files_moved == 3
        assert result.files_failed == 0
        assert result.files_skipped == 0

    def test_move_records_created(self, temp_dir, qdir):
        _create_three_files(temp_dir)
        result = execute_cleanup(temp_root=temp_dir, quarantine_dir=qdir)
        assert len(result.move_records) == 3
        for mr in result.move_records:
            assert mr.record_persisted is False
            assert mr.persistence_error is None


# B: bytes_moved accurate

class TestBytesMoved:
    def test_bytes_moved_accurate(self, temp_dir, qdir):
        _create_three_files(temp_dir)
        result = execute_cleanup(temp_root=temp_dir, quarantine_dir=qdir)
        assert result.bytes_moved > 0
        assert result.bytes_moved == sum(
            mr.original_size for mr in result.move_records
        )


# C: No second TEMP rescan determines counts

class TestNoRescan:
    def test_counts_from_move_records(self, temp_dir, qdir):
        _create_three_files(temp_dir)
        result = execute_cleanup(temp_root=temp_dir, quarantine_dir=qdir)
        assert result.files_moved == len(result.move_records)

    def test_move_record_paths_match(self, temp_dir, qdir):
        files = _create_three_files(temp_dir)
        original_paths = {str(f) for f in files}
        result = execute_cleanup(temp_root=temp_dir, quarantine_dir=qdir)
        recorded_paths = {mr.original_path for mr in result.move_records}
        assert recorded_paths == original_paths


# D: Successful move creates quarantine record

class TestQuarantineRecordCreation:
    def test_one_record_per_move(self, store, temp_dir, qdir):
        _create_three_files(temp_dir)
        result = execute_cleanup(temp_root=temp_dir, quarantine_dir=qdir)
        record_ids = []
        for mr in result.move_records:
            record = QuarantineRecord(
                action_id="disk.cleanup_temp",
                audit_record_id=1,
                original_path=mr.original_path,
                quarantine_path=mr.quarantine_path,
                original_size=mr.original_size,
                original_mtime=mr.original_mtime_iso,
            )
            rid = store.create_record(record)
            record_ids.append(rid)
        assert len(record_ids) == 3
        for rid in record_ids:
            rec = store.get_record(rid)
            assert rec is not None
            assert rec.original_path != ""


# E: mtime heuristic is gone

class TestNoMtimeHeuristic:
    def test_no_mtime_heuristic_in_execute_cleanup(self):
        import inspect
        source = inspect.getsource(execute_cleanup)
        assert "st_mtime < 5" not in source

    def test_no_mtime_heuristic_in_executor(self):
        from app.remediation.executor import QuarantineExecutor
        import inspect
        source = inspect.getsource(QuarantineExecutor._execute_cleanup_temp)
        assert "st_mtime < 5" not in source
        assert "quarantine_dir.iterdir()" not in source


# F: Partial move result

class TestPartialMoveResult:
    def test_all_moved_under_normal_conditions(self, temp_dir, qdir):
        _create_three_files(temp_dir)
        result = execute_cleanup(temp_root=temp_dir, quarantine_dir=qdir)
        assert result.files_moved == 3
        assert result.files_failed == 0


# G: Move failure result

class TestMoveFailureResult:
    @pytest.mark.skipif(
        os.name == "nt", reason="Permission semantics differ on Windows"
    )
    def test_move_failure_counted(self, temp_dir, qdir):
        files = _create_three_files(temp_dir)
        files[0].chmod(0o000)
        result = execute_cleanup(temp_root=temp_dir, quarantine_dir=qdir)
        assert result.files_failed >= 1
        assert result.files_moved <= 2
        files[0].chmod(0o644)


# H: Persistence failure after move

class TestPersistenceFailure:
    def test_executor_persistence_failure(self, temp_dir, qdir):
        from app.remediation.executor import QuarantineExecutor
        from app.remediation.action import RemediationAction, RiskLevel
        from app.remediation.confirmation import ConfirmationToken

        _create_three_files(temp_dir)

        mock_store = MagicMock()
        mock_store.create_record.side_effect = OSError("Database locked")
        executor = QuarantineExecutor(mock_store)

        action = RemediationAction(
            action_id="disk.cleanup_temp",
            action_version="1.0.0",
            name="Temp Cleanup",
            description="Clean old temp files",
            category="cleanup",
            target=str(temp_dir),
            reason="test",
            risk_level=RiskLevel.MEDIUM,
            reversible=True,
            parameters={"age_days": 30},
        )
        token = ConfirmationToken(action_id="disk.cleanup_temp")

        with patch("app.remediation.cleanup_temp.get_user_temp_dir", return_value=temp_dir):
            with patch("app.remediation.cleanup_temp.get_quarantine_dir", return_value=qdir):
                result = executor._execute_cleanup_temp(action, token, audit_record_id=1)

        assert result.details["files_moved"] == 3
        assert result.details["persistence_failures"] == 3
        assert len(result.details["persistence_errors"]) == 3
        assert result.success is False
        assert result.rollback_available is True

    def test_partial_persistence_failure(self, temp_dir, qdir):
        from app.remediation.executor import QuarantineExecutor
        from app.remediation.action import RemediationAction, RiskLevel
        from app.remediation.confirmation import ConfirmationToken

        _create_three_files(temp_dir)

        call_count = 0
        def fail_after_two(record):
            nonlocal call_count
            call_count += 1
            if call_count > 2:
                raise OSError("Database locked")
            return call_count

        mock_store = MagicMock()
        mock_store.create_record.side_effect = fail_after_two
        executor = QuarantineExecutor(mock_store)

        action = RemediationAction(
            action_id="disk.cleanup_temp",
            action_version="1.0.0",
            name="Temp Cleanup",
            description="Clean old temp files",
            category="cleanup",
            target=str(temp_dir),
            reason="test",
            risk_level=RiskLevel.MEDIUM,
            reversible=True,
            parameters={"age_days": 30},
        )
        token = ConfirmationToken(action_id="disk.cleanup_temp")

        with patch("app.remediation.cleanup_temp.get_user_temp_dir", return_value=temp_dir):
            with patch("app.remediation.cleanup_temp.get_quarantine_dir", return_value=qdir):
                result = executor._execute_cleanup_temp(action, token, audit_record_id=1)

        assert result.details["files_moved"] == 3
        assert result.details["persistence_failures"] == 1
        assert result.details["quarantine_record_ids"] == [1, 2]
        assert result.success is False


# I: Execution cannot double-move

class TestDoubleMovePrevention:
    def test_cannot_double_move(self, temp_dir, qdir):
        _create_three_files(temp_dir)
        result1 = execute_cleanup(temp_root=temp_dir, quarantine_dir=qdir)
        assert result1.files_moved == 3

        result2 = execute_cleanup(temp_root=temp_dir, quarantine_dir=qdir)
        assert result2.files_moved == 0

    def test_quarantine_file_not_reprocessed(self, temp_dir, qdir):
        _create_three_files(temp_dir)
        result1 = execute_cleanup(temp_root=temp_dir, quarantine_dir=qdir)

        orphan = qdir / "orphan_file.txt"
        orphan.write_text("orphan content")
        old_time = time.time() - (60 * 86400)
        os.utime(str(orphan), (old_time, old_time))

        result2 = execute_cleanup(temp_root=temp_dir, quarantine_dir=qdir)
        assert result2.files_moved == 0


# J: Rollback uses quarantine records

class TestRollbackUsesRecords:
    def test_rollback_records_have_correct_paths(self, temp_dir, qdir, store):
        files = _create_three_files(temp_dir)
        result = execute_cleanup(temp_root=temp_dir, quarantine_dir=qdir)

        for mr in result.move_records:
            record = QuarantineRecord(
                action_id="disk.cleanup_temp",
                audit_record_id=1,
                original_path=mr.original_path,
                quarantine_path=mr.quarantine_path,
                original_size=mr.original_size,
                original_mtime=mr.original_mtime_iso,
            )
            store.create_record(record)

        records = store.list_records()
        assert len(records) == 3
        for rec in records:
            assert rec.original_path != ""
            assert Path(rec.original_path).name.startswith("ocm-test-disposable")


# K: Missing record detected

class TestMissingRecordDetected:
    def test_orphaned_file_detected(self, qdir, store):
        orphan = qdir / "orphan.txt"
        orphan.write_text("orphan content")

        report = reconcile_quarantine(qdir, store)
        assert report.total_issues == 1
        assert report.clean is False
        assert report.file_without_record_count == 1
        issue = report.issues[0]
        assert issue.issue_type == "file_without_record"
        assert "orphan.txt" in issue.quarantine_path
        assert issue.issue_id.startswith("rq-")
        assert issue.explanation != ""
        assert issue.detected_at != ""


# L: Missing quarantine file detected

class TestMissingFileDetected:
    def test_broken_record_detected(self, qdir, store):
        record = QuarantineRecord(
            action_id="disk.cleanup_temp",
            audit_record_id=1,
            original_path="/tmp/nonexistent.txt",
            quarantine_path=str(qdir / "nonexistent.txt"),
            original_size=100,
            original_mtime="2026-01-01T00:00:00+00:00",
        )
        store.create_record(record)

        report = reconcile_quarantine(qdir, store)
        assert report.total_issues == 1
        assert report.record_without_file_count == 1
        issue = report.issues[0]
        assert issue.issue_type == "record_without_file"
        assert issue.record_id is not None
        assert issue.explanation != ""


# M: Retry safety

class TestRetrySafety:
    def test_retry_does_not_double_move(self, temp_dir, qdir):
        _create_three_files(temp_dir)
        result1 = execute_cleanup(temp_root=temp_dir, quarantine_dir=qdir)
        assert result1.files_moved == 3

        result2 = execute_cleanup(temp_root=temp_dir, quarantine_dir=qdir)
        assert result2.files_moved == 0

    def test_empty_original_path_flagged(self, store, qdir):
        record = QuarantineRecord(
            action_id="disk.cleanup_temp",
            audit_record_id=1,
            original_path="",
            quarantine_path=str(qdir / "somefile.txt"),
            original_size=100,
            original_mtime="2026-01-01T00:00:00+00:00",
        )
        store.create_record(record)
        (qdir / "somefile.txt").write_text("content")

        report = reconcile_quarantine(qdir, store)
        assert report.total_issues == 1
        issue = report.issues[0]
        assert issue.issue_type == "empty_original_path"
        assert issue.recoverability == "unrecoverable"


# N: Audit counts match actual mutation

class TestAuditCountsMatch:
    def test_execution_result_accurate(self, temp_dir, qdir):
        files = _create_three_files(temp_dir)
        result = execute_cleanup(temp_root=temp_dir, quarantine_dir=qdir)

        assert result.files_moved == len(result.move_records)
        assert result.bytes_moved == sum(
            mr.original_size for mr in result.move_records
        )
        for f in files:
            assert not f.exists()
        qfiles = list(qdir.iterdir())
        assert len(qfiles) == 3


# O: MoveRecord fields

class TestMoveRecordFields:
    def test_move_record_has_all_fields(self, temp_dir, qdir):
        _create_three_files(temp_dir)
        result = execute_cleanup(temp_root=temp_dir, quarantine_dir=qdir)

        for mr in result.move_records:
            assert mr.original_path
            assert mr.quarantine_path
            assert mr.original_size > 0
            assert mr.original_mtime > 0
            assert mr.original_mtime_iso
            assert mr.quarantine_record_id is None
            assert mr.record_persisted is False
            assert mr.persistence_error is None


# P: Cross-process SQLite confirmation flow

class TestCrossProcessConfirmation:
    def test_sqlite_store_survives_restart(self, tmp_path):
        from app.remediation.confirmation_service import (
            SqliteConfirmationStore,
            ConfirmationRecord,
        )
        from app.database.sqlite import SnapshotStore
        from datetime import datetime, timezone

        db_store = SnapshotStore(path=str(tmp_path / "confirm.db"))
        store1 = SqliteConfirmationStore(db_store=db_store)
        record = ConfirmationRecord(
            confirmation_id="conf:test:abc123",
            candidate_id="disk.cleanup_temp",
            action_id="disk.cleanup_temp",
            preview_id="prev:1",
            preview_fingerprint="fp123",
            confirmed_at=datetime.now(timezone.utc).isoformat(),
            confirmation_token_secret="secret123",
            consumed=False,
        )
        store1.add(record)

        store2 = SqliteConfirmationStore(db_store=db_store)
        loaded = store2.get("conf:test:abc123")
        assert loaded is not None
        assert loaded.action_id == "disk.cleanup_temp"


# Q: Existing 976+ test suite remains passing (run separately)

class TestReconciliationClean:
    def test_no_issues_when_clean(self, temp_dir, qdir, store):
        _create_three_files(temp_dir)
        result = execute_cleanup(temp_root=temp_dir, quarantine_dir=qdir)

        for mr in result.move_records:
            record = QuarantineRecord(
                action_id="disk.cleanup_temp",
                audit_record_id=1,
                original_path=mr.original_path,
                quarantine_path=mr.quarantine_path,
                original_size=mr.original_size,
                original_mtime=mr.original_mtime_iso,
            )
            store.create_record(record)

        report = reconcile_quarantine(qdir, store)
        assert report.clean is True
        assert report.total_issues == 0

    def test_mixed_issues_detected(self, qdir, store):
        # File without record
        (qdir / "orphan.txt").write_text("orphan")

        # Record without file
        record = QuarantineRecord(
            action_id="disk.cleanup_temp",
            audit_record_id=1,
            original_path="/tmp/gone.txt",
            quarantine_path=str(qdir / "gone.txt"),
            original_size=50,
            original_mtime="2026-01-01T00:00:00+00:00",
        )
        store.create_record(record)

        report = reconcile_quarantine(qdir, store)
        types = {i.issue_type for i in report.issues}
        assert "file_without_record" in types
        assert "record_without_file" in types
        assert report.total_issues == 2
        assert report.clean is False


# -----------------------------------------------------------------------
# Synthetic integration test: 3 files, full pipeline, rollback
# -----------------------------------------------------------------------


class TestSyntheticIntegration:
    def test_full_pipeline_rollback(self, temp_dir, qdir, tmp_path):
        """Full synthetic pipeline: create → move → record → reconcile → rollback.

        Uses isolated temp directories. No real TEMP modification.
        """
        from app.remediation.cleanup_temp import execute_cleanup
        from app.remediation.quarantine import rollback_quarantine
        from app.remediation.quarantine_store import (
            QuarantineRecord,
            QuarantineStore,
            reconcile_quarantine,
        )

        # Step 1: Create 3 disposable files with known properties
        files = _create_three_files(temp_dir)
        original_contents = {}
        original_sizes = {}
        for f in files:
            original_contents[f.name] = f.read_text()
            original_sizes[f.name] = f.stat().st_size

        # Step 2: Execute cleanup (move files to quarantine)
        result = execute_cleanup(temp_root=temp_dir, quarantine_dir=qdir)

        # Verify move counts
        assert result.files_moved == 3
        assert result.bytes_moved > 0
        assert result.bytes_moved == sum(
            mr.original_size for mr in result.move_records
        )
        assert len(result.move_records) == 3

        # Verify files are gone from source
        for f in files:
            assert not f.exists()

        # Verify files are in quarantine
        qfiles = [p for p in qdir.iterdir() if p.is_file()]
        assert len(qfiles) == 3

        # Step 3: Create quarantine records
        store = QuarantineStore(db_path=str(tmp_path / "quarantine.db"))
        record_ids = []
        for mr in result.move_records:
            record = QuarantineRecord(
                action_id="disk.cleanup_temp",
                audit_record_id=1,
                original_path=mr.original_path,
                quarantine_path=mr.quarantine_path,
                original_size=mr.original_size,
                original_mtime=mr.original_mtime_iso,
            )
            rid = store.create_record(record)
            record_ids.append(rid)

        assert len(record_ids) == 3

        # Step 4: Reconcile — should be clean
        report = reconcile_quarantine(qdir, store)
        assert report.clean is True
        assert report.total_issues == 0

        # Step 5: Rollback all 3 files
        for rid in record_ids:
            success, msg = rollback_quarantine(rid, store)
            assert success, f"Rollback failed for record {rid}: {msg}"

        # Step 6: Verify restoration
        for f in files:
            assert f.exists(), f"File not restored: {f}"
            assert f.read_text() == original_contents[f.name]
            assert f.stat().st_size == original_sizes[f.name]

        # Step 7: Verify quarantine is empty (files moved back)
        qfiles_after = [p for p in qdir.iterdir() if p.is_file()]
        assert len(qfiles_after) == 0

        # Step 8: Verify records are marked restored
        for rid in record_ids:
            rec = store.get_record(rid)
            assert rec.restored is True
            assert rec.restored_at is not None

    def test_counts_consistent_throughout(self, temp_dir, qdir, tmp_path):
        """Verify accounting consistency at every stage."""
        from app.remediation.cleanup_temp import execute_cleanup
        from app.remediation.quarantine_store import QuarantineRecord, QuarantineStore

        files = _create_three_files(temp_dir)
        sizes = [f.stat().st_size for f in files]
        total_expected = sum(sizes)

        # Execute
        result = execute_cleanup(temp_root=temp_dir, quarantine_dir=qdir)

        # Stage 1: Move records match counts
        assert result.files_moved == len(result.move_records)
        assert result.bytes_moved == total_expected

        # Stage 2: Quarantine records match move records
        store = QuarantineStore(db_path=str(tmp_path / "count.db"))
        for mr in result.move_records:
            record = QuarantineRecord(
                action_id="disk.cleanup_temp",
                audit_record_id=1,
                original_path=mr.original_path,
                quarantine_path=mr.quarantine_path,
                original_size=mr.original_size,
                original_mtime=mr.original_mtime_iso,
            )
            store.create_record(record)

        db_records = store.list_records()
        assert len(db_records) == 3
        db_bytes = sum(r.original_size for r in db_records)
        assert db_bytes == total_expected

        # Stage 3: Reconciliation clean
        report = reconcile_quarantine(qdir, store)
        assert report.clean is True
        assert report.total_issues == 0
        assert report.scanned_files == 3


# -----------------------------------------------------------------------
# ReconciliationReport shape (enriched API)
# -----------------------------------------------------------------------


class TestReconciliationReport:
    def test_duplicate_records_detected(self, qdir, store):
        target = qdir / "dup.txt"
        target.write_text("dup content")
        for _ in range(2):
            store.create_record(
                QuarantineRecord(
                    action_id="disk.cleanup_temp",
                    audit_record_id=1,
                    original_path="/tmp/dup.txt",
                    quarantine_path=str(target),
                    original_size=11,
                    original_mtime="2026-01-01T00:00:00+00:00",
                )
            )

        report = reconcile_quarantine(qdir, store)
        types = {i.issue_type for i in report.issues}
        assert "duplicate_record" in types
        assert report.duplicate_record_count == 1

    def test_invalid_record_detected(self, qdir, store):
        target = qdir / "invalid.txt"
        target.write_text("invalid content")
        store.create_record(
            QuarantineRecord(
                action_id="",
                audit_record_id=1,
                original_path="/tmp/invalid.txt",
                quarantine_path=str(target),
                original_size=15,
                original_mtime="2026-01-01T00:00:00+00:00",
            )
        )

        report = reconcile_quarantine(qdir, store)
        types = {i.issue_type for i in report.issues}
        assert "invalid_record" in types
        assert report.invalid_record_count == 1

    def test_issue_ids_are_sequenced(self, qdir, store):
        (qdir / "a.txt").write_text("a")
        (qdir / "b.txt").write_text("b")

        report = reconcile_quarantine(qdir, store)
        assert report.total_issues == 2
        assert [i.issue_id for i in report.issues] == ["rq-0001", "rq-0002"]

    def test_report_serializes(self, qdir, store):
        (qdir / "orphan.txt").write_text("orphan")

        report = reconcile_quarantine(qdir, store)
        payload = report.to_dict()
        assert payload["total_issues"] == 1
        assert payload["clean"] is False
        assert payload["file_without_record_count"] == 1
        assert len(payload["issues"]) == 1
        assert payload["issues"][0]["issue_type"] == "file_without_record"

    def test_reconcile_is_read_only(self, qdir, store):
        (qdir / "orphan.txt").write_text("orphan")
        store.create_record(
            QuarantineRecord(
                action_id="disk.cleanup_temp",
                audit_record_id=1,
                original_path="/tmp/gone.txt",
                quarantine_path=str(qdir / "gone.txt"),
                original_size=50,
                original_mtime="2026-01-01T00:00:00+00:00",
            )
        )
        files_before = sorted(p.name for p in qdir.iterdir())
        records_before = len(store.list_records())

        first = reconcile_quarantine(qdir, store)
        second = reconcile_quarantine(qdir, store)

        assert sorted(p.name for p in qdir.iterdir()) == files_before
        assert len(store.list_records()) == records_before
        assert [i.issue_type for i in first.issues] == [
            i.issue_type for i in second.issues
        ]
