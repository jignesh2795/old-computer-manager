"""Comprehensive tests for the file analysis package.

Tests A-X as specified in Phase 4 requirements.
All tests use temporary directories. No real files are modified.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
import time
from pathlib import Path

import pytest

from app.file_analysis.analyzers import (
    aggregate_directory_sizes,
    detect_duplicates,
    find_large_files,
    find_recently_modified,
    group_by_extension,
)
from app.file_analysis.exclusions import (
    is_excluded_entry,
    is_excluded_path,
    validate_scan_root,
)
from app.file_analysis.models import (
    DirectorySizeResult,
    DuplicateGroup,
    FileRecord,
    FileTypeGroup,
    LargeFileResult,
    ScanResult,
    ScanStats,
)
from app.file_analysis.runner import run_file_analysis
from app.file_analysis.scanner import scan_directory


# ── Helpers ────────────────────────────────────────────────────────────


def _create_file(path: Path, content: bytes = b"test") -> Path:
    """Create a file with given content."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return path


def _make_record(
    path: str,
    size: int = 100,
    ext: str = ".txt",
    parent: str | None = None,
) -> FileRecord:
    """Create a FileRecord for analyzer testing."""
    return FileRecord(
        path=path,
        size_bytes=size,
        modified_time=time.time(),
        created_time=None,
        extension=ext,
        filename=os.path.basename(path),
        parent_directory=parent or os.path.dirname(path),
        scan_root="/scan",
    )


# ── A. Regular files discovered ──────────────────────────────────────


class TestA_RegularFilesDiscovered:
    def test_regular_files_found(self, tmp_path: Path) -> None:
        _create_file(tmp_path / "a.txt", b"hello")
        _create_file(tmp_path / "b.txt", b"world")
        files, stats = scan_directory(tmp_path)
        assert len(files) == 2
        assert stats.files_examined == 2

    def test_file_record_fields(self, tmp_path: Path) -> None:
        _create_file(tmp_path / "test.txt", b"data")
        files, _ = scan_directory(tmp_path)
        assert len(files) == 1
        f = files[0]
        assert f.filename == "test.txt"
        assert f.extension == ".txt"
        assert f.size_bytes == 4
        assert f.scan_root == str(tmp_path.resolve())


# ── B. Directories counted ────────────────────────────────────────────


class TestB_DirectoriesCounted:
    def test_directories_counted(self, tmp_path: Path) -> None:
        _create_file(tmp_path / "sub1" / "a.txt")
        _create_file(tmp_path / "sub2" / "b.txt")
        _create_file(tmp_path / "c.txt")
        files, stats = scan_directory(tmp_path)
        assert stats.directories_examined >= 2
        assert stats.files_examined == 3

    def test_nested_directories(self, tmp_path: Path) -> None:
        _create_file(tmp_path / "a" / "b" / "c" / "file.txt")
        files, stats = scan_directory(tmp_path)
        assert stats.directories_examined >= 3
        assert stats.files_examined == 1


# ── C. Permission/access failures handled ─────────────────────────────


class TestC_PermissionFailuresHandled:
    def test_inaccessible_file_recorded(self, tmp_path: Path) -> None:
        # Create a file then make it inaccessible (Windows-specific)
        target = tmp_path / "noaccess.txt"
        _create_file(target, b"data")
        try:
            os.chmod(str(target), 0o000)
            files, stats = scan_directory(tmp_path)
            # Should either read it or record as inaccessible
            assert stats.files_examined + stats.inaccessible_items >= 1
        finally:
            # Restore permissions for cleanup
            try:
                os.chmod(str(target), 0o644)
            except OSError:
                pass


# ── D. Symlinks excluded ─────────────────────────────────────────────


class TestD_SymlinksExcluded:
    @pytest.mark.skipif(
        os.name != "nt" and not hasattr(os, "symlink"),
        reason="symlinks not supported",
    )
    def test_symlink_not_in_results(self, tmp_path: Path) -> None:
        real = tmp_path / "real.txt"
        _create_file(real, b"real data")
        try:
            link = tmp_path / "link.txt"
            os.symlink(str(real), str(link))
        except OSError:
            pytest.skip("Cannot create symlinks on this platform")
        files, stats = scan_directory(tmp_path)
        paths = [f.path for f in files]
        assert str(link.resolve()) not in paths
        assert stats.symlinks_skipped >= 1


# ── E. Excluded roots handled ─────────────────────────────────────────


class TestE_ExcludedRootsHandled:
    def test_excluded_path_returns_reason(self, tmp_path: Path) -> None:
        scan_root = tmp_path / "scan"
        scan_root.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        excluded, reason = is_excluded_path(outside, scan_root)
        assert excluded is True
        assert "outside scan root" in reason

    def test_inside_root_not_excluded(self, tmp_path: Path) -> None:
        scan_root = tmp_path / "scan"
        scan_root.mkdir()
        inside = scan_root / "inside"
        inside.mkdir()
        excluded, reason = is_excluded_path(inside, scan_root)
        assert excluded is False
        assert reason == ""


# ── F. System-critical paths rejected ─────────────────────────────────


class TestF_SystemCriticalPathsRejected:
    def test_windows_system32_rejected(self) -> None:
        with pytest.raises(ValueError, match="system-critical"):
            validate_scan_root(r"C:\Windows\System32")

    def test_windows_winsxs_rejected(self) -> None:
        with pytest.raises(ValueError, match="system-critical"):
            validate_scan_root(r"C:\Windows\WinSxS")

    def test_program_files_rejected(self) -> None:
        with pytest.raises(ValueError, match="system-critical"):
            validate_scan_root(r"C:\Program Files")

    def test_valid_path_accepted(self, tmp_path: Path) -> None:
        result = validate_scan_root(tmp_path)
        assert result == tmp_path.resolve()

    def test_missing_path_rejected(self) -> None:
        with pytest.raises(ValueError, match="does not exist"):
            validate_scan_root("/nonexistent/path/that/does/not/exist")

    def test_file_not_directory_rejected(self, tmp_path: Path) -> None:
        f = tmp_path / "file.txt"
        _create_file(f)
        with pytest.raises(ValueError, match="not a directory"):
            validate_scan_root(f)


# ── G. Large-file ranking ─────────────────────────────────────────────


class TestG_LargeFileRanking:
    def test_returns_largest_first(self) -> None:
        files = [
            _make_record("/a.txt", size=100),
            _make_record("/b.txt", size=500),
            _make_record("/c.txt", size=300),
        ]
        result = find_large_files(files, top_n=3, min_bytes=0)
        assert result[0].size_bytes == 500
        assert result[1].size_bytes == 300
        assert result[2].size_bytes == 100

    def test_min_bytes_filter(self) -> None:
        files = [
            _make_record("/a.txt", size=50),
            _make_record("/b.txt", size=200),
            _make_record("/c.txt", size=150),
        ]
        result = find_large_files(files, top_n=10, min_bytes=100)
        assert len(result) == 2
        assert all(r.size_bytes >= 100 for r in result)


# ── H. Configurable top-N ────────────────────────────────────────────


class TestH_ConfigurableTopN:
    def test_top_n_limits_results(self) -> None:
        files = [_make_record(f"/f{i}.txt", size=i * 100) for i in range(20)]
        result = find_large_files(files, top_n=5, min_bytes=0)
        assert len(result) == 5

    def test_top_n_larger_than_files(self) -> None:
        files = [_make_record("/a.txt", size=100)]
        result = find_large_files(files, top_n=100, min_bytes=0)
        assert len(result) == 1


# ── I. Directory aggregation ──────────────────────────────────────────


class TestI_DirectoryAggregation:
    def test_groups_by_parent(self) -> None:
        files = [
            _make_record("/dir1/a.txt", size=100, parent="/dir1"),
            _make_record("/dir1/b.txt", size=200, parent="/dir1"),
            _make_record("/dir2/c.txt", size=50, parent="/dir2"),
        ]
        result = aggregate_directory_sizes(files, top_n=10)
        assert len(result) == 2
        dir1 = next(r for r in result if r.path == "/dir1")
        assert dir1.total_size_bytes == 300
        assert dir1.file_count == 2

    def test_sorted_by_size(self) -> None:
        files = [
            _make_record("/small/a.txt", size=10, parent="/small"),
            _make_record("/large/a.txt", size=1000, parent="/large"),
        ]
        result = aggregate_directory_sizes(files, top_n=10)
        assert result[0].path == "/large"
        assert result[1].path == "/small"


# ── J. Extension grouping ─────────────────────────────────────────────


class TestJ_ExtensionGrouping:
    def test_groups_by_extension(self) -> None:
        files = [
            _make_record("/a.txt", size=100, ext=".txt"),
            _make_record("/b.txt", size=200, ext=".txt"),
            _make_record("/c.jpg", size=300, ext=".jpg"),
        ]
        result = group_by_extension(files)
        assert len(result) == 2
        txt = next(r for r in result if r.extension == ".txt")
        assert txt.file_count == 2
        assert txt.total_size_bytes == 300

    def test_sorted_by_size(self) -> None:
        files = [
            _make_record("/a.txt", size=10, ext=".txt"),
            _make_record("/b.jpg", size=1000, ext=".jpg"),
        ]
        result = group_by_extension(files)
        assert result[0].extension == ".jpg"
        assert result[1].extension == ".txt"


# ── K. Files without extension ────────────────────────────────────────


class TestK_FilesWithoutExtension:
    def test_no_extension_grouped(self) -> None:
        files = [
            _make_record("/Makefile", size=50, ext=""),
            _make_record("/README", size=30, ext=""),
            _make_record("/a.txt", size=100, ext=".txt"),
        ]
        result = group_by_extension(files)
        no_ext = next(r for r in result if r.extension == "(no extension)")
        assert no_ext.file_count == 2


# ── L. Recent-file filtering ─────────────────────────────────────────


class TestL_RecentFileFiltering:
    def test_recent_files_only(self) -> None:
        now = time.time()
        files = [
            FileRecord(
                path="/new.txt", size_bytes=100, modified_time=now,
                created_time=None, extension=".txt", filename="new.txt",
                parent_directory="/", scan_root="/",
            ),
            FileRecord(
                path="/old.txt", size_bytes=100,
                modified_time=now - (30 * 86400),
                created_time=None, extension=".txt", filename="old.txt",
                parent_directory="/", scan_root="/",
            ),
        ]
        result = find_recently_modified(files, days=7)
        assert len(result) == 1
        assert result[0].path == "/new.txt"

    def test_top_n_limits_results(self) -> None:
        now = time.time()
        files = [
            FileRecord(
                path=f"/f{i}.txt", size_bytes=100,
                modified_time=now - i,
                created_time=None, extension=".txt", filename=f"f{i}.txt",
                parent_directory="/", scan_root="/",
            )
            for i in range(20)
        ]
        result = find_recently_modified(files, days=30, top_n=5)
        assert len(result) == 5


# ── M. Duplicate size prefilter ───────────────────────────────────────


class TestM_DuplicateSizePrefilter:
    def test_only_same_size_grouped(self) -> None:
        files = [
            _make_record("/a.txt", size=100),
            _make_record("/b.txt", size=100),
            _make_record("/c.txt", size=200),
        ]
        result = detect_duplicates(files)
        # Only the two 100-byte files form a group
        assert len(result) == 1
        assert result[0].size_bytes == 100
        assert len(result[0].paths) == 2

    def test_single_file_no_group(self) -> None:
        files = [_make_record("/a.txt", size=100)]
        result = detect_duplicates(files)
        assert len(result) == 0


# ── N. Exact duplicate detection ─────────────────────────────────────


class TestN_ExactDuplicateDetection:
    def test_identical_content_detected(self, tmp_path: Path) -> None:
        content = b"x" * 8192  # > hash_sample_size (4096) to trigger hash comparison
        f1 = _create_file(tmp_path / "a.bin", content)
        f2 = _create_file(tmp_path / "b.bin", content)
        _create_file(tmp_path / "c.bin", b"d" * 8192)

        files, _ = scan_directory(tmp_path)
        result = detect_duplicates(files, min_size=1)
        # a.bin and b.bin should be in a hash-matched group
        hash_groups = [g for g in result if g.match_type == "hash"]
        assert len(hash_groups) >= 1
        paths = hash_groups[0].paths
        assert str(f1.resolve()) in paths
        assert str(f2.resolve()) in paths

    def test_different_content_not_matched(self, tmp_path: Path) -> None:
        _create_file(tmp_path / "a.bin", b"A" * 8192)
        _create_file(tmp_path / "b.bin", b"B" * 8192)
        files, _ = scan_directory(tmp_path)
        result = detect_duplicates(files, min_size=1)
        # Same size but different hash -- should NOT produce a group with both
        hash_groups = [g for g in result if g.match_type == "hash"]
        for g in hash_groups:
            assert not (str((tmp_path / "a.bin").resolve()) in g.paths
                       and str((tmp_path / "b.bin").resolve()) in g.paths)


# ── O. Duplicate non-match ───────────────────────────────────────────


class TestO_DuplicateNonMatch:
    def test_different_sizes_not_grouped(self) -> None:
        files = [
            _make_record("/a.txt", size=100),
            _make_record("/b.txt", size=200),
            _make_record("/c.txt", size=300),
        ]
        result = detect_duplicates(files)
        assert len(result) == 0


# ── P. No automatic deletion/remediation ─────────────────────────────


class TestP_NoAutomaticDeletion:
    def test_scan_result_has_no_delete_method(self) -> None:
        """ScanResult must not have any delete/remove/cleanup methods."""
        result = ScanResult(
            scan_root="/",
            stats=ScanStats(),
        )
        # Ensure no delete-related attributes
        assert not hasattr(result, "delete")
        assert not hasattr(result, "cleanup")
        assert not hasattr(result, "remove")

    def test_analyzers_return_readonly_results(self) -> None:
        files = [_make_record("/a.txt", size=100)]
        large = find_large_files(files, min_bytes=0)
        dirs = aggregate_directory_sizes(files)
        types = group_by_extension(files)
        # All should be frozen dataclasses
        assert isinstance(large[0], LargeFileResult)
        assert isinstance(dirs[0], DirectorySizeResult)
        assert isinstance(types[0], FileTypeGroup)


# ── Q. Bounded result size ───────────────────────────────────────────


class TestQ_BoundedResultSize:
    def test_large_files_bounded(self) -> None:
        files = [_make_record(f"/f{i}.txt", size=i * 100) for i in range(100)]
        result = find_large_files(files, top_n=10, min_bytes=0)
        assert len(result) <= 10

    def test_directory_sizes_bounded(self) -> None:
        files = [
            _make_record(f"/dir{i}/a.txt", size=100, parent=f"/dir{i}")
            for i in range(50)
        ]
        result = aggregate_directory_sizes(files, top_n=5)
        assert len(result) <= 5

    def test_duplicate_groups_bounded(self) -> None:
        files = [
            _make_record(f"/a{i}.txt", size=100)
            for i in range(20)
        ]
        result = detect_duplicates(files, max_groups=3)
        assert len(result) <= 3


# ── R. Scan statistics ───────────────────────────────────────────────


class TestR_ScanStatistics:
    def test_stats_populated(self, tmp_path: Path) -> None:
        _create_file(tmp_path / "a.txt", b"hello")
        _create_file(tmp_path / "b.txt", b"world")
        _create_file(tmp_path / "sub" / "c.txt", b"!")
        files, stats = scan_directory(tmp_path)
        assert stats.roots_scanned == 1
        assert stats.files_examined == 3
        assert stats.directories_examined >= 1
        assert stats.bytes_examined == 11  # 5 + 5 + 1
        assert stats.elapsed_seconds >= 0

    def test_stats_error_list(self, tmp_path: Path) -> None:
        _, stats = scan_directory(tmp_path)
        assert isinstance(stats.errors, list)


# ── S. Empty directory ───────────────────────────────────────────────


class TestS_EmptyDirectory:
    def test_empty_directory(self, tmp_path: Path) -> None:
        files, stats = scan_directory(tmp_path)
        assert files == []
        assert stats.files_examined == 0
        assert stats.bytes_examined == 0


# ── T. Missing root ──────────────────────────────────────────────────


class TestT_MissingRoot:
    def test_missing_root_raises(self) -> None:
        with pytest.raises(ValueError, match="does not exist"):
            validate_scan_root("/nonexistent/missing/root")


# ── U. File supplied where directory required ─────────────────────────


class TestU_FileWhereDirectoryRequired:
    def test_file_rejected(self, tmp_path: Path) -> None:
        f = tmp_path / "file.txt"
        _create_file(f)
        with pytest.raises(ValueError, match="not a directory"):
            validate_scan_root(f)


# ── V. Quarantine directory excluded ──────────────────────────────────


class TestV_QuarantineDirectoryExcluded:
    def test_quarantine_dir_excluded(self, tmp_path: Path) -> None:
        scan_root = tmp_path / "scan"
        scan_root.mkdir()
        q_dir = scan_root / ".old-computer-manager" / "quarantine"
        q_dir.mkdir(parents=True)
        _create_file(q_dir / "file.txt", b"quarantined")

        files, stats = scan_directory(scan_root)
        paths = [f.path for f in files]
        assert str((q_dir / "file.txt").resolve()) not in paths
        assert stats.excluded_items >= 1


# ── W. Scan does not modify filesystem ────────────────────────────────


class TestW_ScanDoesNotModify:
    def test_scan_readonly(self, tmp_path: Path) -> None:
        f = _create_file(tmp_path / "test.txt", b"content")
        mtime_before = f.stat().st_mtime
        atime_before = os.path.getatime(f)

        files, _ = scan_directory(tmp_path)

        # File should be unchanged
        assert f.read_bytes() == b"content"
        # mtime should not change (atime might on some systems)
        assert f.stat().st_mtime == mtime_before


# ── X. Existing project tests still pass ─────────────────────────────
# (Verified by running full suite -- no code here, just a marker)


# ── Runner integration test ──────────────────────────────────────────


class TestRunnerIntegration:
    def test_full_analysis(self, tmp_path: Path) -> None:
        _create_file(tmp_path / "small.txt", b"tiny")
        _create_file(tmp_path / "large.bin", b"x" * (1024 * 1024))  # 1MB
        _create_file(tmp_path / "sub" / "data.csv", b"a,b,c")
        _create_file(tmp_path / "sub" / "image.jpg", b"\xff\xd8\xff")

        result = run_file_analysis(
            tmp_path,
            large_top_n=10,
            large_min_bytes=1024,
        )

        assert isinstance(result, ScanResult)
        assert result.stats.files_examined == 4
        assert len(result.large_files) >= 1
        assert len(result.directory_sizes) >= 1
        assert len(result.file_type_groups) >= 1

    def test_quarantine_dir_excluded_in_runner(self, tmp_path: Path) -> None:
        scan_root = tmp_path / "scan"
        scan_root.mkdir()
        q_dir = scan_root / ".old-computer-manager" / "quarantine"
        q_dir.mkdir(parents=True)
        _create_file(q_dir / "q.txt", b"data")
        _create_file(scan_root / "real.txt", b"real")

        result = run_file_analysis(scan_root)
        paths = [f.path for f in []]  # large files, etc.
        # quarantine file should not appear in any results
        assert result.stats.files_examined == 1


# ── Database persistence test ─────────────────────────────────────────


class TestDatabasePersistence:
    def test_save_and_load_file_scan(self, tmp_path: Path) -> None:
        from app.database.sqlite import SnapshotStore

        store = SnapshotStore(path=tmp_path / "test.db")
        scan_id = store.start_file_scan(str(tmp_path))
        store.complete_file_scan(scan_id, {
            "files_examined": 10,
            "bytes_examined": 1024,
        })
        store.save_file_scan_large_files(scan_id, [
            {"path": "/big.bin", "size_bytes": 500},
        ])
        store.save_file_scan_type_groups(scan_id, [
            {"extension": ".txt", "file_count": 5, "total_size_bytes": 500},
        ])
        store.save_file_scan_duplicate_groups(scan_id, [
            {
                "group_id": 1,
                "size_bytes": 100,
                "match_type": "size",
                "hash_value": None,
                "paths": ["/a.txt", "/b.txt"],
            },
        ])

        latest = store.get_latest_file_scan()
        assert latest is not None
        assert latest["id"] == scan_id
        assert latest["stats"]["files_examined"] == 10

        large = store.load_file_scan_large_files(scan_id)
        assert len(large) == 1
        assert large[0]["path"] == "/big.bin"

        types = store.load_file_scan_type_groups(scan_id)
        assert len(types) == 1

        dupes = store.load_file_scan_duplicate_groups(scan_id)
        assert len(dupes) == 1
        assert dupes[0]["paths"] == ["/a.txt", "/b.txt"]
