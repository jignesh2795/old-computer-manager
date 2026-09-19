"""Tests for Phase 9A: Remediation Action Framework Expansion.

Tests A-W covering catalog, eligibility, action model extension,
registry validation, and audit schema changes.
"""

from __future__ import annotations

import sqlite3
import tempfile
from pathlib import Path

import pytest

from app.remediation.action import (
    BlastRadius,
    EligibilityStatus,
    ImplementationStatus,
    RemediationAction,
    RiskLevel,
    RollbackCategory,
)
from app.remediation.audit import AuditRecord, AuditStore, AuditStatus
from app.remediation.catalog import (
    CATALOG,
    ActionCatalogEntry,
    get_catalog_entries_by_eligibility,
    get_catalog_entries_by_status,
    get_catalog_entry,
    get_production_entries,
    validate_catalog_consistency,
)
from app.remediation.eligibility import (
    EligibilityResult,
    check_eligibility,
    get_blocked_actions,
    get_implemented_actions,
    get_implemented_production_actions,
    get_proposed_actions,
    is_action_allowed,
)
from app.remediation.registry import ActionRegistry, create_default_registry


# ── Test A: ImplementationStatus enum values ──────────────────────

class TestImplementationStatusEnum:
    def test_has_correct_values(self):
        assert ImplementationStatus.IMPLEMENTED.value == "implemented"
        assert ImplementationStatus.PROPOSED.value == "proposed"
        assert ImplementationStatus.BLOCKED.value == "blocked"
        assert ImplementationStatus.NOT_IMPLEMENTED.value == "not_implemented"

    def test_has_four_members(self):
        assert len(ImplementationStatus) == 4


# ── Test B: BlastRadius enum values ──────────────────────────────

class TestBlastRadiusEnum:
    def test_has_correct_values(self):
        assert BlastRadius.SINGLE_FILE.value == "single_file"
        assert BlastRadius.USER_DIRECTORY.value == "user_directory"
        assert BlastRadius.USER_PROFILE.value == "user_profile"
        assert BlastRadius.SYSTEM_WIDE.value == "system_wide"
        assert BlastRadius.BOOTLOADER.value == "bootloader"

    def test_has_five_members(self):
        assert len(BlastRadius) == 5


# ── Test C: RollbackCategory enum values ─────────────────────────

class TestRollbackCategoryEnum:
    def test_has_correct_values(self):
        assert RollbackCategory.SHUTIL_MOVE_RESTORE.value == "shutil_move_restore"
        assert RollbackCategory.REGISTRY_RESTORE.value == "registry_restore"
        assert RollbackCategory.SERVICE_RESTORE.value == "service_restore"
        assert RollbackCategory.STARTUP_RESTORE.value == "startup_restore"
        assert RollbackCategory.SNAPSHOT_RESTORE.value == "snapshot_restore"
        assert RollbackCategory.NOT_APPLICABLE.value == "not_applicable"

    def test_has_six_members(self):
        assert len(RollbackCategory) == 6


# ── Test D: EligibilityStatus enum values ────────────────────────

class TestEligibilityStatusEnum:
    def test_has_correct_values(self):
        assert EligibilityStatus.ELIGIBLE.value == "eligible"
        assert EligibilityStatus.BLOCKED.value == "blocked"
        assert EligibilityStatus.REQUIRES_DESIGN_REVIEW.value == "requires_design_review"
        assert EligibilityStatus.REQUIRES_PRIVILEGE_REVIEW.value == "requires_privilege_review"
        assert EligibilityStatus.REQUIRES_ROLLBACK_DESIGN.value == "requires_rollback_design"

    def test_has_five_members(self):
        assert len(EligibilityStatus) == 5


# ── Test E: RemediationAction backward compatibility ──────────────

class TestRemediationActionBackwardCompat:
    def test_old_code_works_without_new_fields(self):
        action = RemediationAction(
            action_id="test.action",
            name="Test Action",
            description="A test action.",
            risk_level=RiskLevel.LOW,
            target="test",
            reason="testing",
        )
        assert action.action_id == "test.action"
        assert action.implementation_status == ImplementationStatus.NOT_IMPLEMENTED
        assert action.blast_radius == BlastRadius.SINGLE_FILE
        assert action.rollback_category == RollbackCategory.NOT_APPLICABLE
        assert action.eligibility == EligibilityStatus.REQUIRES_DESIGN_REVIEW
        assert action.action_version == "1"
        assert action.category == "general"
        assert action.dependencies == ()


# ── Test F: RemediationAction with new fields ─────────────────────

class TestRemediationActionNewFields:
    def test_with_all_new_fields(self):
        action = RemediationAction(
            action_id="test.action",
            name="Test Action",
            description="A test action.",
            risk_level=RiskLevel.MEDIUM,
            target="test",
            reason="testing",
            implementation_status=ImplementationStatus.IMPLEMENTED,
            blast_radius=BlastRadius.USER_DIRECTORY,
            rollback_category=RollbackCategory.SHUTIL_MOVE_RESTORE,
            dependencies=("dep.action",),
            eligibility=EligibilityStatus.ELIGIBLE,
            action_version="2",
            category="cleanup",
        )
        assert action.implementation_status == ImplementationStatus.IMPLEMENTED
        assert action.blast_radius == BlastRadius.USER_DIRECTORY
        assert action.rollback_category == RollbackCategory.SHUTIL_MOVE_RESTORE
        assert action.dependencies == ("dep.action",)
        assert action.eligibility == EligibilityStatus.ELIGIBLE
        assert action.action_version == "2"
        assert action.category == "cleanup"

    def test_frozen(self):
        action = RemediationAction(
            action_id="test.action",
            name="Test",
            description="Test",
            risk_level=RiskLevel.LOW,
            target="test",
            reason="test",
        )
        with pytest.raises(AttributeError):
            action.action_version = "2"  # type: ignore[misc]


# ── Test G: ActionCatalogEntry creation ───────────────────────────

class TestActionCatalogEntry:
    def test_creation(self):
        entry = ActionCatalogEntry(
            action_id="test.action",
            name="Test",
            description="Test",
            risk_level=RiskLevel.LOW,
            implementation_status=ImplementationStatus.PROPOSED,
            blast_radius=BlastRadius.SINGLE_FILE,
            rollback_category=RollbackCategory.NOT_APPLICABLE,
            eligibility=EligibilityStatus.REQUIRES_DESIGN_REVIEW,
            requires_admin=False,
            reversible=True,
        )
        assert entry.action_id == "test.action"
        assert entry.category == "general"
        assert entry.action_version == "1"
        assert entry.dependencies == ()

    def test_frozen(self):
        entry = ActionCatalogEntry(
            action_id="test.action",
            name="Test",
            description="Test",
            risk_level=RiskLevel.LOW,
            implementation_status=ImplementationStatus.PROPOSED,
            blast_radius=BlastRadius.SINGLE_FILE,
            rollback_category=RollbackCategory.NOT_APPLICABLE,
            eligibility=EligibilityStatus.REQUIRES_DESIGN_REVIEW,
            requires_admin=False,
            reversible=True,
        )
        with pytest.raises(AttributeError):
            entry.action_id = "other"  # type: ignore[misc]


# ── Test H: get_catalog_entry ────────────────────────────────────

class TestGetCatalogEntry:
    def test_returns_entry_for_known_action(self):
        entry = get_catalog_entry("user_temp_quarantine")
        assert entry is not None
        assert entry.action_id == "user_temp_quarantine"

    def test_returns_none_for_unknown(self):
        assert get_catalog_entry("nonexistent.action") is None

    def test_demo_actions_in_catalog(self):
        entry = get_catalog_entry("demo.noop.print_message")
        assert entry is not None
        assert entry.category == "demo/test"


# ── Test I: get_catalog_entries_by_status ─────────────────────────

class TestGetCatalogEntriesByStatus:
    def test_implemented_entries(self):
        entries = get_catalog_entries_by_status(ImplementationStatus.IMPLEMENTED)
        ids = {e.action_id for e in entries}
        assert "user_temp_quarantine" in ids
        assert "demo.noop.print_message" in ids
        assert "demo.noop.report_status" in ids

    def test_blocked_entries(self):
        entries = get_catalog_entries_by_status(ImplementationStatus.BLOCKED)
        ids = {e.action_id for e in entries}
        assert "startup.disable_entry" in ids
        assert "service.stop_temporary" in ids
        assert "service.disable_unused" in ids
        assert "software.uninstall" in ids
        assert "network.proxy_configure" in ids
        assert "power.plan_optimize" in ids

    def test_proposed_entries(self):
        entries = get_catalog_entries_by_status(ImplementationStatus.PROPOSED)
        ids = {e.action_id for e in entries}
        assert "disk.cleanup_temp" in ids
        assert "disk.cleanup_logs" in ids
        assert "browser.cache_clear" in ids
        assert "update.check_only" in ids


# ── Test J: get_catalog_entries_by_eligibility ────────────────────

class TestGetCatalogEntriesByEligibility:
    def test_eligible_entries(self):
        entries = get_catalog_entries_by_eligibility(EligibilityStatus.ELIGIBLE)
        ids = {e.action_id for e in entries}
        assert "user_temp_quarantine" in ids
        assert "demo.noop.print_message" in ids

    def test_blocked_entries(self):
        entries = get_catalog_entries_by_eligibility(EligibilityStatus.BLOCKED)
        assert len(entries) > 0
        for e in entries:
            assert e.implementation_status == ImplementationStatus.BLOCKED


# ── Test K: get_production_entries ────────────────────────────────

class TestGetProductionEntries:
    def test_excludes_demo(self):
        entries = get_production_entries()
        for e in entries:
            assert e.category != "demo/test"

    def test_includes_user_temp_quarantine(self):
        entries = get_production_entries()
        ids = {e.action_id for e in entries}
        assert "user_temp_quarantine" in ids

    def test_excludes_demo_actions(self):
        entries = get_production_entries()
        ids = {e.action_id for e in entries}
        assert "demo.noop.print_message" not in ids
        assert "demo.noop.report_status" not in ids


# ── Test L: validate_catalog_consistency ──────────────────────────

class TestValidateCatalogConsistency:
    def test_no_errors_for_valid_catalog(self):
        errors = validate_catalog_consistency()
        assert errors == []

    def test_catalog_ids_are_unique(self):
        ids = [e.action_id for e in CATALOG.values()]
        assert len(ids) == len(set(ids))


# ── Test M: check_eligibility for implemented action ──────────────

class TestCheckEligibilityImplemented:
    def test_implemented_action_is_eligible(self):
        result = check_eligibility("user_temp_quarantine")
        assert result.status == EligibilityStatus.ELIGIBLE
        assert result.action_id == "user_temp_quarantine"

    def test_demo_action_is_eligible(self):
        result = check_eligibility("demo.noop.print_message")
        assert result.status == EligibilityStatus.ELIGIBLE


# ── Test N: check_eligibility for blocked action ──────────────────

class TestCheckEligibilityBlocked:
    def test_blocked_action(self):
        result = check_eligibility("startup.disable_entry")
        assert result.status == EligibilityStatus.BLOCKED
        assert len(result.blockers) > 0

    def test_all_blocked_actions(self):
        blocked = get_blocked_actions()
        for entry in blocked:
            result = check_eligibility(entry.action_id)
            assert result.status == EligibilityStatus.BLOCKED


# ── Test O: check_eligibility for proposed action ─────────────────

class TestCheckEligibilityProposed:
    def test_proposed_with_rollback_design(self):
        result = check_eligibility("disk.cleanup_temp")
        assert result.status == EligibilityStatus.REQUIRES_ROLLBACK_DESIGN

    def test_proposed_with_design_review(self):
        result = check_eligibility("browser.cache_clear")
        assert result.status == EligibilityStatus.REQUIRES_DESIGN_REVIEW


# ── Test P: check_eligibility for unknown action ──────────────────

class TestCheckEligibilityUnknown:
    def test_unknown_action(self):
        result = check_eligibility("nonexistent.action")
        assert result.status == EligibilityStatus.REQUIRES_DESIGN_REVIEW
        assert "not in the catalog" in result.reason


# ── Test Q: is_action_allowed ─────────────────────────────────────

class TestIsActionAllowed:
    def test_implemented_is_allowed(self):
        assert is_action_allowed("user_temp_quarantine") is True

    def test_blocked_is_not_allowed(self):
        assert is_action_allowed("startup.disable_entry") is False

    def test_proposed_is_not_allowed(self):
        assert is_action_allowed("disk.cleanup_temp") is False

    def test_unknown_is_not_allowed(self):
        assert is_action_allowed("nonexistent.action") is False


# ── Test R: get_blocked_actions ───────────────────────────────────

class TestGetBlockedActions:
    def test_returns_only_blocked(self):
        actions = get_blocked_actions()
        assert len(actions) > 0
        for a in actions:
            assert a.implementation_status == ImplementationStatus.BLOCKED

    def test_count(self):
        actions = get_blocked_actions()
        assert len(actions) == 6


# ── Test S: get_proposed_actions ──────────────────────────────────

class TestGetProposedActions:
    def test_returns_only_proposed(self):
        actions = get_proposed_actions()
        assert len(actions) > 0
        for a in actions:
            assert a.implementation_status == ImplementationStatus.PROPOSED

    def test_count(self):
        actions = get_proposed_actions()
        assert len(actions) == 4


# ── Test T: get_implemented_actions ───────────────────────────────

class TestGetImplementedActions:
    def test_returns_implemented(self):
        actions = get_implemented_actions()
        assert len(actions) == 3
        for a in actions:
            assert a.implementation_status == ImplementationStatus.IMPLEMENTED

    def test_includes_demos(self):
        actions = get_implemented_actions()
        ids = {a.action_id for a in actions}
        assert "demo.noop.print_message" in ids


# ── Test U: get_implemented_production_actions ────────────────────

class TestGetImplementedProductionActions:
    def test_excludes_demos(self):
        actions = get_implemented_production_actions()
        for a in actions:
            assert a.category != "demo/test"

    def test_only_user_temp_quarantine(self):
        actions = get_implemented_production_actions()
        assert len(actions) == 1
        assert actions[0].action_id == "user_temp_quarantine"


# ── Test V: Registry validates against catalog ────────────────────

class TestRegistryCatalogValidation:
    def test_default_registry_validates(self):
        registry = create_default_registry()
        errors = registry.validate_against_catalog()
        assert errors == []

    def test_registry_has_correct_implementation_status(self):
        registry = create_default_registry()
        action = registry.get("user_temp_quarantine")
        assert action.implementation_status == ImplementationStatus.IMPLEMENTED

    def test_registry_demo_has_demo_category(self):
        registry = create_default_registry()
        action = registry.get("demo.noop.print_message")
        assert action.category == "demo/test"


# ── Test W: Audit schema with action_version ─────────────────────

class TestAuditSchemaMigration:
    def test_audit_record_has_action_version(self):
        record = AuditRecord(
            action_id="user_temp_quarantine",
            action_version="1",
            implementation_status="implemented",
        )
        assert record.action_version == "1"
        assert record.implementation_status == "implemented"

    def test_audit_record_defaults(self):
        record = AuditRecord(action_id="test.action")
        assert record.action_version == "1"
        assert record.implementation_status == "not_implemented"

    def test_audit_store_persists_action_version(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test_audit.db"
            store = AuditStore(str(db_path))

            record = AuditRecord(
                action_id="user_temp_quarantine",
                action_version="1",
                implementation_status="implemented",
                risk_level="medium",
                target="User TEMP directory",
                reason="Test",
            )
            record_id = store.create_record(record)

            loaded = store.get_record(record_id)
            assert loaded is not None
            assert loaded.action_version == "1"
            assert loaded.implementation_status == "implemented"

    def test_audit_store_migration_adds_columns(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "old_audit.db"

            # Create old-style table without new columns
            conn = sqlite3.connect(str(db_path))
            conn.execute("""
                CREATE TABLE remediation_audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action_id TEXT NOT NULL,
                    finding_id INTEGER,
                    discovery_run_id INTEGER,
                    requested_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    executed_at TEXT,
                    status TEXT NOT NULL DEFAULT 'proposed',
                    risk_level TEXT NOT NULL DEFAULT 'low',
                    target TEXT NOT NULL DEFAULT '',
                    reason TEXT NOT NULL DEFAULT '',
                    result_summary TEXT NOT NULL DEFAULT '',
                    rollback_available INTEGER NOT NULL DEFAULT 0,
                    error_message TEXT
                )
            """)
            conn.commit()
            conn.close()

            # AuditStore should migrate automatically
            store = AuditStore(str(db_path))

            record = AuditRecord(
                action_id="test.action",
                action_version="2",
                implementation_status="implemented",
            )
            record_id = store.create_record(record)

            loaded = store.get_record(record_id)
            assert loaded is not None
            assert loaded.action_version == "2"
            assert loaded.implementation_status == "implemented"


# ── Security: No execution paths for blocked/proposed actions ─────

class TestSecurityNoExecutionPaths:
    def test_blocked_actions_not_eligible(self):
        from app.remediation.catalog import CATALOG
        for entry in CATALOG.values():
            if entry.implementation_status == ImplementationStatus.BLOCKED:
                assert entry.eligibility == EligibilityStatus.BLOCKED

    def test_not_implemented_not_eligible(self):
        from app.remediation.catalog import CATALOG
        for entry in CATALOG.values():
            if entry.implementation_status == ImplementationStatus.NOT_IMPLEMENTED:
                assert entry.eligibility != EligibilityStatus.ELIGIBLE

    def test_only_production_implemented_action(self):
        actions = get_implemented_production_actions()
        assert len(actions) == 1
        assert actions[0].action_id == "user_temp_quarantine"

    def test_all_demo_actions_categorized(self):
        from app.remediation.catalog import CATALOG
        for entry in CATALOG.values():
            if entry.action_id.startswith("demo."):
                assert entry.category == "demo/test"
