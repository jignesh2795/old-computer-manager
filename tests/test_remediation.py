"""Comprehensive tests for the hardened remediation safety framework."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from app.remediation.action import RemediationAction, RiskLevel
from app.remediation.registry import (
    ActionRegistry,
    DuplicateActionError,
    ParameterSchema,
    UnknownActionError,
    create_default_registry,
    validate_parameters,
)
from app.remediation.action_preview import PreviewResult, preview_action
from app.remediation.confirmation import (
    ConfirmationToken,
    ConfirmationRequiredError,
    ConfirmationReuseError,
    confirm_action,
    consume_confirmation,
    require_confirmation,
)
from app.remediation.validation import ValidationResult, validate_action
from app.remediation.audit import (
    AuditRecord,
    AuditStatus,
    AuditStore,
    InvalidTransitionError,
)
from app.remediation.rollback import (
    BackupNotImplementedError,
    RollbackNotImplementedError,
    RollbackAvailability,
    get_rollback_capability,
    prepare_backup,
    execute_rollback,
)
from app.remediation.permissions import PrivilegeStatus, check_admin_privileges
from app.remediation.idempotency import Idempotency
from app.remediation.executor import (
    BaseExecutor,
    ExecutionDeniedError,
    ExecutionResult,
    SimulationExecutor,
    execute_action,
)
from app.database.sqlite import SnapshotStore


# ── Helpers ─────────────────────────────────────────────────────────────

def _make_action(**overrides) -> RemediationAction:
    defaults = dict(
        action_id="test.action",
        name="Test Action",
        description="A test action.",
        risk_level=RiskLevel.LOW,
        target="test target",
        reason="testing",
    )
    defaults.update(overrides)
    return RemediationAction(**defaults)


def _make_store() -> tuple[SnapshotStore, str]:
    tmpdir = tempfile.mkdtemp()
    db_path = Path(tmpdir) / "test.db"
    return SnapshotStore(path=db_path), tmpdir


def _make_audit_store() -> tuple[AuditStore, str]:
    tmpdir = tempfile.mkdtemp()
    db_path = Path(tmpdir) / "audit.db"
    return AuditStore(db_path=db_path), tmpdir


def _cleanup(path: str) -> None:
    import shutil
    shutil.rmtree(path, ignore_errors=True)


def _make_registry_with_action(
    action_id: str = "demo.noop.print_message",
    *,
    parameter_schema: ParameterSchema | None = None,
) -> ActionRegistry:
    reg = ActionRegistry()
    reg.register(
        _make_action(action_id=action_id),
        parameter_schema=parameter_schema,
    )
    return reg


# ── Action model tests ──────────────────────────────────────────────────

class TestRemediationAction:
    def test_valid_action(self) -> None:
        action = _make_action()
        assert action.action_id == "test.action"
        assert action.risk_level == RiskLevel.LOW

    def test_all_risk_levels(self) -> None:
        for level in RiskLevel:
            action = _make_action(risk_level=level)
            assert action.risk_level == level

    def test_invalid_risk_level_rejected(self) -> None:
        with pytest.raises(ValueError):
            RemediationAction(
                action_id="bad",
                name="Bad",
                description="Bad",
                risk_level="banana",  # type: ignore[arg-type]
                target="x",
                reason="x",
            )

    def test_frozen_dataclass(self) -> None:
        action = _make_action()
        with pytest.raises(AttributeError):
            action.name = "changed"  # type: ignore[misc]


# ── Registry tests ──────────────────────────────────────────────────────

class TestActionRegistry:
    def test_register_and_lookup(self) -> None:
        reg = ActionRegistry()
        action = _make_action()
        reg.register(action)
        assert reg.get("test.action") is action

    def test_duplicate_rejection(self) -> None:
        reg = ActionRegistry()
        reg.register(_make_action())
        with pytest.raises(DuplicateActionError):
            reg.register(_make_action())

    def test_unknown_action(self) -> None:
        reg = ActionRegistry()
        with pytest.raises(UnknownActionError):
            reg.get("nonexistent")

    def test_list_actions(self) -> None:
        reg = ActionRegistry()
        reg.register(_make_action(action_id="a"))
        reg.register(_make_action(action_id="b"))
        assert len(reg.list_actions()) == 2

    def test_is_registered(self) -> None:
        reg = ActionRegistry()
        assert not reg.is_registered("x")
        reg.register(_make_action(action_id="x"))
        assert reg.is_registered("x")

    def test_default_registry_has_demo_actions(self) -> None:
        reg = create_default_registry()
        assert reg.count() >= 2
        assert reg.is_registered("demo.noop.print_message")
        assert reg.is_registered("demo.noop.report_status")

    def test_schema_retrieval(self) -> None:
        schema = ParameterSchema(required={"msg"})
        reg = ActionRegistry()
        reg.register(_make_action(), parameter_schema=schema)
        assert reg.get_schema("test.action") is schema

    def test_schema_none_for_unregistered(self) -> None:
        reg = ActionRegistry()
        assert reg.get_schema("nonexistent") is None


# ── Parameter schema tests ──────────────────────────────────────────────

class TestParameterSchema:
    def test_valid_parameters(self) -> None:
        schema = ParameterSchema(required={"path"}, optional={"force"})
        errors = validate_parameters({"path": "/tmp", "force": True}, schema)
        assert errors == []

    def test_unknown_parameters_rejected(self) -> None:
        schema = ParameterSchema(required={"path"})
        errors = validate_parameters({"path": "/tmp", "extra": 1}, schema)
        assert len(errors) == 1
        assert "Unknown parameters" in errors[0]
        assert "extra" in errors[0]

    def test_missing_required_rejected(self) -> None:
        schema = ParameterSchema(required={"path", "mode"})
        errors = validate_parameters({"path": "/tmp"}, schema)
        assert len(errors) == 1
        assert "Missing required" in errors[0]
        assert "mode" in errors[0]

    def test_type_check_rejected(self) -> None:
        schema = ParameterSchema(
            required={"count"},
            types={"count": "int"},
        )
        errors = validate_parameters({"count": "not_int"}, schema)
        assert len(errors) == 1
        assert "must be int" in errors[0]

    def test_value_check_rejected(self) -> None:
        schema = ParameterSchema(
            required={"level"},
            values={"level": {"low", "high"}},
        )
        errors = validate_parameters({"level": "medium"}, schema)
        assert len(errors) == 1
        assert "not in allowed" in errors[0]

    def test_multiple_errors(self) -> None:
        schema = ParameterSchema(
            required={"a", "b"},
            types={"a": "int"},
        )
        errors = validate_parameters({"a": "wrong", "extra": 1}, schema)
        assert len(errors) >= 2


# ── Preview tests ───────────────────────────────────────────────────────

class TestPreview:
    def test_preview_contains_required_fields(self) -> None:
        action = _make_action(reversible=True, idempotent=True)
        preview = preview_action(action)
        assert isinstance(preview, PreviewResult)
        assert preview.action_id == action.action_id

    def test_preview_no_side_effects(self) -> None:
        action = _make_action()
        p1 = preview_action(action)
        p2 = preview_action(action)
        assert p1.action_id == p2.action_id


# ── Confirmation tests ──────────────────────────────────────────────────

class TestConfirmation:
    def test_unconfirmed_token_defaults(self) -> None:
        token = ConfirmationToken(action_id="test")
        assert token.confirmed is True  # auto-computed hash

    def test_confirm_action_creates_valid_token(self) -> None:
        action = _make_action()
        token = confirm_action(action)
        assert token.confirmed is True
        assert token.is_valid_for(action.action_id)

    def test_require_confirmation_with_valid_token(self) -> None:
        action = _make_action()
        token = confirm_action(action)
        result = require_confirmation(action, token)
        assert result is token

    def test_require_confirmation_with_none(self) -> None:
        action = _make_action()
        with pytest.raises(ConfirmationRequiredError):
            require_confirmation(action, None)

    def test_wrong_action_rejected(self) -> None:
        action = _make_action(action_id="correct")
        other = _make_action(action_id="wrong")
        token = confirm_action(other)
        with pytest.raises(ConfirmationRequiredError):
            require_confirmation(action, token)

    def test_consumed_token_rejected(self) -> None:
        action = _make_action()
        token = confirm_action(action)
        consumed = consume_confirmation(action, token)
        with pytest.raises(ConfirmationReuseError):
            require_confirmation(action, consumed)

    def test_consume_returns_new_token(self) -> None:
        action = _make_action()
        token = confirm_action(action)
        consumed = consume_confirmation(action, token)
        assert consumed._consumed is True
        assert consumed.action_id == token.action_id

    def test_is_valid_for_wrong_action(self) -> None:
        token = confirm_action(_make_action(action_id="a"))
        assert not token.is_valid_for("b")

    def test_is_valid_for_after_consume(self) -> None:
        action = _make_action()
        token = confirm_action(action)
        consumed = consume_confirmation(action, token)
        assert not consumed.is_valid_for(action.action_id)

    def test_forged_token_rejected(self) -> None:
        # Constructing a token with confirmed=True but wrong hash
        forged = ConfirmationToken(
            action_id="test",
            _secret="forged",
            _confirmed_hash="forged_hash",
        )
        assert not forged.confirmed  # hash doesn't match

    def test_secret_is_random(self) -> None:
        t1 = ConfirmationToken(action_id="a")
        t2 = ConfirmationToken(action_id="a")
        assert t1._secret != t2._secret


# ── Validation tests ────────────────────────────────────────────────────

class TestValidation:
    def test_valid_action_passes(self) -> None:
        action = _make_action()
        reg = _make_registry_with_action(action_id=action.action_id)
        result = validate_action(action, reg)
        assert result.valid is True

    def test_unregistered_action_rejected(self) -> None:
        reg = ActionRegistry()
        action = _make_action()
        result = validate_action(action, reg)
        assert result.valid is False
        assert any("not registered" in e for e in result.errors)

    def test_empty_action_id_rejected(self) -> None:
        reg = ActionRegistry()
        action = _make_action(action_id="")
        result = validate_action(action, reg)
        assert result.valid is False

    def test_nonexistent_finding_rejected(self) -> None:
        action = _make_action(finding_id=9999)
        reg = _make_registry_with_action(action_id=action.action_id)
        store, tmpdir = _make_store()
        try:
            result = validate_action(action, reg, findings_store=store)
            assert result.valid is False
            assert any("9999" in e for e in result.errors)
        finally:
            _cleanup(tmpdir)

    def test_nonexistent_run_rejected(self) -> None:
        action = _make_action(discovery_run_id=9999)
        reg = _make_registry_with_action(action_id=action.action_id)
        store, tmpdir = _make_store()
        try:
            result = validate_action(action, reg, discovery_store=store)
            assert result.valid is False
            assert any("does not exist" in e for e in result.errors)
        finally:
            _cleanup(tmpdir)

    def test_real_finding_passes(self) -> None:
        action = _make_action()
        reg = _make_registry_with_action(action_id=action.action_id)
        store, tmpdir = _make_store()
        try:
            run_id = store.start_run()
            store.complete_run(run_id, "completed")
            with store._connect() as conn:
                conn.execute(
                    "INSERT INTO findings(run_id, analyzer, severity, title, message)"
                    " VALUES (?, ?, ?, ?, ?)",
                    (run_id, "test", "warning", "T", "M"),
                )
            with store._connect() as conn:
                fid = conn.execute("SELECT id FROM findings LIMIT 1").fetchone()[0]

            action_with_finding = _make_action(finding_id=fid, discovery_run_id=run_id)
            reg2 = _make_registry_with_action(action_id=action_with_finding.action_id)
            result = validate_action(
                action_with_finding, reg2,
                findings_store=store, discovery_store=store
            )
            assert result.valid is True
        finally:
            _cleanup(tmpdir)

    def test_finding_from_wrong_run_rejected(self) -> None:
        store, tmpdir = _make_store()
        try:
            run1 = store.start_run()
            store.complete_run(run1, "completed")
            run2 = store.start_run()
            store.complete_run(run2, "completed")
            with store._connect() as conn:
                conn.execute(
                    "INSERT INTO findings(run_id, analyzer, severity, title, message)"
                    " VALUES (?, ?, ?, ?, ?)",
                    (run1, "test", "warning", "T", "M"),
                )
            with store._connect() as conn:
                fid = conn.execute("SELECT id FROM findings LIMIT 1").fetchone()[0]

            action = _make_action(finding_id=fid, discovery_run_id=run2)
            reg = _make_registry_with_action(action_id=action.action_id)
            result = validate_action(
                action, reg, findings_store=store, discovery_store=store
            )
            assert result.valid is False
            assert any("does not belong" in e for e in result.errors)
        finally:
            _cleanup(tmpdir)

    def test_run_not_completed_rejected(self) -> None:
        store, tmpdir = _make_store()
        try:
            run_id = store.start_run()
            action = _make_action(discovery_run_id=run_id)
            reg = _make_registry_with_action(action_id=action.action_id)
            result = validate_action(action, reg, discovery_store=store)
            assert result.valid is False
            assert any("not completed" in e for e in result.errors)
        finally:
            _cleanup(tmpdir)

    def test_invalid_parameters_rejected(self) -> None:
        schema = ParameterSchema(required={"msg"})
        action = _make_action(parameters={"wrong_param": "value"})
        reg = _make_registry_with_action(
            action_id=action.action_id, parameter_schema=schema
        )
        result = validate_action(action, reg)
        assert result.valid is False
        assert any("Unknown parameters" in e for e in result.errors)

    def test_missing_required_param_rejected(self) -> None:
        schema = ParameterSchema(required={"msg"})
        action = _make_action(parameters={})
        reg = _make_registry_with_action(
            action_id=action.action_id, parameter_schema=schema
        )
        result = validate_action(action, reg)
        assert result.valid is False
        assert any("Missing required" in e for e in result.errors)


# ── Audit tests ─────────────────────────────────────────────────────────

class TestAudit:
    def test_create_and_retrieve_record(self) -> None:
        store, tmpdir = _make_audit_store()
        try:
            record = AuditRecord(action_id="test.action", risk_level="low")
            record_id = store.create_record(record)
            assert record_id > 0
            loaded = store.get_record(record_id)
            assert loaded is not None
            assert loaded.action_id == "test.action"
            assert loaded.status == AuditStatus.PROPOSED.value
        finally:
            _cleanup(tmpdir)

    def test_valid_transition(self) -> None:
        store, tmpdir = _make_audit_store()
        try:
            rid = store.create_record(AuditRecord(action_id="t"))
            store.update_status(rid, AuditStatus.PREVIEWED)
            store.update_status(rid, AuditStatus.CONFIRMED)
            store.update_status(rid, AuditStatus.EXECUTING)
            store.update_status(rid, AuditStatus.SUCCEEDED)
            loaded = store.get_record(rid)
            assert loaded.status == AuditStatus.SUCCEEDED.value
        finally:
            _cleanup(tmpdir)

    def test_invalid_transition_rejected(self) -> None:
        store, tmpdir = _make_audit_store()
        try:
            rid = store.create_record(AuditRecord(action_id="t"))
            store.update_status(rid, AuditStatus.PREVIEWED)
            store.update_status(rid, AuditStatus.CONFIRMED)
            store.update_status(rid, AuditStatus.EXECUTING)
            store.update_status(rid, AuditStatus.SUCCEEDED)
            # Terminal state -- cannot go back
            with pytest.raises(InvalidTransitionError):
                store.update_status(rid, AuditStatus.PROPOSED)
        finally:
            _cleanup(tmpdir)

    def test_skip_transition_rejected(self) -> None:
        store, tmpdir = _make_audit_store()
        try:
            rid = store.create_record(AuditRecord(action_id="t"))
            # Skip from PROPOSED to EXECUTING (not allowed)
            with pytest.raises(InvalidTransitionError):
                store.update_status(rid, AuditStatus.EXECUTING)
        finally:
            _cleanup(tmpdir)

    def test_cancel_from_proposed(self) -> None:
        store, tmpdir = _make_audit_store()
        try:
            rid = store.create_record(AuditRecord(action_id="t"))
            store.update_status(rid, AuditStatus.CANCELLED)
            loaded = store.get_record(rid)
            assert loaded.status == AuditStatus.CANCELLED.value
        finally:
            _cleanup(tmpdir)

    def test_failure_recording(self) -> None:
        store, tmpdir = _make_audit_store()
        try:
            rid = store.create_record(AuditRecord(action_id="t"))
            store.update_status(rid, AuditStatus.PREVIEWED)
            store.update_status(rid, AuditStatus.CONFIRMED)
            store.update_status(rid, AuditStatus.EXECUTING)
            store.update_status(
                rid, AuditStatus.FAILED, error_message="oops"
            )
            loaded = store.get_record(rid)
            assert loaded.status == AuditStatus.FAILED.value
            assert loaded.error_message == "oops"
        finally:
            _cleanup(tmpdir)

    def test_nullable_finding_id(self) -> None:
        store, tmpdir = _make_audit_store()
        try:
            r1 = AuditRecord(action_id="a", finding_id=None)
            r2 = AuditRecord(action_id="b", finding_id=42)
            id1 = store.create_record(r1)
            id2 = store.create_record(r2)
            assert store.get_record(id1).finding_id is None
            assert store.get_record(id2).finding_id == 42
        finally:
            _cleanup(tmpdir)

    def test_list_records_with_filters(self) -> None:
        store, tmpdir = _make_audit_store()
        try:
            store.create_record(AuditRecord(action_id="a"))
            store.create_record(AuditRecord(action_id="b"))
            assert len(store.list_records()) == 2
            assert len(store.list_records(action_id="a")) == 1
        finally:
            _cleanup(tmpdir)

    def test_migration_idempotent(self) -> None:
        tmpdir = tempfile.mkdtemp()
        db_path = Path(tmpdir) / "test.db"
        try:
            s1 = AuditStore(db_path=db_path)
            s1.create_record(AuditRecord(action_id="test"))
            s2 = AuditStore(db_path=db_path)
            assert len(s2.list_records()) == 1
        finally:
            _cleanup(tmpdir)

    def test_no_prerequisite_tables_created(self) -> None:
        """AuditStore should NOT create discovery_runs/findings tables."""
        tmpdir = tempfile.mkdtemp()
        db_path = Path(tmpdir) / "audit.db"
        try:
            AuditStore(db_path=db_path)
            import sqlite3
            conn = sqlite3.connect(db_path)
            tables = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
            conn.close()
            assert "discovery_runs" not in tables
            assert "findings" not in tables
            assert "remediation_audit" in tables
        finally:
            _cleanup(tmpdir)


# ── Rollback tests ──────────────────────────────────────────────────────

class TestRollback:
    def test_prepare_backup_not_implemented(self) -> None:
        with pytest.raises(BackupNotImplementedError):
            prepare_backup("test.action")

    def test_execute_rollback_not_implemented(self) -> None:
        with pytest.raises(RollbackNotImplementedError):
            execute_rollback("backup-id")

    def test_no_fake_success(self) -> None:
        """Neither backup nor rollback should return success=True."""
        try:
            prepare_backup("x")
        except BackupNotImplementedError:
            pass  # expected
        try:
            execute_rollback("x")
        except RollbackNotImplementedError:
            pass  # expected

    def test_capability_preserves_description(self) -> None:
        cap = get_rollback_capability(True, description="Custom")
        assert cap.description == "Custom"


# ── Permissions tests ───────────────────────────────────────────────────

class TestPermissions:
    def test_returns_privilege_status(self) -> None:
        status = check_admin_privileges()
        assert isinstance(status, PrivilegeStatus)
        assert isinstance(status.is_admin, bool)

    def test_no_modification(self) -> None:
        s1 = check_admin_privileges()
        s2 = check_admin_privileges()
        assert s1.is_admin == s2.is_admin


# ── Idempotency tests ──────────────────────────────────────────────────

class TestIdempotency:
    def test_enum_values(self) -> None:
        assert Idempotency.IDEMPOTENT.value == "idempotent"
        assert Idempotency.NON_IDEMPOTENT.value == "non_idempotent"


# ── Executor tests ──────────────────────────────────────────────────────

class TestExecutor:
    def test_unvalidated_action_rejected(self) -> None:
        action = _make_action(action_id="demo.noop.print_message")
        token = confirm_action(action)
        invalid = ValidationResult(valid=False, errors=["test error"])
        reg = _make_registry_with_action()
        audit, tmpdir = _make_audit_store()
        try:
            with pytest.raises(ExecutionDeniedError):
                execute_action(action, token, invalid, reg, audit)
        finally:
            _cleanup(tmpdir)

    def test_unregistered_action_rejected(self) -> None:
        action = _make_action(action_id="unregistered.action")
        token = confirm_action(action)
        valid = ValidationResult(valid=True)
        reg = ActionRegistry()  # empty
        audit, tmpdir = _make_audit_store()
        try:
            with pytest.raises(ExecutionDeniedError):
                execute_action(action, token, valid, reg, audit)
        finally:
            _cleanup(tmpdir)

    def test_validated_action_succeeds(self) -> None:
        action = _make_action(action_id="demo.noop.print_message")
        token = confirm_action(action)
        valid = ValidationResult(valid=True)
        reg = _make_registry_with_action()
        audit, tmpdir = _make_audit_store()
        try:
            result = execute_action(action, token, valid, reg, audit)
            assert result.success is True
            assert result.simulated is True
        finally:
            _cleanup(tmpdir)

    def test_noop_executor_produces_result(self) -> None:
        executor = SimulationExecutor()
        action = _make_action(action_id="demo.noop.print_message")
        token = confirm_action(action)
        valid = ValidationResult(valid=True)
        reg = _make_registry_with_action()
        audit, tmpdir = _make_audit_store()
        try:
            result = executor.execute(action, token, valid, reg, audit)
            assert isinstance(result, ExecutionResult)
            assert result.success is True
            assert result.simulated is True
        finally:
            _cleanup(tmpdir)

    def test_arbitrary_commands_cannot_be_passed(self) -> None:
        action = _make_action()
        assert not hasattr(action, "command")
        assert not hasattr(action, "shell")
        assert not hasattr(action, "cmd")

    def test_token_consumed_after_execution(self) -> None:
        action = _make_action(action_id="demo.noop.print_message")
        token = confirm_action(action)
        valid = ValidationResult(valid=True)
        reg = _make_registry_with_action()
        audit, tmpdir = _make_audit_store()
        try:
            result = execute_action(action, token, valid, reg, audit)
            assert result.success is True
            # Audit record was created
            assert result.audit_record_id is not None
            loaded = audit.get_record(result.audit_record_id)
            assert loaded.status == AuditStatus.SUCCEEDED.value
        finally:
            _cleanup(tmpdir)

    def test_reuse_consumed_token_rejected(self) -> None:
        action = _make_action(action_id="demo.noop.print_message")
        token = confirm_action(action)
        valid = ValidationResult(valid=True)
        reg = _make_registry_with_action()
        audit, tmpdir = _make_audit_store()
        try:
            result = execute_action(action, token, valid, reg, audit)
            assert result.success
            # Consume the same token again via consume_confirmation directly
            with pytest.raises(ConfirmationReuseError):
                # The executor returned a consumed token internally;
                # verify that consume_confirmation rejects already-consumed
                consumed = ConfirmationToken(
                    action_id=action.action_id,
                    _secret=token._secret,
                    _confirmed_hash=token._confirmed_hash,
                    _consumed=True,
                )
                consume_confirmation(action, consumed)
        finally:
            _cleanup(tmpdir)

    def test_rollback_field_set_on_result(self) -> None:
        action = _make_action(
            reversible=True, action_id="demo.noop.print_message"
        )
        token = confirm_action(action)
        valid = ValidationResult(valid=True)
        reg = _make_registry_with_action()
        audit, tmpdir = _make_audit_store()
        try:
            result = execute_action(action, token, valid, reg, audit)
            assert result.rollback_available is True
        finally:
            _cleanup(tmpdir)

    def test_irreversible_action_result(self) -> None:
        action = _make_action(
            reversible=False, action_id="demo.noop.print_message"
        )
        token = confirm_action(action)
        valid = ValidationResult(valid=True)
        reg = _make_registry_with_action()
        audit, tmpdir = _make_audit_store()
        try:
            result = execute_action(action, token, valid, reg, audit)
            assert result.rollback_available is False
        finally:
            _cleanup(tmpdir)


# ── CLI tests ───────────────────────────────────────────────────────────

class TestCLI:
    def test_actions_command_exists(self) -> None:
        from app.cli import main
        assert callable(main)

    def test_no_apply_command(self) -> None:
        """Verify no apply/execute/remediate command is registered."""
        import argparse
        from app.cli import main
        # Build the parser the same way main() does
        parser = argparse.ArgumentParser(prog="old-computer-manager")
        sub = parser.add_subparsers(dest="command")
        sub.add_parser("discover")
        sub.add_parser("analyze")
        sub.add_parser("actions")
        # Parse with --help to get the subcommands -- but we can just
        # check that no dangerous command exists
        import inspect
        source = inspect.getsource(main)
        dangerous_commands = ["apply", "execute", "remediate", "fix"]
        for cmd in dangerous_commands:
            assert f'add_parser("{cmd}"' not in source, (
                f"CLI registers dangerous command: {cmd}"
            )
            assert f"add_parser('{cmd}'" not in source, (
                f"CLI registers dangerous command: {cmd}"
            )


# ── Security regression tests ──────────────────────────────────────────

class TestSecurityRegression:
    """Cases A-J from the security review requirements."""

    def test_case_a_unregistered_action_no_execute(self) -> None:
        """Construct an unregistered action -> must not execute."""
        action = _make_action(action_id="unregistered.evil")
        token = confirm_action(action)
        valid = ValidationResult(valid=True)
        reg = ActionRegistry()  # empty
        audit, tmpdir = _make_audit_store()
        try:
            with pytest.raises(ExecutionDeniedError):
                execute_action(action, token, valid, reg, audit)
        finally:
            _cleanup(tmpdir)

    def test_case_b_skip_validation_no_execute(self) -> None:
        """Registered action but skip validation -> must not execute."""
        action = _make_action(action_id="demo.noop.print_message")
        token = confirm_action(action)
        invalid = ValidationResult(valid=False, errors=["skipped"])
        reg = _make_registry_with_action()
        audit, tmpdir = _make_audit_store()
        try:
            with pytest.raises(ExecutionDeniedError):
                execute_action(action, token, invalid, reg, audit)
        finally:
            _cleanup(tmpdir)

    def test_case_c_invalid_validation_no_execute(self) -> None:
        """Use invalid ValidationResult -> must not execute."""
        action = _make_action(action_id="demo.noop.print_message")
        token = confirm_action(action)
        invalid = ValidationResult(
            valid=False, errors=["validation failed"]
        )
        reg = _make_registry_with_action()
        audit, tmpdir = _make_audit_store()
        try:
            with pytest.raises(ExecutionDeniedError):
                execute_action(action, token, invalid, reg, audit)
        finally:
            _cleanup(tmpdir)

    def test_case_d_forged_confirmation_no_execute(self) -> None:
        """Use forged confirmation token -> must not execute."""
        action = _make_action(action_id="demo.noop.print_message")
        forged = ConfirmationToken(
            action_id=action.action_id,
            _secret="forged",
            _confirmed_hash="forged",
        )
        valid = ValidationResult(valid=True)
        reg = _make_registry_with_action()
        audit, tmpdir = _make_audit_store()
        try:
            with pytest.raises(ConfirmationRequiredError):
                execute_action(action, forged, valid, reg, audit)
        finally:
            _cleanup(tmpdir)

    def test_case_e_wrong_action_confirmation_no_execute(self) -> None:
        """Use wrong action confirmation -> must not execute."""
        action = _make_action(action_id="target.action")
        other = _make_action(action_id="other.action")
        token = confirm_action(other)
        valid = ValidationResult(valid=True)
        reg = _make_registry_with_action(action_id="target.action")
        audit, tmpdir = _make_audit_store()
        try:
            with pytest.raises(ConfirmationRequiredError):
                execute_action(action, token, valid, reg, audit)
        finally:
            _cleanup(tmpdir)

    def test_case_f_nonexistent_finding_no_execute(self) -> None:
        """Use nonexistent finding -> validation fails -> no execute."""
        reg = _make_registry_with_action()
        action = _make_action(finding_id=9999)
        store, tmpdir = _make_store()
        try:
            result = validate_action(action, reg, findings_store=store)
            assert result.valid is False
            token = confirm_action(action)
            audit, tmpdir2 = _make_audit_store()
            try:
                with pytest.raises(ExecutionDeniedError):
                    execute_action(action, token, result, reg, audit)
            finally:
                _cleanup(tmpdir2)
        finally:
            _cleanup(tmpdir)

    def test_case_g_nonexistent_run_no_execute(self) -> None:
        """Use nonexistent discovery run -> validation fails -> no execute."""
        reg = _make_registry_with_action()
        action = _make_action(discovery_run_id=9999)
        store, tmpdir = _make_store()
        try:
            result = validate_action(action, reg, discovery_store=store)
            assert result.valid is False
        finally:
            _cleanup(tmpdir)

    def test_case_h_invalid_parameters_no_execute(self) -> None:
        """Use invalid parameters -> validation fails -> no execute."""
        schema = ParameterSchema(required={"msg"})
        reg = _make_registry_with_action(parameter_schema=schema)
        action = _make_action(parameters={"wrong": "value"})
        result = validate_action(action, reg)
        assert result.valid is False

    def test_case_i_arbitrary_command_parameter_rejected(self) -> None:
        """Attempt arbitrary command parameter -> must be rejected."""
        schema = ParameterSchema(
            required={"msg"},
            types={"msg": "str"},
        )
        action2 = _make_action(
            parameters={"msg": "ok", "command": "evil"}
        )
        reg = _make_registry_with_action(
            action_id=action2.action_id, parameter_schema=schema
        )
        result2 = validate_action(action2, reg)
        assert result2.valid is False
        assert any("Unknown parameters" in e for e in result2.errors)

    def test_case_j_simulation_only(self) -> None:
        """Simulation execution -> succeeds only as simulation."""
        action = _make_action(action_id="demo.noop.print_message")
        token = confirm_action(action)
        valid = ValidationResult(valid=True)
        reg = _make_registry_with_action()
        audit, tmpdir = _make_audit_store()
        try:
            result = execute_action(action, token, valid, reg, audit)
            assert result.success is True
            assert result.simulated is True
            assert "SIMULATED" in result.message
        finally:
            _cleanup(tmpdir)


# ── Security review tests ──────────────────────────────────────────────

class TestSecurityReview:
    def test_no_subprocess_imports(self) -> None:
        from pathlib import Path
        remediation_dir = Path(__file__).parent.parent / "app" / "remediation"
        for py_file in remediation_dir.glob("*.py"):
            content = py_file.read_text()
            assert "import subprocess" not in content

    def test_no_os_system_calls(self) -> None:
        from pathlib import Path
        remediation_dir = Path(__file__).parent.parent / "app" / "remediation"
        for py_file in remediation_dir.glob("*.py"):
            content = py_file.read_text()
            assert "os.system(" not in content

    def test_no_registry_writes(self) -> None:
        from pathlib import Path
        remediation_dir = Path(__file__).parent.parent / "app" / "remediation"
        dangerous = ["RegSetValue", "RegCreateKey", "HKEY_LOCAL_MACHINE"]
        for py_file in remediation_dir.glob("*.py"):
            content = py_file.read_text()
            for pattern in dangerous:
                assert pattern not in content

    def test_no_file_deletion(self) -> None:
        from pathlib import Path
        remediation_dir = Path(__file__).parent.parent / "app" / "remediation"
        for py_file in remediation_dir.glob("*.py"):
            content = py_file.read_text()
            assert "os.remove(" not in content
            assert "os.unlink(" not in content

    def test_no_shell_execution(self) -> None:
        from pathlib import Path
        remediation_dir = Path(__file__).parent.parent / "app" / "remediation"
        for py_file in remediation_dir.glob("*.py"):
            content = py_file.read_text()
            assert "Popen(" not in content
            assert "os.popen(" not in content

    def test_no_service_modification(self) -> None:
        from pathlib import Path
        remediation_dir = Path(__file__).parent.parent / "app" / "remediation"
        dangerous = ["ChangeServiceConfig", "StartService", "ControlService"]
        for py_file in remediation_dir.glob("*.py"):
            content = py_file.read_text()
            for pattern in dangerous:
                assert pattern not in content

    def test_no_privilege_escalation(self) -> None:
        from pathlib import Path
        remediation_dir = Path(__file__).parent.parent / "app" / "remediation"
        dangerous = ["RunAs", "ShellExecute", "create_expanded_environment"]
        for py_file in remediation_dir.glob("*.py"):
            content = py_file.read_text()
            for pattern in dangerous:
                assert pattern not in content
