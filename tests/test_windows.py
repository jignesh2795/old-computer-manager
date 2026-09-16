"""Tests for windows collectors returning CollectorResult."""

from __future__ import annotations

from unittest.mock import patch

from app.collectors.result import CollectorResult
from app.collectors.windows import collect_bios, collect_computer_system, collect_os


class TestCollectOs:
    def test_returns_collector_result(self) -> None:
        result = collect_os()
        assert isinstance(result, CollectorResult)

    @patch("app.collectors.windows.platform")
    def test_not_supported_on_non_windows(self, mock_platform: object) -> None:
        mock_platform.system.return_value = "Linux"  # type: ignore[attr-defined]
        result = collect_os()
        assert result.status == "not_supported"
        assert result.payload is None
        assert result.error_message is None

    @patch("app.collectors.windows._powershell_json")
    def test_propagates_error_message(self, mock_ps: object) -> None:
        mock_ps.return_value = (None, "PowerShell exited with code 1")  # type: ignore[attr-defined]
        result = collect_os()
        assert result.status == "failed"
        assert result.error_message == "PowerShell exited with code 1"
        assert result.payload is None

    @patch("app.collectors.windows._powershell_json")
    def test_success(self, mock_ps: object) -> None:
        mock_ps.return_value = ({"Caption": "Windows 10"}, None)  # type: ignore[attr-defined]
        result = collect_os()
        assert result.status == "ok"
        assert result.payload == {"Caption": "Windows 10"}
        assert result.error_message is None


class TestCollectBios:
    def test_returns_collector_result(self) -> None:
        result = collect_bios()
        assert isinstance(result, CollectorResult)

    @patch("app.collectors.windows.platform")
    def test_not_supported_on_non_windows(self, mock_platform: object) -> None:
        mock_platform.system.return_value = "Darwin"  # type: ignore[attr-defined]
        result = collect_bios()
        assert result.status == "not_supported"

    @patch("app.collectors.windows._powershell_json")
    def test_propagates_error_message(self, mock_ps: object) -> None:
        mock_ps.return_value = (None, "JSON parse error: Expecting value")  # type: ignore[attr-defined]
        result = collect_bios()
        assert result.status == "failed"
        assert result.error_message == "JSON parse error: Expecting value"


class TestCollectComputerSystem:
    def test_returns_collector_result(self) -> None:
        result = collect_computer_system()
        assert isinstance(result, CollectorResult)

    @patch("app.collectors.windows.platform")
    def test_not_supported_on_non_windows(self, mock_platform: object) -> None:
        mock_platform.system.return_value = "Linux"  # type: ignore[attr-defined]
        result = collect_computer_system()
        assert result.status == "not_supported"

    @patch("app.collectors.windows._powershell_json")
    def test_propagates_error_message(self, mock_ps: object) -> None:
        mock_ps.return_value = (None, "powershell.exe not found")  # type: ignore[attr-defined]
        result = collect_computer_system()
        assert result.status == "failed"
        assert result.error_message == "powershell.exe not found"
