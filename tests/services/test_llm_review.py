"""Unit tests for LLMCodeReviewService response parsing."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "llm_scanner"))

from clients.openai_compatible import OpenAICompatibleClient  # noqa: E402
from models.bandit_report import IssueSeverity  # noqa: E402
from models.scan import ScanSeverity  # noqa: E402
from models.static_finding import AnalyzerTool, StaticFinding  # noqa: E402
from services.llm_review import LLMCodeReviewService, ReviewItem  # noqa: E402

_CONTEXT_TEXT = "def run(cmd):\n    import os\n    os.system(cmd)"


def _make_finding(*, is_root: bool = True, snippet_line: int = 3) -> StaticFinding:
    return StaticFinding(
        tool=AnalyzerTool.BANDIT,
        rule_id="B605",
        cwe_id=78,
        severity=IssueSeverity.HIGH,
        message="Starting a process\n  with a shell.",
        file_path=Path("main.py"),
        repo_line=snippet_line,
        snippet_line=snippet_line,
        is_root=is_root,
    )


def _make_item(**kwargs: object) -> ReviewItem:
    defaults: dict[str, object] = {
        "root_id": "root1",
        "file_path": Path("main.py"),
        "line_start": 1,
        "line_end": 5,
        "context_text": "def foo(): pass",
        "static_findings": [],
    }
    defaults.update(kwargs)
    return ReviewItem(**defaults)  # type: ignore[arg-type]


def _make_service() -> LLMCodeReviewService:
    client = OpenAICompatibleClient(base_url="http://localhost/v1", api_key="x", model="m")
    return LLMCodeReviewService(client=client)


class TestLLMCodeReviewServiceParsing:
    """Tests for _parse_response — the JSON-parsing core of the review service."""

    def test_vulnerable_true_high_severity(self) -> None:
        svc = _make_service()
        item = _make_item()
        response = (
            'Reasoning text.\n{"vulnerable": true, "severity": "HIGH", '
            '"description": "SQL injection", "cwe_id": 89}'
        )
        f = svc._parse_response(item, response)
        assert f.vulnerable is True
        assert f.severity == ScanSeverity.HIGH
        assert f.cwe_id == 89
        assert "SQL injection" in (f.description or "")

    def test_not_vulnerable(self) -> None:
        svc = _make_service()
        f = svc._parse_response(
            _make_item(),
            '{"vulnerable": false, "severity": null, "description": null, "cwe_id": null}',
        )
        assert f.vulnerable is False
        assert f.severity is None

    def test_json_buried_in_reasoning(self) -> None:
        """JSON at end of long reasoning text is still parsed."""
        long_prefix = "Let me think...\n" * 20
        response = (
            long_prefix
            + '{"vulnerable": true, "severity": "MEDIUM", "description": "XSS", "cwe_id": 79}'
        )
        svc = _make_service()
        f = svc._parse_response(_make_item(), response)
        assert f.vulnerable is True
        assert f.severity == ScanSeverity.MEDIUM

    def test_fallback_on_no_json(self) -> None:
        """Malformed response → default to not vulnerable, no crash."""
        svc = _make_service()
        f = svc._parse_response(_make_item(), "No JSON here at all, just text.")
        assert f.vulnerable is False

    def test_fallback_on_invalid_json(self) -> None:
        svc = _make_service()
        f = svc._parse_response(_make_item(), "{broken json ]}")
        assert f.vulnerable is False

    def test_critical_severity(self) -> None:
        svc = _make_service()
        f = svc._parse_response(
            _make_item(),
            '{"vulnerable": true, "severity": "CRITICAL", "description": "RCE", "cwe_id": 94}',
        )
        assert f.severity == ScanSeverity.CRITICAL

    def test_cwe_as_string_int(self) -> None:
        """LLM may return cwe_id as a string digit."""
        svc = _make_service()
        f = svc._parse_response(
            _make_item(),
            '{"vulnerable": true, "severity": "LOW", "description": "d", "cwe_id": "22"}',
        )
        assert f.cwe_id == 22

    def test_static_findings_preserved(self) -> None:
        finding = _make_finding()
        item = _make_item(static_findings=[finding])
        svc = _make_service()
        f = svc._parse_response(
            item,
            '{"vulnerable": false, "severity": null, "description": null, "cwe_id": null}',
        )
        assert f.static_findings == [finding]

    def test_empty_review_returns_empty_list(self) -> None:
        """review([]) short-circuits without calling the LLM."""
        svc = _make_service()
        findings = svc.review([])
        assert findings == []

    def test_low_severity(self) -> None:
        svc = _make_service()
        f = svc._parse_response(
            _make_item(),
            '{"vulnerable": true, "severity": "LOW", "description": "minor issue", "cwe_id": null}',
        )
        assert f.severity == ScanSeverity.LOW
        assert f.cwe_id is None


class TestLLMCodeReviewServicePrompt:
    """Tests for _build_messages — the strict v2 prompt and its static-findings block."""

    def test_system_prompt_is_strict_v2_with_output_contract(self) -> None:
        system = _make_service()._build_messages(_make_item())[0].content
        assert system.startswith("You are a code security analyst. Determine whether")
        assert "False alarms are costly." in system
        assert '"vulnerable" (bool)' in system

    def test_user_prompt_renders_root_findings(self) -> None:
        item = _make_item(context_text=_CONTEXT_TEXT, static_findings=[_make_finding()])
        user = _make_service()._build_messages(item)[1].content
        assert user == (
            "Analyze this code for a real, exploitable security vulnerability:\n\n"
            f"{_CONTEXT_TEXT}\n\n"
            "Static analyzer findings in the function under analysis "
            "(automated tools; may be false positives):\n"
            "1. [bandit B605 | CWE-78 | HIGH] Starting a process with a shell.\n"
            "   Flagged line: os.system(cmd)"
        )

    def test_user_prompt_skips_context_only_findings(self) -> None:
        item = _make_item(
            context_text=_CONTEXT_TEXT, static_findings=[_make_finding(is_root=False)]
        )
        user = _make_service()._build_messages(item)[1].content
        assert user.endswith(
            "\n\nStatic analyzer findings in the function under analysis: none reported."
        )
