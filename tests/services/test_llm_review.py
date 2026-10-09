"""Unit tests for LLMCodeReviewService response parsing."""

import json
import sys
from pathlib import Path
from typing import cast

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "llm_scanner"))

from clients.openai_compatible import OpenAICompatibleClient  # noqa: E402
from models.bandit_report import IssueSeverity  # noqa: E402
from models.scan import ScanSeverity  # noqa: E402
from models.static_finding import AnalyzerTool, StaticFinding  # noqa: E402
from services.llm_review import (  # noqa: E402
    LLMCodeReviewService,
    ReviewItem,
    ReviewRoot,
)
from services.llm_review import _context_seed as _make_service_seed  # noqa: E402

_SAFE_VERDICT = '{"vulnerable": false, "severity": null, "description": null, "cwe_id": null}'
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

    def test_system_prompt_requires_numeric_range_checks(self) -> None:
        system = _make_service()._build_messages(_make_item())[0].content
        assert "checked for sign and range, not only type" in system

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


class TestLLMCodeReviewServiceStructuredOutput:
    """Tests for the optional schema-constrained review replies."""

    def test_bare_json_with_braces_in_description(self) -> None:
        description = "f'ping {host}' runs in a shell. " + "x" * 600
        response = json.dumps(
            {"vulnerable": True, "severity": "HIGH", "description": description, "cwe_id": 78}
        )
        f = _make_service()._parse_response(_make_item(), response)
        assert f.vulnerable is True
        assert f.description == description
        assert f.cwe_id == 78

    @pytest.mark.parametrize("structured_output", [True, False])
    def test_review_sends_schema_only_when_enabled(
        self, monkeypatch: pytest.MonkeyPatch, structured_output: bool
    ) -> None:
        captured: dict[str, object] = {}

        async def fake_chat_batch_samples(
            _self: OpenAICompatibleClient, batches: list[object], **kwargs: object
        ) -> list[list[str]]:
            captured.update(kwargs)
            return [[_SAFE_VERDICT]]

        monkeypatch.setattr(OpenAICompatibleClient, "chat_batch_samples", fake_chat_batch_samples)
        svc = _make_service().model_copy(update={"structured_output": structured_output})

        svc.review([_make_item()])

        response_format = captured["response_format"]
        if not structured_output:
            assert response_format is None
            return
        assert isinstance(response_format, dict)
        schema = response_format["json_schema"]["schema"]
        assert schema["required"] == ["vulnerable", "severity", "description", "cwe_id", "root"]


class TestLLMCodeReviewServiceFencedJson:
    """Regression: fenced verdicts quoting code with braces were dropped as not vulnerable."""

    def test_fenced_json_with_braces_in_description(self) -> None:
        response = (
            "Reasoning.\n```json\n{\n"
            '  "vulnerable": true,\n  "severity": "HIGH",\n'
            '  "description": "sort_field reaches `ORDER BY {sort_field} {direction}`.",\n'
            '  "cwe_id": 89\n}\n```'
        )
        f = _make_service()._parse_response(_make_item(), response)
        assert f.vulnerable is True
        assert f.cwe_id == 89

    def test_last_verdict_wins(self) -> None:
        response = (
            'Draft: {"vulnerable": true, "severity": "LOW", "description": "x", "cwe_id": 1}\n'
            'Final: {"vulnerable": false, "severity": null, "description": null, "cwe_id": null}'
        )
        assert _make_service()._parse_response(_make_item(), response).vulnerable is False

    def test_runaway_integer_is_not_a_crash(self) -> None:
        response = '{"vulnerable": true, "severity": "HIGH", "description": "d", "cwe_id": ' + (
            "1" * 5000 + "}"
        )
        assert _make_service()._parse_response(_make_item(), response).vulnerable is False


def _vuln_verdict(description: str) -> str:
    return json.dumps(
        {"vulnerable": True, "severity": "HIGH", "description": description, "cwe_id": 89}
    )


class TestLLMCodeReviewServiceSelfConsistency:
    """Tests for majority voting over sampled completions."""

    def test_majority_vulnerable_takes_first_agreeing_sample(self) -> None:
        responses = [_SAFE_VERDICT, _vuln_verdict("first"), _vuln_verdict("second")]
        f = _make_service()._build_finding(_make_item(), responses)
        assert f.vulnerable is True
        assert f.description == "first"
        assert (f.vulnerable_votes, f.total_votes) == (2, 3)

    def test_majority_safe_drops_minority_details(self) -> None:
        responses = [_vuln_verdict("lone"), _SAFE_VERDICT, "no json at all"]
        f = _make_service()._build_finding(_make_item(), responses)
        assert f.vulnerable is False
        assert f.description is None
        assert (f.vulnerable_votes, f.total_votes) == (1, 3)

    def test_tie_goes_to_first_label(self) -> None:
        responses = [_vuln_verdict("first"), _SAFE_VERDICT]
        assert _make_service()._build_finding(_make_item(), responses).vulnerable is True

    def test_review_orders_requests_by_context_and_restores_input_order(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured: dict[str, object] = {}

        async def fake_chat_batch_samples(
            _self: OpenAICompatibleClient, batches: list[list[object]], **kwargs: object
        ) -> list[list[str]]:
            captured.update(kwargs, batches=batches)
            return [
                [_vuln_verdict(str(batch[1]))] * 3
                if "b_ctx" in str(batch[1])
                else [_SAFE_VERDICT] * 3
                for batch in batches
            ]

        monkeypatch.setattr(OpenAICompatibleClient, "chat_batch_samples", fake_chat_batch_samples)
        svc = _make_service().model_copy(update={"self_consistency_samples": 3})
        items = [_make_item(context_text="b_ctx"), _make_item(context_text="a_ctx")]

        findings = svc.review(items)

        assert [f.vulnerable for f in findings] == [True, False]
        assert captured["samples"] == 3
        sent = cast(list[list[object]], captured["batches"])
        assert "a_ctx" in str(sent[0][1]) and "b_ctx" in str(sent[1][1])
        seeds = cast(list[int], captured["seeds"])
        assert len(set(seeds)) == 2
        assert seeds == [_make_service_seed("a_ctx"), _make_service_seed("b_ctx")]


_GROUPED_CONTEXT: str = (
    "# ===== ROOT 1/2: a.py:1-2 | code under analysis =====\n"
    "def a(): pass\n"
    "# ===== ROOT 2/2: b.py:5-9 | code under analysis =====\n"
    "def b(cmd):\n"
    "    os.system(cmd)"
)
_GROUPED_ROOTS: tuple[ReviewRoot, ...] = (
    ReviewRoot(Path("/repo/a.py"), 1, 2),
    ReviewRoot(Path("/repo/b.py"), 5, 9),
)


def _rooted_verdict(root: object) -> str:
    return json.dumps(
        {"vulnerable": True, "severity": "HIGH", "description": "d", "cwe_id": 78, "root": root}
    )


class TestLLMCodeReviewServiceRootLocation:
    """Tests for locating grouped-context findings at the ROOT the model names."""

    def test_reported_root_sets_location(self) -> None:
        item = _make_item(context_text=_GROUPED_CONTEXT, roots=_GROUPED_ROOTS)
        f = _make_service()._parse_response(item, _rooted_verdict(2))
        assert (f.file_path, f.line_start, f.line_end) == (Path("/repo/b.py"), 5, 9)

    @pytest.mark.parametrize("root", [None, 0, 3, True])
    def test_invalid_root_falls_back_to_flagged_root(self, root: object) -> None:
        item = _make_item(
            context_text=_GROUPED_CONTEXT,
            roots=_GROUPED_ROOTS,
            static_findings=[_make_finding(snippet_line=5)],
        )
        f = _make_service()._parse_response(item, _rooted_verdict(root))
        assert f.file_path == Path("/repo/b.py")

    def test_invalid_root_without_findings_falls_back_to_first_root(self) -> None:
        item = _make_item(context_text=_GROUPED_CONTEXT, roots=_GROUPED_ROOTS)
        f = _make_service()._parse_response(item, _rooted_verdict(None))
        assert f.file_path == Path("/repo/a.py")

    def test_item_without_roots_keeps_item_location(self) -> None:
        f = _make_service()._parse_response(_make_item(), _rooted_verdict(1))
        assert (f.file_path, f.line_start, f.line_end) == (Path("main.py"), 1, 5)
