import re
import subprocess
import sys
from pathlib import Path
from typing import Final

from clients.analyzers.base import IStaticAnalyzer
from models.base import StaticAnalyzerReport
from models.bugbear_report import BugbearIssue

BUGBEAR_SECURITY_RULES: Final[tuple[str, ...]] = (
    "B002",  # ``++n`` is a no-op: counters (failed logins, rate limits) never move
    "B003",  # assigning ``os.environ`` leaves subprocesses with stale configuration
    "B005",  # multi-character ``.strip()`` strips characters, not a prefix/suffix (sanitizers)
    "B006",  # mutable default argument shared by every call (cross-request state)
    "B008",  # call in a default evaluated once (shared object, reused token/time)
    "B012",  # return/break/continue in ``finally`` silences exceptions (fail-open)
    "B015",  # comparison result unused: a check that is never enforced
    "B019",  # ``functools.cache`` on methods: cache shared across instances, unbounded growth
    "B023",  # closure does not bind the loop variable: callbacks act on the last value
    "B032",  # ``x: value`` annotation where an assignment was intended
    "B034",  # ``re.sub``/``re.split`` count/flags passed positionally (sanitizer regex flags lost)
    "B039",  # mutable or call-evaluated ``ContextVar`` default shared across contexts
    "B909",  # mutating a collection while iterating it skips elements (filters, validation)
)
"""Bugbear rules whose findings can be real vulnerabilities or logic bugs; style,
test-hygiene and performance rules are left out."""

DEFAULT_ARGUMENT_FACTORIES: Final[tuple[str, ...]] = tuple(
    f"{prefix}{name}"
    for prefix in ("", "fastapi.")
    for name in ("Depends", "Security", "Query", "Path", "Body", "Header", "Cookie", "Form", "File")
)
"""Framework parameter markers that are idiomatic call defaults (exempt from B008)."""

_FLAKE8_LINE: Final[re.Pattern[str]] = re.compile(r"^(.*?):(\d+):(\d+):\s+([A-Z]+\d+)\s+(.*)$")


class BugbearStaticAnalyzer(IStaticAnalyzer):
    """Run the security-relevant flake8-bugbear rules via flake8 and parse the default output.

    flake8 prints ``<path>:<line>:<col>: <code> <message>`` per finding.
    """

    src: Path

    def run(self) -> StaticAnalyzerReport[BugbearIssue]:  # type: ignore
        # flake8 exits non-zero when it reports issues, so the exit code is not checked.
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "flake8",
                f"--select={','.join(BUGBEAR_SECURITY_RULES)}",
                f"--extend-immutable-calls={','.join(DEFAULT_ARGUMENT_FACTORIES)}",
                str(self.src),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        return StaticAnalyzerReport(
            issues=[
                BugbearIssue(
                    code=match[4],
                    file=Path(match[1]),
                    reason=match[5].strip(),
                    line_number=int(match[2]),
                    column_number=int(match[3]),
                )
                for line in result.stdout.splitlines()
                if (match := _FLAKE8_LINE.match(line.strip()))
            ]
        )
