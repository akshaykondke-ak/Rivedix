import datetime
from typing import Any, Dict, List
from ..pentoolkit.modules.base import PentoolkitModule


class TemplateModule:
    """
    Base module class. All scanning modules should inherit from this.

    Standard module lifecycle:
        1. prepare()
        2. validate_target()
        3. run()
        4. parse_output()
        5. format_findings()
        6. return standardized result dict
    """

    # Basic module metadata (override in each module)
    name: str = "base"
    description: str = "Base Pentoolkit Module"
    version: str = "0.1"

    def __init__(self, config=None, logger=None):
        self.config = config
        self.logger = logger
        self.raw_output = ""     # raw scanner output
        self.findings = []       # parsed issues/facts

    # -------------------------------------------------------------
    # Phase 1 — PREPARE MODULE
    # -------------------------------------------------------------
    def prepare(self) -> None:
        """Optional: prepare environment, check binary exists, etc."""
        pass

    # -------------------------------------------------------------
    # Phase 2 — VALIDATE TARGET INPUT
    # -------------------------------------------------------------
    def validate_target(self, target: str) -> bool:
        """Validate target (host/IP). Override as needed."""
        if not target:
            raise ValueError("Target cannot be empty.")
        return True

    # -------------------------------------------------------------
    # Phase 3 — MAIN EXECUTION FUNCTION
    # -------------------------------------------------------------
    def run(self, target: str) -> Dict[str, Any]:
        """
        Main logic of the module.
        This must be implemented by child classes.
        Should return raw scanner output or combined structured output.
        """
        raise NotImplementedError("Module must implement run().")

    # -------------------------------------------------------------
    # Phase 4 — PARSE OUTPUT
    # -------------------------------------------------------------
    def parse_output(self) -> List[Dict[str, Any]]:
        """
        Parse raw tool output. Override based on tool format.
        Must return list of findings.
        """
        return []

    # -------------------------------------------------------------
    # Phase 5 — FORMAT FINDINGS FOR REPORT
    # -------------------------------------------------------------
    def format_findings(self) -> List[Dict[str, Any]]:
        """
        Standardize findings:
           - title
           - description
           - severity
           - evidence
        """
        formatted = []
        for f in self.findings:
            formatted.append({
                "title": f.get("title", "Unknown Finding"),
                "description": f.get("description", "No description"),
                "severity": f.get("severity", "info"),
                "evidence": f.get("evidence", ""),
            })
        return formatted

    # -------------------------------------------------------------
    # Phase 6 — FINAL RESULT STRUCTURE
    # -------------------------------------------------------------
    def build_result(self) -> Dict[str, Any]:
        finished = datetime.datetime.utcnow().isoformat()

        return {
            "metadata": {
                "tool": self.name,
                "description": self.description,
                "version": self.version,
                "finished": finished,
            },
            "findings": self.format_findings(),
            "raw": self.raw_output,
        }
