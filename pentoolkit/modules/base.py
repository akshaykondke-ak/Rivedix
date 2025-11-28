"""
Base module class for all Pentoolkit security tools.
Provides lifecycle hooks, error handling, and standardized output.
"""

import datetime
import shutil
from typing import Any, Dict, List, Optional
from pathlib import Path

from pentoolkit.utils.process import ProcessExecutor, ProcessResult
from pentoolkit.utils.helpers import normalize_target, validate_severity


class PentoolkitModule:
    """
    Base class for all security tool modules.
    
    Lifecycle:
        1. __init__() - Initialize with config and logger
        2. prepare() - Validate binary and prerequisites
        3. validate_target() - Check target format
        4. run() - Execute the tool (MUST OVERRIDE)
        5. parse_output() - Parse raw output into findings
        6. build_result() - Create standardized result dict
    
    Standardized Output Format:
        {
            "metadata": {
                "tool": "nmap",
                "target": "example.com",
                "version": "1.0",
                "finished": "2024-11-27T10:30:00Z",
                "duration": 45.2,
                "success": true,
                "error": null
            },
            "findings": [
                {
                    "title": "Open Port 443/tcp",
                    "description": "HTTPS service detected",
                    "severity": "info",
                    "evidence": "443/tcp open https"
                }
            ],
            "raw": "raw tool output here"
        }
    """

    # Module metadata (override in child classes)
    name: str = "base"
    description: str = "Base Pentoolkit Module"
    version: str = "1.0"
    
    # Binary requirements (set in child classes)
    required_binary: Optional[str] = None
    min_version: Optional[str] = None

    def __init__(self, config: Optional[Any] = None, logger: Optional[Any] = None):
        """
        Initialize module.
        
        Args:
            config: Tool configuration from config.yaml
            logger: Logger instance (from utils.logging)
        """
        self.config = config
        self.logger = logger
        
        # Execution state
        self.raw_output: str = ""
        self.findings: List[Dict[str, Any]] = []
        self.binary_path: Optional[str] = None
        
        # Runtime hints (set by runner or CLI)
        self.selected_scan_type: Optional[str] = None
        
        # Process executor for safe subprocess calls
        self.executor = ProcessExecutor(
            default_timeout=self._get_timeout(),
            logger=logger
        )
        
        # Execution metadata
        self._start_time: Optional[float] = None
        self._end_time: Optional[float] = None
        self._error: Optional[str] = None

    # ========================================================================
    # CONFIGURATION HELPERS
    # ========================================================================

    def _get_config_value(self, key: str, default: Any = None) -> Any:
        """
        Safely get configuration value.
        
        Args:
            key: Configuration key
            default: Default value if not found
            
        Returns:
            Configuration value or default
        """
        if self.config is None:
            return default
        return getattr(self.config, key, default)

    def _get_timeout(self) -> int:
        """Get tool timeout from config or use default."""
        return self._get_config_value("timeout", 300)

    def _get_binary_path(self) -> str:
        """Get binary path from config or use binary name."""
        return self._get_config_value("path", self.required_binary or self.name)

    # ========================================================================
    # LIFECYCLE HOOKS
    # ========================================================================

    def prepare(self) -> None:
        """
        Prepare module for execution.
        - Validates required binary exists
        - Checks version if needed
        - Sets up any prerequisites
        
        Override this in child classes for custom preparation.
        
        Raises:
            RuntimeError: If binary not found or version incompatible
        """
        if self.required_binary:
            binary_name = self._get_binary_path()
            
            if self.logger:
                self.logger.debug(f"Validating binary: {binary_name}")
            
            # Validate binary
            is_valid, path_or_error = self.executor.validate_binary(
                binary_name,
                min_version=self.min_version
            )
            
            if not is_valid:
                raise RuntimeError(
                    f"Binary validation failed for {binary_name}: {path_or_error}"
                )
            
            self.binary_path = path_or_error
            
            if self.logger:
                self.logger.info(f"Binary validated: {self.binary_path}")

    def validate_target(self, target: str) -> bool:
        """
        Validate target format.
        
        Args:
            target: Target (IP, domain, or URL)
            
        Returns:
            True if valid
            
        Raises:
            ValueError: If target is invalid
        """
        if not target or not isinstance(target, str):
            raise ValueError("Target must be a non-empty string")
        
        # Normalize target
        target = normalize_target(target)
        
        if not target:
            raise ValueError("Target is empty after normalization")
        
        return True

    def run(self, target: str) -> str:
        """
        Execute the tool on target.
        
        **MUST BE OVERRIDDEN IN CHILD CLASSES**
        
        Args:
            target: Target to scan
            
        Returns:
            Raw output from tool
            
        Raises:
            NotImplementedError: If not overridden
        """
        raise NotImplementedError(
            f"{self.__class__.__name__} must implement run(target) method"
        )

    def parse_output(self) -> List[Dict[str, Any]]:
        """
        Parse raw output into structured findings.
        
        Override this in child classes to parse tool-specific output.
        
        Returns:
            List of finding dictionaries
        """
        # Default: return empty findings
        # Child classes should override this
        return []

    # ========================================================================
    # RESULT FORMATTING
    # ========================================================================

    def format_findings(self) -> List[Dict[str, Any]]:
        """
        Format findings with validation and standardization.
        
        Returns:
            List of validated findings
        """
        formatted = []
        
        for finding in self.findings:
            # Validate severity
            severity = finding.get("severity", "info").lower()
            if not validate_severity(severity):
                severity = "info"
            
            formatted.append({
                "title": finding.get("title", "Unknown Finding"),
                "description": finding.get("description", "No description available"),
                "severity": severity,
                "evidence": finding.get("evidence", ""),
                # Preserve any additional fields
                **{k: v for k, v in finding.items() 
                   if k not in ("title", "description", "severity", "evidence")}
            })
        
        return formatted

    def build_result(self, target: str) -> Dict[str, Any]:
        """
        Build standardized result dictionary.
        
        Args:
            target: Target that was scanned
            
        Returns:
            Standardized result dictionary
        """
        import time
        
        finished = datetime.datetime.now(datetime.UTC).isoformat()
        
        # Calculate duration if timing available
        duration = None
        if self._start_time and self._end_time:
            duration = self._end_time - self._start_time
        
        return {
            "metadata": {
                "tool": self.name,
                "target": target,
                "description": self.description,
                "version": self.version,
                "finished": finished,
                "duration": duration,
                "success": self._error is None,
                "error": self._error
            },
            "findings": self.format_findings(),
            "raw": self.raw_output,
        }

    # ========================================================================
    # HELPER METHODS
    # ========================================================================

    def _require_binary(self, name: str, path_hint: Optional[str] = None) -> str:
        """
        DEPRECATED: Use prepare() instead.
        
        Check for binary existence and return path.
        
        Args:
            name: Binary name
            path_hint: Optional explicit path
            
        Returns:
            Path to binary
            
        Raises:
            RuntimeError: If binary not found
        """
        if path_hint:
            # Try explicit path first
            if shutil.which(path_hint):
                return path_hint
        
        # Check PATH
        binary_path = shutil.which(name)
        if not binary_path:
            raise RuntimeError(f"Required binary '{name}' not found in PATH")
        
        return binary_path

    def _run_command(
        self,
        cmd: str | List[str],
        timeout: Optional[int] = None,
        **kwargs
    ) -> ProcessResult:
        """
        Execute a command safely using ProcessExecutor.
        
        Args:
            cmd: Command string or list
            timeout: Timeout in seconds
            **kwargs: Additional arguments for ProcessExecutor.run()
            
        Returns:
            ProcessResult object
        """
        return self.executor.run(cmd, timeout=timeout, **kwargs)

    def _add_finding(
        self,
        title: str,
        description: str,
        severity: str = "info",
        evidence: str = "",
        **extra_fields
    ):
        """
        Add a finding to the results.
        
        Args:
            title: Finding title
            description: Finding description
            severity: Severity level
            evidence: Supporting evidence
            **extra_fields: Additional custom fields
        """
        finding = {
            "title": title,
            "description": description,
            "severity": severity.lower(),
            "evidence": evidence,
            **extra_fields
        }
        self.findings.append(finding)

    def _log_info(self, msg: str):
        """Log info message if logger available."""
        if self.logger:
            self.logger.info(f"[{self.name}] {msg}")

    def _log_debug(self, msg: str):
        """Log debug message if logger available."""
        if self.logger:
            self.logger.debug(f"[{self.name}] {msg}")

    def _log_warning(self, msg: str):
        """Log warning message if logger available."""
        if self.logger:
            self.logger.warning(f"[{self.name}] {msg}")

    def _log_error(self, msg: str, exc_info: bool = False):
        """Log error message if logger available."""
        if self.logger:
            self.logger.error(f"[{self.name}] {msg}", exc_info=exc_info)

    # ========================================================================
    # CONTEXT MANAGERS (OPTIONAL)
    # ========================================================================

    def __enter__(self):
        """Context manager entry."""
        import time
        self._start_time = time.time()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        import time
        self._end_time = time.time()
        
        if exc_val:
            self._error = str(exc_val)
            self._log_error(f"Execution failed: {exc_val}", exc_info=True)
        
        return False  # Don't suppress exceptions


# Convenience base class for tools that need binary validation
class BinaryModule(PentoolkitModule):
    """
    Base class for modules that require a specific binary.
    Automatically validates binary in prepare().
    
    Usage:
        class NmapModule(BinaryModule):
            required_binary = "nmap"
            min_version = "7.0"
    """
    
    def prepare(self) -> None:
        """Validate required binary (calls parent implementation)."""
        if not self.required_binary:
            raise RuntimeError(
                f"{self.__class__.__name__} must set 'required_binary' attribute"
            )
        super().prepare()
