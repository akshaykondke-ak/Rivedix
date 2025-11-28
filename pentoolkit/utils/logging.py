"""
Pentoolkit Logging Infrastructure
Provides structured logging with file rotation, severity filtering, and context tracking.
"""

import logging
import sys
from pathlib import Path
from logging.handlers import RotatingFileHandler
from typing import Optional
from datetime import datetime


class PentoolkitLogger:
    """
    Centralized logger for Pentoolkit with:
    - Console + file output
    - Automatic log rotation
    - Contextual logging (run_id, tool, target)
    - Severity-based filtering
    """

    _instances = {}  # Singleton per name

    def __init__(
        self,
        name: str = "pentoolkit",
        log_level: str = "INFO",
        log_dir: str = "results/logs",
        console_output: bool = True,
        file_output: bool = True,
        max_bytes: int = 10 * 1024 * 1024,  # 10MB
        backup_count: int = 5,
    ):
        """
        Initialize logger with file rotation and console output.
        
        Args:
            name: Logger name (use different names for different components)
            log_level: Minimum severity (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            log_dir: Directory for log files
            console_output: Enable console logging
            file_output: Enable file logging
            max_bytes: Max log file size before rotation
            backup_count: Number of backup files to keep
        """
        self.name = name
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        # Create logger
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, log_level.upper()))
        self.logger.handlers.clear()  # Remove any existing handlers

        # Formatter with timestamp, level, name, and message
        formatter = logging.Formatter(
            fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )

        # Console handler
        if console_output:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setFormatter(formatter)
            console_handler.setLevel(logging.INFO)  # Console shows INFO+
            self.logger.addHandler(console_handler)

        # File handler with rotation
        if file_output:
            log_file = self.log_dir / f"{name}.log"
            file_handler = RotatingFileHandler(
                log_file,
                maxBytes=max_bytes,
                backupCount=backup_count,
                encoding="utf-8"
            )
            file_handler.setFormatter(formatter)
            file_handler.setLevel(logging.DEBUG)  # File captures everything
            self.logger.addHandler(file_handler)

        # Context storage (run_id, tool, target)
        self._context = {}

    @classmethod
    def get_logger(
        cls,
        name: str = "pentoolkit",
        log_level: str = "INFO",
        **kwargs
    ) -> "PentoolkitLogger":
        """
        Get or create a logger instance (singleton per name).
        
        Usage:
            logger = PentoolkitLogger.get_logger("pentoolkit.runner")
            logger.info("Starting scan")
        """
        if name not in cls._instances:
            cls._instances[name] = cls(name=name, log_level=log_level, **kwargs)
        return cls._instances[name]

    def set_context(self, **kwargs):
        """
        Set contextual information for subsequent logs.
        
        Example:
            logger.set_context(run_id="20241127_example", tool="nmap")
            logger.info("Scan started")  # Will include context
        """
        self._context.update(kwargs)

    def clear_context(self):
        """Clear all context information."""
        self._context.clear()

    def _format_message(self, msg: str) -> str:
        """Add context to message if available."""
        if not self._context:
            return msg
        
        context_str = " | ".join(f"{k}={v}" for k, v in self._context.items())
        return f"[{context_str}] {msg}"

    # Standard logging methods
    def debug(self, msg: str, **kwargs):
        """Log debug message."""
        self.logger.debug(self._format_message(msg), **kwargs)

    def info(self, msg: str, **kwargs):
        """Log info message."""
        self.logger.info(self._format_message(msg), **kwargs)

    def warning(self, msg: str, **kwargs):
        """Log warning message."""
        self.logger.warning(self._format_message(msg), **kwargs)

    def error(self, msg: str, exc_info: bool = False, **kwargs):
        """
        Log error message.
        
        Args:
            msg: Error message
            exc_info: Include exception traceback
        """
        self.logger.error(self._format_message(msg), exc_info=exc_info, **kwargs)

    def critical(self, msg: str, exc_info: bool = False, **kwargs):
        """Log critical message."""
        self.logger.critical(self._format_message(msg), exc_info=exc_info, **kwargs)

    def exception(self, msg: str, **kwargs):
        """Log exception with full traceback."""
        self.logger.exception(self._format_message(msg), **kwargs)

    # Convenience methods for common patterns
    def log_tool_start(self, tool: str, target: str):
        """Log tool execution start."""
        self.set_context(tool=tool, target=target)
        self.info(f"Starting {tool} scan")

    def log_tool_end(self, tool: str, target: str, success: bool, duration: float = None):
        """Log tool execution end."""
        status = "SUCCESS" if success else "FAILED"
        duration_str = f" ({duration:.2f}s)" if duration else ""
        self.info(f"Finished {tool} scan - {status}{duration_str}")
        self.clear_context()

    def log_tool_error(self, tool: str, target: str, error: Exception):
        """Log tool execution error with traceback."""
        self.set_context(tool=tool, target=target)
        self.exception(f"Tool execution failed: {error}")
        self.clear_context()

    def log_scan_summary(self, run_id: str, targets: list, tools: list, total_findings: int):
        """Log scan completion summary."""
        self.set_context(run_id=run_id)
        self.info(
            f"Scan completed: {len(targets)} target(s), "
            f"{len(tools)} tool(s), {total_findings} finding(s)"
        )
        self.clear_context()


# Global logger instance
_default_logger: Optional[PentoolkitLogger] = None


def get_logger(name: str = "pentoolkit", **kwargs) -> PentoolkitLogger:
    """
    Get the default Pentoolkit logger.
    
    Usage:
        from pentoolkit.utils.logging import get_logger
        logger = get_logger()
        logger.info("Application started")
    """
    global _default_logger
    if _default_logger is None:
        _default_logger = PentoolkitLogger.get_logger(name, **kwargs)
    return _default_logger


def init_logging(log_level: str = "INFO", log_dir: str = "results/logs"):
    """
    Initialize the default logger with custom settings.
    Call this once at application startup.
    
    Usage:
        from pentoolkit.utils.logging import init_logging
        init_logging(log_level="DEBUG")
    """
    global _default_logger
    _default_logger = PentoolkitLogger.get_logger(
        name="pentoolkit",
        log_level=log_level,
        log_dir=log_dir
    )
    return _default_logger