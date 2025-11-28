"""
Safe subprocess execution utilities for Pentoolkit.
Handles timeouts, retries, error handling, and secure command execution.
"""

import subprocess
import shlex
import time
from typing import Optional, List, Tuple, Dict, Any
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ProcessResult:
    """
    Result of a subprocess execution.
    
    Attributes:
        stdout: Standard output
        stderr: Standard error
        returncode: Process exit code
        success: True if returncode == 0
        duration: Execution time in seconds
        timed_out: True if process exceeded timeout
        error: Exception message if execution failed
    """
    stdout: str
    stderr: str
    returncode: int
    success: bool
    duration: float
    timed_out: bool = False
    error: Optional[str] = None

    def has_output(self) -> bool:
        """Check if process produced any output."""
        return bool(self.stdout.strip() or self.stderr.strip())

    def get_combined_output(self) -> str:
        """Get stdout + stderr combined."""
        out = self.stdout.strip()
        err = self.stderr.strip()
        if out and err:
            return f"{out}\n{err}"
        return out or err


class ProcessExecutor:
    """
    Safe subprocess execution with retries, timeouts, and error handling.
    """

    def __init__(
        self,
        default_timeout: int = 300,
        max_retries: int = 0,
        retry_delay: float = 1.0,
        logger=None
    ):
        """
        Initialize executor.
        
        Args:
            default_timeout: Default timeout in seconds
            max_retries: Number of retry attempts on failure
            retry_delay: Delay between retries in seconds
            logger: Optional logger instance
        """
        self.default_timeout = default_timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.logger = logger

    def run(
        self,
        cmd: str | List[str],
        timeout: Optional[int] = None,
        retries: Optional[int] = None,
        shell: bool = False,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        stdin: Optional[str] = None,
        check_returncode: bool = False,
    ) -> ProcessResult:
        """
        Execute a command safely.
        
        Args:
            cmd: Command string or list of arguments
            timeout: Timeout in seconds (uses default if None)
            retries: Number of retries (uses default if None)
            shell: Execute through shell (DANGEROUS - avoid if possible)
            cwd: Working directory
            env: Environment variables
            stdin: Input to pass to process
            check_returncode: Raise exception if returncode != 0
            
        Returns:
            ProcessResult with execution details
            
        Raises:
            RuntimeError: If check_returncode=True and process fails
        """
        timeout = timeout or self.default_timeout
        retries = retries if retries is not None else self.max_retries
        
        attempt = 0
        last_error = None
        
        while attempt <= retries:
            try:
                if attempt > 0:
                    if self.logger:
                        self.logger.warning(
                            f"Retry attempt {attempt}/{retries} after {self.retry_delay}s delay"
                        )
                    time.sleep(self.retry_delay)
                
                result = self._execute_once(
                    cmd=cmd,
                    timeout=timeout,
                    shell=shell,
                    cwd=cwd,
                    env=env,
                    stdin=stdin
                )
                
                # Success - return immediately
                if result.success or not result.timed_out:
                    if check_returncode and not result.success:
                        raise RuntimeError(
                            f"Command failed (rc={result.returncode}): {result.stderr}"
                        )
                    return result
                
                # Timed out - retry
                last_error = "Process timed out"
                attempt += 1
                
            except Exception as e:
                last_error = str(e)
                if self.logger:
                    self.logger.error(f"Execution attempt {attempt} failed: {e}")
                attempt += 1
        
        # All retries exhausted
        error_msg = f"Command failed after {retries + 1} attempts: {last_error}"
        if self.logger:
            self.logger.error(error_msg)
        
        return ProcessResult(
            stdout="",
            stderr=last_error or "",
            returncode=-1,
            success=False,
            duration=0.0,
            timed_out=True,
            error=error_msg
        )

    def _execute_once(
        self,
        cmd: str | List[str],
        timeout: int,
        shell: bool,
        cwd: Optional[str],
        env: Optional[Dict[str, str]],
        stdin: Optional[str]
    ) -> ProcessResult:
        """Execute command once and return result."""
        start_time = time.time()
        timed_out = False
        error = None
        
        try:
            # Prepare command
            if isinstance(cmd, str) and not shell:
                # Split string into args for safety (avoid shell injection)
                cmd_args = shlex.split(cmd)
            else:
                cmd_args = cmd
            
            # Log execution
            if self.logger:
                cmd_str = cmd if isinstance(cmd, str) else " ".join(cmd)
                self.logger.debug(f"Executing: {cmd_str[:200]}")
            
            # Execute
            proc = subprocess.run(
                cmd_args if not shell else cmd,
                shell=shell,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=cwd,
                env=env,
                input=stdin
            )
            
            duration = time.time() - start_time
            
            return ProcessResult(
                stdout=proc.stdout or "",
                stderr=proc.stderr or "",
                returncode=proc.returncode,
                success=(proc.returncode == 0),
                duration=duration,
                timed_out=False
            )
            
        except subprocess.TimeoutExpired as e:
            duration = time.time() - start_time
            timed_out = True
            error = f"Timeout after {timeout}s"
            
            return ProcessResult(
                stdout=e.stdout.decode() if e.stdout else "",
                stderr=e.stderr.decode() if e.stderr else "",
                returncode=-1,
                success=False,
                duration=duration,
                timed_out=True,
                error=error
            )
            
        except Exception as e:
            duration = time.time() - start_time
            error = str(e)
            
            return ProcessResult(
                stdout="",
                stderr=error,
                returncode=-1,
                success=False,
                duration=duration,
                error=error
            )

    def run_binary(
        self,
        binary: str,
        args: List[str],
        timeout: Optional[int] = None,
        **kwargs
    ) -> ProcessResult:
        """
        Execute a binary with arguments safely (no shell).
        
        Args:
            binary: Binary name or path
            args: List of arguments
            timeout: Timeout in seconds
            **kwargs: Additional arguments for run()
            
        Returns:
            ProcessResult
        """
        cmd = [binary] + args
        return self.run(cmd, timeout=timeout, shell=False, **kwargs)

    def validate_binary(self, binary: str, min_version: Optional[str] = None) -> Tuple[bool, str]:
        """
        Validate binary exists and is executable.
        
        Args:
            binary: Binary name or path
            min_version: Optional minimum version (format: "1.2.3")
            
        Returns:
            (is_valid, path_or_error)
        """
        import shutil
        
        # Check if binary exists
        binary_path = shutil.which(binary)
        if not binary_path:
            return False, f"Binary '{binary}' not found in PATH"
        
        # Check if executable
        path_obj = Path(binary_path)
        if not path_obj.exists():
            return False, f"Binary path does not exist: {binary_path}"
        
        if not path_obj.is_file():
            return False, f"Binary path is not a file: {binary_path}"
        
        # Try to execute with --version to verify it works
        try:
            result = self.run(
                [binary_path, "--version"],
                timeout=5,
                check_returncode=False
            )
            
            if not result.has_output():
                # Try -v flag
                result = self.run(
                    [binary_path, "-v"],
                    timeout=5,
                    check_returncode=False
                )
            
            # Version check (simplified - extend as needed)
            if min_version and result.has_output():
                # This is a basic check - you'd need regex for real version parsing
                output = result.get_combined_output().lower()
                if min_version.lower() not in output:
                    return (
                        False,
                        f"Binary version check failed (expected >= {min_version})"
                    )
            
            return True, binary_path
            
        except Exception as e:
            return False, f"Binary validation failed: {e}"


# Global executor instance
_default_executor: Optional[ProcessExecutor] = None


def get_executor(logger=None, **kwargs) -> ProcessExecutor:
    """
    Get the default process executor.
    
    Usage:
        from pentoolkit.utils.process import get_executor
        executor = get_executor()
        result = executor.run("nmap -v")
    """
    global _default_executor
    if _default_executor is None:
        _default_executor = ProcessExecutor(logger=logger, **kwargs)
    return _default_executor


def run_command(cmd: str, timeout: int = 300, logger=None, **kwargs) -> ProcessResult:
    """
    Convenience function to run a command.
    
    Usage:
        from pentoolkit.utils.process import run_command
        result = run_command("nmap -v example.com", timeout=60)
        if result.success:
            print(result.stdout)
    """
    executor = get_executor(logger=logger)
    return executor.run(cmd, timeout=timeout, **kwargs)