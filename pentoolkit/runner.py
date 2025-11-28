"""
Pentoolkit Execution Engine - Refactored with robust error handling.
Orchestrates tool execution across multiple targets with proper logging and resilience.
"""

import concurrent.futures
import datetime
import ipaddress
import os
import json
import time
from typing import Dict, List, Any, Optional
from pathlib import Path

from pentoolkit.config import ConfigLoader
from pentoolkit.registry import ModuleRegistry
from pentoolkit.utils.logging import get_logger
from pentoolkit.utils.helpers import (
    is_valid_ip,
    is_private_ip,
    ip_in_range,
    normalize_target,
    ensure_directory,
    save_json
)


class Runner:
    """
    Central execution engine with:
    - Robust error handling (tools don't crash the scan)
    - Proper logging
    - Target validation
    - Concurrent execution
    - Automatic result saving
    """

    def __init__(self, config_path: str = "config.yaml"):
        """
        Initialize runner with configuration and module registry.
        
        Args:
            config_path: Path to config.yaml file
        """
        # Initialize logging
        self.logger = get_logger("pentoolkit.runner")
        self.logger.info("Initializing Pentoolkit Runner")
        
        # Load configuration
        try:
            self.config_loader = ConfigLoader(config_path)
            self.config = self.config_loader.load()
            self.logger.info(f"Configuration loaded from {config_path}")
        except Exception as e:
            self.logger.error(f"Failed to load configuration: {e}", exc_info=True)
            raise RuntimeError(f"Configuration error: {e}")
        
        # Discover modules
        try:
            self.registry = ModuleRegistry()
            self.registry.discover_modules()
            modules = self.registry.list_modules()
            self.logger.info(f"Discovered {len(modules)} modules: {', '.join(modules)}")
        except Exception as e:
            self.logger.error(f"Failed to discover modules: {e}", exc_info=True)
            raise RuntimeError(f"Module discovery error: {e}")
        
        # Extract config shortcuts
        self.global_cfg = self.config.global_
        self.exec_cfg = self.config.execution
        
        # Runtime state
        self.selected_scan_type: Optional[str] = None
        self._execution_stats = {
            "total_targets": 0,
            "successful_scans": 0,
            "failed_scans": 0,
            "total_findings": 0
        }

    # ========================================================================
    # TARGET VALIDATION
    # ========================================================================

    def _validate_target_allowed(self, target: str) -> bool:
        """
        Validate target is allowed according to execution config.
        
        Raises:
            PermissionError: If target is not allowed
            ValueError: If target is invalid
        """
        # Normalize target
        target = normalize_target(target)
        
        # Try to extract IP if it's a URL/domain
        if not is_valid_ip(target):
            # For domains/URLs, we'll allow them (DNS resolution happens at tool level)
            return True
        
        # If it's an IP, apply restrictions
        try:
            ip_obj = ipaddress.ip_address(target)
            
            # Check if internal scan is allowed
            if ip_obj.is_private:
                if not self.exec_cfg.allow_internal_scans:
                    raise PermissionError(
                        f"Internal IP scan detected ({target}), "
                        f"but allow_internal_scans=False in config"
                    )
                
                # Check allowed ranges
                if self.exec_cfg.allowed_ranges:
                    allowed = any(
                        ip_in_range(target, cidr)
                        for cidr in self.exec_cfg.allowed_ranges
                    )
                    
                    if not allowed:
                        raise PermissionError(
                            f"Target {target} is not in allowed internal ranges: "
                            f"{self.exec_cfg.allowed_ranges}"
                        )
            
            return True
            
        except ValueError as e:
            raise ValueError(f"Invalid target format: {target}")

    # ========================================================================
    # SINGLE TOOL EXECUTION
    # ========================================================================

    def execute_one(self, tool_name: str, target: str) -> Dict[str, Any]:
        """
        Execute a single tool on a single target with full error handling.
        
        This method NEVER crashes - it always returns a result dict,
        even if the tool fails completely.
        
        Args:
            tool_name: Name of tool to execute
            target: Target (IP, domain, or URL)
            
        Returns:
            Result dictionary with metadata, findings, and raw output
        """
        start_time = time.time()
        
        # Initialize result container (always exists)
        result = {
            "metadata": {
                "tool": tool_name,
                "target": target,
                "started": datetime.datetime.now(datetime.UTC).isoformat(),
                "finished": None,
                "duration": None,
                "success": False,
                "error": None
            },
            "findings": [],
            "raw": ""
        }
        
        try:
            # Step 1: Validate target
            try:
                self._validate_target_allowed(target)
            except (PermissionError, ValueError) as e:
                self.logger.warning(f"Target validation failed for {target}: {e}")
                result["metadata"]["error"] = f"Target validation failed: {e}"
                result["metadata"]["finished"] = datetime.datetime.now(datetime.UTC).isoformat()
                result["metadata"]["duration"] = time.time() - start_time
                return result
            
            # Step 2: Get module class
            try:
                module_class = self.registry.get(tool_name)
            except KeyError as e:
                self.logger.error(f"Module '{tool_name}' not found in registry")
                result["metadata"]["error"] = f"Module not found: {tool_name}"
                result["metadata"]["finished"] = datetime.datetime.now(datetime.UTC).isoformat()
                result["metadata"]["duration"] = time.time() - start_time
                return result
            
            # Step 3: Get tool configuration
            try:
                tool_cfg = self.config_loader.tool(tool_name)
            except KeyError as e:
                self.logger.error(f"Configuration for tool '{tool_name}' not found")
                result["metadata"]["error"] = f"Tool configuration missing: {tool_name}"
                result["metadata"]["finished"] = datetime.datetime.now(datetime.UTC).isoformat()
                result["metadata"]["duration"] = time.time() - start_time
                return result
            
            # Step 4: Instantiate module
            try:
                module_instance = module_class(config=tool_cfg, logger=self.logger)
                
                # Pass scan type if applicable (e.g., for nmap)
                if hasattr(self, "selected_scan_type") and self.selected_scan_type:
                    module_instance.selected_scan_type = self.selected_scan_type
                    
            except Exception as e:
                self.logger.error(f"Failed to instantiate {tool_name} module: {e}", exc_info=True)
                result["metadata"]["error"] = f"Module instantiation failed: {e}"
                result["metadata"]["finished"] = datetime.datetime.now(datetime.UTC).isoformat()
                result["metadata"]["duration"] = time.time() - start_time
                return result
            
            # Step 5: Prepare module (check binaries, etc.)
            try:
                self.logger.info(f"Preparing {tool_name} for {target}")
                module_instance.prepare()
            except Exception as e:
                self.logger.error(f"{tool_name} preparation failed: {e}", exc_info=True)
                result["metadata"]["error"] = f"Module preparation failed: {e}"
                result["metadata"]["finished"] = datetime.datetime.now(datetime.UTC).isoformat()
                result["metadata"]["duration"] = time.time() - start_time
                return result
            
            # Step 6: Validate target (module-specific)
            try:
                module_instance.validate_target(target)
            except Exception as e:
                self.logger.error(f"{tool_name} target validation failed for {target}: {e}")
                result["metadata"]["error"] = f"Target validation failed: {e}"
                result["metadata"]["finished"] = datetime.datetime.now(datetime.UTC).isoformat()
                result["metadata"]["duration"] = time.time() - start_time
                return result
            
            # Step 7: Execute tool
            try:
                self.logger.info(f"Running {tool_name} on {target}")
                raw_output = module_instance.run(target)
                module_instance.raw_output = raw_output
                result["raw"] = raw_output
                self.logger.debug(f"{tool_name} produced {len(raw_output)} bytes of output")
            except Exception as e:
                self.logger.error(f"{tool_name} execution failed: {e}", exc_info=True)
                result["metadata"]["error"] = f"Tool execution failed: {e}"
                result["metadata"]["finished"] = datetime.datetime.now(datetime.UTC).isoformat()
                result["metadata"]["duration"] = time.time() - start_time
                return result
            
            # Step 8: Parse output
            try:
                findings = module_instance.parse_output()
                module_instance.findings = findings
                result["findings"] = findings
                self.logger.info(f"{tool_name} found {len(findings)} findings for {target}")
            except Exception as e:
                self.logger.error(f"{tool_name} output parsing failed: {e}", exc_info=True)
                # Parsing failure is not fatal - we have raw output
                result["metadata"]["error"] = f"Output parsing failed: {e}"
                result["findings"] = []
            
            # Success!
            result["metadata"]["success"] = True
            result["metadata"]["error"] = None
            self._execution_stats["successful_scans"] += 1
            self._execution_stats["total_findings"] += len(result["findings"])
            
        except Exception as e:
            # Catch-all for any unexpected errors
            self.logger.exception(f"Unexpected error during {tool_name} execution: {e}")
            result["metadata"]["error"] = f"Unexpected error: {e}"
            self._execution_stats["failed_scans"] += 1
        
        finally:
            # Always set completion timestamp and duration
            result["metadata"]["finished"] = datetime.datetime.now(datetime.UTC).isoformat()
            result["metadata"]["duration"] = time.time() - start_time
        
        return result

    # ========================================================================
    # MULTI-TARGET EXECUTION
    # ========================================================================

    def execute_tool_multi(
        self,
        tool_name: str,
        targets: List[str]
    ) -> List[Dict[str, Any]]:
        """
        Execute a tool across multiple targets concurrently.
        
        Args:
            tool_name: Name of tool to execute
            targets: List of targets
            
        Returns:
            List of result dictionaries (one per target)
        """
        self.logger.info(
            f"Starting {tool_name} execution on {len(targets)} target(s) "
            f"with concurrency={self.global_cfg.concurrency}"
        )
        
        results = []
        
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.global_cfg.concurrency
        ) as executor:
            # Submit all tasks
            futures = {
                executor.submit(self.execute_one, tool_name, target): target
                for target in targets
            }
            
            # Collect results as they complete
            for future in concurrent.futures.as_completed(futures):
                target = futures[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    # This should never happen (execute_one handles all errors)
                    # but just in case...
                    self.logger.exception(f"Future execution failed for {target}: {e}")
                    results.append({
                        "metadata": {
                            "tool": tool_name,
                            "target": target,
                            "error": f"Future execution error: {e}",
                            "success": False
                        },
                        "findings": [],
                        "raw": ""
                    })
        
        successful = sum(1 for r in results if r["metadata"].get("success"))
        failed = len(results) - successful
        self.logger.info(
            f"{tool_name} completed: {successful} successful, {failed} failed"
        )
        
        return results

    # ========================================================================
    # EXECUTE ALL TOOLS
    # ========================================================================

    def execute_all(self, targets: List[str]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Execute all enabled tools in correct order.
        
        Execution order:
            1. httpx (discovery)
            2. all other tools (parallel-capable)
            3. nuclei (last, uses httpx results)
        
        Args:
            targets: List of targets
            
        Returns:
            Dictionary mapping tool names to their results
        """
        self._execution_stats["total_targets"] = len(targets)
        self.logger.info(f"Starting full scan on {len(targets)} target(s)")
        
        # Get enabled tools
        enabled_tools = [
            name for name, cfg in self.config.tools.items()
            if cfg.enabled
        ]
        
        if not enabled_tools:
            self.logger.warning("No tools enabled in configuration!")
            return {}
        
        # Order tools: httpx → others → nuclei
        ordered_tools = []
        
        if "httpx" in enabled_tools:
            ordered_tools.append("httpx")
        
        for tool in enabled_tools:
            if tool not in ("httpx", "nuclei"):
                ordered_tools.append(tool)
        
        if "nuclei" in enabled_tools:
            ordered_tools.append("nuclei")
        
        # Remove duplicates while preserving order
        seen = set()
        ordered_tools = [t for t in ordered_tools if not (t in seen or seen.add(t))]
        
        self.logger.info(f"Execution order: {' → '.join(ordered_tools)}")
        
        # Execute each tool in order
        all_results = {}
        
        for tool_name in ordered_tools:
            try:
                self.logger.info(f"▶ Starting {tool_name}")
                tool_results = self.execute_tool_multi(tool_name, targets)
                all_results[tool_name] = tool_results
            except Exception as e:
                self.logger.error(f"{tool_name} execution failed: {e}", exc_info=True)
                # Continue with other tools even if one fails
                all_results[tool_name] = []
        
        # Log summary
        total_findings = sum(
            len(r["findings"])
            for results in all_results.values()
            for r in results
        )
        
        self.logger.info(
            f"Scan completed: {len(ordered_tools)} tool(s), "
            f"{self._execution_stats['successful_scans']} successful scans, "
            f"{self._execution_stats['failed_scans']} failed scans, "
            f"{total_findings} total findings"
        )
        
        return all_results

    # ========================================================================
    # SAVE RESULTS
    # ========================================================================

    def save_run(
        self,
        run_id: str,
        targets: List[str],
        all_results: Dict[str, List[Any]]
    ) -> str:
        """
        Save scan results to disk.
        
        Structure:
            results/runs/{run_id}/
                meta.json
                {tool_name}.json (for each tool)
        
        Args:
            run_id: Unique run identifier
            targets: List of targets scanned
            all_results: Results dictionary from execute_all()
            
        Returns:
            Path to run directory
        """
        base_dir = Path("results") / "runs" / run_id
        ensure_directory(base_dir)
        
        try:
            # Save each tool's results
            for tool_name, results in all_results.items():
                tool_file = base_dir / f"{tool_name}.json"
                save_json(results, tool_file)
                self.logger.debug(f"Saved {tool_name} results to {tool_file}")
            
            # Save metadata
            meta = {
                "run_id": run_id,
                "targets": targets,
                "tools": list(all_results.keys()),
                "timestamp": run_id.split("_")[0],
                "stats": self._execution_stats
            }
            
            meta_file = base_dir / "meta.json"
            save_json(meta, meta_file)
            
            self.logger.info(f"Results saved to {base_dir}")
            return str(base_dir)
            
        except Exception as e:
            self.logger.error(f"Failed to save results: {e}", exc_info=True)
            raise RuntimeError(f"Result save error: {e}")


















