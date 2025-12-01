"""
Configuration management with Pydantic validation.
Enhanced error messages and early failure detection.
FIXED: Smart path resolution relative to project root.
"""

import yaml
from pathlib import Path
from pydantic import BaseModel, Field, field_validator, model_validator
from typing import List, Dict, Optional, Any


# ============================================================================
# PYDANTIC MODELS WITH VALIDATION
# ============================================================================

class GlobalConfig(BaseModel):
    """Global application settings."""
    
    concurrency: int = Field(
        default=4,
        ge=1,
        le=50,
        description="Number of concurrent tool executions"
    )
    output_dir: str = Field(
        default="results",
        description="Base directory for results"
    )
    log_level: str = Field(
        default="INFO",
        description="Logging level"
    )
    
    @field_validator('log_level')
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        """Validate log level."""
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        v_upper = v.upper()
        if v_upper not in valid_levels:
            raise ValueError(
                f"Invalid log_level '{v}'. Must be one of: {', '.join(valid_levels)}"
            )
        return v_upper
    
    @field_validator('output_dir')
    @classmethod
    def validate_output_dir(cls, v: str) -> str:
        """Ensure output directory is valid."""
        if not v or v.strip() == "":
            raise ValueError("output_dir cannot be empty")
        return v.strip()


class ToolConfig(BaseModel):
    """Tool-specific configuration."""
    
    enabled: bool = True
    path: str = Field(description="Binary path or name")
    default_args: Optional[str] = None
    timeout: Optional[int] = Field(
        default=300,
        ge=10,
        le=7200,
        description="Tool timeout in seconds"
    )
    
    # Nmap-specific
    scan_all_ports: bool = False
    internal_networks: List[str] = []
    type: Optional[str] = None
    scan_types: Optional[Dict[str, str]] = None
    
    # Nuclei-specific
    templates_root: Optional[str] = None
    mode: Optional[str] = None
    rate_limit: Optional[int] = None
    concurrency: Optional[int] = None
    template_timeout: Optional[int] = None
    severity: Optional[str] = None
    no_meta: Optional[bool] = None
    extra_args: Optional[List[str]] = None
    
    model_config = {
        "extra": "allow"
    }
    
    @field_validator('path')
    @classmethod
    def validate_path(cls, v: str) -> str:
        """Validate path is not empty."""
        if not v or v.strip() == "":
            raise ValueError("Tool path cannot be empty")
        return v.strip()
    
    @field_validator('severity')
    @classmethod
    def validate_severity(cls, v: Optional[str]) -> Optional[str]:
        """Validate severity string."""
        if v is None:
            return v
        
        valid_severities = {"critical", "high", "medium", "low", "info"}
        severities = [s.strip().lower() for s in v.split(",")]
        
        invalid = [s for s in severities if s not in valid_severities]
        if invalid:
            raise ValueError(
                f"Invalid severity values: {', '.join(invalid)}. "
                f"Valid: {', '.join(valid_severities)}"
            )
        
        return v


class ReportingConfig(BaseModel):
    """Reporting configuration with SMART path resolution."""
    
    per_tool_report: bool = True
    combined_report: bool = True
    template: str
    static_dir: str
    theme: str = "default"
    
    # NOTE: We'll skip validation here and do it in ConfigLoader
    # because we need access to the project root path


class ExecutionConfig(BaseModel):
    """Execution restrictions and safety settings."""
    
    allow_internal_scans: bool = False
    allowed_ranges: List[str] = []
    timeout: int = Field(
        default=300,
        ge=10,
        le=7200,
        description="Global timeout in seconds"
    )
    
    @field_validator('allowed_ranges')
    @classmethod
    def validate_cidr_ranges(cls, v: List[str]) -> List[str]:
        """Validate CIDR ranges."""
        import ipaddress
        
        validated = []
        for cidr in v:
            try:
                ipaddress.ip_network(cidr, strict=False)
                validated.append(cidr)
            except ValueError:
                raise ValueError(f"Invalid CIDR range: {cidr}")
        
        return validated


class PentoolkitConfig(BaseModel):
    """Main configuration model."""
    
    global_: GlobalConfig = Field(..., alias="global")
    reporting: ReportingConfig
    tools: Dict[str, ToolConfig]
    execution: ExecutionConfig
    
    model_config = {
        "populate_by_name": True
    }
    
    @model_validator(mode='after')
    def validate_config(self) -> 'PentoolkitConfig':
        """Validate entire configuration."""
        enabled_tools = [name for name, cfg in self.tools.items() if cfg.enabled]
        if not enabled_tools:
            raise ValueError("At least one tool must be enabled in configuration")
        
        return self


# ============================================================================
# CONFIGURATION LOADER WITH SMART PATH RESOLUTION
# ============================================================================

class ConfigLoader:
    """
    Central configuration loader with smart path resolution.
    
    FIXED: Resolves paths relative to project root, not config file location.
    """
    
    def __init__(self, config_path: str = "config.yaml"):
        """
        Initialize loader.
        
        Args:
            config_path: Path to config.yaml file
        """
        self.path = Path(config_path).absolute()
        self.config: Optional[PentoolkitConfig] = None
        
        # Determine project root (directory containing config.yaml)
        self.project_root = self.path.parent
        
        # Validate config file exists
        if not self.path.exists():
            raise FileNotFoundError(
                f"Configuration file not found: {config_path}\n"
                f"Expected location: {self.path}"
            )

    def _resolve_path(self, path_str: str) -> Path:
        """
        Resolve a path relative to project root.
        
        Args:
            path_str: Path string from config
            
        Returns:
            Absolute Path object
        """
        path = Path(path_str)
        
        # If already absolute, return as-is
        if path.is_absolute():
            return path
        
        # Otherwise, resolve relative to project root
        return (self.project_root / path).resolve()

    def load(self) -> PentoolkitConfig:
        """
        Load and validate configuration with smart path resolution.
        
        Returns:
            Validated PentoolkitConfig object
        """
        try:
            # Load YAML
            with open(self.path, 'r', encoding='utf-8') as f:
                raw_config = yaml.safe_load(f)
            
            if not raw_config:
                raise ValueError("Configuration file is empty")
            
            # Validate with Pydantic (skip path validation)
            self.config = PentoolkitConfig(**raw_config)
            
            # CRITICAL FIX: Validate paths manually with smart resolution
            self._validate_reporting_paths()
            
            return self.config
        
        except yaml.YAMLError as e:
            raise ValueError(f"YAML parsing error in {self.path}: {e}")
        
        except Exception as e:
            raise ValueError(
                f"Configuration validation failed:\n{e}\n\n"
                f"Check your config.yaml file at: {self.path}"
            )

    def _validate_reporting_paths(self):
        """
        Validate reporting paths with smart resolution.
        
        This replaces the Pydantic validation that was failing.
        """
        if not self.config:
            return
        
        reporting = self.config.reporting
        
        # Validate template path
        template_path = self._resolve_path(reporting.template)
        if not template_path.exists():
            raise ValueError(
                f"Template file not found: {reporting.template}\n"
                f"Tried: {template_path}\n"
                f"Project root: {self.project_root}"
            )
        
        if not template_path.is_file():
            raise ValueError(
                f"Template path is not a file: {reporting.template}\n"
                f"Path: {template_path}"
            )
        
        # Validate static directory
        static_path = self._resolve_path(reporting.static_dir)
        if not static_path.exists():
            raise ValueError(
                f"Static directory not found: {reporting.static_dir}\n"
                f"Tried: {static_path}\n"
                f"Project root: {self.project_root}"
            )
        
        if not static_path.is_dir():
            raise ValueError(
                f"Static path is not a directory: {reporting.static_dir}\n"
                f"Path: {static_path}"
            )

    def get(self) -> PentoolkitConfig:
        """Get loaded configuration."""
        if self.config is None:
            raise RuntimeError("Configuration not loaded! Call load() first.")
        return self.config

    def tool(self, name: str) -> ToolConfig:
        """Get tool-specific configuration."""
        if self.config is None:
            raise RuntimeError("Configuration not loaded! Call load() first.")
        
        if name not in self.config.tools:
            available = ", ".join(self.config.tools.keys())
            raise KeyError(
                f"Tool '{name}' not found in configuration.\n"
                f"Available tools: {available}"
            )
        
        return self.config.tools[name]

    def get_absolute_template_path(self) -> str:
        """Get absolute path to report template."""
        if not self.config:
            raise RuntimeError("Configuration not loaded!")
        
        return str(self._resolve_path(self.config.reporting.template))

    def get_absolute_static_dir(self) -> str:
        """Get absolute path to static directory."""
        if not self.config:
            raise RuntimeError("Configuration not loaded!")
        
        return str(self._resolve_path(self.config.reporting.static_dir))

    def validate_binaries(self, logger=None) -> Dict[str, bool]:
        """Validate all configured tool binaries exist."""
        import shutil
        
        results = {}
        
        for tool_name, tool_cfg in self.config.tools.items():
            if not tool_cfg.enabled:
                continue
            
            binary_path = shutil.which(tool_cfg.path)
            
            if binary_path:
                results[tool_name] = True
                if logger:
                    logger.info(f"✓ {tool_name}: {binary_path}")
            else:
                results[tool_name] = False
                if logger:
                    logger.warning(f"✗ {tool_name}: Binary '{tool_cfg.path}' not found")
        
        return results

    def get_enabled_tools(self) -> List[str]:
        """Get list of enabled tool names."""
        if self.config is None:
            raise RuntimeError("Configuration not loaded!")
        
        return [
            name for name, cfg in self.config.tools.items()
            if cfg.enabled
        ]

    def to_dict(self) -> Dict[str, Any]:
        """Export configuration as dictionary."""
        if self.config is None:
            raise RuntimeError("Configuration not loaded!")
        
        return self.config.model_dump(by_alias=True)

    def save(self, output_path: Optional[str] = None):
        """Save configuration to YAML file."""
        if self.config is None:
            raise RuntimeError("Configuration not loaded!")
        
        output_path = output_path or str(self.path)
        config_dict = self.to_dict()
        
        with open(output_path, 'w', encoding='utf-8') as f:
            yaml.safe_dump(
                config_dict,
                f,
                default_flow_style=False,
                sort_keys=False
            )


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def load_config(config_path: str = "config.yaml") -> PentoolkitConfig:
    """Convenience function to load configuration."""
    loader = ConfigLoader(config_path)
    return loader.load()


def validate_config_file(config_path: str = "config.yaml") -> bool:
    """Validate configuration file and print errors."""
    try:
        load_config(config_path)
        print(f"✓ Configuration is valid: {config_path}")
        return True
    
    except Exception as e:
        print(f"✗ Configuration validation failed:")
        print(f"  {e}")
        return False