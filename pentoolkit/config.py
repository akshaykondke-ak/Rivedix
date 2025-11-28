"""
Configuration management with Pydantic validation.
Enhanced error messages and early failure detection.
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
        "extra": "allow"  # Allow tool-specific extras
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
    """Reporting configuration."""
    
    per_tool_report: bool = True
    combined_report: bool = True
    template: str
    static_dir: str
    theme: str = "default"
    
    @field_validator('template', 'static_dir')
    @classmethod
    def validate_path_exists(cls, v: str, info) -> str:
        """Validate that template and static_dir exist."""
        path = Path(v)
        
        # For template, check file exists
        if info.field_name == 'template':
            if not path.exists():
                raise ValueError(f"Template file not found: {v}")
            if not path.is_file():
                raise ValueError(f"Template path is not a file: {v}")
        
        # For static_dir, check directory exists
        elif info.field_name == 'static_dir':
            if not path.exists():
                raise ValueError(f"Static directory not found: {v}")
            if not path.is_dir():
                raise ValueError(f"Static path is not a directory: {v}")
        
        return v


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
                # Validate CIDR notation
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
        # Ensure at least one tool is enabled
        enabled_tools = [name for name, cfg in self.tools.items() if cfg.enabled]
        if not enabled_tools:
            raise ValueError("At least one tool must be enabled in configuration")
        
        # Validate internal scan settings
        if self.execution.allow_internal_scans and not self.execution.allowed_ranges:
            # This is OK - means all internal ranges allowed
            pass
        
        return self


# ============================================================================
# CONFIGURATION LOADER
# ============================================================================

class ConfigLoader:
    """
    Central configuration loader with validation and error reporting.
    """
    
    def __init__(self, config_path: str = "config.yaml"):
        """
        Initialize loader.
        
        Args:
            config_path: Path to config.yaml file
        """
        self.path = Path(config_path)
        self.config: Optional[PentoolkitConfig] = None
        
        # Validate path exists
        if not self.path.exists():
            raise FileNotFoundError(
                f"Configuration file not found: {config_path}\n"
                f"Expected location: {self.path.absolute()}"
            )

    def load(self) -> PentoolkitConfig:
        """
        Load and validate configuration.
        
        Returns:
            Validated PentoolkitConfig object
            
        Raises:
            ValueError: If configuration is invalid
            yaml.YAMLError: If YAML parsing fails
        """
        try:
            # Load YAML
            with open(self.path, 'r', encoding='utf-8') as f:
                raw_config = yaml.safe_load(f)
            
            if not raw_config:
                raise ValueError("Configuration file is empty")
            
            # Validate with Pydantic
            self.config = PentoolkitConfig(**raw_config)
            
            return self.config
        
        except yaml.YAMLError as e:
            raise ValueError(f"YAML parsing error in {self.path}: {e}")
        
        except Exception as e:
            # Enhance error message
            raise ValueError(
                f"Configuration validation failed:\n{e}\n\n"
                f"Check your config.yaml file at: {self.path.absolute()}"
            )

    def get(self) -> PentoolkitConfig:
        """
        Get loaded configuration.
        
        Returns:
            PentoolkitConfig object
            
        Raises:
            RuntimeError: If config not loaded yet
        """
        if self.config is None:
            raise RuntimeError(
                "Configuration not loaded! Call load() first."
            )
        return self.config

    def tool(self, name: str) -> ToolConfig:
        """
        Get tool-specific configuration.
        
        Args:
            name: Tool name
            
        Returns:
            ToolConfig object
            
        Raises:
            RuntimeError: If config not loaded
            KeyError: If tool not found
        """
        if self.config is None:
            raise RuntimeError("Configuration not loaded! Call load() first.")
        
        if name not in self.config.tools:
            available = ", ".join(self.config.tools.keys())
            raise KeyError(
                f"Tool '{name}' not found in configuration.\n"
                f"Available tools: {available}"
            )
        
        return self.config.tools[name]

    def validate_binaries(self, logger=None) -> Dict[str, bool]:
        """
        Validate all configured tool binaries exist.
        
        Args:
            logger: Optional logger for output
            
        Returns:
            Dictionary mapping tool names to validation status
        """
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
        """
        Get list of enabled tool names.
        
        Returns:
            List of tool names that are enabled
        """
        if self.config is None:
            raise RuntimeError("Configuration not loaded!")
        
        return [
            name for name, cfg in self.config.tools.items()
            if cfg.enabled
        ]

    def to_dict(self) -> Dict[str, Any]:
        """
        Export configuration as dictionary.
        
        Returns:
            Configuration dictionary
        """
        if self.config is None:
            raise RuntimeError("Configuration not loaded!")
        
        return self.config.model_dump(by_alias=True)

    def save(self, output_path: Optional[str] = None):
        """
        Save configuration to YAML file.
        
        Args:
            output_path: Output path (uses original path if None)
        """
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
    """
    Convenience function to load configuration.
    
    Args:
        config_path: Path to config file
        
    Returns:
        Loaded and validated configuration
    """
    loader = ConfigLoader(config_path)
    return loader.load()


def validate_config_file(config_path: str = "config.yaml") -> bool:
    """
    Validate configuration file and print errors.
    
    Args:
        config_path: Path to config file
        
    Returns:
        True if valid, False otherwise
    """
    try:
        load_config(config_path)
        print(f"✓ Configuration is valid: {config_path}")
        return True
    
    except Exception as e:
        print(f"✗ Configuration validation failed:")
        print(f"  {e}")
        return False

