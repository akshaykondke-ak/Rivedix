import importlib
import os
import pkgutil
from typing import Dict, Type

from pentoolkit.modules.base import PentoolkitModule



class ModuleRegistry:
    """
    Auto-discovers all modules inside pentoolkit/modules/ that inherit
    from PentoolkitModule. No manual registration needed.
    """

    def __init__(self):
        self.modules: Dict[str, Type[PentoolkitModule]] = {}

    def discover_modules(self):
        """Scan the modules directory and load all Pentoolkit modules."""

        package_path = os.path.dirname(__file__) + "/modules"

        # Iterate over all Python files in modules/
        for _, module_name, is_pkg in pkgutil.iter_modules([package_path]):
            if is_pkg:
                continue  # No sub-packages for now

            full_name = f"pentoolkit.modules.{module_name}"

            try:
                module = importlib.import_module(full_name)

                # Find all classes inheriting from PentoolkitModule
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)

                    if isinstance(attr, type) and issubclass(attr, PentoolkitModule):
                        if attr is PentoolkitModule:
                            continue  # Skip base class

                        instance = attr()

                        # Register using module's "name" attribute
                        self.modules[instance.name] = attr

            except Exception as e:
                print(f"[ERROR] Failed to load module {full_name}: {e}")

    def get(self, name: str) -> Type[PentoolkitModule]:
        """Return module class by name."""
        if name not in self.modules:
            raise KeyError(f"Module '{name}' not found.")
        return self.modules[name]

    def list_modules(self):
        """Return available modules."""
        return list(self.modules.keys())
