# debug_paths.py
from pathlib import Path
from pentoolkit.config import ConfigLoader

loader = ConfigLoader("config.yaml")
print(f"Config path: {loader.path}")
print(f"Project root: {loader.project_root}")

# Try loading
try:
    config = loader.load()
    print("✓ Config loaded successfully!")
    print(f"Template path: {loader.get_absolute_template_path()}")
    print(f"Static dir: {loader.get_absolute_static_dir()}")
except Exception as e:
    print(f"✗ Error: {e}")
    
    # Check what paths exist
    possible_template = loader.project_root / "pentoolkit/report/templates/report.html"
    print(f"\nChecking: {possible_template}")
    print(f"Exists: {possible_template.exists()}")
    
    if possible_template.exists():
        print("✓ Template file exists!")
    else:
        print("✗ Template file NOT found")
        print("\nListing pentoolkit/report/:")
        report_dir = loader.project_root / "pentoolkit/report"
        if report_dir.exists():
            for item in report_dir.rglob("*"):
                print(f"  {item.relative_to(loader.project_root)}")