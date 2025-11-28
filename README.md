python -m pentoolkit.cli scan --all --target rivedix.com
python -m pentoolkit.cli scan --tool whatweb --target rivedix.com
pentoolkit scan --tool subfinder --target example.com
python -m pentoolkit.cli list-runs 

rm -rf build dist *.egg-info
pip install -e .
python -m pentoolkit.cli list-modules

python -m pentoolkit.cli list-modules
python -m pentoolkit.cli scan --tool nmap --type test --target example.com
python -m pentoolkit.cli scan --all --type test --target example.com
python -m pentoolkit.cli report --run <run_id>
