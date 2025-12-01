# ============================================================================
# FILE 1: tests/conftest.py - Pytest Configuration & Fixtures
# ============================================================================

import pytest
import json
from pathlib import Path
from unittest.mock import Mock
from pentoolkit.modules.nmap_module import NmapModule
from pentoolkit.modules.httpx_module import HttpxModule
from pentoolkit.modules.nuclei_module import NucleiModule


@pytest.fixture
def mock_config():
    """Mock tool configuration."""
    config = Mock()
    config.path = "nmap"
    config.timeout = 300
    config.enabled = True
    return config


@pytest.fixture
def mock_logger():
    """Mock logger."""
    logger = Mock()
    logger.info = Mock()
    logger.debug = Mock()
    logger.warning = Mock()
    logger.error = Mock()
    return logger


@pytest.fixture
def nmap_module(mock_config, mock_logger):
    """Nmap module instance."""
    return NmapModule(config=mock_config, logger=mock_logger)


@pytest.fixture
def httpx_module(mock_config, mock_logger):
    """Httpx module instance."""
    return HttpxModule(config=mock_config, logger=mock_logger)


@pytest.fixture
def nuclei_module(mock_config, mock_logger):
    """Nuclei module instance."""
    return NucleiModule(config=mock_config, logger=mock_logger)


# Sample tool outputs for testing
@pytest.fixture
def nmap_xml_output():
    """Real nmap XML output sample."""
    return """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<?xml-stylesheet href="file:///usr/bin/../share/nmap/nmap.xsl" type="text/xsl"?>
<nmaprun scanner="nmap" args="nmap -T3 -Pn -sV --top-ports 100 -oX - scanme.nmap.org" 
         start="1764328565" version="7.98" xmloutputversion="1.05">
<host starttime="1764328566" endtime="1764328582">
    <address addr="45.33.32.156" addrtype="ipv4"/>
    <hostnames>
        <hostname name="scanme.nmap.org" type="user"/>
    </hostnames>
    <ports>
        <port protocol="tcp" portid="22">
            <state state="open" reason="syn-ack"/>
            <service name="ssh" product="OpenSSH" version="6.6.1p1 Ubuntu" extrainfo="Ubuntu Linux"/>
        </port>
        <port protocol="tcp" portid="80">
            <state state="open" reason="syn-ack"/>
            <service name="http" product="Apache httpd" version="2.4.7" extrainfo="(Ubuntu)"/>
        </port>
    </ports>
</host>
<runstats>
    <finished time="1764328582" timestr="Fri Nov 28 16:46:22 2025"/>
    <hosts up="1" down="0" total="1"/>
</runstats>
</nmaprun>"""


@pytest.fixture
def httpx_json_output():
    """Real httpx JSON output sample."""
    return """{"url":"https://scanme.nmap.org","status_code":200,"content_length":7835,"title":"Insecure.Org","server":"Apache/2.4.7 (Ubuntu)","tech":["Apache 2.4.7","PHP 5.5.9","OpenSSL 1.0.1","Ubuntu"],"headers":{"Server":"Apache/2.4.7 (Ubuntu)","Content-Type":"text/html; charset=UTF-8"}}"""


@pytest.fixture
def nuclei_json_output():
    """Real nuclei JSON output sample."""
    return """{"template-id":"apache-detect","info":{"name":"Apache Web Server Detection","severity":"info"},"matched-at":"https://scanme.nmap.org","host":"scanme.nmap.org"}"""

