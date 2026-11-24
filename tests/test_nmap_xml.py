from pathlib import Path

import pytest

from secmcp.parsers.nmap_xml import MAX_SCRIPT_OUTPUT, NmapParseError, parse_nmap_xml

FIXTURE = Path(__file__).parent / "fixtures" / "nmap_service_version.xml"


def test_parse_fixture() -> None:
    scan = parse_nmap_xml(FIXTURE.read_bytes())
    assert scan.hosts_total == 2
    assert scan.hosts_up == 1
    assert scan.elapsed_s == 31.2

    host = scan.hosts[0]
    assert host.address == "203.0.113.10"
    assert host.state == "up"
    assert host.hostnames == ["www.example.com", "web-01.example.com"]
    assert [p.port for p in host.ports] == [22, 80, 443, 3306, 8080]
    assert [s.id for s in host.scripts] == ["clock-skew"]

    ssh = host.ports[0]
    assert ssh.protocol == "tcp"
    assert ssh.state == "open"
    assert ssh.service == "ssh"
    assert ssh.product == "OpenSSH"
    assert ssh.version == "8.9p1 Ubuntu 3ubuntu0.10"
    assert ssh.extra_info == "Ubuntu Linux; protocol 2.0"

    http = host.ports[1]
    assert [(s.id, s.output) for s in http.scripts] == [
        ("http-title", "Example Domain"),
        ("http-server-header", "nginx/1.18.0 (Ubuntu)"),
    ]
    assert host.ports[3].state == "filtered"
    assert scan.hosts[1].state == "down"


def test_summary() -> None:
    scan = parse_nmap_xml(FIXTURE.read_text())
    assert scan.summary.splitlines() == [
        "1 of 2 hosts up",
        "203.0.113.10 (www.example.com): 3 open: 22/tcp ssh OpenSSH 8.9p1 Ubuntu "
        "3ubuntu0.10, 80/tcp http nginx 1.18.0, 443/tcp https",
    ]


def test_long_script_output_is_truncated() -> None:
    xml = (
        '<nmaprun><host><status state="up"/>'
        '<address addr="203.0.113.1" addrtype="ipv4"/>'
        '<ports><port protocol="tcp" portid="80"><state state="open"/>'
        f'<script id="big" output="{"a" * (MAX_SCRIPT_OUTPUT + 10)}"/></port></ports>'
        "</host></nmaprun>"
    )
    output = parse_nmap_xml(xml).hosts[0].ports[0].scripts[0].output
    assert output.endswith("[script output truncated]")
    assert len(output) < MAX_SCRIPT_OUTPUT + 50


@pytest.mark.parametrize(
    "data",
    [
        FIXTURE.read_text()[:600],
        "<other/>",
        '<!DOCTYPE x [<!ENTITY a "b">]><nmaprun>&a;</nmaprun>',
    ],
)
def test_invalid_xml(data: str) -> None:
    with pytest.raises(NmapParseError):
        parse_nmap_xml(data)


def test_empty_scan() -> None:
    scan = parse_nmap_xml("<nmaprun></nmaprun>")
    assert scan.hosts == []
    assert scan.summary == "0 of 0 hosts up"
