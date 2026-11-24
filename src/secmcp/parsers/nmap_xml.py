"""Parse nmap -oX output into structured models."""

from xml.etree.ElementTree import Element, ParseError

from defusedxml import DefusedXmlException
from defusedxml.ElementTree import fromstring
from pydantic import BaseModel

MAX_SCRIPT_OUTPUT = 4000


class NmapParseError(ValueError):
    pass


class ScriptOutput(BaseModel):
    id: str
    output: str


class Port(BaseModel):
    port: int
    protocol: str
    state: str
    reason: str | None = None
    service: str | None = None
    product: str | None = None
    version: str | None = None
    extra_info: str | None = None
    scripts: list[ScriptOutput] = []


class Host(BaseModel):
    address: str
    state: str
    hostnames: list[str] = []
    ports: list[Port] = []
    scripts: list[ScriptOutput] = []


class NmapScan(BaseModel):
    hosts: list[Host]
    hosts_up: int
    hosts_total: int
    elapsed_s: float | None = None
    summary: str


def _script(element: Element) -> ScriptOutput:
    output = element.get("output", "").strip()
    if len(output) > MAX_SCRIPT_OUTPUT:
        output = output[:MAX_SCRIPT_OUTPUT] + "\n[script output truncated]"
    return ScriptOutput(id=element.get("id", ""), output=output)


def _port(element: Element) -> Port:
    state = element.find("state")
    service = element.find("service")
    return Port(
        port=int(element.get("portid", "0")),
        protocol=element.get("protocol", ""),
        state=state.get("state", "unknown") if state is not None else "unknown",
        reason=state.get("reason") if state is not None else None,
        service=service.get("name") if service is not None else None,
        product=service.get("product") if service is not None else None,
        version=service.get("version") if service is not None else None,
        extra_info=service.get("extrainfo") if service is not None else None,
        scripts=[_script(script) for script in element.findall("script")],
    )


def _host(element: Element) -> Host:
    addresses = element.findall("address")
    ip = next((a for a in addresses if a.get("addrtype") in ("ipv4", "ipv6")), None)
    status = element.find("status")
    return Host(
        address=(ip if ip is not None else addresses[0]).get("addr", ""),
        state=status.get("state", "unknown") if status is not None else "unknown",
        hostnames=[h.get("name", "") for h in element.findall("hostnames/hostname")],
        ports=[_port(port) for port in element.findall("ports/port")],
        scripts=[_script(script) for script in element.findall("hostscript/script")],
    )


def _describe_port(port: Port) -> str:
    parts = [f"{port.port}/{port.protocol}", port.service, port.product, port.version]
    return " ".join(part for part in parts if part)


def summarize(hosts: list[Host]) -> str:
    """Build a short human-readable summary of a scan."""
    up = [host for host in hosts if host.state == "up"]
    lines = [f"{len(up)} of {len(hosts)} hosts up"]
    for host in up:
        name = (
            f"{host.address} ({host.hostnames[0]})" if host.hostnames else host.address
        )
        open_ports = [port for port in host.ports if port.state == "open"]
        if open_ports:
            described = ", ".join(_describe_port(port) for port in open_ports)
            lines.append(f"{name}: {len(open_ports)} open: {described}")
        else:
            lines.append(f"{name}: no open ports found")
    return "\n".join(lines)


def parse_nmap_xml(data: str | bytes) -> NmapScan:
    """Parse nmap XML output, raising NmapParseError if it is incomplete or invalid."""
    try:
        root = fromstring(data)
    except (ParseError, DefusedXmlException) as exc:
        raise NmapParseError(f"invalid nmap xml: {exc}") from None
    if root.tag != "nmaprun":
        raise NmapParseError(f"unexpected root element {root.tag!r}")
    hosts = [_host(element) for element in root.findall("host")]
    finished = root.find("runstats/finished")
    elapsed = finished.get("elapsed") if finished is not None else None
    return NmapScan(
        hosts=hosts,
        hosts_up=sum(1 for host in hosts if host.state == "up"),
        hosts_total=len(hosts),
        elapsed_s=float(elapsed) if elapsed else None,
        summary=summarize(hosts),
    )
