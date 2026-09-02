"""
nmap.py - Nmap XML output parser.

Parses `nmap -oX -` XML into structured hosts/services dicts. Pure function.
"""

from typing import Any
from xml.etree import ElementTree as ET

from quarr.core.exceptions import ToolOutputParseError


def parse_nmap_xml(xml: str) -> dict[str, Any]:
    if not xml or not xml.strip():
        raise ToolOutputParseError("Empty nmap XML output")

    try:
        root = ET.fromstring(xml)
    except ET.ParseError as e:
        raise ToolOutputParseError("Malformed nmap XML", context={"error": str(e)}) from e

    hosts = []
    services = []
    for host in root.findall("host"):
        addr_el = host.find("address")
        address = addr_el.get("addr") if addr_el is not None else None
        if not address:
            continue

        hostname = None
        hn = host.find("hostnames/hostname")
        if hn is not None:
            hostname = hn.get("name")

        status_el = host.find("status")
        state = status_el.get("state") if status_el is not None else "up"

        host_services = []
        for port in host.findall("ports/port"):
            state_el = port.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            svc_el = port.find("service")
            svc = {
                "host": address,
                "port": int(port.get("portid")),
                "protocol": port.get("protocol", "tcp"),
                "name": svc_el.get("name") if svc_el is not None else None,
                "product": svc_el.get("product") if svc_el is not None else None,
                "version": svc_el.get("version") if svc_el is not None else None,
            }
            host_services.append(svc)
            services.append(svc)

        hosts.append(
            {
                "address": address,
                "hostname": hostname,
                "state": state,
                "services": host_services,
            }
        )

    return {"hosts": hosts, "services": services}
