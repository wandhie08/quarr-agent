"""
parsers.py - Tool Output Parsers

Mengubah output mentah dari Kali tools menjadi structured data.
LLM tidak pernah melihat raw output — hanya parsed result.
"""

import json
import re
from typing import Any


class NmapParser:
    """Parse nmap output."""

    @staticmethod
    def parse_host_discovery(raw_output: str) -> dict[str, Any]:
        hosts = []
        for match in re.finditer(
            r'Nmap scan report for (?:(\S+) \()?(\d+\.\d+\.\d+\.\d+)\)?',
            raw_output
        ):
            hostname = match.group(1)
            ip = match.group(2)
            host_data = {"address": ip}
            if hostname:
                host_data["hostname"] = hostname
            hosts.append(host_data)

        for match in re.finditer(
            r'Nmap scan report for (\d+\.\d+\.\d+\.\d+)\s',
            raw_output
        ):
            ip = match.group(1)
            if not any(h["address"] == ip for h in hosts):
                hosts.append({"address": ip})

        summary_match = re.search(r'Nmap done.*?(\d+) hosts? up', raw_output)
        summary = summary_match.group(0) if summary_match else ""

        return {
            "hosts": hosts,
            "raw_summary": summary,
            "total_up": len(hosts)
        }

    @staticmethod
    def parse_service_scan(raw_output: str) -> dict[str, Any]:
        result = {
            "host": None, "hostname": None,
            "services": [], "os_detection": None, "raw_summary": ""
        }

        host_match = re.search(
            r'Nmap scan report for (?:(\S+) \()?(\d+\.\d+\.\d+\.\d+)\)?',
            raw_output
        )
        if host_match:
            result["hostname"] = host_match.group(1)
            result["host"] = host_match.group(2)
        else:
            host_match = re.search(r'Nmap scan report for (\d+\.\d+\.\d+\.\d+)', raw_output)
            if host_match:
                result["host"] = host_match.group(1)

        port_pattern = re.compile(
            r'(\d+)/(tcp|udp)\s+(open|filtered|closed)\s+(\S+)(?:\s+(.+))?'
        )
        for match in port_pattern.finditer(raw_output):
            port = int(match.group(1))
            protocol = match.group(2)
            state = match.group(3)
            service_name = match.group(4)
            version_info = match.group(5)

            service = {
                "port": port, "protocol": protocol, "state": state,
                "name": service_name if service_name != "unknown" else None,
            }
            if version_info:
                version_info = version_info.strip()
                service["version_raw"] = version_info
                ver_match = re.match(r'(\S+)\s+([\d.]+\S*)\s*(.*)', version_info)
                if ver_match:
                    service["product"] = ver_match.group(1)
                    service["version"] = ver_match.group(2)
                    if ver_match.group(3):
                        service["extra_info"] = ver_match.group(3).strip()
                else:
                    service["product"] = version_info

            if state == "open":
                result["services"].append(service)

        os_match = re.search(r'OS details?:\s*(.+)', raw_output)
        if os_match:
            result["os_detection"] = os_match.group(1).strip()

        summary_match = re.search(r'Nmap done.*', raw_output)
        if summary_match:
            result["raw_summary"] = summary_match.group(0)

        return result


class SubdomainParser:
    """Parse subdomain enumeration output."""

    @staticmethod
    def parse(raw_output: str) -> dict[str, Any]:
        lines = [ln.strip() for ln in raw_output.strip().split('\n') if ln.strip()]
        subdomains = [ln for ln in lines if '.' in ln and not ln.startswith('[')]
        return {
            "subdomains": subdomains,
            "total": len(subdomains),
            "summary": f"Found {len(subdomains)} subdomain(s)"
        }


class WebFingerprintParser:
    """Parse whatweb output."""

    @staticmethod
    def parse(raw_output: str) -> dict[str, Any]:
        technologies = []
        # WhatWeb format: https://target [200 OK] Apache[2.4.52], PHP[8.1]
        tech_pattern = re.compile(r'(\w[\w\-./]+)\[([^\]]*)\]')
        for match in tech_pattern.finditer(raw_output):
            tech_name = match.group(1)
            tech_version = match.group(2)
            technologies.append({
                "name": tech_name,
                "version": tech_version if tech_version else None
            })

        # Status code
        status_match = re.search(r'\[(\d{3})\s*([^\]]*)\]', raw_output)
        status = None
        if status_match:
            status = {"code": int(status_match.group(1)), "text": status_match.group(2)}

        return {
            "technologies": technologies,
            "status": status,
            "total": len(technologies),
            "summary": f"Found {len(technologies)} technologies"
        }


class GobusterParser:
    """Parse gobuster output."""

    @staticmethod
    def parse(raw_output: str) -> dict[str, Any]:
        entries = []
        for line in raw_output.strip().split('\n'):
            line = line.strip()
            if not line:
                continue
            # Format: /path (Status: 200) [Size: 1234]
            match = re.match(r'(/\S*)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?', line)
            if match:
                entries.append({
                    "path": match.group(1),
                    "status": int(match.group(2)),
                    "size": int(match.group(3)) if match.group(3) else None
                })
            else:
                # Simple format: just paths
                if line.startswith('/'):
                    entries.append({"path": line, "status": None, "size": None})

        return {
            "entries": entries,
            "total": len(entries),
            "summary": f"Found {len(entries)} path(s)"
        }


class NucleiParser:
    """Parse nuclei JSONL output."""

    @staticmethod
    def parse(raw_output: str) -> dict[str, Any]:
        findings = []
        for line in raw_output.strip().split('\n'):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                findings.append({
                    "template_id": data.get("template-id", "unknown"),
                    "name": data.get("info", {}).get("name", "unknown"),
                    "severity": data.get("info", {}).get("severity", "unknown"),
                    "matched_at": data.get("matched-at", ""),
                    "description": data.get("info", {}).get("description", ""),
                    "tags": data.get("info", {}).get("tags", []),
                    "reference": data.get("info", {}).get("reference", []),
                })
            except json.JSONDecodeError:
                # Non-JSON line: try text format [severity] [template-id] ...
                text_match = re.match(
                    r'\[(\w+)\]\s+\[([^\]]+)\](?:\s+\[([^\]]+)\])?\s*(.*)',
                    line
                )
                if text_match:
                    findings.append({
                        "severity": text_match.group(1),
                        "template_id": text_match.group(2),
                        "protocol": text_match.group(3),
                        "matched_at": text_match.group(4),
                    })

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(key=lambda f: severity_order.get(f.get("severity", "info"), 5))

        return {
            "findings": findings,
            "total": len(findings),
            "by_severity": {
                sev: len([f for f in findings if f.get("severity") == sev])
                for sev in ["critical", "high", "medium", "low", "info"]
                if any(f.get("severity") == sev for f in findings)
            },
            "summary": f"Found {len(findings)} issue(s)"
        }


class SQLMapParser:
    """Parse sqlmap output."""

    @staticmethod
    def parse(raw_output: str) -> dict[str, Any]:
        vulnerable = False
        injections = []
        dbms = None

        for line in raw_output.split('\n'):
            line_lower = line.lower().strip()
            if 'is vulnerable' in line_lower or 'injectable' in line_lower:
                vulnerable = True
            if 'type:' in line_lower and 'injection' in line_lower:
                injections.append(line.strip())
            if 'back-end dbms' in line_lower:
                dbms_match = re.search(r'back-end DBMS:\s*(.+)', line, re.IGNORECASE)
                if dbms_match:
                    dbms = dbms_match.group(1).strip()

        parameters = re.findall(r"parameter '(\w+)' is vulnerable", raw_output, re.IGNORECASE)

        return {
            "vulnerable": vulnerable,
            "parameters": parameters,
            "injection_types": injections,
            "dbms": dbms,
            "summary": (
                f"SQL Injection {'FOUND' if vulnerable else 'not found'}"
                + (f" in parameter(s): {', '.join(parameters)}" if parameters else "")
                + (f" | DBMS: {dbms}" if dbms else "")
            )
        }


class HydraParser:
    """Parse hydra output."""

    @staticmethod
    def parse(raw_output: str) -> dict[str, Any]:
        credentials = []
        for line in raw_output.split('\n'):
            # [22][ssh] host: 10.10.10.20   login: admin   password: password123
            match = re.search(
                r'login:\s*(\S+)\s+password:\s*(\S+)',
                line, re.IGNORECASE
            )
            if match:
                credentials.append({
                    "username": match.group(1),
                    "password": match.group(2),
                })

        return {
            "success": len(credentials) > 0,
            "credentials": credentials,
            "total": len(credentials),
            "summary": (
                f"Found {len(credentials)} valid credential(s)"
                if credentials else "No valid credentials found"
            )
        }


class GenericParser:
    """Fallback parser."""

    @staticmethod
    def parse(tool_name: str, raw_output: str, max_lines: int = 80) -> dict[str, Any]:
        lines = raw_output.strip().split('\n')
        truncated = len(lines) > max_lines
        return {
            "tool": tool_name,
            "output_lines": len(lines),
            "truncated": truncated,
            "content": '\n'.join(lines[:max_lines]),
            "summary": f"{tool_name} returned {len(lines)} lines of output"
        }


# === Router ===

def _extract_embedded_json(raw_output: str) -> dict[str, Any] | None:
    """Extract the structured dict embedded by the modern integration layer.

    ToolIntegration handlers return a summary string shaped like:

        [nmap] OK
        { ... json of ToolResult.parsed ... }

    (see quarr/tools/registry._summarize). That structured data is
    authoritative; re-parsing the summary text with the legacy regex parsers
    loses fields such as discovered services. Returns the parsed dict, or None
    if the output is not in that format.
    """
    if not raw_output:
        return None
    brace = raw_output.find("{")
    if brace == -1:
        return None
    header = raw_output[:brace]
    if "OK" not in header and "FAILED" not in header:
        return None
    try:
        data = json.loads(raw_output[brace:])
    except (json.JSONDecodeError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def parse_tool_output(tool_name: str, raw_output: str) -> dict[str, Any]:
    """Pilih parser yang tepat berdasarkan tool name."""

    # Modern integration handlers embed their structured result as JSON in the
    # summary string (see registry._summarize). Prefer that authoritative data
    # over re-parsing the summary text (which loses services, etc.).
    embedded = _extract_embedded_json(raw_output)
    if embedded is not None:
        if tool_name == "network_discovery":
            embedded.setdefault("total_up", len(embedded.get("hosts", [])))
        elif tool_name == "service_enumeration" and not embedded.get("host"):
            services = embedded.get("services", [])
            if services:
                embedded["host"] = services[0].get("host")
        return embedded

    # Mobile tools → mobile parsers
    mobile_tools = {
        "apk_decompile", "apk_secrets_scan", "apk_manifest_analysis",
        "adb_storage_check",
    }
    if tool_name in mobile_tools:
        from quarr.parsers.mobile import parse_mobile_output
        return parse_mobile_output(tool_name, raw_output)

    parser_map = {
        "network_discovery": lambda o: NmapParser.parse_host_discovery(o),
        "service_enumeration": lambda o: NmapParser.parse_service_scan(o),
        "subdomain_enum": lambda o: SubdomainParser.parse(o),
        "web_fingerprint": lambda o: WebFingerprintParser.parse(o),
        "web_content_discovery": lambda o: GobusterParser.parse(o),
        "vulnerability_scan": lambda o: NucleiParser.parse(o),
        "sqli_scan": lambda o: SQLMapParser.parse(o),
        "bruteforce_login": lambda o: HydraParser.parse(o),
    }

    parser = parser_map.get(tool_name)
    if parser:
        try:
            return parser(raw_output)
        except Exception:
            pass

    return GenericParser.parse(tool_name, raw_output)
