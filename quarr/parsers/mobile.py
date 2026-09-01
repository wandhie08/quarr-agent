"""
mobile_parsers.py - M8: Parsers for Mobile Tool Output
"""

import re
import json
from typing import Dict, Any, List


class APKDecompileParser:
    @staticmethod
    def parse(raw_output: str) -> Dict[str, Any]:
        apktool_match = re.search(r'\[apktool\] Decoded to (\S+) \((\d+) files\)', raw_output)
        jadx_match = re.search(r'\[jadx\] Decompiled to (\S+) \((\d+) files\)', raw_output)

        return {
            "apktool": {
                "success": apktool_match is not None,
                "path": apktool_match.group(1) if apktool_match else None,
                "files": int(apktool_match.group(2)) if apktool_match else 0,
            },
            "jadx": {
                "success": jadx_match is not None,
                "path": jadx_match.group(1) if jadx_match else None,
                "files": int(jadx_match.group(2)) if jadx_match else 0,
            },
            "summary": (
                f"APK decompiled: apktool ({apktool_match.group(2) if apktool_match else 0} files), "
                f"jadx ({jadx_match.group(2) if jadx_match else 0} files)"
            )
        }


class SecretsParser:
    @staticmethod
    def parse(raw_output: str) -> Dict[str, Any]:
        secrets = []
        api_endpoints = []

        in_secrets = False
        in_endpoints = False

        for line in raw_output.split("\n"):
            line = line.strip()
            if "SECRETS FOUND" in line:
                in_secrets = True
                in_endpoints = False
                continue
            elif "API ENDPOINTS" in line:
                in_endpoints = True
                in_secrets = False
                continue
            elif line.startswith("==="):
                in_secrets = False
                in_endpoints = False
                continue

            if in_secrets and line and ":" in line:
                # file:line:content
                parts = line.split(":", 2)
                if len(parts) >= 3:
                    secrets.append({
                        "file": parts[0],
                        "line": parts[1],
                        "content": parts[2].strip()[:200],
                    })
            elif in_endpoints and line:
                url_match = re.search(r'(https?://[^\s"\']+)', line)
                if url_match:
                    api_endpoints.append(url_match.group(1))

        return {
            "secrets": secrets[:30],
            "api_endpoints": list(set(api_endpoints))[:20],
            "total_secrets": len(secrets),
            "total_endpoints": len(set(api_endpoints)),
            "summary": f"Found {len(secrets)} secret(s) and {len(set(api_endpoints))} API endpoint(s)"
        }


class ManifestParser:
    @staticmethod
    def parse(raw_output: str) -> Dict[str, Any]:
        findings = []
        app_info = {}

        for line in raw_output.split("\n"):
            line = line.strip()

            # Parse info
            if line.startswith("Package:"):
                app_info["package"] = line.split(":", 1)[1].strip()
            elif line.startswith("minSdkVersion:"):
                app_info["min_sdk"] = line.split(":", 1)[1].strip()
            elif line.startswith("targetSdkVersion:"):
                app_info["target_sdk"] = line.split(":", 1)[1].strip()
            elif line.startswith("Dangerous permissions:"):
                app_info["dangerous_permissions"] = line.split(":", 1)[1].strip()
            elif line.startswith("Deeplink hosts:"):
                app_info["deeplink_hosts"] = line.split(":", 1)[1].strip()

            # Parse findings
            severity_match = re.match(r'\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]\s+(.+)', line)
            if severity_match:
                findings.append({
                    "severity": severity_match.group(1).lower(),
                    "description": severity_match.group(2),
                })

        # Sort by severity
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(key=lambda f: sev_order.get(f["severity"], 5))

        by_severity = {}
        for f in findings:
            s = f["severity"]
            by_severity[s] = by_severity.get(s, 0) + 1

        return {
            "app_info": app_info,
            "findings": findings,
            "total_findings": len(findings),
            "by_severity": by_severity,
            "summary": (
                f"Manifest analysis: {len(findings)} finding(s) "
                f"({', '.join(f'{k}: {v}' for k, v in by_severity.items())})"
            )
        }


class StorageParser:
    @staticmethod
    def parse(raw_output: str) -> Dict[str, Any]:
        sensitive_data = []
        databases = []
        external_files = []

        section = None
        for line in raw_output.split("\n"):
            line = line.strip()
            if "SENSITIVE DATA" in line:
                section = "sensitive"
            elif "DATABASES" in line:
                section = "databases"
            elif "EXTERNAL STORAGE" in line:
                section = "external"
            elif line.startswith("==="):
                section = None
            elif line and section == "sensitive":
                sensitive_data.append(line[:200])
            elif line and section == "databases":
                databases.append(line)
            elif line and section == "external":
                external_files.append(line)

        return {
            "sensitive_data": sensitive_data[:20],
            "databases": databases[:10],
            "external_files": external_files[:10],
            "summary": (
                f"Storage: {len(sensitive_data)} sensitive item(s), "
                f"{len(databases)} database(s), "
                f"{len(external_files)} external file(s)"
            )
        }


def parse_mobile_output(tool_name: str, raw_output: str) -> Dict[str, Any]:
    """Router for mobile tool parsers."""
    parser_map = {
        "apk_decompile": APKDecompileParser.parse,
        "apk_secrets_scan": SecretsParser.parse,
        "apk_manifest_analysis": ManifestParser.parse,
        "adb_storage_check": StorageParser.parse,
    }

    parser = parser_map.get(tool_name)
    if parser:
        try:
            return parser(raw_output)
        except Exception:
            pass

    # Generic
    lines = raw_output.strip().split("\n")
    return {
        "tool": tool_name,
        "output_lines": len(lines),
        "content": "\n".join(lines[:80]),
        "summary": f"{tool_name}: {len(lines)} lines of output"
    }
