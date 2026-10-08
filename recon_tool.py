#!/usr/bin/env python3
import argparse
import json
import socket
import ssl
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List
from urllib.parse import urlparse

import requests

try:
    import dns.resolver
except ModuleNotFoundError as exc:  # pragma: no cover
    raise SystemExit("dnspython is required. Install with: pip install -r requirements.txt") from exc

COMMON_PATHS = [
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/admin",
    "/login",
    "/wp-admin",
    "/api",
    "/graphql",
    "/cgi-bin",
    "/.git/config",
    "/backup",
    "/.env",
    "/server-status",
    "/phpinfo.php",
]
COMMON_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 8080, 8443, 3306, 3389]


def normalize_url(raw_url: str) -> str:
    value = raw_url.strip()
    if not value:
        raise ValueError("A URL is required.")
    if "//" not in value:
        value = "https://" + value
    parsed = urlparse(value)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError(f"Invalid URL: {raw_url}")
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only http:// and https:// URLs are supported.")
    return f"{parsed.scheme}://{parsed.netloc}"


def extract_host_and_domain(url: str):
    parsed = urlparse(url)
    host = parsed.hostname or parsed.netloc
    domain = host
    if host and host.count(".") > 1:
        parts = host.split(".")
        domain = ".".join(parts[-2:])
    return host, domain


def dns_lookup(domain: str) -> Dict[str, List[str]]:
    records: Dict[str, List[str]] = {}
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 5

    for record_type in ("A", "AAAA", "NS", "MX", "TXT"):
        try:
            answer = resolver.resolve(domain, record_type)
            records[record_type] = sorted(str(item) for item in answer)
        except dns.resolver.NoAnswer:
            records[record_type] = []
        except dns.resolver.NXDOMAIN:
            records[record_type] = ["NXDOMAIN"]
        except dns.resolver.LifetimeTimeout:
            records[record_type] = ["DNS timeout"]
        except Exception:
            records[record_type] = ["Lookup failed"]
    return records


def fetch_http_summary(target_url: str) -> Dict[str, Any]:
    headers = {"User-Agent": "Mozilla/5.0 reconnaissance-scanner/1.0"}
    try:
        response = requests.get(target_url, timeout=10, headers=headers, allow_redirects=True)
        content = response.text or ""
        title = ""
        try:
            start = content.lower().find("<title>")
            if start != -1:
                end = content.lower().find("</title>", start)
                if end != -1:
                    title = content[start + 7 : end].strip()
        except Exception:
            title = ""

        summary = {
            "status_code": response.status_code,
            "final_url": response.url,
            "server": response.headers.get("Server", ""),
            "x_powered_by": response.headers.get("X-Powered-By", ""),
            "content_type": response.headers.get("Content-Type", ""),
            "title": title,
            "response_time_ms": round(response.elapsed.total_seconds() * 1000, 2),
            "headers": dict(response.headers),
        }
        return summary
    except requests.RequestException as exc:
        return {"error": str(exc), "status_code": None}


def ssl_summary(host: str, port: int = 443) -> Dict[str, Any]:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as wrapped:
                cert = wrapped.getpeercert()
                return {
                    "protocol": wrapped.version(),
                    "cipher": wrapped.cipher(),
                    "issuer": cert.get("issuer", ""),
                    "subject": cert.get("subject", ""),
                    "not_before": cert.get("notBefore", ""),
                    "not_after": cert.get("notAfter", ""),
                    "subject_alt_names": cert.get("subjectAltName", []),
                }
    except Exception as exc:
        return {"error": str(exc)}


def port_scan(host: str, ports: List[int] = None) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    for port in ports or COMMON_PORTS:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.5)
        try:
            sock.connect((host, port))
            results.append({"port": port, "state": "open"})
        except OSError:
            pass
        finally:
            sock.close()
    return results


def directory_enumeration(base_url: str) -> List[Dict[str, Any]]:
    base = base_url.rstrip("/")
    findings: List[Dict[str, Any]] = []
    headers = {"User-Agent": "Mozilla/5.0 reconnaissance-scanner/1.0"}

    for path in COMMON_PATHS:
        url = f"{base}{path}"
        try:
            response = requests.get(url, timeout=5, headers=headers, allow_redirects=False)
        except requests.RequestException:
            continue

        status = response.status_code
        if status in (200, 301, 302, 401, 403, 500):
            findings.append({
                "path": path,
                "status_code": status,
                "location": response.headers.get("Location", ""),
                "content_type": response.headers.get("Content-Type", ""),
            })

    return findings


def extract_security_headers(headers: Dict[str, str]) -> Dict[str, Any]:
    security_checks = {
        "strict_transport_security": headers.get("Strict-Transport-Security", "missing"),
        "x_frame_options": headers.get("X-Frame-Options", "missing"),
        "x_content_type_options": headers.get("X-Content-Type-Options", "missing"),
        "content_security_policy": headers.get("Content-Security-Policy", "missing"),
        "referrer_policy": headers.get("Referrer-Policy", "missing"),
    }
    missing = [name for name, value in security_checks.items() if value == "missing"]
    return {"checks": security_checks, "missing": missing}


def subdomain_lookup(domain: str) -> List[str]:
    try:
        response = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=10)
        if response.status_code != 200:
            return []
        data = response.json()
        subdomains = []
        for item in data:
            name = item.get("name_value")
            if not name:
                continue
            for candidate in name.split("\n"):
                value = candidate.strip().lower()
                if value and value.endswith(domain) and value not in subdomains:
                    subdomains.append(value)
        return sorted(subdomains)[:20]
    except Exception:
        return []


def run_recon(target_url: str) -> Dict[str, Any]:
    normalized = normalize_url(target_url)
    parsed = urlparse(normalized)
    host, domain = extract_host_and_domain(normalized)
    http_summary = fetch_http_summary(normalized)
    security_headers = extract_security_headers(http_summary.get("headers", {})) if http_summary.get("headers") else {"checks": {}, "missing": []}

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": normalized,
        "host": host,
        "domain": domain,
        "tools_used": [
            {"name": "dnspython", "purpose": "DNS record lookups"},
            {"name": "requests", "purpose": "HTTP requests, directory probing, and subdomain discovery"},
            {"name": "ssl", "purpose": "TLS certificate inspection"},
            {"name": "socket", "purpose": "Port scanning"},
        ],
        "passive": {
            "dns": dns_lookup(domain),
            "http": http_summary,
            "tls": ssl_summary(host, 443 if parsed.scheme == "https" else 80),
            "security_headers": security_headers,
            "subdomains": subdomain_lookup(domain),
        },
        "active": {
            "ports": port_scan(host),
            "interesting_paths": directory_enumeration(normalized),
        },
    }
    return report


def flatten_cert_entries(value: Any) -> str:
    if not value:
        return "Unknown"
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        parts: List[str] = []
        for item in value:
            if isinstance(item, list):
                for sub_item in item:
                    if isinstance(sub_item, list) and len(sub_item) == 2:
                        _, text = sub_item
                        if isinstance(text, str) and text not in parts:
                            parts.append(text)
                    elif isinstance(sub_item, str) and sub_item not in parts:
                        parts.append(sub_item)
            elif isinstance(item, str) and item not in parts:
                parts.append(item)
        return ", ".join(parts) if parts else "Unknown"
    return str(value)


def summarize_recon(report: Dict[str, Any]) -> Dict[str, Any]:
    http = report["passive"]["http"]
    tls = report["passive"]["tls"]
    open_ports = report["active"]["ports"]
    paths = report["active"]["interesting_paths"]
    dns = report["passive"]["dns"]
    security_headers = report["passive"].get("security_headers", {"missing": []})
    subdomains = report["passive"].get("subdomains", [])

    score = 0
    findings: List[str] = []

    if http.get("status_code") and http["status_code"] >= 500:
        score += 20
        findings.append("The site is returning server-side errors, suggesting instability or a misconfigured application layer.")
    elif http.get("status_code") and http["status_code"] in (401, 403):
        score += 15
        findings.append("Access to resources is restricted, which may indicate protected admin or sensitive endpoints.")

    missing_headers = security_headers.get("missing", [])
    if missing_headers:
        score += min(25, len(missing_headers) * 8)
        findings.append(f"Security headers are missing: {', '.join(missing_headers).replace('_', ' ')}. This reduces browser-side protection.")

    if open_ports:
        sensitive_ports = {21, 22, 23, 80, 443, 3306, 3389, 8080, 8443}
        detected = sorted({item["port"] for item in open_ports if item["port"] in sensitive_ports})
        if detected:
            score += min(25, len(detected) * 7)
            findings.append(f"Common internet-facing service ports are open: {', '.join(str(port) for port in detected)}.")

    if paths:
        score += min(25, len(paths) * 8)
        findings.append("The scan found likely exposed web paths, which may reveal hidden admin or development assets.")

    if subdomains:
        score += min(15, len(subdomains) * 2)
        findings.append(f"Subdomain discovery returned {len(subdomains)} likely hostnames, which expands the attack surface.")

    if tls.get("error"):
        score += 20
        findings.append("TLS inspection failed, which can indicate certificate or protocol issues.")
    elif tls.get("not_after"):
        try:
            expiry = datetime.strptime(tls["not_after"], "%b %d %H:%M:%S %Y %Z")
            days_left = (expiry - datetime.now()).days
            if days_left <= 30:
                score += 20
                findings.append(f"The TLS certificate expires in {days_left} days, which is a maintenance issue worth tracking.")
        except Exception:
            pass

    if any(value == ["DNS timeout"] or value == ["Lookup failed"] or value == ["NXDOMAIN"] for value in dns.values()):
        score += 10
        findings.append("Some DNS records timed out or failed, which can indicate incomplete public visibility or resolution problems.")

    if not findings:
        findings.append("No obvious weaknesses were detected in this reconnaissance pass; the target appears relatively clean.")

    score = min(score, 100)
    if score >= 70:
        severity = "HIGH RISK"
    elif score >= 35:
        severity = "MEDIUM RISK"
    else:
        severity = "LOW RISK"

    overall = "The target appears comparatively exposed and should be reviewed for hidden endpoints, weak headers, and exposed services."
    if score < 35:
        overall = "The target appears relatively clean from a quick reconnaissance perspective, with no major exposure indicators detected."
    elif score < 70:
        overall = "The target shows some exposure patterns, but nothing immediately conclusive. It should still be reviewed for hardening gaps."

    return {"score": score, "severity": severity, "overall": overall, "findings": findings}


def format_text_report(report: Dict[str, Any]) -> str:
    summary = summarize_recon(report)
    lines: List[str] = []
    lines.append("=" * 78)
    lines.append("Website Reconnaissance Report")
    lines.append("=" * 78)
    lines.append(f"Target:        {report['target']}")
    lines.append(f"Host:          {report['host']}")
    lines.append(f"Domain:        {report['domain']}")
    lines.append(f"Timestamp:     {report['timestamp']}")
    lines.append("")

    lines.append("PASSIVE RECON")
    lines.append("-" * 78)
    http = report["passive"]["http"]
    if http.get("error"):
        lines.append(f"HTTP:          ERROR - {http['error']}")
    else:
        lines.append(f"HTTP status:   {http.get('status_code')}")
        lines.append(f"Server:        {http.get('server') or 'Unknown'}")
        lines.append(f"Title:         {http.get('title') or 'Unknown'}")
        lines.append(f"Final URL:     {http.get('final_url') or 'Unknown'}")
        lines.append(f"Response time: {http.get('response_time_ms')} ms")

    dns = report["passive"]["dns"]
    lines.append("DNS records:")
    record_found = False
    for record_type, values in dns.items():
        if values:
            record_found = True
            display_values = ", ".join(values[:5])
            lines.append(f"  - {record_type}: {display_values}")
    if not record_found:
        lines.append("  - No DNS records found")

    tls = report["passive"]["tls"]
    if tls.get("error"):
        lines.append(f"TLS:           ERROR - {tls['error']}")
    else:
        lines.append(f"TLS protocol: {tls.get('protocol') or 'Unknown'}")
        if tls.get("issuer"):
            lines.append(f"TLS issuer:   {flatten_cert_entries(tls['issuer'])}")
        if tls.get("subject_alt_names"):
            alt_names = ", ".join(name[1] for name in tls["subject_alt_names"] if isinstance(name, list) and len(name) > 1)
            lines.append(f"SAN:          {alt_names or 'None'}")
        if tls.get("not_after"):
            lines.append(f"TLS expiry:   {tls['not_after']}")

    lines.append("")
    lines.append("TOOLS USED")
    lines.append("-" * 78)
    for tool in report.get("tools_used", []):
        lines.append(f"- {tool['name']}: {tool['purpose']}")

    lines.append("")
    lines.append("ACTIVE RECON")
    lines.append("-" * 78)
    open_ports = report["active"]["ports"]
    if open_ports:
        port_list = ", ".join(str(item["port"]) for item in open_ports)
        lines.append(f"Open ports:   {port_list}")
    else:
        lines.append("Open ports:   None detected")

    paths = report["active"]["interesting_paths"]
    if paths:
        lines.append("Interesting paths:")
        for item in paths[:10]:
            lines.append(f"  - {item['path']} -> HTTP {item['status_code']}")
    else:
        lines.append("Interesting paths: None found")

    lines.append("")
    lines.append("SUMMARY")
    lines.append("-" * 78)
    lines.append(f"Risk score:    {summary['score']}/100")
    lines.append(f"Risk level:    {summary['severity']}")
    lines.append(f"Overall:       {summary['overall']}")

    lines.append("")
    lines.append("PASSIVE DETAILS")
    lines.append("-" * 78)
    security_headers = report["passive"].get("security_headers", {})
    missing_headers = security_headers.get("missing", [])
    if missing_headers:
        lines.append("Missing security headers:")
        for header in missing_headers:
            lines.append(f"  - {header.replace('_', ' ').title()}")
    else:
        lines.append("Missing security headers: None")

    subdomains = report["passive"].get("subdomains", [])
    if subdomains:
        lines.append("Likely subdomains:")
        for subdomain in subdomains[:10]:
            lines.append(f"  - {subdomain}")
    else:
        lines.append("Likely subdomains: None found")

    lines.append("")
    lines.append("FINDINGS")
    lines.append("-" * 78)
    for index, finding in enumerate(summary["findings"], start=1):
        lines.append(f"{index}. {finding}")

    lines.append("=" * 78)
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Passive + active website reconnaissance CLI")
    parser.add_argument("url", help="Target URL, for example: https://example.com")
    parser.add_argument("--json", action="store_true", help="Emit JSON only")
    args = parser.parse_args()

    try:
        report = run_recon(args.url)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0

    print(format_text_report(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
