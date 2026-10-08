# Website Reconnaissance Tool

This project provides a lightweight reconnaissance tool that accepts a target URL and performs passive and active checks. It now includes both a CLI and a simple browser-based web interface.

## Features

- DNS lookups for A, AAAA, NS, MX, and TXT records
- HTTP response analysis, including status codes, headers, title, and server information
- TLS certificate inspection
- Port scan for common services
- Directory enumeration for likely web paths
- Subdomain discovery via public certificate transparency data
- Security header analysis
- A clean browser form that shows the full reconnaissance report in one view

## Setup

```bash
python -m pip install -r requirements.txt
```

## Web interface usage

```bash
python app.py
```

Then open:

```text
http://127.0.0.1:5000/
```

## CLI usage

```bash
python recon_tool.py https://example.com
```

JSON output:

```bash
python recon_tool.py https://example.com --json
```

## Notes

This tool is intentionally focused on ethical reconnaissance and introspection. Use it only against systems you own or are explicitly authorized to test.
