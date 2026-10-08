# Website Reconnaissance Tool

This project provides a lightweight reconnaissance CLI that accepts a target URL and performs a combination of passive and active checks.

## Features

- DNS lookups for A, AAAA, NS, MX, and TXT records
- HTTP response analysis, including status code, headers, title, and server information
- Basic TLS certificate inspection
- Port scan for common services
- Directory enumeration of likely web paths

## Setup

```bash
python -m pip install -r requirements.txt
```

## Usage

```bash
python recon_tool.py https://example.com
```

JSON output:

```bash
python recon_tool.py https://example.com --json
```

## Example output

```text
Target: https://example.com
Host: example.com
Domain: example.com

Passive recon:
  - HTTP status: 200
  - Server: nginx
  - Title: Example Domain
  - A: 93.184.216.34

Active recon:
  - Open ports: 80, 443
  - Interesting paths:
      * /robots.txt -> HTTP 200
```

## Notes

This tool is intentionally focused on ethical reconnaissance and introspection. Use it only against systems you own or are explicitly authorized to test.
