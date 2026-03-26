# ungate
**Advanced 403/401 Bypass Framework & Access Control Tester**

ungate is a high-performance, concurrent Go tool designed for professional
bug bounty hunters and penetration testers targeting misconfigured access controls.

**Key Feature: Auto-Calibration.**
ungate baselines the target before scanning to eliminate false positives,
so every hit it surfaces is genuinely interesting.

## Features
- **11 Bypass Techniques**: Verb tampering, header injection, path manipulation, encoding tricks, and more.
- **500+ Payloads**: Covers IP headers, end-paths, mid-paths, user-agents, content-types, and host headers.
- **Auto-Calibration**: Baselines response length and status to filter noise automatically.
- **Concurrency**: Blazing fast scanning using Go routines with configurable thread count.
- **JSON Output**: Machine-readable results for pipeline integration and reporting.

## Installation
```
go install github.com/aptspyder/ungate/v2@latest
```

## Usage
```
ungate -u https://target.com/admin
ungate -u https://target.com/admin -k verbs,headers
ungate -u https://target.com/admin -x http://127.0.0.1:8080 -v
ungate -u https://target.com/admin -H 'Authorization: Bearer TOKEN' -o out.txt
ungate -u https://target.com/admin --json -o results.json
```

## Disclaimer
This tool is strictly for educational purposes and authorized security research only.
Any actions and/or activities related to the material contained within this repository
are solely your responsibility. The developers will not be held responsible for any
misuse or damage caused by this program. Do not use this tool on systems you do not
have explicit permission to test.
