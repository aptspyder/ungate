

**403/401 bypass framework — built for bug bounty hunters**

[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat-square&logo=go)](https://golang.org)
[![Release](https://img.shields.io/github/v/release/aptspyder/ungate?style=flat-square&color=00ff88)](https://github.com/aptspyder/ungate/releases)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)

</div>

---

Automatically tests **verb tampering, header injection, path manipulation, double encoding, unicode tricks, host header abuse, user-agent spoofing** and more — with auto-calibration to eliminate noise.

## Install
```bash
go install github.com/aptspyder/ungate@latest
```

**Add to PATH:**
```bash
# Linux / Kali / WSL
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc && source ~/.bashrc

# Zsh
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.zshrc && source ~/.zshrc

# Windows PowerShell
$env:PATH += ";$(go env GOPATH)\bin"
```

## Usage
```
ungate [options]

  -u  <url>             target URL (required)
  -t  <method>          HTTP method (default: GET)
  -H  <header>          'Key: Value' — repeatable
  -x  <proxy>           proxy URL (e.g. http://127.0.0.1:8080)
  -i  <ip>              custom IP for header injection
  -a  <agent>           custom User-Agent
  -k  <techs>           comma-sep techniques or 'all' (default: all)
  -g  <n>               max goroutines (default: 50)
  -d  <ms>              delay between requests (ms)
  -o  <file>            save output to file
  -r                    follow redirects
  -l                    stop on 429 rate limit
  -v                    verbose: show all results
  --json                JSON output
  --random-agent        random User-Agent per request
  --no-color            disable color
  --no-banner           disable banner
  --version             print version
```

## Examples
```bash
# Full scan
ungate -u https://target.com/admin

# Specific techniques only
ungate -u https://target.com/admin -k verbs,headers

# Through Burp Suite
ungate -u https://target.com/admin -x http://127.0.0.1:8080 -v

# With auth token + save output
ungate -u https://target.com/admin -H 'Authorization: Bearer TOKEN' -o out.txt

# JSON output for pipeline
ungate -u https://target.com/admin --json -o results.json | jq .

# Rate-limit safe with delay
ungate -u https://target.com/admin -d 200 -l
```

## Techniques

| Tag | Technique | Description |
|-----|-----------|-------------|
| `VERB` | HTTP Verb Tampering | 50+ methods including WebDAV, arbitrary verbs |
| `HDR-IP` | Header IP Injection | 80+ headers × 50+ IP values |
| `HDR` | Header Injection | Method overrides, auth bypass, cache control |
| `EPATH` | End-Path Payloads | Suffix tricks: `%00`, `..;/`, `.json`, `?debug=1` |
| `MPATH` | Mid-Path Insertion | Inject traversal sequences between path segments |
| `DBLENC` | Double Encoding | `%252f`, `%2520`, nested percent encoding |
| `UNIC` | Unicode / Overlong UTF-8 | `%u002f`, `%c0%af`, overlong sequences |
| `CASE` | Path Case Switching | Mixed-case path permutations |
| `HTTP` | HTTP Version Bypass | Connection header manipulation |
| `UA` | User-Agent Spoofing | Crawlers, health checkers, cloud providers |
| `HOST` | Host Header Injection | localhost, internal subdomains, port variants |
| `CTYPE` | Content-Type Fuzzing | 40+ content types including exotic MIME types |

## Detects

`VERB-BYPASS` `IP-HEADER` `HDR-OVERRIDE` `PATH-TRAVERSAL` `DOUBLE-ENC` `UNICODE` `CASE-BYPASS` `UA-BYPASS` `HOST-BYPASS` `CTYPE-BYPASS`

## Disclaimer

This tool is strictly for educational purposes and authorized security research only. Any actions and/or activities related to the material contained within this repository are solely your responsibility. The developers will not be held responsible for any misuse or damage caused by this program. Do not use this tool on systems you do not have explicit permission to test.
