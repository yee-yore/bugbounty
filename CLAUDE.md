# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

STOMON (Subdomain Takeover Monitor) is a vulnerability scanner for bug bounty hunting. It enumerates subdomains for target domains and checks for potential subdomain takeover vulnerabilities using the `baddns` tool.

## Key Commands

### Single Domain Scan
```bash
./stomon.sh -d example.com
```

### Fast Parallel Scan
```bash
./stomon.sh -d example.com -w 10
```

### Scan Multiple Domains from List
```bash
./stomon.sh -l domain_list.txt -c 3
```

### VPS Daemon Mode (24h interval)
```bash
./stomon.sh -l domain_list.txt -vps 24
```

### Filter by Confidence Level
```bash
./stomon.sh -d example.com --confidence confirmed
```

## Project Architecture

### Core Components

1. **stomon.sh**: Main bash script that orchestrates the scanning process
   - Subdomain enumeration using `subfinder`
   - Vulnerability detection using `baddns`
   - Parallel processing support for faster scans
   - Telegram notifications for alerts
   - AI-powered false positive detection via OpenAI API

2. **Data Flow**:
   ```
   Target Domain → Subfinder → Subdomains → BadDNS → Vulnerability Detection → Reports/Alerts
   ```

3. **Output Structure**:
   ```
   results/
   └── {domain}/
       └── {timestamp}/
           ├── all_subdomains.txt     # All enumerated subdomains
           ├── subdomains.txt         # Filtered by depth
           ├── baddns_raw.json        # Raw baddns scan results
           ├── vulnerable_confirmed.txt # High confidence vulnerabilities
           ├── vulnerable_probable.txt  # Medium confidence findings
           ├── vulnerable_all.txt      # All potential vulnerabilities
           ├── report.json            # JSON format report
           └── summary.txt            # Human-readable summary
   ```

## Key Configuration Variables

- **TELEGRAM_ENABLED**: Enable/disable Telegram notifications
- **TELEGRAM_BOT_TOKEN**: Bot token for sending alerts
- **TELEGRAM_CHAT_ID**: Chat ID for receiving alerts
- **OPENAI_API_KEY**: API key for AI false positive analysis
- **ENABLE_AI_ANALYSIS**: Enable/disable AI analysis
- **BADDNS_WORKERS**: Number of parallel workers (1=safe, 10=fast, 20+=very fast)
- **CONFIDENCE_LEVEL**: Filter results (all|confirmed|probable)
- **OUTPUT_FORMAT**: Output format (all|json|text)

## Dependencies

- **subfinder**: Subdomain enumeration tool
- **baddns**: Subdomain takeover vulnerability detection
- **jq**: JSON parsing (optional but recommended)
- **curl**: API communications for Telegram and OpenAI

## Security Considerations

The script contains API keys and tokens that should be managed securely. Consider:
- Moving sensitive credentials to environment variables
- Using a `.env` file with proper gitignore
- Rotating API keys regularly
- Never committing credentials to version control

## Common Development Tasks

### Adding New Domains
Edit `domain_list.txt` and add domains, one per line.

### Checking Scan History
```bash
tail -f scan_history.log
```

### Viewing Latest Results
Results are stored in `results/{domain}/{timestamp}/` directories.

### Adjusting Scan Performance
- Use `-w` flag to control parallel workers
- Higher values = faster scans but may trigger rate limits
- Recommended: 5-10 for balanced performance