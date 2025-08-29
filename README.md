# STOMON

A powerful subdomain takeover monitor for bug bounty hunters. Features parallel scanning, AI-powered false positive detection, and automated alerts.

## Features

- **Subdomain Enumeration** - Uses subfinder for comprehensive subdomain discovery
- **Parallel Scanning** - Multi-threaded scanning with configurable workers
- **AI False Positive Detection** - OpenAI integration to reduce false positives
- **Telegram Alerts** - Real-time notifications for discovered vulnerabilities
- **Daemon Mode** - Continuous monitoring with scheduled scans

## Workflow

1. **Subdomain Enumeration** - Discovers all subdomains using subfinder
2. **Vulnerability Scanning** - Checks each subdomain for takeover vulnerabilities using baddns
3. **False Positive Analysis** - Uses OpenAI API to analyze and filter results (optional)
4. **Alert & Report** - Sends Telegram notifications and generates detailed reports

## Prerequisites

```bash
# Required tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
pip install baddns # https://github.com/blacklanternsecurity/baddns

# Optional (recommended)
brew install jq  # For JSON parsing
```

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yee-yore/stomon.git
cd stomon
```

2. Configure credentials:
```bash
cp .env.example .env
# Edit .env with your credentials
nano .env
```

## Configuration

### Setting up Credentials

1. **Copy the example environment file:**
```bash
cp .env.example .env
```

2. **Edit `.env` file with your credentials:**

```bash
# Telegram Configuration (Optional)
TELEGRAM_ENABLED=true
TELEGRAM_BOT_TOKEN=your-bot-token-here
TELEGRAM_CHAT_ID=your-chat-id-here

# OpenAI Configuration (Optional)
ENABLE_AI_ANALYSIS=true
OPENAI_API_KEY=sk-your-api-key-here
```

### Getting Credentials

#### Telegram Bot Setup:
1. Message [@BotFather](https://t.me/botfather) on Telegram
2. Create a new bot with `/newbot`
3. Copy the bot token
4. Get your chat ID from [@userinfobot](https://t.me/userinfobot)

#### OpenAI API Key:
1. Visit [OpenAI API Keys](https://platform.openai.com/api-keys)
2. Create a new API key
3. Copy and save securely

## Usage

```bash
# Make the script executable
chmod +x stomon.sh
```

### Single Domain Scan
```bash
./stomon.sh -d example.com
```

### Fast Parallel Scan
```bash
./stomon.sh -d example.com -w 10
```

### Scan Multiple Domains
```bash
# Add domains to domain_list.txt (one per line)
./stomon.sh -l domain_list.txt -c 3 -w 5
```

### Daemon Mode (VPS Monitoring)
```bash
# Scan every 24 hours
./stomon.sh -l domain_list.txt -vps 24
```

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `-d DOMAIN` | Target domain to scan | - |
| `-l FILE` | Scan domains from list file | - |
| `-w N` | Parallel baddns workers | 1 |
| `-c N` | Concurrent domain scans | 1 |
| `-o FORMAT` | Output format (all/json/text) | all |
| `--confidence LEVEL` | Filter results (all/confirmed/probable) | all |
| `-vps HOURS` | Daemon mode interval | - |
| `--help` | Show help message | - |

## Output Structure

```
results/
└── example.com/
    └── 20250829_123456/
        ├── all_subdomains.txt      # All enumerated subdomains
        ├── subdomains.txt          # Filtered subdomains
        ├── baddns_raw.json         # Raw scan results
        ├── vulnerable_confirmed.txt # High confidence findings
        ├── vulnerable_probable.txt  # Medium confidence findings
        ├── vulnerable_all.txt      # All potential vulnerabilities
        ├── report.json             # JSON report
        └── summary.txt             # Human-readable summary
```

## Performance Tips

- **Workers (`-w`):**
  - `1`: Safe, slow (default)
  - `5`: Balanced
  - `10`: Fast
  - `20+`: Very fast (may trigger rate limits)

- **Concurrency (`-c`):**
  - Number of domains to scan simultaneously
  - Recommended: 3-5 for optimal performance

## Disclaimer

This tool is for educational and authorized testing purposes only. Always ensure you have permission before scanning any domains. The authors are not responsible for any misuse or damage caused by this tool.