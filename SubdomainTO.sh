#!/bin/bash

TARGET=""
LIST_MODE=false
DOMAIN_LIST="domain_list.txt"
VPS_MODE=false
INTERVAL=24
CONCURRENCY=1
DEPTH=1
LOG_LEVEL="INFO"
BADDNS_TIMEOUT=30

# Telegram notifications (set via environment variables for security)
# export TELEGRAM_BOT_TOKEN="your_token"
# export TELEGRAM_CHAT_ID="your_chat_id"
TELEGRAM_ENABLED=${TELEGRAM_ENABLED:-false}
TELEGRAM_BOT_TOKEN=${TELEGRAM_BOT_TOKEN:-""}
TELEGRAM_CHAT_ID=${TELEGRAM_CHAT_ID:-""}

#############################################
# ========== FUNCTIONS ==================== #
#############################################

show_help() {
    cat << EOF
SubdomainTO - Subdomain Takeover Scanner v2.0
=====================================

USAGE:
    $0 -d <domain> [options]
    $0 -l <file> [options]

OPTIONS:
    -h, --help          Show this help message
    -d <domain>         Scan single domain
    -l <file>           Scan domains from list file
    -c <number>         Number of concurrent scans (default: 1)
    -depth <number>     Subdomain depth (0=all, 1=*.domain, 2=*.*.domain, default: 1)
    -vps <hours>        Run in daemon mode, repeat every N hours

EXAMPLES:
    # Single domain scan
    $0 -d example.com
    
    # Scan list with 3 concurrent threads
    $0 -l domains.txt -c 3
    
    # Deep scan (2 levels) 
    $0 -d example.com -depth 2
    
    # VPS monitoring mode (24h interval)
    $0 -l domains.txt -c 3 -vps 24

ENVIRONMENT:
    TELEGRAM_ENABLED    Set to 'true' to enable alerts
    TELEGRAM_BOT_TOKEN  Your Telegram bot token
    TELEGRAM_CHAT_ID    Your Telegram chat ID

EOF
    exit 0
}

log() {
    local level="$1"; shift
    local message="$*"
    local ts=$(date '+%Y-%m-%d %H:%M:%S')
    case $level in
        DEBUG) [ "$LOG_LEVEL" = "DEBUG" ] && echo "[$ts] [DEBUG] $message" ;;
        INFO) echo "[$ts] [INFO] $message" ;;
        WARN) echo "[$ts] [WARN] $message" >&2 ;;
        ERROR) echo "[$ts] [ERROR] $message" >&2 ;;
    esac
}

check_deps() {
    local missing_deps=0
    
    if ! command -v subfinder >/dev/null 2>&1; then
        log ERROR "subfinder is not installed. Install from: https://github.com/projectdiscovery/subfinder"
        missing_deps=1
    fi
    
    if ! command -v baddns >/dev/null 2>&1; then
        log ERROR "baddns is not installed. Install: pip install baddns"
        missing_deps=1
    fi
    
    if [ $missing_deps -eq 1 ]; then
        log ERROR "Please install missing dependencies"
        exit 1
    fi
}

parse_baddns() {
    local file="$1"
    [ ! -f "$file" ] && return
    
    # Extract domains with potential vulnerabilities
    grep -E "CNAME.*Found|dangling|vulnerable|hijack|takeover" "$file" 2>/dev/null | \
        grep -oE '[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | \
        grep -v "^[0-9]" | \
        sort -u
}

collect_vulnerable_subdomains() {
    local temp_file=$(mktemp)
    
    parse_baddns "baddns.txt" >> "$temp_file" 2>/dev/null
    
    if [ -s "$temp_file" ]; then
        sort -u "$temp_file" > vulnerable_subdomains.txt
        local count=$(wc -l < vulnerable_subdomains.txt)
        log DEBUG "Found vulnerable subdomains: $(cat vulnerable_subdomains.txt | tr '\n' ' ')"
    else
        > vulnerable_subdomains.txt
        local count=0
    fi
    
    rm -f "$temp_file"
    echo "$count"
}

telegram_alert() {
    local domain="$1" vuln_count="$2"
    
    [ "$TELEGRAM_ENABLED" != "true" ] && return
    [ "$vuln_count" -eq 0 ] && return
    [ -z "$TELEGRAM_BOT_TOKEN" ] && return
    [ -z "$TELEGRAM_CHAT_ID" ] && return
    
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local api="https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage"
    
    local msg=$'🚨 *SUBDOMAIN TAKEOVER ALERT*\n\n'
    msg+=$'Date: `'"$timestamp"$'`\n'
    msg+=$'Target: `'"$domain"$'`\n'
    msg+=$'Vulnerabilities: '"$vuln_count"$'\n\n'
    
    if [ -f "vulnerable_subdomains.txt" ] && [ -s "vulnerable_subdomains.txt" ]; then
        msg+=$'*Vulnerable Subdomains:*\n'
        local count=0
        while IFS= read -r subdomain && [ $count -lt 10 ]; do
            msg+=$'• `'"$subdomain"$'`\n'
            ((count++))
        done < vulnerable_subdomains.txt
        
        local total_found=$(wc -l < vulnerable_subdomains.txt)
        if [ "$total_found" -gt 10 ]; then
            msg+=$'\n_... and '"$((total_found - 10))"$' more_\n'
        fi
    fi
    
    curl -s -X POST "$api" \
        -d chat_id="$TELEGRAM_CHAT_ID" \
        -d text="$msg" \
        -d parse_mode=Markdown >/dev/null 2>&1
}

#############################################
# ========== SCANNING ===================== #
#############################################

run_scan() {
    local domain="$1"
    local ts=$(date +%Y%m%d_%H%M%S)
    local out="results/${domain}/${ts}"
    
    mkdir -p "$out" && cd "$out" || return
    
    # Enumeration phase
    if command -v subfinder >/dev/null; then
        subfinder -d "$domain" -all -silent -nc > all_subdomains.txt 2>/dev/null
    else
        log ERROR "$domain: subfinder not found"
        return 1
    fi
    
    # Filter subdomains based on depth
    if [ "$DEPTH" -eq 0 ]; then
        cp all_subdomains.txt subdomains.txt
    elif [ "$DEPTH" -eq 1 ]; then
        grep -E "^[^.]+\.$domain$" all_subdomains.txt > subdomains.txt
    elif [ "$DEPTH" -eq 2 ]; then
        grep -E "^[^.]+\.$domain$|^[^.]+\.[^.]+\.$domain$" all_subdomains.txt > subdomains.txt
    elif [ "$DEPTH" -eq 3 ]; then
        grep -E "^[^.]+\.$domain$|^[^.]+\.[^.]+\.$domain$|^[^.]+\.[^.]+\.[^.]+\.$domain$" all_subdomains.txt > subdomains.txt
    else
        cp all_subdomains.txt subdomains.txt
    fi
    
    local total_subs=$(wc -l < subdomains.txt 2>/dev/null || echo 0)
    log INFO "$domain: Found $total_subs subdomains (depth=$DEPTH)"
    
    # Vulnerability detection phase
    if command -v baddns >/dev/null; then
        > baddns.txt
        local count=0
        
        if [ "$CONCURRENCY" -eq 1 ]; then
            # Single mode with progress bar
            while read -r subdomain; do
                ((count++))
                local percent=$((count * 100 / total_subs))
                local bars=$((percent / 10))
                local progress="["
                for ((i=0; i<10; i++)); do
                    [ $i -lt $bars ] && progress+="#" || progress+="."
                done
                progress+="]"
                
                printf "\r[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] %s: Scanning... %s %d%%" "$domain" "$progress" "$percent"
                
                timeout ${BADDNS_TIMEOUT} baddns "$subdomain" -s 2>&1 >> baddns.txt
                echo "---" >> baddns.txt
            done < subdomains.txt
            printf "\r%80s\r" " "
        else
            # Concurrent mode - no progress bar
            while read -r subdomain; do
                timeout ${BADDNS_TIMEOUT} baddns "$subdomain" -s 2>&1 >> baddns.txt
                echo "---" >> baddns.txt
            done < subdomains.txt
        fi
    fi
    
    # Parse results
    local total=$(collect_vulnerable_subdomains)
    log INFO "$domain: Vulnerabilities: $total"
    
    # Log to history
    echo "$(date '+%Y-%m-%d %H:%M:%S') | $domain | Vulnerabilities: $total" >> ../../../scan_history.log
    
    # Send alert if configured
    telegram_alert "$domain" "$total"
    
    # Cleanup old results (keep last 7 days)
    find ../.. -path "*/results/*/*" -type d -mtime +7 -exec rm -rf {} \; 2>/dev/null || true
    
    cd ../../..
}

run_single_scan() {
    if [ "$LIST_MODE" = "true" ] && [ -f "$DOMAIN_LIST" ]; then
        local total_domains=$(grep -v '^#' "$DOMAIN_LIST" | grep -v '^$' | wc -l | tr -d ' ')
        local completed=0
        local started=0
        
        log INFO "Scanning $total_domains domains from $DOMAIN_LIST (concurrency: $CONCURRENCY)"
        
        local running_jobs=()
        local running_domains=()
        
        while IFS= read -r domain || [ -n "$domain" ]; do
            [[ -z "$domain" || "$domain" =~ ^# ]] && continue
            domain=$(echo "$domain" | tr -d '\r\n' | xargs)
            [ -z "$domain" ] && continue
            
            # Wait if max concurrency reached
            while [ ${#running_jobs[@]} -ge $CONCURRENCY ]; do
                local new_jobs=()
                local new_domains=()
                for i in "${!running_jobs[@]}"; do
                    if kill -0 "${running_jobs[$i]}" 2>/dev/null; then
                        new_jobs+=("${running_jobs[$i]}")
                        new_domains+=("${running_domains[$i]}")
                    else
                        ((completed++))
                    fi
                done
                running_jobs=("${new_jobs[@]}")
                running_domains=("${new_domains[@]}")
                
                if [ ${#running_jobs[@]} -ge $CONCURRENCY ]; then
                    sleep 1
                fi
            done
            
            ((started++))
            log INFO "[$started/$total_domains] Starting: $domain"
            run_scan "$domain" &
            running_jobs+=("$!")
            running_domains+=("$domain")
            
        done < "$DOMAIN_LIST"
        
        # Wait for remaining jobs
        for job in "${running_jobs[@]}"; do
            wait "$job" 2>/dev/null
        done
        
        log INFO "All $total_domains scans completed"
    else
        run_scan "$TARGET"
    fi
}

run_daemon() {
    local interval="$1"
    
    while true; do
        if [ "$LIST_MODE" = "true" ] && [ -f "$DOMAIN_LIST" ]; then
            log INFO "Starting scan cycle (interval: ${interval}h)"
            run_single_scan
        else
            run_scan "$TARGET"
        fi
        
        log INFO "Waiting $interval hours until next cycle..."
        sleep "$(( interval * 3600 ))"
    done
}

#############################################
# ========== MAIN ========================= #
#############################################

# Parse command-line arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help) 
            show_help 
            ;;
        -d)
            if [ -z "$2" ] || [[ "$2" =~ ^- ]]; then
                echo "Error: -d requires a domain name"
                exit 1
            fi
            TARGET="$2"
            shift 2
            ;;
        -l)
            if [ -z "$2" ] || [[ "$2" =~ ^- ]]; then
                echo "Error: -l requires a filename"
                exit 1
            fi
            DOMAIN_LIST="$2"
            LIST_MODE=true
            shift 2
            ;;
        -c)
            if [[ ! "$2" =~ ^[0-9]+$ ]] || [ "$2" -lt 1 ]; then
                echo "Error: -c requires a positive number"
                exit 1
            fi
            CONCURRENCY="$2"
            shift 2
            ;;
        -depth)
            if [[ ! "$2" =~ ^[0-9]+$ ]]; then
                echo "Error: -depth requires a number"
                exit 1
            fi
            DEPTH="$2"
            shift 2
            ;;
        -vps)
            VPS_MODE=true
            if [[ ! "$2" =~ ^[0-9]+$ ]]; then
                echo "Error: -vps requires a numeric hour value"
                exit 1
            fi
            INTERVAL="$2"
            shift 2
            ;;
        -*)
            echo "Error: Unknown option: $1"
            echo "Use -h or --help for usage"
            exit 1
            ;;
        *)
            echo "Error: Unexpected argument: $1"
            echo "Use -h or --help for usage"
            exit 1
            ;;
    esac
done

# Validate input
if [ "$LIST_MODE" = "true" ] && [ -n "$TARGET" ]; then
    echo "Error: Cannot use both -d and -l options"
    exit 1
fi

if [ "$LIST_MODE" = "true" ]; then
    if [ ! -f "$DOMAIN_LIST" ]; then
        echo "Error: Domain list file '$DOMAIN_LIST' not found"
        exit 1
    fi
elif [ -z "$TARGET" ]; then
    echo "Error: No domain specified. Use -d <domain> or -l <file>"
    echo "Use -h or --help for usage"
    exit 1
fi

# Check dependencies
check_deps

# Main execution
if $VPS_MODE; then
    log INFO "Starting VPS daemon mode (interval: ${INTERVAL}h)"
    run_daemon "$INTERVAL"
else
    run_single_scan
fi
