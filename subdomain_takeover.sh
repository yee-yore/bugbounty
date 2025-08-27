#!/bin/bash

# Subdomain Takeover Scanner v3.0
# Enhanced with proper baddns JSON parsing

TARGET=""
LIST_MODE=false
DOMAIN_LIST="domain_list.txt"
VPS_MODE=false
INTERVAL=24
CONCURRENCY=1
DEPTH=1
LOG_LEVEL="INFO"
BADDNS_TIMEOUT=30
OUTPUT_FORMAT="all"  # all, json, text
CONFIDENCE_LEVEL="all"

# Telegram notifications
TELEGRAM_ENABLED=${TELEGRAM_ENABLED:-false}
TELEGRAM_BOT_TOKEN=${TELEGRAM_BOT_TOKEN:-""}
TELEGRAM_CHAT_ID=${TELEGRAM_CHAT_ID:-""}

#############################################
# ========== FUNCTIONS ==================== #
#############################################

show_help() {
    cat << EOF
subdomain_takeover - Subdomain Takeover Scanner v3.0
=====================================

USAGE:
    $0 -d <domain> [options]
    $0 -l <file> [options]

OPTIONS:
    -h, --help          Show this help message
    -d <domain>         Scan single domain
    -l <file>           Scan domains from list file
    -c <number>         Number of concurrent domain scans (default: 1)
    -depth <number>     Subdomain depth (0=all, 1=*.domain, 2=*.*.domain, default: 1)
    -vps <hours>        Run in daemon mode, repeat every N hours
    -o <format>         Output format: all, json, text (default: all)
    --confidence <level> Minimum confidence: all, confirmed, probable (default: all)

EXAMPLES:
    # Single domain scan with JSON output
    $0 -d example.com -o json
    
    # Scan list with 3 concurrent threads
    $0 -l domains.txt -c 3
    
    # Scan with high confidence only
    $0 -d example.com --confidence confirmed
    
    # VPS monitoring mode
    $0 -l domains.txt -vps 24 --confidence probable

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
    
    if ! command -v jq >/dev/null 2>&1; then
        log WARN "jq is not installed. JSON parsing will be limited. Install: brew install jq (macOS) or apt-get install jq (Linux)"
    fi
    
    if [ $missing_deps -eq 1 ]; then
        log ERROR "Please install missing dependencies"
        exit 1
    fi
}

# Parse baddns JSON output properly
parse_baddns_json() {
    local file="$1"
    local confidence_filter="$2"
    
    [ ! -f "$file" ] && return
    
    if command -v jq >/dev/null 2>&1; then
        # Use jq for proper JSON parsing
        case "$confidence_filter" in
            confirmed)
                jq -r 'select(.confidence == "CONFIRMED") | .target' "$file" 2>/dev/null | sort -u
                ;;
            probable)
                jq -r 'select(.confidence == "CONFIRMED" or .confidence == "PROBABLE") | .target' "$file" 2>/dev/null | sort -u
                ;;
            *)
                jq -r '.target' "$file" 2>/dev/null | sort -u
                ;;
        esac
    else
        # Fallback to grep/sed if jq not available
        grep -o '"target"[[:space:]]*:[[:space:]]*"[^"]*"' "$file" 2>/dev/null | \
            sed 's/.*"target"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/' | \
            sort -u
    fi
}

# Generate comprehensive reports
generate_reports() {
    local output_dir="$1"
    local confidence_level="${2:-all}"
    
    # Parse vulnerabilities by confidence level
    parse_baddns_json "$output_dir/baddns_raw.json" "confirmed" > "$output_dir/vulnerable_confirmed.txt"
    parse_baddns_json "$output_dir/baddns_raw.json" "probable" > "$output_dir/vulnerable_probable.txt"  
    parse_baddns_json "$output_dir/baddns_raw.json" "all" > "$output_dir/vulnerable_all.txt"
    
    # Generate summary counts
    local confirmed_count=$(wc -l < "$output_dir/vulnerable_confirmed.txt" 2>/dev/null || echo 0)
    local probable_count=$(wc -l < "$output_dir/vulnerable_probable.txt" 2>/dev/null || echo 0)
    local possible_count=$(wc -l < "$output_dir/vulnerable_all.txt" 2>/dev/null || echo 0)
    
    # Create JSON report if jq available
    if command -v jq >/dev/null 2>&1 && [ "$OUTPUT_FORMAT" != "text" ]; then
        cat > "$output_dir/report.json" <<EOF
{
    "scan_time": "$(date -Iseconds)",
    "total_subdomains": $(wc -l < "$output_dir/subdomains.txt" 2>/dev/null || echo 0),
    "vulnerabilities": {
        "confirmed": $confirmed_count,
        "probable": $((probable_count - confirmed_count)),
        "possible": $((possible_count - probable_count)),
        "total": $possible_count
    },
    "findings": 
EOF
        # Add findings array
        if [ -s "$output_dir/baddns_raw.json" ]; then
            echo "[" >> "$output_dir/report.json"
            sed 's/^/    /' "$output_dir/baddns_raw.json" | sed '$ ! s/$/,/' >> "$output_dir/report.json"
            echo "]" >> "$output_dir/report.json"
        else
            echo "[]" >> "$output_dir/report.json"
        fi
        echo "}" >> "$output_dir/report.json"
    fi
    
    # Create text summary
    if [ "$OUTPUT_FORMAT" != "json" ]; then
        cat > "$output_dir/summary.txt" <<EOF
==========================================
Subdomain Takeover Scan Results
==========================================
Scan Time: $(date)
Total Subdomains: $(wc -l < "$output_dir/subdomains.txt" 2>/dev/null || echo 0)

Vulnerabilities Found:
- CONFIRMED: $confirmed_count
- PROBABLE: $((probable_count - confirmed_count))
- POSSIBLE: $((possible_count - probable_count))
- TOTAL: $possible_count

Detailed results:
- vulnerable_confirmed.txt: High confidence takeover opportunities
- vulnerable_probable.txt: Medium confidence findings
- vulnerable_all.txt: All potential vulnerabilities
==========================================
EOF
    fi
    
    # Return count based on confidence filter
    case "$confidence_level" in
        confirmed) echo "$confirmed_count" ;;
        probable) echo "$probable_count" ;;
        *) echo "$possible_count" ;;
    esac
}

telegram_alert() {
    local domain="$1" 
    local confirmed="$2"
    local probable="$3"
    local possible="$4"
    
    [ "$TELEGRAM_ENABLED" != "true" ] && return
    [ "$confirmed" -eq 0 ] && [ "$probable" -eq 0 ] && [ "$possible" -eq 0 ] && return
    [ -z "$TELEGRAM_BOT_TOKEN" ] || [ -z "$TELEGRAM_CHAT_ID" ] && return
    
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local api="https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage"
    
    local msg=$'🚨 *SUBDOMAIN TAKEOVER ALERT*\n\n'
    msg+=$'Date: `'"$timestamp"$'`\n'
    msg+=$'Target: `'"$domain"$'`\n\n'
    msg+=$'*Vulnerabilities Found:*\n'
    msg+=$'🔴 Confirmed: '"$confirmed"$'\n'
    msg+=$'🟠 Probable: '"$probable"$'\n'
    msg+=$'🟡 Possible: '"$possible"$'\n\n'
    
    if [ -f "vulnerable_confirmed.txt" ] && [ -s "vulnerable_confirmed.txt" ]; then
        msg+=$'*High Confidence Targets:*\n'
        local count=0
        while IFS= read -r subdomain && [ $count -lt 5 ]; do
            msg+=$'• `'"$subdomain"$'`\n'
            ((count++))
        done < vulnerable_confirmed.txt
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
    
    log INFO "$domain: Starting scan"
    
    # Enumeration phase
    log INFO "$domain: Enumerating subdomains with subfinder"
    if command -v subfinder >/dev/null; then
        subfinder -d "$domain" -all -silent -nc > all_subdomains.txt 2>/dev/null
    else
        log ERROR "$domain: subfinder not found"
        cd ../../..
        return 1
    fi
    
    # Filter subdomains based on depth
    if [ "$DEPTH" -eq 0 ]; then
        cp all_subdomains.txt subdomains.txt
    elif [ "$DEPTH" -eq 1 ]; then
        grep -E "^[^.]+\.$domain$" all_subdomains.txt > subdomains.txt
    elif [ "$DEPTH" -eq 2 ]; then
        grep -E "^[^.]+\.$domain$|^[^.]+\.[^.]+\.$domain$" all_subdomains.txt > subdomains.txt
    else
        cp all_subdomains.txt subdomains.txt
    fi
    
    local total_subs=$(wc -l < subdomains.txt 2>/dev/null || echo 0)
    log INFO "$domain: Found $total_subs subdomains (depth=$DEPTH)"
    
    # Vulnerability detection phase
    if [ "$total_subs" -gt 0 ]; then
        log INFO "$domain: Scanning for subdomain takeover vulnerabilities"
        
        # Sequential scanning with progress
        > baddns_raw.json
        local count=0
        while IFS= read -r subdomain; do
            ((count++))
            local percent=$((count * 100 / total_subs))
            printf "\r[%s] [INFO] %s: Scanning... [%d/%d] %d%%" \
                "$(date '+%Y-%m-%d %H:%M:%S')" "$domain" "$count" "$total_subs" "$percent"
            
            # Use baddns with silent mode for JSON output
            timeout "$BADDNS_TIMEOUT" baddns -s "$subdomain" 2>/dev/null >> baddns_raw.json
        done < subdomains.txt
        printf "\r%80s\r" " "
    fi
    
    # Generate reports
    log INFO "$domain: Generating reports"
    local vuln_count=$(generate_reports "." "$CONFIDENCE_LEVEL")
    
    # Get detailed counts for Telegram
    local confirmed_count=$(wc -l < vulnerable_confirmed.txt 2>/dev/null || echo 0)
    local probable_count=$(wc -l < vulnerable_probable.txt 2>/dev/null || echo 0)
    local possible_count=$(wc -l < vulnerable_all.txt 2>/dev/null || echo 0)
    
    log INFO "$domain: Scan complete - Confirmed: $confirmed_count, Probable: $((probable_count - confirmed_count)), Possible: $((possible_count - probable_count))"
    
    # Log to history
    echo "$(date '+%Y-%m-%d %H:%M:%S') | $domain | C:$confirmed_count P:$((probable_count - confirmed_count)) L:$((possible_count - probable_count))" >> ../../../scan_history.log
    
    # Send alert
    telegram_alert "$domain" "$confirmed_count" "$((probable_count - confirmed_count))" "$((possible_count - probable_count))"
    
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
                        log INFO "[$completed/$total_domains] Completed: ${running_domains[$i]}"
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
        for i in "${!running_jobs[@]}"; do
            wait "${running_jobs[$i]}" 2>/dev/null
            ((completed++))
            log INFO "[$completed/$total_domains] Completed: ${running_domains[$i]}"
        done
        
        log INFO "All $total_domains scans completed"
    else
        run_scan "$TARGET"
    fi
}

run_daemon() {
    local interval="$1"
    
    while true; do
        log INFO "Starting scan cycle (interval: ${interval}h)"
        run_single_scan
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
        -o)
            if [[ ! "$2" =~ ^(all|json|text)$ ]]; then
                echo "Error: -o requires: all, json, or text"
                exit 1
            fi
            OUTPUT_FORMAT="$2"
            shift 2
            ;;
        --confidence)
            if [[ ! "$2" =~ ^(all|confirmed|probable)$ ]]; then
                echo "Error: --confidence requires: all, confirmed, or probable"
                exit 1
            fi
            CONFIDENCE_LEVEL="$2"
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
