#!/bin/bash

#############################################
# ========== CONFIGURATION ================ #
#############################################

# Core settings
TARGET=""
LIST_MODE=false
DOMAIN_LIST="domain_list.txt"
VPS_MODE=false
INTERVAL=24
CONCURRENCY=1
DEPTH=1
LOG_LEVEL="INFO"
BADDNS_TIMEOUT=30
BADDNS_WORKERS=1
OUTPUT_FORMAT="all"
CONFIDENCE_LEVEL="all"

# Telegram notifications (set via environment variables)
TELEGRAM_ENABLED=${TELEGRAM_ENABLED:-false}
TELEGRAM_BOT_TOKEN=${TELEGRAM_BOT_TOKEN:-""}
TELEGRAM_CHAT_ID=${TELEGRAM_CHAT_ID:-""}

# OpenAI API for false positive analysis
OPENAI_API_KEY=${OPENAI_API_KEY:-""}
ENABLE_AI_ANALYSIS=${ENABLE_AI_ANALYSIS:-false}

#############################################
# ========== HELPER FUNCTIONS ============= #
#############################################

show_help() {
    cat << EOF
Usage: subdomain_takeover.sh -d DOMAIN [OPTIONS]

Subdomain Takeover Scanner - Find vulnerable subdomains

OPTIONS:
  -d DOMAIN          Target domain to scan
  -l FILE            Scan domains from list file
  -w N               Parallel baddns workers (default: 1, faster: 10+)
  -c N               Concurrent domain scans (default: 1)
  -o FORMAT          Output: all|json|text (default: all)
  --confidence LVL   Filter: all|confirmed|probable (default: all)
  --help-full        Show detailed help with all options

EXAMPLES:
  subdomain_takeover.sh -d example.com
  subdomain_takeover.sh -d example.com -w 10        # Fast scan
  subdomain_takeover.sh -l domains.txt -c 3         # List scan
  
SETUP:
  export TELEGRAM_ENABLED=true                      # Enable alerts
  export ENABLE_AI_ANALYSIS=true                    # Enable AI FP detection
  export OPENAI_API_KEY="sk-..."                    # Set API key

EOF
    exit 0
}

show_help_full() {
    cat << EOF
Subdomain Takeover Scanner v3.0
Author: yee-yore
=====================================

USAGE:
    $0 -d <domain> [options]
    $0 -l <file> [options]

ALL OPTIONS:
    -h, --help          Show basic help
    --help-full         Show this detailed help
    -d <domain>         Target domain to scan
    -l <file>           Scan domains from list file
    -c <number>         Number of concurrent domain scans (default: 1)
    -w <number>         Number of parallel baddns workers (default: 1)
    -depth <number>     Subdomain depth (0=all, 1=*.domain, 2=*.*.domain)
    -vps <hours>        Run in daemon mode, repeat every N hours
    -o <format>         Output format: all, json, text (default: all)
    --confidence <level> Minimum confidence: all, confirmed, probable

ENVIRONMENT VARIABLES:
    TELEGRAM_ENABLED    Set to 'true' to enable Telegram alerts
    TELEGRAM_BOT_TOKEN  Your Telegram bot token
    TELEGRAM_CHAT_ID    Your Telegram chat ID
    OPENAI_API_KEY      OpenAI API key for false positive analysis
    ENABLE_AI_ANALYSIS  Enable AI-powered false positive detection

ADVANCED EXAMPLES:
    # VPS monitoring mode (24h interval)
    $0 -l domains.txt -vps 24 --confidence probable
    
    # Fast parallel scanning with AI analysis
    ENABLE_AI_ANALYSIS=true $0 -d example.com -w 20
    
    # JSON output for automation
    $0 -d example.com -o json --confidence confirmed

PERFORMANCE TIPS:
    -w 1   : Safe, slow (default)
    -w 5   : Balanced
    -w 10  : Fast
    -w 20+ : Very fast (may trigger rate limits)

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
        log ERROR "subfinder not found. Install: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        missing_deps=1
    fi
    
    if ! command -v baddns >/dev/null 2>&1; then
        log ERROR "baddns not found. Install: pip install baddns"
        missing_deps=1
    fi
    
    if ! command -v jq >/dev/null 2>&1; then
        log WARN "jq not found (optional). Install for better JSON parsing: brew install jq"
    fi
    
    [ $missing_deps -eq 1 ] && exit 1
}

#############################################
# ========== PARSING FUNCTIONS ============ #
#############################################

parse_baddns_json() {
    local file="$1"
    local confidence_filter="$2"
    
    [ ! -f "$file" ] && return
    
    if command -v jq >/dev/null 2>&1; then
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

analyze_false_positive() {
    local target="$1"
    local cname="$2"
    local signature="$3"
    local domain_root="$4"
    
    [ "$ENABLE_AI_ANALYSIS" != "true" ] && echo "N/A|AI disabled" && return
    [ -z "$OPENAI_API_KEY" ] && echo "No API key|Configure OPENAI_API_KEY" && return
    
    local prompt="Analyze this subdomain takeover detection for false positive probability. Reply with only: HIGH, MEDIUM, or LOW followed by a brief reason (max 10 words).

Target: $target
CNAME: $cname
Detection: $signature
Root domain: $domain_root

Consider:
1. Is CNAME pointing to same organization's domain?
2. Naming convention suggests internal infrastructure?
3. Private/internal service pattern?

Response format: PROBABILITY|reason"

    # Make API call
    local api_response=$(curl -s -X POST "https://api.openai.com/v1/chat/completions" \
        -H "Authorization: Bearer $OPENAI_API_KEY" \
        -H "Content-Type: application/json" \
        -d '{
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": "'"$(echo "$prompt" | sed 's/"/\\"/g' | tr '\n' ' ')"'"}],
            "temperature": 0.3,
            "max_tokens": 30
        }' 2>/dev/null)
    
    log DEBUG "OpenAI API response: $api_response"
    
    # Check for API error
    local error=$(echo "$api_response" | jq -r '.error.message' 2>/dev/null)
    if [ -n "$error" ] && [ "$error" != "null" ]; then
        log ERROR "OpenAI API error: $error"
        echo "API Error|Check logs"
        return
    fi
    
    # Extract response
    local response=$(echo "$api_response" | jq -r '.choices[0].message.content' 2>/dev/null)
    
    if [ -z "$response" ] || [ "$response" = "null" ]; then
        log WARN "Empty OpenAI response for $target"
        echo "Analysis failed|No response"
        return
    fi
    
    echo "$response"
}

#############################################
# ========== REPORTING FUNCTIONS ========== #
#############################################

generate_reports() {
    local output_dir="$1"
    local confidence_level="${2:-all}"
    
    # Parse vulnerabilities by confidence level
    parse_baddns_json "$output_dir/baddns_raw.json" "confirmed" > "$output_dir/vulnerable_confirmed.txt"
    parse_baddns_json "$output_dir/baddns_raw.json" "probable" > "$output_dir/vulnerable_probable.txt"  
    parse_baddns_json "$output_dir/baddns_raw.json" "all" > "$output_dir/vulnerable_all.txt"
    
    # Count vulnerabilities
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
    local output_dir="$5"
    
    [ "$TELEGRAM_ENABLED" != "true" ] && return
    [ "$confirmed" -eq 0 ] && [ "$probable" -eq 0 ] && [ "$possible" -eq 0 ] && return
    [ -z "$TELEGRAM_BOT_TOKEN" ] || [ -z "$TELEGRAM_CHAT_ID" ] && return
    
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local api="https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage"
    
    local msg=$'🚨 *SUBDOMAIN TAKEOVER ALERT*\n\n'
    msg+=$'Date: `'"$timestamp"$'`\n'
    msg+=$'Target: `'"$domain"$'`\n\n'
    msg+=$'*Vulnerabilities Found:*\n'
    msg+=$'Confirmed: '"$confirmed"$'\n'
    msg+=$'Probable: '"$probable"$'\n'
    msg+=$'Possible: '"$possible"$'\n\n'
    
    # Add AI analysis if enabled
    if [ "$ENABLE_AI_ANALYSIS" = "true" ] && [ -f "$output_dir/baddns_raw.json" ]; then
        msg+=$'*📊 AI Analysis:*\n'
        local has_findings=false
        
        # Analyze confirmed vulnerabilities
        if [ -f "$output_dir/vulnerable_confirmed.txt" ] && [ -s "$output_dir/vulnerable_confirmed.txt" ]; then
            while IFS= read -r subdomain; do
                local finding=$(jq -r --arg target "$subdomain" 'select(.target == $target) | @json' "$output_dir/baddns_raw.json" 2>/dev/null | head -1)
                if [ -n "$finding" ]; then
                    local cname=$(echo "$finding" | jq -r '.trigger' 2>/dev/null)
                    local signature=$(echo "$finding" | jq -r '.signature' 2>/dev/null)
                    local ai_result=$(analyze_false_positive "$subdomain" "$cname" "$signature" "$domain")
                    local fp_prob=$(echo "$ai_result" | cut -d'|' -f1)
                    local fp_reason=$(echo "$ai_result" | cut -d'|' -f2)
                    
                    msg+=$'\n• `'"$subdomain"$'`\n'
                    if [ "$fp_prob" = "null" ] || [ -z "$fp_prob" ]; then
                        msg+=$'  └ FP Risk: Analysis failed\n'
                    else
                        msg+=$'  └ FP Risk: '"$fp_prob"$'\n'
                    fi
                    if [ -n "$fp_reason" ] && [ "$fp_reason" != "null" ]; then
                        msg+=$'  └ '"$fp_reason"$'\n'
                    fi
                    has_findings=true
                fi
            done < "$output_dir/vulnerable_confirmed.txt"
        fi
        
        # Analyze probable if no confirmed
        if [ "$has_findings" = "false" ] && [ -f "$output_dir/vulnerable_probable.txt" ] && [ -s "$output_dir/vulnerable_probable.txt" ]; then
            while IFS= read -r subdomain; do
                local finding=$(jq -r --arg target "$subdomain" 'select(.target == $target) | @json' "$output_dir/baddns_raw.json" 2>/dev/null | head -1)
                if [ -n "$finding" ]; then
                    local cname=$(echo "$finding" | jq -r '.trigger' 2>/dev/null)
                    local signature=$(echo "$finding" | jq -r '.signature' 2>/dev/null)
                    local ai_result=$(analyze_false_positive "$subdomain" "$cname" "$signature" "$domain")
                    local fp_prob=$(echo "$ai_result" | cut -d'|' -f1)
                    local fp_reason=$(echo "$ai_result" | cut -d'|' -f2)
                    
                    msg+=$'\n• `'"$subdomain"$'`\n'
                    if [ "$fp_prob" = "null" ] || [ -z "$fp_prob" ]; then
                        msg+=$'  └ FP Risk: Analysis failed\n'
                    else
                        msg+=$'  └ FP Risk: '"$fp_prob"$'\n'
                    fi
                    if [ -n "$fp_reason" ] && [ "$fp_reason" != "null" ]; then
                        msg+=$'  └ '"$fp_reason"$'\n'
                    fi
                    has_findings=true
                fi
            done < "$output_dir/vulnerable_probable.txt"
        fi
        
        # Analyze possible if no confirmed or probable
        if [ "$has_findings" = "false" ] && [ -f "$output_dir/vulnerable_all.txt" ] && [ -s "$output_dir/vulnerable_all.txt" ]; then
            while IFS= read -r subdomain; do
                local finding=$(jq -r --arg target "$subdomain" 'select(.target == $target) | @json' "$output_dir/baddns_raw.json" 2>/dev/null | head -1)
                if [ -n "$finding" ]; then
                    local cname=$(echo "$finding" | jq -r '.trigger' 2>/dev/null)
                    local signature=$(echo "$finding" | jq -r '.signature' 2>/dev/null)
                    local confidence=$(echo "$finding" | jq -r '.confidence' 2>/dev/null)
                    
                    if [ "$confidence" = "POSSIBLE" ]; then
                        local ai_result=$(analyze_false_positive "$subdomain" "$cname" "$signature" "$domain")
                        local fp_prob=$(echo "$ai_result" | cut -d'|' -f1)
                        local fp_reason=$(echo "$ai_result" | cut -d'|' -f2)
                        
                        msg+=$'\n• `'"$subdomain"$'` (Low confidence)\n'
                        if [ "$fp_prob" = "null" ] || [ -z "$fp_prob" ]; then
                            msg+=$'  └ FP Risk: Analysis failed\n'
                        else
                            msg+=$'  └ FP Risk: '"$fp_prob"$'\n'
                        fi
                        if [ -n "$fp_reason" ] && [ "$fp_reason" != "null" ]; then
                            msg+=$'  └ '"$fp_reason"$'\n'
                        fi
                        has_findings=true
                    fi
                fi
            done < "$output_dir/vulnerable_all.txt"
        fi
    elif [ -f "$output_dir/vulnerable_confirmed.txt" ] && [ -s "$output_dir/vulnerable_confirmed.txt" ]; then
        # Fallback: List targets if AI disabled
        msg+=$'*High Confidence Targets:*\n'
        local count=0
        while IFS= read -r subdomain && [ $count -lt 5 ]; do
            msg+=$'• `'"$subdomain"$'`\n'
            ((count++))
        done < "$output_dir/vulnerable_confirmed.txt"
    fi
    
    curl -s -X POST "$api" \
        -d chat_id="$TELEGRAM_CHAT_ID" \
        -d text="$msg" \
        -d parse_mode=Markdown >/dev/null 2>&1
}

#############################################
# ========== SCANNING FUNCTIONS =========== #
#############################################

parallel_baddns_scan() {
    local subdomains_file="$1"
    local output_file="$2"
    local workers="$3"
    local total_subs="$4"
    
    log INFO "Starting parallel baddns scan with $workers workers"
    
    # Create temporary directory for individual results
    local temp_dir=$(mktemp -d)
    
    # Create progress tracking
    local progress_pipe=$(mktemp -u)
    mkfifo "$progress_pipe"
    
    # Progress monitor
    (
        local completed=0
        while read -r line < "$progress_pipe"; do
            ((completed++))
            local percent=$((completed * 100 / total_subs))
            printf "\r[%s] [INFO] Scanning... [%d/%d] %d%% (workers: %d)" \
                "$(date '+%Y-%m-%d %H:%M:%S')" "$completed" "$total_subs" "$percent" "$workers"
        done
        printf "\r%80s\r" " "
    ) &
    local progress_pid=$!
    
    # Run baddns in parallel
    cat "$subdomains_file" | \
        xargs -P "$workers" -I {} sh -c '
            subdomain="$1"
            temp_dir="$2"
            timeout="$3"
            progress_pipe="$4"
            
            timeout "$timeout" baddns -s "$subdomain" > "$temp_dir/${subdomain//\//_}.json" 2>/dev/null
            echo "done" > "$progress_pipe"
        ' -- {} "$temp_dir" "$BADDNS_TIMEOUT" "$progress_pipe"
    
    # Cleanup progress
    echo "done" > "$progress_pipe"
    kill $progress_pid 2>/dev/null
    wait $progress_pid 2>/dev/null
    rm -f "$progress_pipe"
    
    # Combine results
    > "$output_file"
    for json_file in "$temp_dir"/*.json; do
        [ -f "$json_file" ] && [ -s "$json_file" ] && cat "$json_file" >> "$output_file"
    done
    
    rm -rf "$temp_dir"
    log INFO "Parallel scan completed"
}

run_scan() {
    local domain="$1"
    local ts=$(date +%Y%m%d_%H%M%S)
    local out="results/${domain}/${ts}"
    
    mkdir -p "$out" && cd "$out" || return
    
    log INFO "$domain: Starting scan"
    
    # Enumeration
    log INFO "$domain: Enumerating subdomains"
    if command -v subfinder >/dev/null; then
        subfinder -d "$domain" -all -silent -nc > all_subdomains.txt 2>/dev/null
    else
        log ERROR "$domain: subfinder not found"
        cd ../../..
        return 1
    fi
    
    # Filter by depth
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
    
    # Vulnerability detection
    if [ "$total_subs" -gt 0 ]; then
        log INFO "$domain: Scanning for vulnerabilities"
        
        if [ "$BADDNS_WORKERS" -gt 1 ]; then
            parallel_baddns_scan "subdomains.txt" "baddns_raw.json" "$BADDNS_WORKERS" "$total_subs"
        else
            # Sequential scanning
            > baddns_raw.json
            local count=0
            while IFS= read -r subdomain; do
                ((count++))
                local percent=$((count * 100 / total_subs))
                printf "\r[%s] [INFO] %s: Scanning... [%d/%d] %d%%" \
                    "$(date '+%Y-%m-%d %H:%M:%S')" "$domain" "$count" "$total_subs" "$percent"
                
                timeout "$BADDNS_TIMEOUT" baddns -s "$subdomain" 2>/dev/null >> baddns_raw.json
            done < subdomains.txt
            printf "\r%80s\r" " "
        fi
    fi
    
    # Generate reports
    log INFO "$domain: Generating reports"
    local vuln_count=$(generate_reports "." "$CONFIDENCE_LEVEL")
    
    # Get counts
    local confirmed_count=$(wc -l < vulnerable_confirmed.txt 2>/dev/null || echo 0)
    local probable_count=$(wc -l < vulnerable_probable.txt 2>/dev/null || echo 0)
    local possible_count=$(wc -l < vulnerable_all.txt 2>/dev/null || echo 0)
    
    log INFO "$domain: Complete - Confirmed: $confirmed_count, Probable: $((probable_count - confirmed_count)), Possible: $((possible_count - probable_count))"
    
    # Log history
    echo "$(date '+%Y-%m-%d %H:%M:%S') | $domain | C:$confirmed_count P:$((probable_count - confirmed_count)) L:$((possible_count - probable_count))" >> ../../../scan_history.log
    
    # Send alert
    telegram_alert "$domain" "$confirmed_count" "$((probable_count - confirmed_count))" "$((possible_count - probable_count))" "."
    
    # Cleanup old results
    find ../.. -path "*/results/*/*" -type d -mtime +7 -exec rm -rf {} \; 2>/dev/null || true
    
    cd ../../..
}

run_single_scan() {
    if [ "$LIST_MODE" = "true" ] && [ -f "$DOMAIN_LIST" ]; then
        local total_domains=$(grep -v '^#' "$DOMAIN_LIST" | grep -v '^$' | wc -l | tr -d ' ')
        local completed=0
        local started=0
        
        log INFO "Scanning $total_domains domains from $DOMAIN_LIST"
        
        local running_jobs=()
        local running_domains=()
        
        while IFS= read -r domain || [ -n "$domain" ]; do
            [[ -z "$domain" || "$domain" =~ ^# ]] && continue
            domain=$(echo "$domain" | tr -d '\r\n' | xargs)
            [ -z "$domain" ] && continue
            
            # Wait for concurrency limit
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
                
                [ ${#running_jobs[@]} -ge $CONCURRENCY ] && sleep 1
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
        
        log INFO "All scans completed"
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

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help) 
            show_help 
            ;;
        --help-full)
            show_help_full
            ;;
        -d)
            [ -z "$2" ] || [[ "$2" =~ ^- ]] && echo "Error: -d requires a domain" && exit 1
            TARGET="$2"
            shift 2
            ;;
        -l)
            [ -z "$2" ] || [[ "$2" =~ ^- ]] && echo "Error: -l requires a file" && exit 1
            DOMAIN_LIST="$2"
            LIST_MODE=true
            shift 2
            ;;
        -c)
            [[ ! "$2" =~ ^[0-9]+$ ]] || [ "$2" -lt 1 ] && echo "Error: -c requires a positive number" && exit 1
            CONCURRENCY="$2"
            shift 2
            ;;
        -w)
            [[ ! "$2" =~ ^[0-9]+$ ]] || [ "$2" -lt 1 ] && echo "Error: -w requires a positive number" && exit 1
            BADDNS_WORKERS="$2"
            shift 2
            ;;
        -depth)
            [[ ! "$2" =~ ^[0-9]+$ ]] && echo "Error: -depth requires a number" && exit 1
            DEPTH="$2"
            shift 2
            ;;
        -vps)
            VPS_MODE=true
            [[ ! "$2" =~ ^[0-9]+$ ]] && echo "Error: -vps requires hours" && exit 1
            INTERVAL="$2"
            shift 2
            ;;
        -o)
            [[ ! "$2" =~ ^(all|json|text)$ ]] && echo "Error: -o requires: all, json, or text" && exit 1
            OUTPUT_FORMAT="$2"
            shift 2
            ;;
        --confidence)
            [[ ! "$2" =~ ^(all|confirmed|probable)$ ]] && echo "Error: --confidence requires: all, confirmed, or probable" && exit 1
            CONFIDENCE_LEVEL="$2"
            shift 2
            ;;
        -*)
            echo "Error: Unknown option: $1"
            echo "Use --help for usage"
            exit 1
            ;;
        *)
            echo "Error: Unexpected argument: $1"
            exit 1
            ;;
    esac
done

# Validate input
if [ "$LIST_MODE" = "true" ] && [ -n "$TARGET" ]; then
    echo "Error: Cannot use both -d and -l"
    exit 1
fi

if [ "$LIST_MODE" = "true" ]; then
    [ ! -f "$DOMAIN_LIST" ] && echo "Error: Domain list '$DOMAIN_LIST' not found" && exit 1
elif [ -z "$TARGET" ]; then
    echo "Error: No domain specified. Use -d <domain>"
    echo "Use --help for usage"
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
