#!/usr/bin/env bash
# =============================================================================
# Ghaymah Security Audit Script (Internship Version)
# =============================================================================
# Purpose : Audit listening ports, SSL/TLS, and file permissions.
# Usage   : chmod +x ghaymah_audit.sh && sudo ./ghaymah_audit.sh <domain> <port> <dir>
# Example : sudo ./ghaymah_audit.sh example.com 443 ./app
# =============================================================================

set -uo pipefail

# ── Configuration ────────────────────────────────────────────────────────────
TARGET_DOMAIN="${1:-ghaymah.systems}"
TARGET_PORT="${2:-443}"
TARGET_DIR="${3:-.}"

REPORT_DIR="./audit_reports"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_FILE="${REPORT_DIR}/ghaymah_audit_${TIMESTAMP}.txt"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Counters for summary
CRITICAL_COUNT=0
WARNING_COUNT=0
PASS_COUNT=0

# ── Setup ────────────────────────────────────────────────────────────────────
mkdir -p "${REPORT_DIR}"

log() {
    local level="$1"
    shift
    local msg="$*"
    case "${level}" in
        CRITICAL|FAIL)
            echo -e "${RED}[FAIL]${NC} ${msg}"
            ((CRITICAL_COUNT++)) || true
            ;;
        WARNING)
            echo -e "${YELLOW}[WARNING]${NC} ${msg}"
            ((WARNING_COUNT++)) || true
            ;;
        PASS)
            echo -e "${GREEN}[PASS]${NC} ${msg}"
            ((PASS_COUNT++)) || true
            ;;
        INFO)
            echo -e "${CYAN}${msg}${NC}"
            ;;
        SECTION)
            echo -e "\n-----------------------------------"
            echo -e "${msg}"
            echo -e "-----------------------------------\n"
            ;;
    esac
    echo "[${level}] ${msg}" >> "${REPORT_FILE}"
}

check_dependencies() {
    local deps=("openssl" "find" "awk" "grep" "curl")
    for dep in "${deps[@]}"; do
        if ! command -v "${dep}" &>/dev/null; then
            log CRITICAL "Missing dependency: ${dep}"
            exit 1
        fi
    done
}

# =============================================================================
# PORT AUDIT
# =============================================================================
audit_listening_ports() {
    log SECTION "PORT AUDIT"

    # Define the required ports and their protocol names
    declare -A ports=(
        [22]="SSH"
        [80]="HTTP"
        [443]="HTTPS"
        [3306]="MySQL"
        [5432]="PostgreSQL"
        [6379]="Redis"
        [27017]="MongoDB"
    )

    for port in "${!ports[@]}"; do
        local service_name="${ports[$port]}"
        
        # Check if port is open on target
        if (echo >/dev/tcp/${TARGET_DOMAIN}/"${port}") 2>/dev/null; then
            # Categorize the findings based on expected exposure
            case "${port}" in
                80|443) 
                    log PASS "${service_name} (${port}) reachable"
                    ;;
                22)
                    log WARNING "${service_name} (${port}) exposed — ensure strong auth"
                    ;;
                *)
                    log WARNING "${service_name} (${port}) exposed — database/cache should not be public"
                    ;;
            esac
        else
            case "${port}" in
                80|443) 
                    log FAIL "${service_name} (${port}) unavailable"
                    ;;
                *)
                    log PASS "${service_name} (${port}) closed"
                    ;;
            esac
        fi
    done
}

# =============================================================================
# SSL/TLS AUDIT
# =============================================================================
audit_ssl_tls() {
    log SECTION "SSL AUDIT"

    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" "https://${TARGET_DOMAIN}" 2>/dev/null || echo "000")

    if [[ "${status}" == "200" ]]; then
        log PASS "HTTPS response code: ${status}"
    else
        log WARNING "HTTPS response code: ${status}"
    fi

    if ! timeout 5 bash -c "echo >/dev/tcp/${TARGET_DOMAIN}/${TARGET_PORT}" 2>/dev/null; then
        log FAIL "Cannot connect to ${TARGET_DOMAIN}:${TARGET_PORT} for SSL checks."
        return
    fi

    # Check TLS 1.3
    if echo | timeout 10 openssl s_client -connect "${TARGET_DOMAIN}:${TARGET_PORT}" -tls1_3 2>/dev/null | grep -q "Cipher is"; then
        log PASS "TLS 1.3 Enabled"
    else
        log WARNING "TLS 1.3 Disabled or Unavailable"
    fi

    # Check certificate validity and expiry
    local expiry_date
    expiry_date=$(echo | timeout 10 openssl s_client -connect "${TARGET_DOMAIN}:${TARGET_PORT}" -servername "${TARGET_DOMAIN}" 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2 || true)
    
    if [[ -n "${expiry_date}" ]]; then
        local expiry_epoch
        expiry_epoch=$(date -d "${expiry_date}" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "${expiry_date}" +%s 2>/dev/null || echo "0")
        local now_epoch
        now_epoch=$(date +%s)
        
        if [[ "${expiry_epoch}" -gt 0 ]]; then
            local days_remaining=$(( (expiry_epoch - now_epoch) / 86400 ))
            if [[ "${days_remaining}" -lt 0 ]]; then
                log FAIL "Certificate Expired"
            elif [[ "${days_remaining}" -lt 30 ]]; then
                log WARNING "Certificate expires soon (${days_remaining} days)"
            else
                log PASS "Certificate Valid (${days_remaining} days remaining)"
            fi
        else
            log FAIL "Failed to parse certificate expiry."
        fi
    else
        log FAIL "Could not retrieve certificate."
    fi

    # Check Security Headers
    if command -v curl &>/dev/null; then
        local headers
        headers=$(curl -sI "https://${TARGET_DOMAIN}" --max-time 10 2>/dev/null || true)
        
        declare -A header_checks=(
            ["strict-transport-security"]="HSTS"
            ["content-security-policy"]="Content-Security-Policy"
            ["x-frame-options"]="X-Frame-Options"
            ["x-content-type-options"]="X-Content-Type-Options"
            ["referrer-policy"]="Referrer-Policy"
            ["permissions-policy"]="Permissions-Policy"
        )

        for header_name in "${!header_checks[@]}"; do
            local header_label="${header_checks[$header_name]}"
            if echo "${headers}" | grep -qi "${header_name}"; then
                log PASS "${header_label} Enabled"
            else
                log WARNING "${header_label} Missing"
            fi
        done
    else
        log WARNING "curl not found, skipping HTTP security header checks."
    fi
}

# =============================================================================
# PERMISSIONS AUDIT
# =============================================================================
audit_permissions() {
    log SECTION "PERMISSION AUDIT"

    if [[ ! -d "${TARGET_DIR}" ]]; then
        log FAIL "Target directory ${TARGET_DIR} does not exist."
        return
    fi

    # Check World-Writable Files
    local ww_files
    ww_files=$(find "${TARGET_DIR}" -type f -perm -o+w 2>/dev/null)
    if [[ -z "${ww_files}" ]]; then
        log PASS "No world writable files"
    else
        while IFS= read -r file; do
            [[ -z "$file" ]] && continue
            local perms
            perms=$(stat -c "%a" "$file" 2>/dev/null)
            log WARNING "World writable file: ${file} (${perms})"
        done <<< "${ww_files}"
    fi

    # Check World-Writable Directories
    local ww_dirs
    ww_dirs=$(find "${TARGET_DIR}" -type d -perm -o+w 2>/dev/null)
    if [[ -z "${ww_dirs}" ]]; then
        log PASS "No world writable directories"
    else
        while IFS= read -r dir; do
            [[ -z "$dir" ]] && continue
            local perms
            perms=$(stat -c "%a" "$dir" 2>/dev/null)
            log WARNING "World writable directory: ${dir} (${perms})"
        done <<< "${ww_dirs}"
    fi
}

# =============================================================================
# SUMMARY
# =============================================================================
generate_summary() {
    log SECTION "SUMMARY"
    
    local overall="PASS"
    if [[ "${CRITICAL_COUNT}" -gt 0 ]]; then
        overall="FAIL"
    elif [[ "${WARNING_COUNT}" -gt 0 ]]; then
        overall="WARNING"
    fi

    echo -e "Critical : ${CRITICAL_COUNT}"
    echo -e "Warnings : ${WARNING_COUNT}"
    echo -e "Passed   : ${PASS_COUNT}"
    echo -e ""
    
    if [[ "${overall}" == "PASS" ]]; then
        echo -e "Overall  : ${GREEN}${overall}${NC}"
    elif [[ "${overall}" == "WARNING" ]]; then
        echo -e "Overall  : ${YELLOW}${overall}${NC}"
    else
        echo -e "Overall  : ${RED}${overall}${NC}"
    fi
    
    # Save to report file
    {
        echo "Critical : ${CRITICAL_COUNT}"
        echo "Warnings : ${WARNING_COUNT}"
        echo "Passed   : ${PASS_COUNT}"
        echo "Overall  : ${overall}"
    } >> "${REPORT_FILE}"
}

# =============================================================================
# MAIN
# =============================================================================
main() {
    echo -e "=================================================="
    echo -e "GHAYMAH SECURITY AUDIT"
    echo -e "=================================================="
    echo -e "\nTarget:\n${TARGET_DOMAIN}\n"
    
    echo "Audit Started: $(date)" > "${REPORT_FILE}"

    check_dependencies

    audit_listening_ports
    audit_ssl_tls
    audit_permissions
    
    generate_summary
}

main "$@"
