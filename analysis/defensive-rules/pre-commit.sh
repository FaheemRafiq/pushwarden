#!/bin/bash
# pushwarden:allow-signatures
# PushWarden Pre-Commit Hook
# Detects malware signatures before they're committed
# Install: cp pre-commit.sh .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}[PushWarden] Pre-commit hook active${NC}"

INFECTED=0

check_file() {
    local file="$1"
    local content
    content=$(cat "$file" 2>/dev/null || return)

    # Literal signatures
    if echo "$content" | grep -q "rmcej%otb%"; then
        echo -e "${RED}CRITICAL: $file contains literal malware signature (rmcej%otb%)${NC}"
        INFECTED=1
    fi

    if echo "$content" | grep -qE "global\['!'\]\s*=\s*'[A-Z0-9-]{4,}'"; then
        echo -e "${RED}CRITICAL: $file contains Lazarus campaign marker (global['!'])${NC}"
        INFECTED=1
    fi

    if echo "$content" | grep -qE "global\['_V'\]\s*=\s*'[A-Z0-9-]{4,}'"; then
        echo -e "${RED}CRITICAL: $file contains Lazarus variant marker (global['_V'])${NC}"
        INFECTED=1
    fi

    if echo "$content" | grep -q '\$_1e42'; then
        echo -e "${RED}CRITICAL: $file contains malware variable (\$_1e42)${NC}"
        INFECTED=1
    fi

    # Stage 1 loader patterns
    if echo "$content" | grep -q "atob(process.env"; then
        echo -e "${RED}CRITICAL: $file contains stage-1 loader (atob + process.env)${NC}"
        INFECTED=1
    fi

    if echo "$content" | grep -q "eval(atob"; then
        echo -e "${RED}CRITICAL: $file contains eval(atob) payload${NC}"
        INFECTED=1
    fi

    # Size anomaly in config files
    if echo "$file" | grep -qE '\.(config\.)' ; then
        local size
        size=$(wc -c < "$file")
        if [ "$size" -gt 1024 ]; then
            echo -e "${YELLOW}WARNING: Config file $file is unusually large ($size bytes, normal <300)${NC}"
            INFECTED=1
        fi

        # Check for long lines (payload hidden after spaces)
        if grep -qP '.{300,}' "$file" 2>/dev/null; then
            echo -e "${YELLOW}WARNING: Config file $file has lines >300 chars (possible hidden payload)${NC}"
            INFECTED=1
        fi
    fi

    # Propagation scripts
    if echo "$content" | grep -qE 'temp_auto_push\.bat|temp_interactive_push\.bat|config\.bat|auto_push\.bat'; then
        echo -e "${RED}CRITICAL: $file references propagation scripts${NC}"
        INFECTED=1
    fi
}

# Get staged files
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM 2>/dev/null || true)

if [ -z "$STAGED_FILES" ]; then
    echo -e "${GREEN}[PushWarden] No files to check${NC}"
    exit 0
fi

echo "$STAGED_FILES" | while IFS= read -r file; do
    if [ -f "$file" ]; then
        check_file "$file"
    fi
done

if [ "$INFECTED" -eq 1 ]; then
    echo ""
    echo -e "${RED}========================================${NC}"
    echo -e "${RED}  BLOCKED: Malware signatures detected  ${NC}"
    echo -e "${RED}  Commit aborted for your safety          ${NC}"
    echo -e "${RED}========================================${NC}"
    echo ""
    echo "To bypass (NOT recommended): git commit --no-verify"
    echo "To scan: python3 ~/Coding/pushwarden/threat_scanner.py ."
    exit 1
fi

echo -e "${GREEN}[PushWarden] All files passed - no malware detected${NC}"
exit 0
