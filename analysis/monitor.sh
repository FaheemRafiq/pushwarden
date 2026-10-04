#!/bin/bash
# PushWarden Malware Analysis Monitor
# Runs inside Docker container with network disabled
# Intercepts and logs all malware behavior

set -euo pipefail

OUTPUT="/analysis/output"
SAMPLE="/analysis/samples/c2-implant.js"
LOG="$OUTPUT/monitor.log"

mkdir -p "$OUTPUT"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG"
}

cleanup() {
    log "Cleaning up..."
    kill $(jobs -p) 2>/dev/null || true
    wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

log "============================================"
log "  PUSHWARDEN MALWARE ANALYSIS MONITOR"
log "============================================"
log "Sample: $SAMPLE"
log "Output: $OUTPUT"

if [ ! -f "$SAMPLE" ]; then
    log "ERROR: Sample not found at $SAMPLE"
    log "Place the malware sample there and re-run"
    exit 1
fi

log ""
log "[1] FILE SYSTEM MONITOR"
log "Setting up inotifywait on /tmp, /home, /analysis..."
(
    inotifywait -m -r -e create,modify,delete,move \
        /tmp /home /analysis 2>/dev/null | \
    while read dir event file; do
        log "  FS EVENT: $event $dir$file"
        if [[ "$file" == *.js ]] || [[ "$file" == *.bat ]] || [[ "$file" == *.sh ]]; then
            log "  *** SUSPICIOUS FILE OPERATION: $dir$file ***"
            if [ -f "$dir$file" ]; then
                cp "$dir$file" "$OUTPUT/captured-$(date +%s)-$(basename $dir$file)" 2>/dev/null || true
                log "  Captured copy to output directory"
            fi
        fi
    done
) &
FS_MONITOR_PID=$!
log "  FS monitor PID: $FS_MONITOR_PID"

log ""
log "[2] NETWORK MONITOR"
(
    tcpdump -i any -w "$OUTPUT/network-capture.pcap" -XX 2>/dev/null &
    TCPDUMP_PID=$!
    log "  tcpdump PID: $TCPDUMP_PID"
) &
sleep 1

log ""
log "[3] PROCESS MONITOR"
(
    while true; do
        ps aux 2>/dev/null | grep -v "grep\|monitor\|tcpdump\|inotify" >> "$OUTPUT/process-log.txt"
        sleep 0.5
    done
) &
PROC_MONITOR_PID=$!

log ""
log "[4] GLOBAL VARIABLE MONITOR"
(
    while true; do
        node -e "
            const globals = ['_V', '_H', '_H2', '_t_u', '_t_s', 'r', 'm', 'i', '!'];
            globals.forEach(g => {
                if (global[g] !== undefined) {
                    const val = typeof global[g] === 'object' ? '[object]' : String(global[g]).substring(0, 200);
                    console.log('[' + new Date().toISOString() + '] GLOBAL: global[\"' + g + '\"] = ' + val);
                }
            });
        " 2>/dev/null >> "$OUTPUT/globals-log.txt"
        sleep 1
    done
) &
GLOBAL_MONITOR_PID=$!

log ""
log "[5] ENVIRONMENT VARIABLE ACCESS MONITOR"
(
    node -e "
        const original = process.env;
        const proxy = new Proxy(original, {
            get(target, prop) {
                const trace = new Error().stack.split('\n').slice(1, 4).join(' <- ');
                console.log('[' + new Date().toISOString() + '] ENV ACCESS: ' + prop + ' from ' + trace);
                return target[prop];
            }
        });
        Object.defineProperty(process, 'env', { value: proxy, writable: false });
        console.log('[ENV MONITOR] Proxy active, waiting for malware...');
    " 2>/dev/null >> "$OUTPUT/env-access-log.txt"
) &
ENV_MONITOR_PID=$!

log ""
log "All monitors active:"
log "  FS monitor:    $FS_MONITOR_PID"
log "  Global monitor: $GLOBAL_MONITOR_PID"
log "  Process monitor: $PROC_MONITOR_PID"
log ""
log "============================================"
log "EXECUTING MALWARE SAMPLE IN ISOLATED ENV"
log "============================================"

export ETH_RPC_URL="http://127.0.0.1:8545"
export SECRET_KEY="mock-test-key"

log "ETH_RPC_URL=$ETH_RPC_URL"
log "Running with strace..."
log ""

(
    timeout 30 strace -f -e trace=network,process,file,write \
        node "$SAMPLE" 2>"$OUTPUT/strace.log" || true
) &
MALWARE_PID=$!

log "Malware PID: $MALWARE_PID"
log "Waiting for execution (max 30s)..."

wait $MALWARE_PID 2>/dev/null || true

log ""
log "============================================"
log "ANALYSIS COMPLETE"
log "============================================"
log ""
log "Output files:"
ls -la "$OUTPUT/" | tee -a "$LOG"
log ""
log "Key findings:"
if [ -f "$OUTPUT/globals-log.txt" ] && [ -s "$OUTPUT/globals-log.txt" ]; then
    log "  Global variables set:"
    cat "$OUTPUT/globals-log.txt" | tail -20 | tee -a "$LOG"
fi
if [ -f "$OUTPUT/env-access-log.txt" ] && [ -s "$OUTPUT/env-access-log.txt" ]; then
    log "  Environment variables accessed:"
    cat "$OUTPUT/env-access-log.txt" | tail -20 | tee -a "$LOG"
fi
if [ -f "$OUTPUT/c2-intercept.log" ] && [ -s "$OUTPUT/c2-intercept.log" ]; then
    log "  C2 communications intercepted:"
    cat "$OUTPUT/c2-intercept.log" | tail -30 | tee -a "$LOG"
fi

cleanup
