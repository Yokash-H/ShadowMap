#!/bin/bash
set -e

# ShadowBox Sandbox Entrypoint
# Monitors file execution with strace and collects telemetry

TARGET_FILE="/analysis/target"
TELEMETRY_DIR="/telemetry"

echo "[ShadowBox Sandbox] Starting analysis..."

# Snapshot system state before execution
cp /etc/crontab "$TELEMETRY_DIR/crontab.before" 2>/dev/null || true
cp ~/.bashrc "$TELEMETRY_DIR/bashrc.before" 2>/dev/null || true
cp ~/.profile "$TELEMETRY_DIR/profile.before" 2>/dev/null || true

# Determine file type and execution command
FILE_EXT="${TARGET_FILE##*.}"
case "$FILE_EXT" in
    sh)
        EXEC_CMD="bash $TARGET_FILE"
        ;;
    py)
        EXEC_CMD="python3 $TARGET_FILE"
        ;;
    jar)
        EXEC_CMD="java -jar $TARGET_FILE"
        ;;
    *)
        EXEC_CMD="bash $TARGET_FILE"
        ;;
esac

# Execute with strace monitoring
strace -f -e trace=network,file,process \
    -o "$TELEMETRY_DIR/strace.log" \
    $EXEC_CMD > "$TELEMETRY_DIR/stdout.log" 2>"$TELEMETRY_DIR/stderr.log" || true

# Collect post-execution state
ss -tunap > "$TELEMETRY_DIR/netstat.log" 2>/dev/null || true

# Diff system files for persistence detection
diff "$TELEMETRY_DIR/crontab.before" /etc/crontab > "$TELEMETRY_DIR/crontab.diff" 2>/dev/null || true
diff "$TELEMETRY_DIR/bashrc.before" ~/.bashrc > "$TELEMETRY_DIR/bashrc.diff" 2>/dev/null || true
diff "$TELEMETRY_DIR/profile.before" ~/.profile > "$TELEMETRY_DIR/profile.diff" 2>/dev/null || true

echo "[ShadowBox Sandbox] Analysis complete."
