#!/bin/bash
# PreToolUse hook: BLOCKING policy guard for tool execution
# Returns exit code 2 with JSON to block dangerous operations.
# Returns exit code 0 to allow.
#
# Three layers of protection:
#   1. Built-in dangerous pattern detection (always active)
#   2. Local deny list (.symbiont/local-policy.toml) if present
#   3. Cedar policy evaluation (if symbi is on PATH + policies/ exists)
#
# Mode B (SYMBIONT_MANAGED): Defers to outer ORGA Gate.

set -euo pipefail

TOOL_INPUT=$(cat)
TOOL_NAME=$(echo "$TOOL_INPUT" | jq -r '.tool_name // empty' 2>/dev/null)

# Mode B: Inside CliExecutor — outer ORGA Gate handles hard enforcement.
if [ -n "${SYMBIONT_MANAGED:-}" ]; then
    exit 0
fi

# Skip read-only tools
case "$TOOL_NAME" in
    Read|Glob|Grep|LS|View)
        exit 0
        ;;
esac

# Helper: block with message
block() {
    echo "{\"block\": true, \"message\": \"$1\"}" >&2
    exit 2
}

# --- Layer 1: Built-in dangerous pattern detection ---

if [ "$TOOL_NAME" = "Bash" ]; then
    COMMAND=$(echo "$TOOL_INPUT" | jq -r '.tool_input.command // empty' 2>/dev/null)

    # Block destructive commands
    if echo "$COMMAND" | grep -qE 'rm\s+-rf\s+/|rm\s+-rf\s+\.|mkfs\s|dd\s+if=|:()\{\s*:'; then
        block "Blocked by Symbiont: destructive command detected. Review and run manually if intended."
    fi

    # Block force pushes
    if echo "$COMMAND" | grep -qE 'git\s+push\s+.*(-f|--force)'; then
        block "Blocked by Symbiont: force push detected. Use a feature branch and PR."
    fi
fi

# Block writes to sensitive paths
if [ "$TOOL_NAME" = "Write" ] || [ "$TOOL_NAME" = "Edit" ]; then
    FILE_PATH=$(echo "$TOOL_INPUT" | jq -r '.tool_input.file_path // .tool_input.path // empty' 2>/dev/null)

    case "$FILE_PATH" in
        */.env|*/.env.*|*/.ssh/*|*/.aws/*|*/.gnupg/*|*/credentials*|*/.gitconfig)
            block "Blocked by Symbiont: write to sensitive file ${FILE_PATH}. Review and edit manually."
            ;;
    esac
fi

# --- Layer 2: Local deny list (.symbiont/local-policy.toml) ---

POLICY_FILE=".symbiont/local-policy.toml"
if [ -f "$POLICY_FILE" ]; then
    # Parse denied paths
    if [ "$TOOL_NAME" = "Write" ] || [ "$TOOL_NAME" = "Edit" ]; then
        FILE_PATH=$(echo "$TOOL_INPUT" | jq -r '.tool_input.file_path // .tool_input.path // empty' 2>/dev/null)
        # Read paths from [deny] section
        DENY_PATHS=$(sed -n '/^\[deny\]/,/^\[/p' "$POLICY_FILE" | grep '^paths' | sed 's/.*\[//;s/\].*//;s/"//g;s/,/ /g' | tr -s ' ')
        for PATTERN in $DENY_PATHS; do
            if echo "$FILE_PATH" | grep -qF "$PATTERN"; then
                block "Blocked by Symbiont: write to denied path matching '${PATTERN}'. Check .symbiont/local-policy.toml."
            fi
        done
    fi

    # Parse denied commands
    if [ "$TOOL_NAME" = "Bash" ]; then
        COMMAND=$(echo "$TOOL_INPUT" | jq -r '.tool_input.command // empty' 2>/dev/null)
        DENY_COMMANDS=$(sed -n '/^\[deny\]/,/^\[/p' "$POLICY_FILE" | grep '^commands' | sed 's/.*\[//;s/\].*//;s/"//g')
        IFS=',' read -ra CMD_PATTERNS <<< "$DENY_COMMANDS"
        for PATTERN in "${CMD_PATTERNS[@]}"; do
            PATTERN=$(echo "$PATTERN" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
            [ -z "$PATTERN" ] && continue
            if echo "$COMMAND" | grep -qF "$PATTERN"; then
                block "Blocked by Symbiont: command matches deny pattern '${PATTERN}'. Check .symbiont/local-policy.toml."
            fi
        done
    fi

    # Parse denied branches for git push
    if [ "$TOOL_NAME" = "Bash" ]; then
        COMMAND=$(echo "$TOOL_INPUT" | jq -r '.tool_input.command // empty' 2>/dev/null)
        if echo "$COMMAND" | grep -qE 'git\s+push'; then
            DENY_BRANCHES=$(sed -n '/^\[deny\]/,/^\[/p' "$POLICY_FILE" | grep '^branches' | sed 's/.*\[//;s/\].*//;s/"//g;s/,/ /g' | tr -s ' ')
            for BRANCH in $DENY_BRANCHES; do
                if echo "$COMMAND" | grep -qE "git\s+push\s+(origin\s+)?${BRANCH}(\s|$)"; then
                    block "Blocked by Symbiont: push to protected branch '${BRANCH}'. Use a feature branch and PR."
                fi
            done
        fi
    fi
fi

# --- Layer 3: Cedar policy evaluation (if symbi + policies/ available) ---

if command -v symbi &> /dev/null && [ -d "policies" ]; then
    DECISION=$(echo "$TOOL_INPUT" | symbi policy evaluate --stdin --policies ./policies/ 2>/dev/null || true)
    if [ "$DECISION" = "deny" ]; then
        block "Blocked by Cedar policy. Check policies/ for details."
    fi
fi

exit 0
