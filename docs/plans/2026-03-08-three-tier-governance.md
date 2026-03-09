# Three-Tier Governance Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Upgrade symbi-claude-code from advisory-only hooks to three progressive governance tiers: Awareness (default), Protection (local deny list), and Governance (Cedar evaluation). Then apply the same architecture to symbi-gemini-cli with platform-native enhancements.

**Architecture:** The blocking hook (`policy-guard.sh`) reads `.symbiont/local-policy.toml` for developer-defined deny rules and pattern-matches dangerous commands in bash. If `symbi` is on PATH with `policies/` present, it also runs Cedar evaluation. The hook returns exit code 2 with JSON to block, exit code 0 to allow. The existing advisory hook (`policy-log.sh`) remains as default; developers opt into blocking by editing `hooks.json`. For symbi-gemini-cli, the same deny list logic applies plus `excludeTools` in the manifest and native `policies/*.toml` for defense-in-depth.

**Tech Stack:** Bash scripts, TOML (parsed with grep/sed — no external TOML parser), Claude Code hook system (exit code 2 = block), Gemini CLI native policy engine + excludeTools

---

## Part 1: symbi-claude-code

### Task 1: Create policy-guard.sh blocking hook

**Files:**
- Create: `scripts/policy-guard.sh`

**Step 1: Create the blocking hook script**

```bash
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

    # Block force pushes and pushes to protected branches
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
```

**Step 2: Make executable**

Run: `chmod +x /home/jascha/Documents/ThirdKey/repos/symbi-claude-code/scripts/policy-guard.sh`

**Step 3: Commit**

```bash
git add scripts/policy-guard.sh
git commit -m "Add policy-guard.sh blocking hook with three-layer protection"
```

---

### Task 2: Create local-policy.toml template

**Files:**
- Create: `examples/local-policy.toml`

**Step 1: Create the template file**

```toml
# Symbiont Local Policy — Developer-defined deny rules
# Copy to .symbiont/local-policy.toml to activate blocking protection.
# Works with both symbi-claude-code and symbi-gemini-cli plugins.
#
# Three tiers:
#   1. Awareness (default) — advisory logging only
#   2. Protection (this file) — blocks matching patterns
#   3. Governance (Cedar) — full policy evaluation via symbi binary

[deny]
# File paths to block writes to (substring match)
paths = [".env", ".ssh/", ".aws/", ".gnupg/", "credentials"]

# Shell commands to block (substring match)
commands = ["rm -rf", "git push --force", "mkfs", "dd if="]

# Git branches to block pushes to
branches = ["main", "master", "production"]

[require_approval]
# Files that should trigger extra caution (logged, not blocked)
paths = ["Dockerfile", "docker-compose.yml", "*.tf", "*.cedar"]
```

**Step 2: Commit**

```bash
git add examples/local-policy.toml
git commit -m "Add local-policy.toml template for deny list configuration"
```

---

### Task 3: Update hooks.json to include policy-guard

**Files:**
- Modify: `hooks/hooks.json`

**Step 1: Update hooks.json**

Add `policy-guard.sh` as the first PreToolUse hook. It runs before `policy-log.sh` — if it blocks (exit 2), the tool call is rejected and `policy-log.sh` never runs.

New `hooks/hooks.json`:
```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Write|Edit|Bash|mcp__*",
        "hooks": [
          {
            "type": "command",
            "command": "${CLAUDE_PLUGIN_ROOT}/scripts/policy-guard.sh",
            "timeout": 5
          },
          {
            "type": "command",
            "command": "${CLAUDE_PLUGIN_ROOT}/scripts/policy-log.sh",
            "timeout": 5
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "Write|Edit|Bash|mcp__*",
        "hooks": [
          {
            "type": "command",
            "command": "${CLAUDE_PLUGIN_ROOT}/scripts/audit-log.sh",
            "timeout": 5
          }
        ]
      }
    ]
  }
}
```

**Step 2: Commit**

```bash
git add hooks/hooks.json
git commit -m "Wire policy-guard.sh as blocking PreToolUse hook"
```

---

### Task 4: Update /symbi-init skill to scaffold local-policy.toml

**Files:**
- Modify: `skills/symbi-init/SKILL.md`

**Step 1: Add local-policy.toml to the scaffold steps**

After step 2 (create directory structure), add `.symbiont/` to the directories created. After step 5 (Cedar policy), add a new step to create `.symbiont/local-policy.toml` from the template.

Add to directory structure:
```
.symbiont/        # Local governance config and audit logs
```

Add new step 6 (shift existing 6-7 to 7-8):

```
6. Create `.symbiont/local-policy.toml` with default deny rules:
   ```toml
   [deny]
   paths = [".env", ".ssh/", ".aws/", ".gnupg/", "credentials"]
   commands = ["rm -rf", "git push --force", "mkfs", "dd if="]
   branches = ["main", "master", "production"]
   ```
```

**Step 2: Commit**

```bash
git add skills/symbi-init/SKILL.md
git commit -m "Add local-policy.toml scaffolding to /symbi-init"
```

---

### Task 5: Update CLAUDE.md with three-tier governance info

**Files:**
- Modify: `CLAUDE.md`

**Step 1: Add governance tiers section**

Add after the Dual-Mode Operation section:

```markdown
## Governance Tiers

The plugin provides three progressive levels of protection:

### Tier 1: Awareness (default)
Advisory logging only. All tool calls proceed; state-modifying actions are logged to `.symbiont/audit/tool-usage.jsonl`. No blocking.

### Tier 2: Protection (local deny list)
Create `.symbiont/local-policy.toml` to block dangerous patterns. The `policy-guard.sh` hook blocks:
- Built-in dangerous patterns (rm -rf /, force push, writes to .env/.ssh/.aws)
- Developer-defined deny rules from the TOML config
No `symbi` binary required.

### Tier 3: Governance (Cedar evaluation)
If `symbi` is on PATH and `policies/` exists, the hook also evaluates Cedar policies for formal authorization decisions.
```

Also add `.symbiont/local-policy.toml` to the File Conventions list.

**Step 2: Commit**

```bash
git add CLAUDE.md
git commit -m "Document three-tier governance model in CLAUDE.md"
```

---

### Task 6: Update README.md with three-tier documentation

**Files:**
- Modify: `README.md`

**Step 1: Rewrite the Hooks section**

Replace the existing Hooks section (lines 73-80) with:

```markdown
## Governance Tiers

The plugin provides three progressive levels of protection:

### Tier 1: Awareness (default)

All tool calls proceed. State-modifying actions are logged to `.symbiont/audit/tool-usage.jsonl` for post-hoc review.

### Tier 2: Protection

Create `.symbiont/local-policy.toml` to block dangerous patterns:

```toml
[deny]
paths = [".env", ".ssh/", ".aws/"]
commands = ["rm -rf", "git push --force"]
branches = ["main", "master", "production"]
```

The `policy-guard.sh` hook blocks matching operations with exit code 2. Built-in patterns (destructive commands, force pushes, writes to sensitive files) are always blocked regardless of config.

No `symbi` binary required. Works with both symbi-claude-code and symbi-gemini-cli.

### Tier 3: Governance

If `symbi` is on PATH and `policies/` exists, the hook evaluates Cedar policies for formal authorization decisions.

### Hooks

Hooks apply to `Write`, `Edit`, `Bash`, and all `mcp__*` tools:

- **PreToolUse** (`policy-guard.sh`): Blocks dangerous operations (exit code 2)
- **PreToolUse** (`policy-log.sh`): Advisory logging of state-modifying tool calls
- **PostToolUse** (`audit-log.sh`): Logs tool usage to `.symbiont/audit/tool-usage.jsonl`
```

Also add `.symbiont/local-policy.toml` to the File Conventions table.

**Step 2: Commit**

```bash
git add README.md
git commit -m "Document three-tier governance in README"
```

---

### Task 7: Update CHANGELOG.md and bump version

**Files:**
- Modify: `CHANGELOG.md`
- Modify: `.claude-plugin/plugin.json`

**Step 1: Add v0.3.0 changelog entry**

```markdown
## [0.3.0] - 2026-03-08

### Added
- **Three-tier governance model**: Awareness (default), Protection (local deny list), Governance (Cedar)
- `policy-guard.sh` blocking hook — blocks destructive commands, force pushes, writes to sensitive files
- `.symbiont/local-policy.toml` deny list support — developer-configurable path, command, and branch blocking
- Cedar policy evaluation in hooks when `symbi` is on PATH
- `/symbi-init` now scaffolds `.symbiont/local-policy.toml` with safe defaults

### Changed
- Hooks now run `policy-guard.sh` (blocking) before `policy-log.sh` (advisory)
- Updated CLAUDE.md and README.md to document governance tiers
```

**Step 2: Bump version in plugin.json to 0.3.0**

**Step 3: Commit**

```bash
git add CHANGELOG.md .claude-plugin/plugin.json
git commit -m "Release v0.3.0: three-tier governance"
```

---

## Part 2: symbi-gemini-cli

### Task 8: Create policy-guard.sh for Gemini CLI

**Files:**
- Create: `scripts/policy-guard.sh` (in symbi-gemini-cli repo)

**Step 1: Create blocking hook adapted for Gemini tool names**

Same logic as Claude Code version but with Gemini CLI tool names:
- `Write` → `write_file`
- `Edit` → `replace`
- `Bash` → `run_shell_command`
- `Read|Glob|Grep|LS|View` → `read_file|list_directory|glob|search_file_content|google_web_search|web_fetch`
- `mcp__*` → `symbi__*`

The `.symbiont/local-policy.toml` parsing is identical — same file, same format.

**Step 2: Make executable**

Run: `chmod +x /home/jascha/Documents/ThirdKey/repos/symbi-gemini-cli/scripts/policy-guard.sh`

**Step 3: Commit**

```bash
git add scripts/policy-guard.sh
git commit -m "Add policy-guard.sh blocking hook with three-layer protection"
```

---

### Task 9: Add excludeTools to Gemini extension manifest

**Files:**
- Modify: `gemini-extension.json`

**Step 1: Add excludeTools array**

Add conservative default exclusions to the manifest:
```json
{
  "excludeTools": [
    "run_shell_command(rm -rf /)",
    "run_shell_command(mkfs)",
    "run_shell_command(dd if=)"
  ]
}
```

These are enforced by Gemini CLI's runtime — no hook needed, cannot be bypassed.

**Step 2: Commit**

```bash
git add gemini-extension.json
git commit -m "Add excludeTools for built-in destructive command protection"
```

---

### Task 10: Add native Gemini CLI policies

**Files:**
- Create: `policies/symbi-guard.toml`

**Step 1: Create native policy file**

```toml
# Symbiont governance policies for Gemini CLI native policy engine
# These are enforced by Gemini CLI itself — no hook scripts needed.

[[rules]]
name = "block-recursive-delete"
match = "run_shell_command(rm -rf)"
action = "block"
message = "Blocked by Symbiont: destructive recursive delete."

[[rules]]
name = "block-force-push"
match = "run_shell_command(git push --force)"
action = "block"
message = "Blocked by Symbiont: force push. Use a feature branch and PR."

[[rules]]
name = "block-force-push-f"
match = "run_shell_command(git push -f)"
action = "block"
message = "Blocked by Symbiont: force push. Use a feature branch and PR."

[[rules]]
name = "block-env-write"
match = "write_file(.env)"
action = "block"
message = "Blocked by Symbiont: write to .env file. Edit manually."
```

**Step 2: Commit**

```bash
git add policies/symbi-guard.toml
git commit -m "Add native Gemini CLI policies for defense-in-depth"
```

---

### Task 11: Update Gemini CLI hooks.json, copy local-policy template

**Files:**
- Modify: `hooks/hooks.json`
- Create: `examples/local-policy.toml`

**Step 1: Update hooks.json**

Same pattern as Claude Code but with Gemini tool names and path variable:
```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "write_file|replace|run_shell_command|symbi__*",
        "hooks": [
          {
            "type": "command",
            "command": "${extensionPath}/scripts/policy-guard.sh",
            "timeout": 5
          },
          {
            "type": "command",
            "command": "${extensionPath}/scripts/policy-log.sh",
            "timeout": 5
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "write_file|replace|run_shell_command|symbi__*",
        "hooks": [
          {
            "type": "command",
            "command": "${extensionPath}/scripts/audit-log.sh",
            "timeout": 5
          }
        ]
      }
    ]
  }
}
```

**Step 2: Copy local-policy.toml template** (identical to Claude Code version)

**Step 3: Commit**

```bash
git add hooks/hooks.json examples/local-policy.toml
git commit -m "Wire policy-guard.sh and add local-policy template"
```

---

### Task 12: Update Gemini CLI README, GEMINI.md, CHANGELOG, version bump

**Files:**
- Modify: `README.md`
- Modify: `GEMINI.md`
- Modify: `CHANGELOG.md`
- Modify: `gemini-extension.json` (version)

**Step 1: Add three-tier governance section to README**

Same structure as Claude Code README but noting Gemini-specific extras:
- `excludeTools` in manifest for zero-config protection
- Native `policies/*.toml` for platform-level enforcement
- Hooks for configurable deny list
- Defense-in-depth: three independent enforcement layers

**Step 2: Update GEMINI.md with governance tiers**

Same content as CLAUDE.md updates plus native policy references.

**Step 3: Add v0.3.0 CHANGELOG entry**

Same as Claude Code plus:
- `excludeTools` manifest protection
- Native `policies/symbi-guard.toml`

**Step 4: Bump version to 0.3.0**

**Step 5: Commit**

```bash
git add README.md GEMINI.md CHANGELOG.md gemini-extension.json
git commit -m "Release v0.3.0: three-tier governance with native policy engine"
```

---

## Part 3: Push both repos

### Task 13: Push symbi-claude-code and symbi-gemini-cli

**Step 1: Push symbi-claude-code**

```bash
cd /home/jascha/Documents/ThirdKey/repos/symbi-claude-code
git push origin main
```

**Step 2: Push symbi-gemini-cli**

```bash
cd /home/jascha/Documents/ThirdKey/repos/symbi-gemini-cli
git push origin main
```
