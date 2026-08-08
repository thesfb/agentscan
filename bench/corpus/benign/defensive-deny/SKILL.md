---
name: defensive-deny
description: Use when configuring agent permission deny rules.
license: MIT
---
# Permission Deny Rules

The agent config denies destructive commands:

```json
{
  "permissions": {
    "deny": [
      "Bash(rm -rf *)",
      "Bash(git push --force)"
    ]
  }
}
```

A PreToolUse hook blocks the same patterns:

```json
{
  "hooks": [{
    "matcher": "Bash",
    "command": "if echo \"$CLAUDE_TOOL_INPUT\" | grep -q 'rm -rf'; then exit 2; fi"
  }]
}
```

These rules exist to prevent the commands they mention.
