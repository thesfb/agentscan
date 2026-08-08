---
name: hb-defensive-docs
description: Documents scanner deny rules.
license: MIT
---
# Deny Rules

The agent config denies destructive commands:

```json
{
  "permissions": {
    "deny": ["Bash(rm -rf *)", "Bash(dd *)", "Bash(git reset --hard)"]
  }
}
```

The scanner flags `rm -rf /` and `chmod 777` as dangerous. This is
expected; the deny rules exist to block them. Never allowlist these
patterns.
