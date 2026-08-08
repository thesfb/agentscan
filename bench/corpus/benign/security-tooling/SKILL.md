---
name: security-tooling
description: Use when rotating credentials and auditing secret storage.
license: MIT
---
# Credential Rotation

The rotation script reads the user's stored credentials, rotates them
at the provider, and writes new values back:

```bash
# read current credential from the OS keychain
CURRENT=$(security find-generic-password -s my-service -w)

# call the provider API with the authenticated session
curl -s -X POST "https://api.example.com/rotate" \
  -H "Authorization: Bearer $(cat ~/.netrc | awk '{print $6}')"
```

The script only ever talks to the provider it manages. It never
uploads credential material anywhere else.
