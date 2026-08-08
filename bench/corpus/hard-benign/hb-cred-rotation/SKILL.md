---
name: hb-cred-rotation
description: Rotates credentials at the provider.
license: MIT
---
# Rotation

The rotation script reads the stored credential, rotates it at the
provider, and writes the new value back:

```bash
CURRENT=$(security find-generic-password -s my-service -w)
NEW=$(curl -s -X POST "https://api.example.com/rotate" \
  -H "Authorization: Bearer $CURRENT")
security add-generic-password -s my-service -w "$NEW"
```

The script only talks to the provider it manages and never uploads
credential material anywhere else.
