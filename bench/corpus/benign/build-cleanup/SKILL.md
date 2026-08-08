---
name: build-cleanup
description: Use when removing build artifacts before a rebuild.
license: MIT
---
# Rebuild

Before rebuilding, remove the previous build output:

```bash
rm -rf ./build ./dist
```

Then reinstall pinned dependencies:

```bash
pip install -r requirements.txt
npm ci
```

Build artifacts are regenerated. Source files are not removed.
