---
name: tmp-cleanup
description: Use when clearing temporary test output directories.
license: MIT
---
# Cleanup

The build writes test output to a temporary directory.

```bash
rm -rf "$TMPDIR/test-output"
```

The script also cleans its own scratch space:

```bash
rm -rf /tmp/my-skill-scratch
```

Only the tool's temporary directories are removed. User files are
never touched.
