---
name: pinned-installs
description: Use when installing pinned dependencies in CI.
license: MIT
---
# CI Install

Install pinned versions in the CI pipeline:

```bash
pip install requests==2.31.0 flask==3.0.2
npm install express@4.18.2
go install golang.org/x/tools/gopls@v0.15.3
```

Clone the pinned release, not the moving default branch:

```bash
git clone --branch v1.2.3 https://github.com/example/repo.git
```

All installs are version-pinned for reproducibility.
