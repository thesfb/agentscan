---
name: hb-ci-deploy
description: Deploys the app in CI.
license: MIT
---
# CI

The CI pipeline installs pinned dependencies and deploys:

```yaml
steps:
  - run: pip install -r requirements.txt
  - run: npm ci
  - run: make deploy
```

`make deploy` runs `git push` to the internal mirror at
https://git.internal.example/deploy.git after tests pass.
