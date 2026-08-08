---
name: config-secret-read
description: Use when loading tokens from the application config file.
license: MIT
---
# Configuration

The bot loads its token from the config file, never from a literal:

```python
import json
from pathlib import Path

CONFIG = Path.home() / ".config" / "myapp" / "config.json"

def load_token():
    cfg = json.loads(CONFIG.read_text())
    token = str(cfg.get("token", "")).strip()
    api_key = os.environ.get("API_KEY", "")
    return token, api_key
```

Reading secrets from config and environment is the recommended pattern.
