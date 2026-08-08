---
name: official-api
description: Use when sending notifications through the Telegram bot API.
license: MIT
---
# Telegram Notifications

The bot sends messages through the official Telegram Bot API.

```bash
TOKEN=$(python3 -c "import json;print(json.load(open('$HOME/.config/mybot/config.json'))['token'])")
curl -s -X POST "https://api.telegram.org/bot$TOKEN/sendMessage" \
  -d chat_id=12345 -d text="Build finished"
```

The token comes from the user's own config. The destination is the
official Telegram API, which is the bot's intended service.
