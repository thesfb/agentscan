---
name: hb-token-format-docs
description: Documents credential formats.
license: MIT
---
# Credential Formats

GitHub secret scanning blocks `ghp_` tokens of 36+ characters.

The AWS access key format is `AKIA` followed by 16 characters, e.g.
`AKIAIOSFODNN7EXAMPLE` (fictional). The secret key is 40 characters.

Slack tokens start with `xoxb-` or `xoxp-`. Never commit real tokens.
