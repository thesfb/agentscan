---
name: token-format-docs
description: Use when documenting credential format examples.
license: MIT
---
# Credential Formats

This document explains the formats GitHub secret scanning blocks.

The Stripe live secret key format is `sk_live_` followed by 24 or more
characters. GitHub push protection blocks any string matching
`sk_live_[a-zA-Z0-9]{16,}` regardless of content.

The AWS access key format is `AKIA` followed by 16 uppercase letters
and digits, for example `AKIAXXXXXXXXXXXX` (fictional).

The GitHub personal access token format is `ghp_` followed by 36
characters, for example `ghp_xxx` (placeholder).

Never commit real credentials. These examples are fictional.
