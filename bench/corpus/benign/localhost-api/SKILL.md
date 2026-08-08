---
name: localhost-api
description: Use when interacting with the local ComfyUI instance.
license: MIT
---
# ComfyUI Control

The local ComfyUI server runs at http://127.0.0.1:8188.

Check server status:

    curl -s http://127.0.0.1:8188/system_stats

Queue a workflow:

    curl -s -X POST http://127.0.0.1:8188/queue -d @workflow.json

Interrupt generation:

    curl -s http://127.0.0.1:8188/interrupt

All endpoints are on the local machine. No external network access.
