# Local Context — Cookie Extractor Project

## Project Overview

Chrome extension (Manifest V3) that auto-collects all browser cookies and exposes them to Claude in Chrome via hidden DOM elements. Includes a Cookie Explorer dashboard at `explorer.html`.

**Version:** 2.0.02
**Key files:** `manifest.json`, `background.js`, `content.js`, `explorer.html`, `popup.html/js`

---

## Why Peekaboo MCP Was Installed

### The Problem
User wanted to send a LinkedIn message to **Keerthanaa Manikandan** (SDE III @ Walmart, 1st-degree connection) with a video invitation to a Funders Forum event. We:
1. Searched LinkedIn, found the person
2. Opened the message compose window (`https://www.linkedin.com/messaging/compose/?recipient=ACoAABltld8BCDCtPB5IfYKzME8m5iYBHIEht2s`)
3. Typed the invitation message (NOT sent yet)
4. Could NOT upload the video file because clicking the attachment button opens a **native macOS Finder file picker dialog**, which Claude in Chrome cannot interact with (it only controls browser tab content)

### The Solution
Installed **Peekaboo** (`@steipete/peekaboo`) — a native Swift MCP server that gives Claude Code full macOS desktop control: mouse, keyboard, screenshots, window management, file picker navigation, OCR, etc.

### Installation Details
- **MCP server:** `peekaboo` in `~/.claude.json`
- **Command:** `npx -y @steipete/peekaboo`
- **Version:** 3.0.0-beta3
- **Permissions:** Screen Recording (granted), Accessibility (granted)
- **Verified working:** Screenshots, app listing all confirmed functional

---

## Full Desktop + Browser Automation Strategy

Claude Code now has **two complementary automation layers** that together provide complete control over the user's machine:

### Layer 1: Claude in Chrome (`mcp__claude-in-chrome__*`)
- Controls **browser tab content** — DOM reading, clicking elements, filling forms, navigating URLs, running JavaScript, reading network/console
- Works with the user's **logged-in sessions and cookies** (LinkedIn, Google, etc.)
- **Limitation:** Cannot interact with anything outside the browser tab — no native OS dialogs, no Finder, no file pickers, no other apps

### Layer 2: Peekaboo (`mcp__peekaboo__*`)
- Controls the **actual macOS desktop** — mouse, keyboard, screenshots, window management, app switching, OCR, file picker navigation
- Can interact with **native dialogs** (file open/save, permission prompts, system alerts)
- Can control **any application** on the Mac, not just Chrome

### How to Use Them Together
**IMPORTANT:** Always prefer Claude in Chrome for in-browser tasks (it's faster, more precise, and has DOM-level access). Fall back to Peekaboo when you hit browser boundaries:

1. **Normal browser work** — Use `mcp__claude-in-chrome__*` tools: navigate, click, type, read pages, run JS
2. **Native dialog appears** (file picker, save dialog, permission prompt) — Switch to `mcp__peekaboo__*`: take a screenshot to see the dialog, then use click/type/hotkey to interact with it
3. **Need to control another app** (Finder, Terminal, Slack, etc.) — Use Peekaboo directly
4. **Back to browser** — Switch back to Claude in Chrome tools

### Example: Upload a File on a Website
```
1. Claude in Chrome: Click the "Upload" button on the webpage
2. (Native file picker opens — Claude in Chrome can't see it)
3. Peekaboo: Take screenshot to see the file picker
4. Peekaboo: Type the file path in the filename field (or navigate to folder)
5. Peekaboo: Click "Open" to confirm selection
6. (File picker closes, back in browser)
7. Claude in Chrome: Verify file appears in the upload area, click Submit
```

This two-layer approach means Claude Code can now **fully automate any task** end-to-end, whether it lives in the browser, on the desktop, or crosses both boundaries.

---

## Pending Task: LinkedIn Video Upload

### What's Done
- LinkedIn message compose is open to Keerthanaa Manikandan
- Message typed: "Hey Keerthanaa! Hope you're doing well. We're hosting a Funders Forum event soon and I think you'd really enjoy it. Sharing the video invite below — would love to have you there! Let me know if you're interested."
- Message is **NOT sent** yet
- Video file NOT attached yet

### What's Needed
1. Use Peekaboo tools (`mcp__peekaboo__*`) to:
   - Navigate to the LinkedIn messaging tab in Chrome
   - Click the attachment/paperclip icon in the message compose area
   - When the native macOS file picker opens, navigate to `/Users/kishore/Downloads/Funders Forum Video.mp4`
   - Select and upload the file
2. Confirm with user before clicking Send

### Key Details
- **Video file:** `/Users/kishore/Downloads/Funders Forum Video.mp4`
- **Recipient:** Keerthanaa Manikandan (LinkedIn URN: `ACoAABltld8BCDCtPB5IfYKzME8m5iYBHIEht2s`)
- **LinkedIn compose URL:** `https://www.linkedin.com/messaging/compose/?recipient=ACoAABltld8BCDCtPB5IfYKzME8m5iYBHIEht2s`
- **LinkedIn file input accepts:** `image/*,.ai,.psd,.pdf,.doc,.docx,.csv,.ppt,.pptx,.pps,.ppsx,.xls,.xlsx,.txt,.eml,.mov,.mp4`

---

## MCP Server Evaluation Context

We evaluated 4 MCP servers for native macOS desktop control. Peekaboo won:

| Server | Verdict |
|---|---|
| **Peekaboo** (steipete) | Best — 20+ tools, Swift-native, 2,274 stars, active dev |
| automation-mcp (ashwwwin) | Alpha, stalled 8+ months, buggy |
| mcp-desktop-automation (tanob) | 6 tools only, abandoned RobotJS dep |
| mcp-remote-macos-use (baryhuang) | VNC-based, wrong architecture for local use |

---

## Cookie Explorer Dashboard

- **URL:** `http://localhost:8765/explorer.html` (needs local server)
- **Recent change (v2.0.02):** Redesigned cookie detail table from 4-column grid to 2-line card layout for readability
