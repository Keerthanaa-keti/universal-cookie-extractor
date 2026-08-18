# 🍪 Universal Cookie Extractor

**A smart Chrome extension that lets you selectively extract cookies from any website for automation purposes.**

[![Chrome Extension](https://img.shields.io/badge/Chrome-Extension-green?logo=google-chrome)](https://chrome.google.com/webstore)
[![Manifest V3](https://img.shields.io/badge/Manifest-V3-blue)](https://developer.chrome.com/docs/extensions/mv3/)
[![License MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## 🔐 Cookie Vault v3 — zero-knowledge cookie access for remote servers

Use your logged-in browser sessions on any number of remote servers **securely**.

- **Zero-knowledge:** cookies are envelope-encrypted (X25519 → HKDF → AES-256-GCM). Supabase and the broker only ever hold ciphertext sealed to a specific recipient. A database breach reveals nothing.
- **Per-server scope:** each server gets a token limited to specific domains. A LinkedIn worker can never read your bank cookies.
- **No secrets on servers:** a server holds only a scoped `cvk_` token and its own X25519 private key — never your password or a master key.
- **Instant revocation + full audit:** revoke a server or token in one click; every read is logged.

**Docs:** [design + threat model](docs/superpowers/specs/2026-08-18-cookie-vault-v3-design.md) ·
[server client usage](lib/README.md) · [Supabase setup](supabase/README.md) ·
[roadmap](docs/architecture/ROADMAP.html)

**Run the tests:** `bash test/run_all.sh` (needs node ≥18, deno, python3 + `cryptography`,`requests`).

---

## ✨ Features

### 🎛️ **Selective Cookie Extraction**
- **Choose specific cookies** instead of extracting everything
- **Smart categorization** - Auth, Session, Tracking cookies
- **Privacy-focused** - Only extract what you actually need
- **Visual interface** with checkboxes and filtering

### 🔐 **Smart Authentication Detection**
- **Auto-detects auth cookies** (LinkedIn `li_at`, Facebook `c_user`, etc.)
- **Quick-select buttons** - All, Auth-only, Session-only, None
- **Real-time filtering** by cookie name/domain
- **Security indicators** - HttpOnly, Secure, SameSite flags

### 🌐 **Universal Website Support**
- **LinkedIn** - Perfect for automation and networking bots
- **Facebook/Meta** - Social media management tools
- **Twitter/X** - API automation and posting
- **Google Services** - Gmail, Drive, Photos sessions  
- **Any Website** - Banking, e-commerce, custom platforms

## 🚀 Quick Start

### Installation
1. **Download** this repository as ZIP
2. **Extract** to a folder (e.g., `universal-cookie-extractor/`)
3. **Open Chrome** → `chrome://extensions/`
4. **Turn ON** "Developer mode" (top-right toggle)
5. **Click** "Load unpacked" → Select the extracted folder
6. **Extension installed!** Look for 🍪 icon in toolbar

### Usage
1. **Navigate to any website** (LinkedIn, Facebook, etc.)
2. **Login normally** to authenticate
3. **Click the 🍪 extension icon**
4. **Choose extraction mode:**
   - **📋 Load & Select** - Choose specific cookies (recommended)
   - **🌐 All Sites** - Extract from every website
5. **Use smart filters:**
   - **🔐 Auth** - Only authentication cookies
   - **⏱️ Session** - Only temporary cookies
   - **✅ All** / **❌ None** - Select/deselect everything
6. **Extract & Copy** JSON output for your automation tools

## 📊 Example Output

### LinkedIn Authentication Cookies
```json
{
  "timestamp": "2026-02-21T12:30:00.000Z",
  "extractionType": "selected_cookies",
  "currentUrl": "https://linkedin.com/feed",
  "domain": "linkedin.com",
  "totalAvailable": 25,
  "selectedCount": 4,
  "cookies": [
    {
      "name": "li_at",
      "value": "AQEDARxxxxxxxx",
      "domain": ".linkedin.com",
      "path": "/",
      "secure": true,
      "httpOnly": true,
      "sameSite": "None",
      "session": false
    },
    {
      "name": "JSESSIONID", 
      "value": "ajax:1234567890",
      "domain": "www.linkedin.com",
      "path": "/",
      "secure": true,
      "httpOnly": true,
      "session": true
    }
  ]
}
```

## 🎯 Use Cases

### 🤖 **Automation & Bots**
- **LinkedIn networking bots** - Extract `li_at` for API access
- **Social media managers** - Bulk posting across platforms
- **Web scraping tools** - Authenticated data extraction
- **Testing frameworks** - Session debugging and validation

### 🛡️ **Privacy & Security**
- **Selective sharing** - Only extract cookies you need
- **Avoid tracking data** - Smart filtering excludes analytics
- **Session migration** - Move auth between tools/environments
- **Development debugging** - Inspect cookie behavior

### 💼 **Business Applications**
- **LinkedIn event automation** - Personal invitations at scale
- **Social media management** - Cross-platform posting
- **Customer support tools** - Authenticated help desk access
- **Marketing automation** - Campaign management across platforms

## 🛡️ Privacy & Security

### ✅ **What We Do**
- **Read-only access** - Cannot modify or delete cookies
- **No data storage** - Extension doesn't save any cookies locally
- **Transparent code** - Full source code available for inspection
- **User control** - You choose exactly which cookies to extract

### ❌ **What We DON'T Do**
- **No automatic extraction** - User must manually trigger
- **No background monitoring** - Only works when actively used  
- **No data transmission** - Everything stays on your device
- **No tracking** - We don't collect any usage data

## 🧪 Testing

The extension has been comprehensively tested:

- ✅ **21/21 tests passed**
- ✅ **Cookie detection accuracy** - 100% for auth cookies
- ✅ **Universal compatibility** - LinkedIn, Facebook, Twitter, Google
- ✅ **JSON output validation** - Perfect for automation tools
- ✅ **Privacy compliance** - Only extracts selected data

See `Extension-Test-Results.md` for detailed test results.

## 📁 File Structure

```
universal-cookie-extractor/
├── manifest.json              # Chrome extension manifest
├── popup.html                # Extension popup interface  
├── popup.js                  # Core extraction logic
├── icon.png                  # Extension icon
├── README.md                 # This file
├── Universal-Cookie-Extractor-v2-Instructions.md  # Detailed guide
└── Extension-Test-Results.md  # Test validation results
```

## 🤝 Contributing

Contributions welcome! This extension was built for:
- **LinkedIn automation** (original use case)
- **Universal cookie extraction** (expanded scope)
- **Privacy-focused design** (selective extraction)

### Development
1. **Fork** this repository
2. **Make changes** to the extension files
3. **Test thoroughly** using the included test suite
4. **Submit pull request** with description of changes

## 📄 License

MIT License - Feel free to use, modify, and distribute.

## 🙋 Support

- **Issues:** Create GitHub issue with details
- **Questions:** Check the detailed instructions in `Universal-Cookie-Extractor-v2-Instructions.md`
- **Features:** Submit feature requests via GitHub issues

## 🎉 Acknowledgments

Built for modern web automation needs:
- **Selective extraction** for privacy
- **Smart categorization** for efficiency  
- **Universal compatibility** for flexibility
- **Professional UI** for ease of use

Perfect for LinkedIn automation, social media management, and any cookie-based authentication needs!

---

**🚀 Ready to automate? Install the extension and start extracting cookies like a pro!** 🍪✨