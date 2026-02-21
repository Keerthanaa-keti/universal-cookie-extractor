# 🍪 Universal Cookie Extractor v2 - **Selective Extraction Edition**

## 🎯 **NEW FEATURE: Choose Your Cookies!**
**✅ Select exactly which cookies to extract**
**✅ Smart filtering and categorization**
**✅ Privacy-focused - only get what you need**

## 🚀 **What's New in v2:**

### **🎛️ Three Extraction Modes:**
1. **📋 Load & Select** - Choose specific cookies from current site
2. **🌐 All Sites** - Extract everything (unchanged)
3. **🔍 Smart Filters** - Quick selection by cookie type

### **🧠 Smart Cookie Categories:**
- **🔐 Auth Cookies** - Login sessions, tokens, CSRF protection
- **⏱️ Session Cookies** - Temporary authentication data
- **💾 Persistent Cookies** - Long-term preferences and settings
- **🔒 Secure Cookies** - HTTPS-only protected cookies

### **🎨 User Interface:**
- **✅ Visual checkbox selection** for each cookie
- **🔍 Real-time filtering** by cookie name/domain
- **📊 Cookie details** - security flags, expiration, type
- **⚡ Quick select buttons** - All, None, Auth-only, Session-only

## 📦 Files Included
- `universal-cookie-extractor-v2.zip` - **The enhanced extension**
- Complete source code + validation tools

## 🚀 Installation (Same as v1)
1. Download `universal-cookie-extractor-v2.zip` 
2. Extract folder → Chrome → `chrome://extensions/`
3. Turn ON "Developer mode" → "Load unpacked"
4. Select extracted folder → Extension installed 🍪

## 🎯 **How to Use v2:**

### **Mode 1: Selective Cookie Extraction** ⭐ **NEW!**

1. **Go to any website** (LinkedIn, Facebook, etc.)
2. **Login normally** to authenticate
3. **Click 🍪 extension icon**
4. **Click "📋 Load & Select Cookies"**
5. **Extension shows all available cookies with:**
   - ✅ Checkboxes to select/deselect
   - 🔐 Cookie name and security info  
   - 🌐 Domain and path details
   - ⏱️ Session vs persistent indicators
6. **Use quick filters:**
   - **✅ All** - Select everything
   - **🔐 Auth** - Only authentication cookies (recommended!)
   - **⏱️ Session** - Only temporary session cookies
   - **❌ None** - Deselect everything
7. **🔍 Filter by name** - Type to search specific cookies
8. **Click "🚀 Extract Selected Cookies"**
9. **Copy JSON output** - Only your chosen cookies!

### **Mode 2: All Sites (Unchanged)**
- Click "🌐 Extract All Cookies (All Sites)"
- Gets cookies from every website you've visited

## 🎯 **Example Usage Scenarios:**

### **LinkedIn Automation:**
1. Go to linkedin.com, login
2. Load cookies → Click "🔐 Auth" button
3. Should auto-select: `li_at`, `JSESSIONID`, `csrf-token`
4. Extract → Perfect for automation!

### **Facebook/Meta:**
1. Go to facebook.com, login
2. Load cookies → Select: `c_user`, `xs`, `fr`, `sb`
3. Ideal for social media automation

### **Google Services:**
1. Go to gmail.com, login  
2. Load cookies → Auth filter gets: `SID`, `HSID`, `SSID`
3. Works across all Google services

## 🔍 **New Output Format:**
```json
{
  "timestamp": "2026-02-21T12:30:00.000Z",
  "extractionType": "selected_cookies",
  "currentUrl": "https://linkedin.com",
  "domain": "linkedin.com", 
  "totalAvailable": 25,
  "selectedCount": 5,
  "cookies": [
    {
      "name": "li_at",
      "value": "AQEDARxxxxxxxx",
      "domain": ".linkedin.com",
      "secure": true,
      "httpOnly": true,
      "session": false
    }
  ]
}
```

## 🛡️ **Privacy & Security Benefits:**

### **v2 Privacy Advantages:**
- **🎯 Precision** - Extract only cookies you need
- **🔒 Security** - Avoid sharing unnecessary data
- **📊 Transparency** - See exactly what you're extracting
- **⚡ Efficiency** - Smaller JSON files, faster automation

### **Smart Defaults:**
- **Auth cookies pre-selected** - Most useful for automation
- **Marketing cookies excluded** - Reduces privacy exposure  
- **Session cookies flagged** - Know what expires soon

## 🧪 **Testing the New Features:**

```bash
# Test selective extraction format
python3 test-cookie-parser.py '{
  "timestamp": "2026-02-21T12:30:00.000Z",
  "extractionType": "selected_cookies", 
  "domain": "linkedin.com",
  "totalAvailable": 25,
  "selectedCount": 3,
  "cookieCount": 3,
  "cookies": [...]
}'
```

## 🚀 **Workflow Examples:**

### **LinkedIn Event Automation:**
1. Load LinkedIn cookies
2. Filter → "🔐 Auth" → Extract  
3. Send to kkbot → Automate event invitations
4. **Privacy win:** Only auth cookies shared, not tracking data

### **Multi-Platform Management:**
1. Load Facebook → Select auth cookies  
2. Load Twitter → Select auth cookies
3. Load Instagram → Select auth cookies
4. **One JSON file** with all social media access

## ⚡ **Quick Start Guide:**
1. **Install extension** 
2. **Go to LinkedIn** → Login
3. **🍪 Click extension** → "📋 Load & Select"  
4. **🔐 Click "Auth"** (pre-selects login cookies)
5. **🚀 Extract Selected** → Copy JSON
6. **Send to kkbot** → Start automation!

## 🎯 **Perfect for kkbot Integration:**
- **Cleaner data** - Only essential cookies for automation
- **Faster processing** - Smaller JSON files  
- **Better privacy** - No unnecessary tracking cookies
- **Smart defaults** - Auth cookies auto-selected

**v2 is the perfect tool for privacy-conscious automation!** 🛡️🤖

Ready to give users complete control over their cookie extraction! 🎛️✨