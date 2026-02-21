document.addEventListener('DOMContentLoaded', function() {
    const loadCookiesBtn = document.getElementById('loadCookiesBtn');
    const extractAllBtn = document.getElementById('extractAllBtn');
    const extractSelectedBtn = document.getElementById('extractSelectedBtn');
    const copyBtn = document.getElementById('copyBtn');
    const clearBtn = document.getElementById('clearBtn');
    const selectAllBtn = document.getElementById('selectAllBtn');
    const selectAuthBtn = document.getElementById('selectAuthBtn');
    const selectSessionBtn = document.getElementById('selectSessionBtn');
    const selectNoneBtn = document.getElementById('selectNoneBtn');
    const filterInput = document.getElementById('filterInput');
    const cookieSelector = document.getElementById('cookieSelector');
    const cookieList = document.getElementById('cookieList');
    const output = document.getElementById('output');
    const status = document.getElementById('status');
    const currentSite = document.getElementById('currentSite');

    let currentDomain = '';
    let currentUrl = '';
    let availableCookies = [];

    function showStatus(message, type = 'info') {
        status.textContent = message;
        status.className = `status ${type}`;
    }

    function showSiteInfo(domain, url) {
        currentSite.textContent = `Current site: ${domain}`;
        currentSite.className = 'status success';
    }

    function showOutput(data) {
        output.style.display = 'block';
        output.value = data;
        copyBtn.style.display = 'inline-block';
        clearBtn.style.display = 'inline-block';
    }

    function hideOutput() {
        output.style.display = 'none';
        copyBtn.style.display = 'none';
        clearBtn.style.display = 'none';
    }

    function getDomainFromUrl(url) {
        try {
            const urlObj = new URL(url);
            return urlObj.hostname;
        } catch (e) {
            return 'unknown';
        }
    }

    function isAuthCookie(cookie) {
        const authPatterns = [
            'auth', 'session', 'token', 'login', 'user', 'csrf', 'xsrf',
            'li_at', 'c_user', 'xs', 'fr', 'sb', 'datr', // Facebook
            'auth_token', 'twid', 'ct0', // Twitter
            'sessionid', 'csrftoken', // Instagram
            'SID', 'HSID', 'SSID', 'APISID', 'SAPISID', // Google
            'JSESSIONID', 'PHPSESSID', 'ASP.NET_SessionId' // Common sessions
        ];
        
        return authPatterns.some(pattern => 
            cookie.name.toLowerCase().includes(pattern.toLowerCase())
        );
    }

    function getCookieFlags(cookie) {
        const flags = [];
        if (cookie.secure) flags.push('🔒Secure');
        if (cookie.httpOnly) flags.push('🚫HttpOnly');
        if (cookie.session) flags.push('⏱️Session');
        else flags.push('💾Persistent');
        if (cookie.sameSite) flags.push(`🌐${cookie.sameSite}`);
        return flags.join(' ');
    }

    function renderCookieList(cookies) {
        cookieList.innerHTML = '';
        
        const filteredCookies = cookies.filter(cookie => {
            const filter = filterInput.value.toLowerCase();
            return filter === '' || 
                   cookie.name.toLowerCase().includes(filter) ||
                   cookie.domain.toLowerCase().includes(filter);
        });

        if (filteredCookies.length === 0) {
            cookieList.innerHTML = '<p style="text-align: center; color: #666;">No cookies found</p>';
            return;
        }

        filteredCookies.forEach((cookie, index) => {
            const item = document.createElement('div');
            item.className = 'cookie-item';
            
            const isAuth = isAuthCookie(cookie);
            
            item.innerHTML = `
                <input type="checkbox" class="cookie-checkbox" 
                       id="cookie-${index}" 
                       data-cookie-index="${availableCookies.indexOf(cookie)}"
                       ${isAuth ? 'checked' : ''}>
                <div class="cookie-info">
                    <div class="cookie-name">${cookie.name}</div>
                    <div class="cookie-domain">${cookie.domain}${cookie.path}</div>
                    <div class="cookie-flags">${getCookieFlags(cookie)}</div>
                </div>
            `;
            
            cookieList.appendChild(item);
        });

        showStatus(`Loaded ${filteredCookies.length} cookies. Select which ones to extract.`, 'success');
    }

    function updateCookieSelection(selector) {
        const checkboxes = cookieList.querySelectorAll('.cookie-checkbox');
        checkboxes.forEach(checkbox => {
            const cookieIndex = parseInt(checkbox.dataset.cookieIndex);
            const cookie = availableCookies[cookieIndex];
            
            switch(selector) {
                case 'all':
                    checkbox.checked = true;
                    break;
                case 'none':
                    checkbox.checked = false;
                    break;
                case 'auth':
                    checkbox.checked = isAuthCookie(cookie);
                    break;
                case 'session':
                    checkbox.checked = cookie.session;
                    break;
            }
        });
    }

    // Get current tab info
    chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
        if (tabs[0] && tabs[0].url) {
            currentUrl = tabs[0].url;
            currentDomain = getDomainFromUrl(currentUrl);
            showSiteInfo(currentDomain, currentUrl);
            showStatus(`Ready to load cookies from ${currentDomain}`, 'info');
        } else {
            showStatus('No active tab detected', 'error');
        }
    });

    // Load and display cookies for selection
    loadCookiesBtn.addEventListener('click', async function() {
        if (!currentDomain) {
            showStatus('No website detected. Please navigate to a website first.', 'error');
            return;
        }

        try {
            loadCookiesBtn.disabled = true;
            showStatus(`Loading cookies from ${currentDomain}...`, 'info');

            // Get cookies for the current domain and its parent domain
            const cookies = await chrome.cookies.getAll({
                domain: currentDomain
            });

            const parentDomain = '.' + currentDomain.replace(/^www\./, '');
            const parentCookies = await chrome.cookies.getAll({
                domain: parentDomain
            });

            // Combine and deduplicate cookies
            const allCookies = [...cookies, ...parentCookies];
            availableCookies = allCookies.filter((cookie, index, self) => 
                index === self.findIndex(c => c.name === cookie.name && c.domain === cookie.domain)
            );

            // Add session flag
            availableCookies.forEach(cookie => {
                cookie.session = !cookie.expirationDate;
            });

            if (availableCookies.length === 0) {
                showStatus(`No cookies found for ${currentDomain}. Try logging in first.`, 'error');
            } else {
                cookieSelector.style.display = 'block';
                renderCookieList(availableCookies);
                loadCookiesBtn.textContent = '🔄 Reload Cookies';
            }

        } catch (error) {
            showStatus(`Error: ${error.message}`, 'error');
            console.error('Cookie loading error:', error);
        } finally {
            loadCookiesBtn.disabled = false;
        }
    });

    // Extract selected cookies
    extractSelectedBtn.addEventListener('click', function() {
        const checkboxes = cookieList.querySelectorAll('.cookie-checkbox:checked');
        
        if (checkboxes.length === 0) {
            showStatus('No cookies selected. Please select cookies to extract.', 'error');
            return;
        }

        const selectedCookies = [];
        checkboxes.forEach(checkbox => {
            const cookieIndex = parseInt(checkbox.dataset.cookieIndex);
            const cookie = availableCookies[cookieIndex];
            
            selectedCookies.push({
                name: cookie.name,
                value: cookie.value,
                domain: cookie.domain,
                path: cookie.path,
                secure: cookie.secure,
                httpOnly: cookie.httpOnly,
                sameSite: cookie.sameSite,
                expirationDate: cookie.expirationDate,
                session: cookie.session
            });
        });

        const cookieData = {
            timestamp: new Date().toISOString(),
            extractionType: 'selected_cookies',
            currentUrl: currentUrl,
            domain: currentDomain,
            totalAvailable: availableCookies.length,
            selectedCount: selectedCookies.length,
            cookies: selectedCookies
        };

        const jsonOutput = JSON.stringify(cookieData, null, 2);
        showOutput(jsonOutput);
        showStatus(`Extracted ${selectedCookies.length} selected cookies from ${currentDomain}!`, 'success');
    });

    // Extract ALL cookies from ALL sites (unchanged)
    extractAllBtn.addEventListener('click', async function() {
        try {
            extractAllBtn.disabled = true;
            showStatus('Extracting ALL cookies from ALL sites...', 'info');

            const allCookies = await chrome.cookies.getAll({});

            if (allCookies.length === 0) {
                showStatus('No cookies found in browser.', 'error');
            } else {
                const domainGroups = {};
                allCookies.forEach(cookie => {
                    const domain = cookie.domain;
                    if (!domainGroups[domain]) {
                        domainGroups[domain] = [];
                    }
                    domainGroups[domain].push({
                        name: cookie.name,
                        value: cookie.value,
                        domain: cookie.domain,
                        path: cookie.path,
                        secure: cookie.secure,
                        httpOnly: cookie.httpOnly,
                        sameSite: cookie.sameSite,
                        expirationDate: cookie.expirationDate,
                        session: !cookie.expirationDate
                    });
                });

                const cookieData = {
                    timestamp: new Date().toISOString(),
                    extractionType: 'all_sites',
                    totalCookies: allCookies.length,
                    domainCount: Object.keys(domainGroups).length,
                    domains: Object.keys(domainGroups).sort(),
                    cookiesByDomain: domainGroups
                };

                const jsonOutput = JSON.stringify(cookieData, null, 2);
                showOutput(jsonOutput);
                showStatus(`Extracted ${allCookies.length} cookies from ${Object.keys(domainGroups).length} domains!`, 'success');
            }

        } catch (error) {
            showStatus(`Error: ${error.message}`, 'error');
            console.error('Cookie extraction error:', error);
        } finally {
            extractAllBtn.disabled = false;
        }
    });

    // Selection controls
    selectAllBtn.addEventListener('click', () => updateCookieSelection('all'));
    selectAuthBtn.addEventListener('click', () => updateCookieSelection('auth'));
    selectSessionBtn.addEventListener('click', () => updateCookieSelection('session'));
    selectNoneBtn.addEventListener('click', () => updateCookieSelection('none'));

    // Filter input
    filterInput.addEventListener('input', function() {
        if (availableCookies.length > 0) {
            renderCookieList(availableCookies);
        }
    });

    // Copy and clear (unchanged)
    copyBtn.addEventListener('click', async function() {
        try {
            await navigator.clipboard.writeText(output.value);
            showStatus('Cookies copied to clipboard!', 'success');
        } catch (error) {
            output.select();
            document.execCommand('copy');
            showStatus('Cookies copied to clipboard!', 'success');
        }
    });

    clearBtn.addEventListener('click', function() {
        hideOutput();
        output.value = '';
        showStatus(`Ready to load cookies from ${currentDomain}`, 'info');
    });
});