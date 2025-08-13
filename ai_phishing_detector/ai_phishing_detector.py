#############
# Phishing Detection Tool with AI to identify potential phishing or scam websites
# This script captures screenshots of suspicious URLs and analyzes them using Google's Gemini AI to detect phishing attempts and scam indicators.
# It uses Playwright with Firefox to handle complex web pages and bypass security warnings.
# Check README.md for more details.
#
# Code is provided as best effort. Use at your own risk
# Author: dominicchua@
# Version: 1.5
#############

import base64
import requests
import json
import os
from playwright.async_api import async_playwright
import asyncio

API_KEY = os.environ.get("GEMINI_APIKEY")
GEMINI_MODEL = "gemini-2.5-flash" # Model for image understanding
GEMINI_API_URL = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent?key={API_KEY}"

async def take_screenshot_firefox_enhanced(url: str) -> dict:
    """
    Takes a full-page screenshot, extracts DOM information (links, forms), and returns them.
    Includes warning page detection and bypass attempts.
    """
    print(f"Analyzing and taking screenshot with Firefox (enhanced): {url}")
    try:
        async with async_playwright() as p:
            browser = await p.firefox.launch(
                headless=True,
                firefox_user_prefs={
                    # Disable all Safe Browse features
                    "browser.safebrowsing.enabled": False,
                    "browser.safebrowsing.malware.enabled": False,
                    "browser.safebrowsing.phishing.enabled": False,
                    "browser.safebrowsing.blockedURIs.enabled": False,
                    "browser.safebrowsing.provider.google4.enabled": False,
                    "browser.safebrowsing.provider.mozilla.enabled": False,
                    "browser.safebrowsing.downloads.enabled": False,
                    "browser.safebrowsing.downloads.remote.enabled": False,
                    
                    # Disable SSL/TLS security warnings and errors
                    "security.tls.insecure_fallback_hosts": "",
                    "security.mixed_content.block_active_content": False,
                    "security.mixed_content.block_display_content": False,
                    "dom.security.https_only_mode": False,
                    "security.ssl.require_safe_negotiation": False,
                    "security.ssl.treat_unsafe_negotiation_as_broken": False,
                    "security.ssl3.rsa_des_ede3_sha": True,
                    "security.default_personal_cert": "Ask Every Time",
                    "security.ssl.errorReporting.enabled": False,
                    "security.ssl.errorReporting.automatic": False,
                    "security.tls.hello_downgrade_check": False,
                    "security.warn_entering_secure": False,
                    "security.warn_entering_weak": False,
                    "security.warn_leaving_secure": False,
                    "security.warn_submit_insecure": False,
                    "security.warn_viewing_mixed": False,
                    
                    # Disable various security checks
                    "browser.xul.error_pages.enabled": False,
                    "network.stricttransportsecurity.preloadlist": False,
                    "security.cert_pinning.enforcement_level": 0,
                    "security.cert_pinning.process_headers_from_non_builtin_roots": False,
                    
                    # Disable updates and telemetry
                    "app.update.enabled": False,
                    "browser.search.update": False,
                    "extensions.update.enabled": False,
                    "toolkit.telemetry.enabled": False,
                    "datareporting.healthreport.uploadEnabled": False,
                    "datareporting.policy.dataSubmissionEnabled": False,
                    
                    # Performance and compatibility settings
                    "dom.ipc.processCount": 1,
                    "browser.tabs.remote.autostart": False,
                    "browser.sessionstore.resume_from_crash": False,
                    "browser.shell.checkDefaultBrowser": False,
                    "browser.rights.3.shown": True,
                    "browser.startup.homepage_override.mstone": "ignore",
                    
                    # Network settings
                    "network.dns.disablePrefetch": True,
                    "network.prefetch-next": False,
                    "network.http.speculative-parallel-limit": 0,
                    
                    # Privacy settings that might help bypass detection
                    "privacy.trackingprotection.enabled": False,
                    "privacy.trackingprotection.pbmode.enabled": False,
                    "privacy.trackingprotection.cryptomining.enabled": False,
                    "privacy.trackingprotection.fingerprinting.enabled": False,
                    
                    # User agent and compatibility
                    "general.useragent.override": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0"
                }
            )
            
            context = await browser.new_context(
                ignore_https_errors=True,
                bypass_csp=True,
                accept_downloads=False,
                java_script_enabled=True,
                viewport={"width": 1280, "height": 720}
            )
            
            page = await context.new_page()
            
            await page.set_extra_http_headers({
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'DNT': '1',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            })
            
            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=45000)
            except Exception as nav_error:
                print(f"Navigation error: {nav_error}")
                await page.goto(url, wait_until="commit", timeout=30000)
            
            await page.wait_for_timeout(3000)
            
            try:
                page_content = (await page.content()).lower()
                page_text = (await page.text_content('body')).lower() if await page.locator('body').count() > 0 else ""
                
                firefox_warnings = [
                    'deceptive site ahead', 'reported attack page', 'this connection is not secure',
                    'warning: potential security risk ahead', 'mozilla firefox has blocked this page',
                    'this site has been reported as unsafe'
                ]
                
                if any(warning in page_text or warning in page_content for warning in firefox_warnings):
                    print("Firefox security warning detected, attempting bypass...")
                    bypass_selectors = [
                        'button:has-text("Advanced")', 'button[id*="advancedButton"]',
                        'button[id*="exceptionDialogButton"]', 'button:has-text("Accept the Risk and Continue")',
                        'button:has-text("Continue to site")', 'a:has-text("Continue")',
                        'a[id*="proceed"]', 'button[id*="proceed"]'
                    ]
                    for selector in bypass_selectors:
                        try:
                            element = await page.wait_for_selector(selector, timeout=2000)
                            if element and await element.is_visible():
                                print(f"Found bypass element: {selector}")
                                await element.click()
                                await page.wait_for_timeout(2000)
                                break
                        except:
                            continue
                    await page.wait_for_timeout(3000)
            except Exception as warning_error:
                print(f"Warning bypass error (continuing): {warning_error}")

            # --- Start of new data extraction ---
            print("Extracting DOM information...")
            
            # Extract all links
            links = await page.eval_on_selector_all('a', 'elements => elements.map(el => el.href)')
            
            # Extract all form actions
            forms = await page.eval_on_selector_all('form', 'elements => elements.map(el => el.action)')
            
            # Get full page HTML
            html_content = await page.content()
            
            print(f"Found {len(links)} links, {len(forms)} forms, and extracted HTML.")
            # --- End of new data extraction ---

            screenshot_bytes = await page.screenshot(full_page=True, type='png')
            print("Screenshot taken successfully with Firefox.")
            
            await context.close()
            await browser.close()
            
            return {
                "screenshot": screenshot_bytes,
                "links": links,
                "forms": forms,
                "html": html_content,
            }
            
    except Exception as e:
        print(f"Firefox analysis failed: {e}")
        raise

async def extract_basic_dom_data(page):
    """
    Extracts basic DOM data that can be used in fallback methods.
    Returns the same structure as the enhanced method.
    """
    try:
        print("Extracting basic DOM information...")
        
        # Enhanced link extraction - capture more than just <a> tags
        links = await page.evaluate('''() => {
            const links = [];
            
            // Standard <a> tags
            document.querySelectorAll('a[href]').forEach(el => {
                links.push(el.href);
            });
            
            // Forms with actions
            document.querySelectorAll('form[action]').forEach(el => {
                links.push(el.action);
            });
            
            // Iframes (potential redirects)
            document.querySelectorAll('iframe[src]').forEach(el => {
                links.push(el.src);
            });
            
            // Meta redirects
            document.querySelectorAll('meta[http-equiv="refresh"]').forEach(el => {
                const content = el.getAttribute('content');
                if (content && content.includes('url=')) {
                    const url = content.split('url=')[1];
                    links.push(url);
                }
            });
            
            // Images (could be tracking pixels or suspicious)
            document.querySelectorAll('img[src]').forEach(el => {
                if (el.src.startsWith('http')) {
                    links.push(el.src);
                }
            });
            
            return [...new Set(links)]; // Remove duplicates
        }''')
        
        # Form actions (keep separate for compatibility)
        forms = await page.evaluate('''() => {
            return Array.from(document.querySelectorAll('form[action]')).map(el => el.action);
        }''')
        
        # Get HTML content
        html_content = await page.content()
        
        print(f"Basic DOM extraction successful: {len(links)} links, {len(forms)} forms")
        
        return {
            "links": links,
            "forms": forms,
            "html": html_content,
        }
        
    except Exception as e:
        print(f"Basic DOM extraction failed: {e}")
        return {
            "links": [],
            "forms": [],
            "html": "",
        }

def _clean_html_for_analysis(html_content: str, max_length: int = 10000) -> str:
    """
    Security-focused HTML cleaning that preserves potential threat indicators.
    KEEPS comments and base64 data as they may contain malicious content.
    """
    if not html_content:
        return "HTML not available."
    
    import re
    
    # Only remove scripts and styles (but preserve their presence)
    # Keep the opening tags so AI knows they existed
    html_content = re.sub(r'<script[^>]*>.*?</script>', '<script>[CONTENT_REMOVED_FOR_ANALYSIS]</script>', html_content, flags=re.DOTALL | re.IGNORECASE)
    html_content = re.sub(r'<style[^>]*>.*?</style>', '<style>[CONTENT_REMOVED_FOR_ANALYSIS]</style>', html_content, flags=re.DOTALL | re.IGNORECASE)
    
    # KEEP comments and base64 data - they may contain malicious indicators!
    # DO NOT remove: <!--comments--> or data:base64 content
    
    # Only remove excessive whitespace (but preserve line breaks for readability)
    html_content = re.sub(r'[ \t]+', ' ', html_content)  # Multiple spaces/tabs to single space
    html_content = re.sub(r'\n\s*\n', '\n', html_content)  # Multiple newlines to single
    html_content = html_content.strip()
    
    # Intelligent truncation prioritizing security-relevant sections
    if len(html_content) > max_length:
        # Priority order: head > forms > body content
        head_match = re.search(r'<head.*?</head>', html_content, re.DOTALL | re.IGNORECASE)
        
        # Find forms (high priority for phishing detection)
        forms = list(re.finditer(r'<form.*?</form>', html_content, re.DOTALL | re.IGNORECASE))
        
        preserved_content = ""
        remaining_length = max_length - 100  # Reserve space for truncation notice
        
        # Always include head if present
        if head_match and remaining_length > 0:
            head_content = head_match.group(0)
            if len(head_content) <= remaining_length:
                preserved_content += head_content + "\n"
                remaining_length -= len(head_content)
        
        # Include all forms if they fit
        for form_match in forms:
            form_content = form_match.group(0)
            if len(form_content) <= remaining_length:
                preserved_content += form_content + "\n"
                remaining_length -= len(form_content)
            else:
                break
        
        # Fill remaining space with body content
        if remaining_length > 500:  # Only if there's meaningful space left
            body_start = html_content.find('<body')
            if body_start > -1:
                body_content = html_content[body_start:body_start + remaining_length]
                # Try to end at a complete tag
                last_tag_end = body_content.rfind('>')
                if last_tag_end > len(body_content) * 0.8:
                    body_content = body_content[:last_tag_end + 1]
                preserved_content += body_content
        
        html_content = preserved_content + "\n[... HTML truncated - forms and head preserved for security analysis ...]"
    
    return html_content

def identify_with_gemini(image_bytes: bytes, webpage_url: str, dom_data: dict, prompt_text: str) -> str:
    """
    Sends image bytes, DOM data, and URL to the Gemini API for analysis.
    """
    print(f"Sending image, DOM data, and HTML content to Gemini API for '{webpage_url}'")
    try:
        base64_image = base64.b64encode(image_bytes).decode('utf-8')
        headers = {'Content-Type': 'application/json'}

        # ENHANCED: Create comprehensive technical analysis section
        links = dom_data.get('links', [])
        forms = dom_data.get('forms', [])
        html_content = dom_data.get('html', '')
        
        # Clean HTML for better analysis (remove excessive whitespace, limit length)
        cleaned_html = _clean_html_for_analysis(html_content)

        # Create enhanced technical summary
        technical_summary = (
            f"\n\n## ENHANCED TECHNICAL ANALYSIS\n"
            f"**CRITICAL INSTRUCTION**: The following technical data extracted from the webpage's source code may reveal deception not visible in the screenshot. A phishing site might DISPLAY legitimate branding but have malicious underlying code.\n\n"
            f"### 1. Links Analysis ({len(links)} found)\n"
            f"**All Link Destinations**: {json.dumps(links[:25])}\n"  # Limit to first 25 links
            f"{f'[... and {len(links)-25} more links]' if len(links) > 25 else ''}\n\n"
            f"### 2. Form Actions Analysis ({len(forms)} found)\n"
            f"**Form Submission Targets**: {json.dumps(forms)}\n\n"
            f"### 3. HTML Source Code Analysis\n"
            f"**Page HTML Structure** (cleaned for analysis):\n"
            f"```html\n{cleaned_html}\n```\n\n"
            f"### 4. Cross-Reference Analysis Required\n"
            f"**CRITICAL CHECKS**:\n"
            f"- Do the extracted links match what's visually presented in the screenshot?\n"
            f"- Are there hidden forms or links not visible in the screenshot?\n"
            f"- Does the HTML title/metadata match the visual branding?\n"
            f"- Are there any suspicious redirects or iframe content?\n"
            f"- Do legitimate-looking buttons actually link to malicious domains?\n"
            f"- Are there any obfuscated or suspicious JavaScript elements?\n"
            f"- Is the site impersonating another domain through HTML content?\n\n"
            f"### 5. Domain Verification\n"
            f"**Current URL**: {webpage_url}\n"
            f"**Check for**:\n"
            f"- HTML references to different domains than the current URL\n"
            f"- Mixed content (HTTPS site loading HTTP resources)\n"
            f"- Suspicious external resources or CDN usage\n"
            f"- Domain spoofing in HTML content vs actual URL\n\n"
            f"### Analysis Instructions:\n"
            f"1. **Visual vs Technical Mismatch**: Look for discrepancies between what the screenshot shows and what the HTML/links reveal\n"
            f"2. **Hidden Elements**: Identify any suspicious elements in HTML that aren't visible in screenshot\n"
            f"3. **Link Destination Analysis**: Verify if visible buttons/links actually go where they claim\n"
            f"4. **Content Authenticity**: Check if HTML source matches the legitimate site it appears to impersonate\n"
            f"5. **Sophisticated Techniques**: Look for advanced phishing techniques like iframe overlays, legitimate link mixing with malicious forms, etc.\n\n"
            f"**REMEMBER**: A single legitimate link (like google.com) does NOT make a phishing site legitimate. Focus on the overall context and any deceptive elements."
        )

        # Combine the base prompt, technical summary, and URL for the AI
        full_prompt_for_ai = f"{prompt_text}{technical_summary}"

        payload = {
            "contents": [
                {
                    "role": "user",
                    "parts": [
                        {"inlineData": {"mimeType": "image/png", "data": base64_image}},
                        {"text": full_prompt_for_ai},
                    ]
                }
            ]
        }

        response = requests.post(GEMINI_API_URL, headers=headers, data=json.dumps(payload))
        response.raise_for_status()
        result = response.json()

        # Extract the text from the response - THIS LOGIC IS PRESERVED FROM THE ORIGINAL
        if result.get("candidates"):
            candidate = result["candidates"][0]
            if candidate.get("content"):
                content = candidate["content"]
                if content.get("parts") and isinstance(content["parts"], list):
                    identified_text = ""
                    for part in content["parts"]:
                        if part.get("text"):
                            identified_text += part["text"]
                    if identified_text:
                        return identified_text
                    else:
                        print("Gemini API response contained parts but no text.")
                        print(json.dumps(result, indent=2))
                        return "AI response received, but no identifiable text in parts."
                else:
                    print("Gemini API response content did not contain a 'parts' list.")
                    print(json.dumps(result, indent=2))
                    return "AI response received, but content structure unexpected (missing 'parts')."
            else:
                print("Gemini API response candidate did not contain 'content'.")
                print(json.dumps(result, indent=2))
                return "AI response received, but candidate structure unexpected (missing 'content')."
        else:
            print("Gemini API response did not contain 'candidates'.")
            print(json.dumps(result, indent=2))
            return "Could not get a clear identification from the AI (missing 'candidates')."

    except requests.exceptions.RequestException as e:
        print(f"Error during API request: {e}")
        if hasattr(e, 'response') and e.response:
            print(f"Response status code: {e.response.status_code}")
            print(f"Response content: {e.response.text}")
        return f"API request failed: {e}"
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return f"An error occurred: {e}"

async def take_screenshot_with_fallback(url: str) -> dict:
    """
    Primary function that tries Firefox with fallback options, ensuring a consistent return type.
    This function consolidates the screenshot logic, including aggressive bypass attempts.
    """
    try:
        # The primary, enhanced method returns a full data dictionary
        return await take_screenshot_firefox_enhanced(url)
    except Exception as e_firefox_primary:
        print(f"Primary Firefox method failed: {e_firefox_primary}")
        
        # Fallback 1: Try Firefox with minimal configuration and enhanced SSL bypass
        print("Trying Firefox with minimal configuration (fallback 1)...")
        try:
            async with async_playwright() as p:
                browser = await p.firefox.launch(
                    headless=True,
                    firefox_user_prefs={
                        "browser.safebrowsing.enabled": False, "browser.safebrowsing.malware.enabled": False,
                        "browser.safebrowsing.phishing.enabled": False, "security.ssl.require_safe_negotiation": False,
                        "security.ssl.treat_unsafe_negotiation_as_broken": False, "security.ssl3.rsa_des_ede3_sha": True,
                        "security.tls.hello_downgrade_check": False, "security.warn_entering_secure": False,
                        "security.warn_entering_weak": False, "security.warn_leaving_secure": False,
                        "security.warn_submit_insecure": False, "security.warn_viewing_mixed": False,
                        "dom.security.https_only_mode": False, "security.mixed_content.block_active_content": False,
                        "security.mixed_content.block_display_content": False, "security.default_personal_cert": "Ask Every Time",
                        "security.ssl.errorReporting.enabled": False, "security.ssl.errorReporting.automatic": False,
                        "network.stricttransportsecurity.preloadlist": False, "security.cert_pinning.enforcement_level": 0,
                    }
                )
                context = await browser.new_context(ignore_https_errors=True)
                page = await context.new_page()
                await page.set_viewport_size({"width": 1280, "height": 720})
                await page.goto(url, wait_until="commit", timeout=60000)
                await page.wait_for_timeout(5000)
                # Extract DOM data before screenshot
                dom_data = await extract_basic_dom_data(page)
                screenshot_bytes = await page.screenshot(full_page=True)
                await context.close()
                await browser.close()
                print("Fallback Firefox method (minimal prefs) succeeded.")
                # Return screenshot with DOM data
                dom_data["screenshot"] = screenshot_bytes
                return dom_data
                
        except Exception as e_firefox_fallback:
            print(f"Firefox fallback method also failed: {e_firefox_fallback}")
            
            # Fallback 2: Try HTTP instead of HTTPS if URL was HTTPS
            if url.startswith('https://'):
                http_url = url.replace('https://', 'http://')
                print(f"Trying HTTP version: {http_url} (fallback 2)...")
                try:
                    async with async_playwright() as p:
                        browser = await p.firefox.launch(
                            headless=True,
                            firefox_user_prefs={
                                "browser.safebrowsing.enabled": False, "browser.safebrowsing.malware.enabled": False,
                                "browser.safebrowsing.phishing.enabled": False, "dom.security.https_only_mode": False,
                            }
                        )
                        page = await browser.new_page()
                        await page.set_viewport_size({"width": 1280, "height": 720})
                        await page.goto(http_url, timeout=45000)
                        await page.wait_for_timeout(3000)
                        # Extract DOM data before screenshot
                        dom_data = await extract_basic_dom_data(page)
                        screenshot_bytes = await page.screenshot(full_page=True)
                        await browser.close()
                        print("HTTP fallback method succeeded.")
                        # Return screenshot with DOM data
                        dom_data["screenshot"] = screenshot_bytes
                        return dom_data
         
                except Exception as e_http_fallback:
                    print(f"HTTP fallback also failed: {e_http_fallback}")
            
            # Final fallback: Try Chromium with aggressive bypass
            print("Trying Chromium as final fallback (fallback 3)...")
            try:
                async with async_playwright() as p:
                    browser = await p.chromium.launch(
                        headless=True,
                        args=[
                            '--disable-web-security', '--disable-features=VizDisplayCompositor', '--disable-extensions',
                            '--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage', '--disable-gpu',
                            '--ignore-certificate-errors', '--ignore-ssl-errors', '--ignore-certificate-errors-spki-list',
                            '--allow-running-insecure-content', '--disable-client-side-phishing-detection',
                            '--disable-component-update', '--disable-default-apps', '--disable-domain-reliability',
                            '--disable-features=AudioServiceOutOfProcess', '--disable-hang-monitor',
                            '--disable-ipc-flooding-protection', '--disable-popup-blocking', '--disable-prompt-on-repost',
                            '--disable-renderer-backgrounding', '--disable-sync', '--force-color-profile=srgb',
                            '--metrics-recording-only', '--no-crash-upload', '--no-default-browser-check',
                            '--no-first-run', '--no-pings', '--password-store=basic', '--use-mock-keychain',
                            '--disable-background-networking', '--disable-background-timer-throttling',
                            '--disable-backgrounding-occluded-windows', '--disable-breakpad',
                            '--disable-component-extensions-with-background-pages', '--disable-features=TranslateUI',
                            '--disable-field-trial-config', '--disable-back-forward-cache'
                        ]
                    )
                    context = await browser.new_context(ignore_https_errors=True, bypass_csp=True)
                    page = await context.new_page()
                    await page.set_viewport_size({"width": 1280, "height": 720})
                    await page.goto(url, wait_until="commit", timeout=45000)
                    await page.wait_for_timeout(3000)
                    # Extract DOM data before screenshot
                    dom_data = await extract_basic_dom_data(page)
                    screenshot_bytes = await page.screenshot(full_page=True)
                    await context.close()
                    await browser.close()
                    print("Chromium fallback method succeeded.")
                    # Return screenshot with DOM data
                    dom_data["screenshot"] = screenshot_bytes
                    return dom_data
                    
            except Exception as e_chromium_fallback:
                print(f"Chromium fallback also failed: {e_chromium_fallback}")
                raise Exception(f"All screenshot methods failed for {url}. "
                                f"Primary Firefox error: {e_firefox_primary}. "
                                f"Fallback Firefox error: {e_firefox_fallback}. "
                                f"Chromium fallback error: {e_chromium_fallback}.")

async def analyze_url_for_phishing(target_url: str) -> str:
    """
    Orchestrates the screenshot capture and AI analysis for a given URL.

    Args:
        target_url (str): The URL of the website to analyze.

    Returns:
        str: The AI's detailed analysis and risk assessment.
    """
    # Timeout for AI analysis in seconds for internal timeout to prevent long waits
    AI_ANALYSIS_TIMEOUT = 120 
    
    async def analysis_logic():
        # ENHANCED Comprehensive phishing detection prompt
        identification_prompt_base = """
        You are a cybersecurity AI assistant specialized in detecting phishing websites through visual analysis of screenshots and comprehensive technical analysis of the underlying HTML/DOM structure.

        ## CRITICAL ANALYSIS APPROACH
        **IMPORTANT**: Phishing sites often display legitimate-looking content while having malicious underlying code. A site showing legitimate branding with some legitimate links may still be a phishing site if it's impersonating a brand or collecting credentials fraudulently.

        ## Analysis Framework
        Evaluate the following elements systematically:

        1. **Visual vs Technical Cross-Reference** (MOST IMPORTANT)
        Are there discrepancies between what the screenshot shows and what the technical analysis reveals?
        - Does the visual branding match the actual domain and HTML content?
        - Do visible buttons and links actually go where they appear to lead?
        - Are there hidden forms or elements not visible in the screenshot?
        - Is the site legitimately from the domain it claims to represent?
        - Does the URL match the branding displayed on the page?

        2. **Branding Consistency**
        Are logos, color schemes, and fonts consistent with known legitimate brands visible on the page? Look for:
        - Misspellings in brand names or logos
        - Poor translations or awkward language  
        - Low-quality, pixelated, or distorted graphics
        - Subtle inconsistencies in colors, fonts, or design elements
        - Incorrect or outdated brand styling

        3. **Design Quality**
        Assess the overall professionalism of the design:
        - Professional layout vs. hastily assembled appearance
        - Consistent alignment and spacing
        - Font consistency throughout the page
        - Image quality and resolution
        - Overall visual coherence and attention to detail

        4. **Textual Content**
        Examine all visible text for red flags:
        - Grammatical errors, spelling mistakes, or unusual phrasing
        - Urgent or threatening language ("Act now!" "Account will be suspended!")
        - Requests for sensitive information (logins, credit cards, SSN, personal details)
        - Generic greetings instead of personalized content
        - Overly dramatic or emotional language

        5. **Interactive Elements & Technical Verification**
        Cross-reference visible elements with the extracted technical data:
        - What information do forms actually collect vs. what they claim?
        - Where do links and buttons actually lead vs. where they appear to go?
        - Are there suspicious payment or credential collection forms?
        - Do button labels and form fields match legitimate site standards?
        - Are there any hidden or misleading elements in the HTML?
        - Are there any pop-ups or overlays that obscure content?
        - Are there any suspicious download links or buttons?
        - Are there any social media links that appear fake or lead to suspicious profiles?

        6. **Sense of Urgency/Threats/Unrealistic Offers**
        Identify manipulation tactics:
        - Undue urgency ("Limited time offer!" "Expires today!")
        - Threats (account suspension, legal action, security breaches)
        - Offers that seem too good to be true
        - Fake countdown timers or limited availability claims
        - Pressure tactics to act immediately

        7. **Content Specificity**
        Evaluate the relevance and authenticity of content:
        - Is content generic or highly specific to a legitimate service?
        - Does it reference real transactions, accounts, or services?
        - Are there specific details that would only be known by legitimate companies?
        - Is the content contextually appropriate for the claimed service?

        8. **Security Indicators**
        Look for fraudulent security elements:
        - Fake security badges or certificates
        - Misleading trust indicators
        - Claims of encryption or security without proper implementation
        - Suspicious SSL indicators or warnings
        - False testimonials or reviews

        9. **URL vs Content Analysis**
        Examine the relationship between the URL and content:
        - Does the domain match the branding and content shown?
        - Are there domain spoofing attempts or typosquatting?
        - Brand impersonation attempts
        - Suspicious subdomains or TLD abuse
        - Character substitution (0 for O, 1 for l, etc.)
        - Overly long or complex domain structures
        - Homograph / unicode phishing attempts

        10. **HTML Source Code Analysis**
        Examine the full HTML source code provided in the Technical Analysis section. Look for:
        - Suspicious JavaScript or obfuscated code that could redirect users or steal data
        - Hidden iframes or elements designed to load malicious content
        - Unusual comments or non-standard HTML structure that might hide malicious intent
        - Embedded scripts from untrusted or unknown third-party domains
        - Form actions that redirect to suspicious domains
        - Any other anomalies that suggest deceptive practices
        - Discrepancies between what's visible and what's in the code

        11. **Advanced Deception Detection**
        Look for sophisticated phishing techniques:
        - Legitimate links mixed with malicious forms to build credibility
        - Iframe overlays hiding malicious content
        - Partial legitimate functionality to build trust
        - Progressive credential harvesting techniques
        - Social engineering through legitimate-appearing elements

        ## Response Requirements

        ### Detailed Analysis
        Provide a comprehensive evaluation addressing each point above. **Pay special attention to any discrepancies between visual appearance and technical reality.**

        ### CRITICAL: Do not be misled by isolated legitimate elements
        A phishing site may include some legitimate links or references to build credibility while still being malicious overall. Focus on the overall authenticity and whether the site is legitimately representing the brand it appears to show.

        ## Risk Assessment Format
        ### Conclude with exactly this format:
        RISK ASSESSMENT: [Low/Medium/High] - [Single sentence reasoning for assessment]

        ### Risk Level Guidelines
        - **Low Risk**: Professional appearance, consistent branding, no obvious red flags, legitimate URL structure, technical elements match visual presentation
        - **Medium Risk**: Some concerning elements but not definitively malicious; could be legitimate site with issues or sophisticated phishing requiring further verification
        - **High Risk**: Clear indicators of phishing/scam; obvious attempts at deception, brand impersonation, or technical elements that contradict visual presentation

        ## Additional Considerations
        - If uncertain, err on the side of caution and recommend verification through official channels
        - Note any sophisticated techniques that might fool casual observers
        - Mention if the site requires additional verification beyond visual analysis
        - Provide specific actionable advice when possible
        - **Remember**: The presence of some legitimate links does not automatically make a site legitimate
        """

        print("Starting enhanced phishing detection process...")
        print(f"Target URL: {target_url}")
        print("-" * 60)

        # Step 1: Take screenshot and extract DOM data
        print("Step 1: Capturing screenshot and DOM data...")
        analysis_data = await take_screenshot_with_fallback(target_url)
        screenshot_bytes = analysis_data["screenshot"]
        print(f"Screenshot captured successfully. Size: {len(screenshot_bytes)} bytes")
        if analysis_data["links"] or analysis_data["forms"]:
            print(f"DOM data extracted: {len(analysis_data['links'])} links, {len(analysis_data['forms'])} forms.")

        # Step 2: Send to Gemini for analysis
        print("\nStep 2: Analyzing with Gemini...")
        ai_identification = await asyncio.to_thread(
            identify_with_gemini,
            screenshot_bytes,
            target_url,
            analysis_data, # Pass the whole dictionary
            identification_prompt_base
        )

        print("\n" + "="*60)
        print("ENHANCED PHISHING DETECTION ANALYSIS RESULTS")
        print("="*60)
        print(f"URL: {target_url}")
        print("-" * 60)
        print(ai_identification)
        print("="*60)

        return ai_identification

    try:
        # Wrap the entire analysis logic in a timeout
        return await asyncio.wait_for(analysis_logic(), timeout=AI_ANALYSIS_TIMEOUT)
    except asyncio.CancelledError:
        # This block is new. It catches the cancellation signal.
        print(f"AI analysis for {target_url} was cancelled.")
        raise  # Re-raise the exception to ensure the task is properly marked as cancelled.
    except asyncio.TimeoutError:
        print(f"AI analysis for {target_url} timed out after {AI_ANALYSIS_TIMEOUT} seconds.")
        # Return a standardized timeout message
        return "[TIMED OUT] AI analysis timed out. This can happen with slow or complex websites."
    except Exception as e:
        print(f"\nProcess failed with error: {e}")
        # Return a standardized error message
        return "[ERROR] AI analysis failed due to an error."

# --- Main Execution (only runs when script is executed directly) ---
if __name__ == "__main__":
    # Example usage when run as a standalone script
    target_url = "https://psuksemsou.xyz/"  # Your example URL
    
    try:
        analysis_result = asyncio.run(analyze_url_for_phishing(target_url))
        # The result is now correctly retrieved
    except Exception as e:
        print(f"Script execution terminated due to an error: {e}")
