#############
# Phishing Detection Tool with AI to identify potential phishing or scam websites
# This script captures screenshots of suspicious URLs and analyzes them using Google's Gemini AI to detect phishing attempts and scam indicators.
# Enhanced with dual browser support (Firefox + Chromium) and user agent testing for evasion detection.
# Now includes smart hybrid analysis that uses dual AI when differences are detected.
# Check README.md for more details.
#
# Code is provided as best effort. Use at your own risk
# Author: dominicchua@
# Version: 2.3.1 - added full AI response if debug is on
#############

import base64
import requests
import json
import os
from playwright.async_api import async_playwright
import asyncio

################
# Configuration
################
API_KEY = os.environ.get("GEMINI_APIKEY")
if not API_KEY:
    raise ValueError("GEMINI_APIKEY environment variable not set. Please set it before running the script.")
GEMINI_MODEL = "gemini-2.5-flash" # Model for image understanding
GEMINI_API_URL = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent?key={API_KEY}"

# 1. Default user agents 
DEFAULT_USER_AGENTS = ["firefox_windows", "chrome_windows", "chrome_android", "chrome_mac"]
AI_ANALYSIS_TIMEOUT = 180  # Timeout for the entire analysis in seconds

#2. AI Prompts
# This prompt is used when analyzing a single browser capture.
PROMPT_SINGLE_ANALYSIS = """
You are a cybersecurity AI assistant specialized in detecting phishing websites through visual analysis of screenshots and comprehensive technical analysis of the underlying HTML/DOM structure.
    
    ## CRITICAL ANALYSIS APPROACH
    **IMPORTANT**: Pay special attention to any signs of evasion or targeting.
    
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
    **RISK ASSESSMENT: Low/Medium/High - [Provide a clear, concise 2-3 sentence explanation that captures the key findings and reasoning. Focus on the most critical factors that led to your assessment. Maximum 400 characters.]**

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


# This prompt is used for a comparative analysis between two different browser captures.
PROMPT_DUAL_ANALYSIS = """
You are a cybersecurity AI assistant specialized in detecting phishing websites through visual analysis of screenshots and comprehensive technical analysis of the underlying HTML/DOM structure.
    
    ***IMPORTANT***:You are analyzing TWO screenshots and datasets from the SAME URL captured with different browsers/user agents to detect evasion techniques.

    ## CRITICAL DUAL ANALYSIS APPROACH
    **IMPORTANT**: You are receiving data from TWO different browser captures of the same URL. Compare them systematically to identify evasion, targeting, or suspicious differences.

    ## Comparative Analysis Framework
    
    1. **Screenshot Comparison** (MOST IMPORTANT)
    - Are the screenshots visually identical or different?
    - If different: What specific visual elements differ?
    - Does one appear legitimate while the other appears malicious?
    - Are there different layouts, colors, branding, or content?
    
    2. **Content Structure Comparison**
    - Compare the number and types of links between both results
    - Compare the forms and their targets between both results
    - Are there different HTML structures or hidden elements?
    - Do the extracted links lead to different destinations?
    
    3. **URL and Redirect Analysis**
    - Compare the final URLs both browsers reached
    - If different: This indicates redirect-based evasion
    - Analyze if one redirect appears legitimate vs malicious
    
    4. **Browser/User Agent Targeting Detection**
    - Identify if the site serves different content to different browsers
    - Look for mobile vs desktop targeting
    - Check for browser-specific exploits or content
    
    5. **Evasion Technique Identification**
    - Browser fingerprinting and discrimination
    - Conditional redirects based on user agent
    - Cloaking legitimate content from certain browsers
    - Serving malicious content only to specific browsers
    
    6. **Threat Assessment**
    - Which result (if any) appears to be the malicious version?
    - Is this sophisticated evasion or legitimate browser differences?
    - What is the primary threat vector being used?
    
    ## Response Requirements
    
    ### Comparison Summary
    Start with a clear comparison: "DUAL BROWSER ANALYSIS: Comparing [Browser1] vs [Browser2] results..."
    
    ### Key Differences
    List the specific differences found between the two results.
    
    ### Evasion Assessment
    Determine if differences indicate malicious evasion or legitimate variation.
    
    ### Risk Assessment Format
    **RISK ASSESSMENT: Low/Medium/High - [Provide a clear, concise 2-3 sentence explanation focusing on browser differences and evasion techniques detected. Maximum 300 characters.]**
    
    ### Enhanced Risk Guidelines for Dual Analysis
    - **Low Risk**: Minor browser differences, similar content, no evasion detected
    - **Medium Risk**: Some differences present but could be legitimate browser variations
    - **High Risk**: Clear evasion detected, different malicious vs legitimate content, sophisticated targeting
    
    Remember: The presence of browser-specific differences in phishing contexts is often a strong indicator of sophisticated evasion techniques.
    
    ## Additional Considerations
    - If uncertain, err on the side of caution and recommend verification through official channels
    - Note any sophisticated techniques that might fool casual observers
    - Mention if the site requires additional verification beyond visual analysis
    - Provide specific actionable advice when possible
    - **Remember**: The presence of some legitimate links does not automatically make a site legitimate
    """

def normalize_url(url: str) -> str:
    """
    Ensures URL has proper protocol prefix.
    """
    url = url.strip()
    
    # If it already has a protocol, return as-is
    if url.startswith(('http://', 'https://')):
        return url
    
    # Add https:// as default
    return f"https://{url}"

# Dual Browser Integration - Firefox + Chromium with user agents
USER_AGENTS_WITH_BROWSERS = {
    # Firefox-based user agents
    "firefox_windows": {
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "browser": "firefox"
    },
    "firefox_mac": {
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
        "browser": "firefox"
    },
    
    # Chromium-based user agents (authentic engine matches)
    "chrome_windows": {
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "browser": "chromium"
    },
    "chrome_mac": {
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "browser": "chromium"
    },
    "chrome_android": {
        "user_agent": "Mozilla/5.0 (Linux; Android 14; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
        "browser": "chromium"
    }
}

async def launch_browser_for_research(p, browser_type: str):
    """
    Launches the appropriate browser with research-optimized settings.
    """
    if browser_type == "firefox":
        return await p.firefox.launch(
            headless=True,
            firefox_user_prefs={
                # Disable all Safe Browsing features
                "browser.safebrowsing.enabled": False,
                "browser.safebrowsing.malware.enabled": False,
                "browser.safebrowsing.phishing.enabled": False,
                "browser.safebrowsing.blockedURIs.enabled": False,
                "browser.safebrowsing.downloads.enabled": False,
                "browser.safebrowsing.downloads.remote.enabled": False,
                
                # Disable SSL/TLS security warnings and errors
                "security.tls.insecure_fallback_hosts": "",
                "security.mixed_content.block_active_content": False,
                "security.mixed_content.block_display_content": False,
                "dom.security.https_only_mode": False,
                "security.ssl.require_safe_negotiation": False,
                "security.ssl.treat_unsafe_negotiation_as_broken": False,
                "security.warn_entering_secure": False,
                "security.warn_leaving_secure": False,
                "security.warn_submit_insecure": False,
                "security.warn_viewing_mixed": False,

                # Disable various security checks
                "browser.xul.error_pages.enabled": False,
                "network.stricttransportsecurity.preloadlist": False,
                "security.cert_pinning.enforcement_level": 0,
                "app.update.enabled": False,
                "toolkit.telemetry.enabled": False,
                "browser.sessionstore.resume_from_crash": False,
                "browser.shell.checkDefaultBrowser": False,
                "network.dns.disablePrefetch": True,
                "network.prefetch-next": False,
                "network.http.speculative-parallel-limit": 0,

                # Privacy settings that might help bypass detection
                "privacy.trackingprotection.enabled": False,
                "privacy.trackingprotection.pbmode.enabled": False,
                "privacy.trackingprotection.cryptomining.enabled": False,
                "privacy.trackingprotection.fingerprinting.enabled": False
            }
        )
    
    elif browser_type == "chromium":
        bypass_args = [
            # Disable all Safe Browsing features
            '--disable-web-security',
            '--disable-client-side-phishing-detection',
            '--disable-component-update',
            '--disable-features=SafeBrowsing',
            '--disable-features=SafeBrowsingExtendedReporting',
            '--safebrowsing-disable-download-protection',
            '--safebrowsing-disable-extension-blacklist',
            
            # Disable SSL/TLS warnings and errors
            '--ignore-certificate-errors',
            '--ignore-ssl-errors',
            '--ignore-certificate-errors-spki-list',
            '--ignore-urlfetcher-cert-requests',
            '--allow-running-insecure-content',
            '--disable-certificate-transparency',
            '--disable-cert-verification-for-testing',
            '--reduce-security-for-testing',

            # Disabled various security checks
            '--disable-background-networking',
            '--disable-domain-reliability',
            '--disable-features=NetworkPrediction',
            '--disable-features=Prerender',
            '--disable-background-timer-throttling',
            '--network-service-logging-enabled',
            '--disable-popup-blocking',
            '--disable-prompt-on-repost',
            '--no-first-run',
            '--no-default-browser-check',
            '--disable-hang-monitor',
            '--no-sandbox',
            '--disable-setuid-sandbox',
            '--disable-dev-shm-usage',
            '--disable-gpu',
            '--disable-blink-features=AutomationControlled',
            '--exclude-switches=enable-automation',

             # Privacy settings that might help bypass detection
            '--disable-features=PrivacySandboxSettings4',
            '--disable-features=TrustTokens',
            '--disable-features=InterestFeedContentSuggestions',
            '--disable-features=FingerprintingClientRectsNoiseProtection',
            '--disable-features=PrivacySandboxAdsAPIsOverride',
            '--disable-features=EnforceDeprecationPolicyForCookies',

            # Performance and Resource
            '--metrics-recording-only',
            '--no-crash-upload',
            '--no-pings'
        ]
        return await p.chromium.launch(headless=True, args=bypass_args)
    
    else:
        raise ValueError(f"Unsupported browser type: {browser_type}")

async def create_browser_context(browser, browser_type: str, user_agent: str, is_mobile: bool = False):
    """
    Creates appropriate context for the browser type.
    """
    viewport = {"width": 375, "height": 667} if is_mobile else {"width": 1280, "height": 720}
    
    context_options = {
        'user_agent': user_agent,
        'ignore_https_errors': True,
        'bypass_csp': True,
        'viewport': viewport
    }
    
    if browser_type == "chromium":
        context_options['extra_http_headers'] = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
    
    return await browser.new_context(**context_options)

async def handle_security_warnings(page, browser_type: str):
    """
    Handle security warnings for both Firefox and Chromium.
    """
    try:
        await page.wait_for_timeout(2000)
        
        if browser_type == "firefox":
            selectors_to_try = [
                'button:has-text("Advanced")', 
                'button[id*="advancedButton"]',
                'button:has-text("Accept the Risk and Continue")',
                'a:has-text("Continue")',
                'a[id*="proceed"]'
            ]
        elif browser_type == "chromium":
            selectors_to_try = [
                '#proceed-button',
                '#details-button',
                'button:has-text("Advanced")',
                'a:has-text("Proceed")',
                '.small-link'
            ]
        
        for selector in selectors_to_try:
            try:
                element = await page.wait_for_selector(selector, timeout=1000)
                if element and await element.is_visible():
                    print(f"Found {browser_type} security warning: {selector}")
                    await element.click()
                    await page.wait_for_timeout(2000)
                    
                    if "advanced" in selector.lower() or "details" in selector.lower():
                        proceed_selectors = ['a:has-text("Proceed")', 'a:has-text("Continue")', '.small-link']
                        for proceed_selector in proceed_selectors:
                            try:
                                proceed_element = await page.wait_for_selector(proceed_selector, timeout=2000)
                                if proceed_element and await proceed_element.is_visible():
                                    await proceed_element.click()
                                    await page.wait_for_timeout(2000)
                                    break
                            except:
                                continue
                    break
            except:
                continue
                
    except Exception as e:
        print(f"{browser_type} warning bypass completed: {e}")

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

async def take_screenshot_with_browser(url: str, browser_type: str, user_agent: str) -> dict:
    """
    Takes screenshot using specified browser type with proper configuration.
    """
    print(f"Taking screenshot with {browser_type}: {user_agent[:50]}...")
    
    async with async_playwright() as p:
        browser = await launch_browser_for_research(p, browser_type)
        
        try:
            is_mobile = "android" in user_agent.lower() or "mobile" in user_agent.lower()
            context = await create_browser_context(browser, browser_type, user_agent, is_mobile)
            page = await context.new_page()
            
            # Navigate
            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=45000)
            except Exception as nav_error:
                print(f"Navigation error: {nav_error}")
                await page.goto(url, wait_until="commit", timeout=30000)
            
            # Handle security warnings
            await handle_security_warnings(page, browser_type)
            
            # Wait for content
            await page.wait_for_timeout(3000)
            
            # Extract data
            page_title = await page.title()
            final_url = page.url
            dom_data = await extract_basic_dom_data(page)
            screenshot_bytes = await page.screenshot(full_page=True, type='png')
            
            print(f"✅ {browser_type}: '{page_title[:30]}...', {len(dom_data['links'])} links, {len(dom_data['forms'])} forms")
            
            result = {
                "screenshot": screenshot_bytes,
                "links": dom_data["links"],
                "forms": dom_data["forms"],
                "html": dom_data["html"],
                "title": page_title,
                "final_url": final_url,
                "browser_type": browser_type,
                "user_agent": user_agent
            }
            
            await context.close()
            return result
            
        finally:
            await browser.close()

async def analyze_with_dual_browsers(url: str, test_user_agents: list = None) -> dict:
    """
    Analyzes URL with multiple user agents across Firefox and Chromium.
    """
    if test_user_agents is None:
        # Use the default list from the configuration section
        test_user_agents = DEFAULT_USER_AGENTS
    
    print(f"🔍 Starting dual-browser analysis for: {url}")
    print(f"Testing {len(test_user_agents)} user agents across Firefox and Chromium")
    print("-" * 60)
    
    results = {}
    
    for ua_key in test_user_agents:
        if ua_key not in USER_AGENTS_WITH_BROWSERS:
            print(f"Warning: Unknown user agent key '{ua_key}', skipping...")
            continue
        
        ua_config = USER_AGENTS_WITH_BROWSERS[ua_key]
        user_agent = ua_config["user_agent"]
        browser_type = ua_config["browser"]
        
        try:
            result = await take_screenshot_with_browser(url, browser_type, user_agent)
            results[ua_key] = result
            
        except Exception as e:
            print(f"❌ {ua_key} ({browser_type}) failed: {e}")
            results[ua_key] = {
                "error": str(e), 
                "user_agent": user_agent, 
                "browser_type": browser_type
            }
    
    return results

# Smart Hybrid Analysis Functions

def calculate_score(result: dict) -> int:
    """
    Calculates the content richness score for a result.
    """
    return (
        len(result.get("html", "")) + 
        len(result.get("links", [])) * 100 + 
        len(result.get("forms", [])) * 200
    )

def get_top_2_results(browser_results: dict) -> list:
    """
    Gets the top 2 results by score.
    Returns list of (ua_key, result_data) tuples.
    """
    successful_results = {k: v for k, v in browser_results.items() if "error" not in v}
    
    if len(successful_results) < 2:
        return [(k, v) for k, v in successful_results.items()][:1]  # Return top 1 if only 1 success
    
    # Score and sort results
    scored_results = []
    for ua_key, result in successful_results.items():
        score = calculate_score(result)
        scored_results.append((ua_key, result, score))
    
    # Sort by score (highest first) and return top 2
    scored_results.sort(key=lambda x: x[2], reverse=True)
    return [(ua_key, result) for ua_key, result, score in scored_results[:2]]

def should_use_dual_analysis(browser_results: dict) -> tuple:
    """
    Determines if dual analysis is worth the extra cost.
    Returns (should_use_dual: bool, reason: str).
    """
    top_2 = get_top_2_results(browser_results)
    
    if len(top_2) < 2:
        return False, "Only one successful result available"
    
    result1_ua, result1_data = top_2[0]
    result2_ua, result2_data = top_2[1]
    
    # Check for significant differences
    reasons = []
    
    # 1. Different final URLs (redirects)
    url1 = result1_data.get("final_url", "").strip()
    url2 = result2_data.get("final_url", "").strip()
    if url1 != url2:
        reasons.append(f"Different final URLs: {url1} vs {url2}")
    
    # 2. Different page titles
    title1 = result1_data.get("title", "").strip()
    title2 = result2_data.get("title", "").strip()
    if title1 != title2:
        reasons.append(f"Different page titles: '{title1[:30]}...' vs '{title2[:30]}...'")
    
    # 3. Significant difference in content richness
    score1 = calculate_score(result1_data)
    score2 = calculate_score(result2_data)
    if score1 > 0:  # Avoid division by zero
        score_diff_percent = abs(score1 - score2) / score1
        if score_diff_percent > 0.25: 
            reasons.append(f"Significant content difference: {score1} vs {score2} ({score_diff_percent:.1%} gap)")
    
    # 4. Different browser engines
    browser1 = result1_data.get("browser_type")
    browser2 = result2_data.get("browser_type")
    if browser1 != browser2:
        reasons.append(f"Different browser engines: {browser1} vs {browser2}")
    
    # 5. Significant difference in link/form counts 
    links_diff = abs(len(result1_data.get("links", [])) - len(result2_data.get("links", [])))
    forms_diff = abs(len(result1_data.get("forms", [])) - len(result2_data.get("forms", [])))
    if links_diff > 4 or forms_diff > 1: 
        reasons.append(f"Content structure differs: {links_diff} link difference, {forms_diff} form difference")
    
    if reasons:
        reason_text = "; ".join(reasons)
        return True, reason_text
    else:
        return False, "No significant differences detected"

def get_dual_analysis_prompt() -> str:
    """
    Returns the centrally-configured prompt for comparative dual analysis.
    """
    return PROMPT_DUAL_ANALYSIS

def identify_with_gemini_dual(screenshot1_bytes: bytes, screenshot2_bytes: bytes, webpage_url: str, data1: dict, data2: dict, prompt_text: str) -> str:
    """
    Sends two screenshots and datasets to Gemini for comparative analysis.
    """
    print(f"Sending dual analysis (2 screenshots + data) to Gemini API for '{webpage_url}'")
    try:
        base64_image1 = base64.b64encode(screenshot1_bytes).decode('utf-8')
        base64_image2 = base64.b64encode(screenshot2_bytes).decode('utf-8')
        headers = {'Content-Type': 'application/json'}

        # Create comparative technical summary
        technical_summary = f"""

## DUAL BROWSER TECHNICAL COMPARISON
**ANALYSIS TYPE**: Comparative analysis of the same URL from two different browser/user-agent combinations.

### Browser 1 Analysis: {data1.get('user_agent', 'Unknown')}
**Final URL**: {data1.get('final_url', 'Unknown')}
**Page Title**: {data1.get('title', 'Unknown')}
**Links Found**: {len(data1.get('links', []))} - {json.dumps(data1.get('links', [])[:15])}
**Forms Found**: {len(data1.get('forms', []))} - {json.dumps(data1.get('forms', []))}
**HTML Length**: {len(data1.get('html', ''))} characters

### Browser 2 Analysis: {data2.get('user_agent', 'Unknown')}
**Final URL**: {data2.get('final_url', 'Unknown')}
**Page Title**: {data2.get('title', 'Unknown')}
**Links Found**: {len(data2.get('links', []))} - {json.dumps(data2.get('links', [])[:15])}
**Forms Found**: {len(data2.get('forms', []))} - {json.dumps(data2.get('forms', []))}
**HTML Length**: {len(data2.get('html', ''))} characters

### Critical Comparison Points:
- **URL Consistency**: Do both browsers end up at the same final URL?
- **Content Consistency**: Are the links, forms, and content similar?
- **Visual Consistency**: Do the screenshots show the same page layout and content?
- **Suspicious Patterns**: Any evidence of browser-specific targeting or evasion?

### Analysis Instructions:
1. **Compare screenshots side-by-side** for visual differences
2. **Cross-reference technical data** with visual content
3. **Identify any evasion techniques** or browser discrimination
4. **Determine which result (if any) represents the genuine threat**
5. **Assess the sophistication** of any detected evasion methods

**REMEMBER**: Sophisticated phishing often uses browser fingerprinting to serve different content to different browsers, security tools, or user agents.
"""

        # Combine the base prompt with technical summary
        full_prompt_for_ai = f"{prompt_text}{technical_summary}"

        payload = {
            "contents": [
                {
                    "role": "user",
                    "parts": [
                        {"inlineData": {"mimeType": "image/png", "data": base64_image1}},
                        {"inlineData": {"mimeType": "image/png", "data": base64_image2}},
                        {"text": full_prompt_for_ai},
                    ]
                }
            ]
        }

        response = requests.post(GEMINI_API_URL, headers=headers, data=json.dumps(payload))
        response.raise_for_status()
        result = response.json()

        # Extract text response (same logic as single analysis)
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

        return "Could not get a clear dual analysis from the AI."

    except requests.exceptions.RequestException as e:
        print(f"Error during dual AI analysis: {e}")
        return f"Dual AI analysis failed: {e}"
    except Exception as e:
        print(f"Unexpected error in dual analysis: {e}")
        return f"Dual analysis error: {e}"

async def analyze_with_smart_dual_ai(target_url: str, browser_results: dict, debug_mode: bool = False) -> str:
    """
    Smart analysis that uses dual AI analysis only when significant differences are detected.
    """

    # Check if dual analysis is needed
    use_dual, reason = should_use_dual_analysis(browser_results)
    
    if use_dual:
        print(f"🔍 Using DUAL AI analysis - Reason: {reason}")
        return await analyze_with_dual_ai(target_url, browser_results, debug_mode)
    else:
        print(f"✅ Using SINGLE AI analysis - {reason}")
        return await analyze_with_single_ai(target_url, browser_results, debug_mode)

async def analyze_with_dual_ai(target_url: str, browser_results: dict, debug_mode: bool = False) -> str:
    """
    Performs dual AI analysis comparing top 2 results.
    """
    top_2 = get_top_2_results(browser_results)
    
    if len(top_2) < 2:
        print("⚠️ Insufficient results for dual analysis, falling back to single")
        return await analyze_with_single_ai(target_url, browser_results, debug_mode)
    
    result1_ua, result1_data = top_2[0]
    result2_ua, result2_data = top_2[1]
    
    print(f"📊 Dual analysis: {result1_ua} vs {result2_ua}")
    
    # Prepare data for dual analysis
    data1 = {
        "user_agent": result1_ua,
        "final_url": result1_data.get("final_url"),
        "title": result1_data.get("title"),
        "links": result1_data.get("links", []),
        "forms": result1_data.get("forms", []),
        "html": result1_data.get("html", "")
    }
    
    data2 = {
        "user_agent": result2_ua,
        "final_url": result2_data.get("final_url"),
        "title": result2_data.get("title"),
        "links": result2_data.get("links", []),
        "forms": result2_data.get("forms", []),
        "html": result2_data.get("html", "")
    }
    
    # Run dual AI analysis
    ai_identification = await asyncio.to_thread(
        identify_with_gemini_dual,
        result1_data["screenshot"],
        result2_data["screenshot"],
        target_url,
        data1,
        data2,
        get_dual_analysis_prompt()
    )
    
    # Build response based on debug mode
    if debug_mode:
        # Include full technical details
        final_report = f"""
{ai_identification}

{"="*60}
SMART DUAL BROWSER ANALYSIS SUMMARY
{"="*60}
🔍 DUAL ANALYSIS TRIGGERED - Significant differences detected:

🥇 Primary Result: {result1_ua} ({result1_data.get('browser_type', 'unknown')})
   • Title: '{result1_data.get('title', 'Unknown')[:50]}...'
   • Final URL: {result1_data.get('final_url', 'Unknown')}
   • Content: {len(result1_data.get('links', []))} links, {len(result1_data.get('forms', []))} forms

🥈 Secondary Result: {result2_ua} ({result2_data.get('browser_type', 'unknown')})
   • Title: '{result2_data.get('title', 'Unknown')[:50]}...'
   • Final URL: {result2_data.get('final_url', 'Unknown')}
   • Content: {len(result2_data.get('links', []))} links, {len(result2_data.get('forms', []))} forms

📋 All Browser Results:
"""
        
        for ua_key, result in browser_results.items():
            if "error" in result:
                final_report += f"❌ {ua_key} ({result.get('browser_type', 'unknown')}): {result['error']}\n"
            else:
                browser_type = result.get('browser_type', 'unknown')
                final_report += f"✅ {ua_key} ({browser_type}): '{result.get('title', '')[:30]}...', {len(result.get('links', []))} links, {len(result.get('forms', []))} forms\n"
        
        final_report += f"\n⚠️ Dual analysis used due to significant browser differences."
    else:
        # Return only the AI analysis without technical details
        final_report = ai_identification
    
    return final_report

async def analyze_with_single_ai(target_url: str, browser_results: dict, debug_mode: bool = False) -> str:    
    """
    Standard single AI analysis using the best result.
    """
    best_result = select_best_result(browser_results)
    
    if not best_result:
        return "❌ All browser tests failed - site may be blocking automated access or is unreachable."
    
    best_ua, best_data = best_result
    print(f"📊 Single analysis using: {best_ua} ({best_data.get('browser_type', 'unknown')})")
    
    # Run single AI analysis (existing logic)
    ai_identification = await asyncio.to_thread(
        identify_with_gemini,
        best_data["screenshot"],
        target_url,
        {
            "links": best_data["links"],
            "forms": best_data["forms"], 
            "html": best_data["html"]
        },
        get_single_analysis_prompt(browser_results)
    )
    
    # Build response based on debug mode
    if debug_mode:
        # Include technical details
        final_report = f"""
{ai_identification}

{"="*60}
SINGLE BROWSER ANALYSIS SUMMARY
{"="*60}
✅ SINGLE ANALYSIS USED - No significant differences detected between browsers.

📊 Analysis based on: {best_ua} ({best_data.get('browser_type', 'unknown')})
   • Title: '{best_data.get('title', 'Unknown')[:50]}...'
   • Final URL: {best_data.get('final_url', 'Unknown')}
   • Content: {len(best_data.get('links', []))} links, {len(best_data.get('forms', []))} forms

📋 All Browser Results:
"""
        
        for ua_key, result in browser_results.items():
            if "error" in result:
                final_report += f"❌ {ua_key} ({result.get('browser_type', 'unknown')}): {result['error']}\n"
            else:
                browser_type = result.get('browser_type', 'unknown')
                final_report += f"✅ {ua_key} ({browser_type}): '{result.get('title', '')[:30]}...', {len(result.get('links', []))} links, {len(result.get('forms', []))} forms\n"
    else:
        # Return only the AI analysis without technical details
        final_report = ai_identification
    
    return final_report

def select_best_result(browser_results: dict) -> tuple:
    """
    Selects the best result from browser tests.
    """
    successful_results = {k: v for k, v in browser_results.items() if "error" not in v}
    
    if not successful_results:
        return None
    
    # Score results (prefer more content)
    best_score = 0
    best_result = None
    
    for ua_key, result in successful_results.items():
        score = calculate_score(result)
        
        if score > best_score:
            best_score = score
            best_result = (ua_key, result)
    
    return best_result

def get_single_analysis_prompt(browser_results: dict) -> str:
    """
    Returns the centrally-configured prompt for single analysis.
    """
    return PROMPT_SINGLE_ANALYSIS
    

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
        # Priority order: head > forms > iframes > body content
        head_match = re.search(r'<head.*?</head>', html_content, re.DOTALL | re.IGNORECASE)
        
        # Find forms (high priority for phishing detection)
        forms = list(re.finditer(r'<form.*?</form>', html_content, re.DOTALL | re.IGNORECASE))
        
        # Find iframes (also high priority for deception)
        iframes = list(re.finditer(r'<iframe.*?</iframe>', html_content, re.DOTALL | re.IGNORECASE))
        
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
        
        # Include all iframes if they fit
        for iframe_match in iframes:
            iframe_content = iframe_match.group(0)
            if len(iframe_content) <= remaining_length:
                preserved_content += iframe_content + "\n"
                remaining_length -= len(iframe_content)
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
        
        html_content = preserved_content + "\n[... HTML truncated - head, forms, and iframes preserved for security analysis ...]"
    
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

# Updated main analysis function with smart hybrid approach
async def analyze_url_for_phishing(target_url: str, debug_mode: bool = False) -> str:
    """
    Main function for phishing analysis - now uses smart hybrid dual browser approach.
    This maintains compatibility with the Telegram bot.
    """
    # Normalize the URL to ensure it has a protocol
    target_url = normalize_url(target_url)
    
    async def analysis_logic():
        print(f"🔍 Starting smart hybrid dual-browser phishing analysis for: {target_url}")
        if debug_mode:
            print("🔍 Debug mode enabled - will include technical browser details")
        print("-" * 80)
        
        # Test with multiple browsers and user agents
        browser_results = await analyze_with_dual_browsers(target_url)
        
        # Smart hybrid analysis decision with debug mode
        return await analyze_with_smart_dual_ai(target_url, browser_results, debug_mode)

    try:
        # Use the timeout from the configuration section
        return await asyncio.wait_for(analysis_logic(), timeout=AI_ANALYSIS_TIMEOUT)
    except asyncio.CancelledError:
        print(f"AI analysis for {target_url} was cancelled.")
        raise
    except asyncio.TimeoutError:
        print(f"AI analysis for {target_url} timed out after {AI_ANALYSIS_TIMEOUT} seconds.")
        return "[TIMED OUT] Smart hybrid analysis timed out. This can happen with complex websites or dual analysis."
    except Exception as e:
        print(f"\nSmart hybrid analysis failed with error: {e}")
        return f"[ERROR] Smart hybrid analysis failed: {e}"

# --- Main Execution (only runs when script is executed directly) ---
if __name__ == "__main__":
    # Example usage when run as a standalone script
    target_url = input("Enter URL: ")
    
    try:
        print("Using smart hybrid dual browser analysis...")
        analysis_result = asyncio.run(analyze_url_for_phishing(target_url))
        
        print("\n" + "="*80)
        print("ANALYSIS RESULTS")
        print("="*80)
        print(analysis_result)
        
    except Exception as e:
        print(f"Script execution terminated due to an error: {e}")