import base64
import requests
import json
import os # Still needed for potential error handling/debugging, but no file ops for screenshot
from playwright.sync_api import sync_playwright

# --- Configuration ---
API_KEY = os.environ.get("GEMINI_APIKEY")
GEMINI_MODEL = "gemini-2.5-flash-preview-05-20" # Model for image understanding
GEMINI_API_URL = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent?key={API_KEY}"

def take_screenshot_firefox_enhanced(url: str) -> bytes:
    """
    Takes a full-page screenshot using Firefox with enhanced Safe Browsing bypass.
    Includes warning page detection and bypass attempts.
    """
    print(f"Taking screenshot with Firefox (enhanced): {url}")  
    try:
        with sync_playwright() as p:
            browser = p.firefox.launch(
                headless=True,
                firefox_user_prefs={
                    # Disable all Safe Browsing features
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
            
            context = browser.new_context(
                ignore_https_errors=True,
                bypass_csp=True,
                accept_downloads=False,
                java_script_enabled=True,  # Keep JS enabled to handle any dynamic content
                viewport={"width": 1280, "height": 720}
            )
            
            page = context.new_page()
            
            # Set additional headers to look more like a regular browser
            page.set_extra_http_headers({
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'DNT': '1',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            })
            
            # Navigate to the URL
            try:
                page.goto(url, wait_until="domcontentloaded", timeout=60000)
            except Exception as nav_error:
                print(f"Navigation error: {nav_error}")
                # Try with a simpler wait condition
                page.goto(url, wait_until="commit", timeout=30000)
            
            # Wait for page to load
            page.wait_for_timeout(3000)
            
            # Check for Firefox-specific warning pages and bypass them
            try:
                page_content = page.content().lower()
                page_text = page.text_content('body').lower() if page.locator('body').count() > 0 else ""
                
                # Firefox warning indicators
                firefox_warnings = [
                    'deceptive site ahead',
                    'reported attack page',
                    'this connection is not secure',
                    'warning: potential security risk ahead',
                    'mozilla firefox has blocked this page',
                    'this site has been reported as unsafe'
                ]
                
                if any(warning in page_text or warning in page_content for warning in firefox_warnings):
                    print("Firefox security warning detected, attempting bypass...")
                    
                    # Try to find and click bypass buttons
                    bypass_selectors = [
                        'button:has-text("Advanced")',
                        'button[id*="advancedButton"]',
                        'button[id*="exceptionDialogButton"]',
                        'button:has-text("Accept the Risk and Continue")',
                        'button:has-text("Continue to site")',
                        'a:has-text("Continue")',
                        'a[id*="proceed"]',
                        'button[id*="proceed"]'
                    ]
                    
                    for selector in bypass_selectors:
                        try:
                            element = page.wait_for_selector(selector, timeout=2000)
                            if element and element.is_visible():
                                print(f"Found bypass element: {selector}")
                                element.click()
                                page.wait_for_timeout(2000)
                                break
                        except:
                            continue
                    
                    # Additional wait after bypass attempt
                    page.wait_for_timeout(3000)
                
            except Exception as warning_error:
                print(f"Warning bypass error (continuing): {warning_error}")
            
            # Take the screenshot (PNG doesn't support quality parameter)
            screenshot_bytes = page.screenshot(
                full_page=True,
                type='png'
            )
            print("Screenshot taken successfully with Firefox.")
            
            context.close()
            browser.close()
            
            return screenshot_bytes
            
    except Exception as e:
        print(f"Firefox screenshot failed: {e}")
        raise

def identify_image_with_gemini_from_bytes(image_bytes: bytes, webpage_url: str, prompt_text: str) -> str:
    """
    Sends image bytes and the target URL to the Gemini API for identification/description.
    """
    print(f"Sending image (bytes) and URL '{webpage_url}' to Gemini API")
    try:
        # Encode the image bytes to base64
        base64_image = base64.b64encode(image_bytes).decode('utf-8')

        headers = {
            'Content-Type': 'application/json',
        }

        # Combine the base prompt text with the URL for the AI to analyze
        full_prompt_for_ai = f"{prompt_text}\n\nAdditionally, consider the URL of this website: {webpage_url}. Does this URL itself (e.g., domain name, subdomains) suggest typo-squatting, brand impersonation, or any other attempt to masquerade as a legitimate site? Provide analysis on both the visual content and the URL."

        payload = {
            "contents": [
                {
                    "role": "user",
                    "parts": [
                        {
                            "inlineData": {
                                "mimeType": "image/png",
                                "data": base64_image
                            }
                        },
                        {
                            "text": full_prompt_for_ai
                        }
                    ]
                }
            ]
        }

        # Make the API request
        response = requests.post(GEMINI_API_URL, headers=headers, data=json.dumps(payload))
        response.raise_for_status()

        result = response.json()

        # Extract the text from the response
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

def take_screenshot_with_fallback(url: str) -> bytes:
    """
    Primary function that tries Firefox with fallback options.
    """
    try:
        return take_screenshot_firefox_enhanced(url)
    except Exception as e:
        print(f"Primary Firefox method failed: {e}")
        
        # Fallback: Try Firefox with minimal configuration and enhanced SSL bypass
        print("Trying Firefox with minimal configuration...")
        try:
            with sync_playwright() as p:
                browser = p.firefox.launch(
                    headless=True,
                    firefox_user_prefs={
                        # Disable Safe Browsing
                        "browser.safebrowsing.enabled": False,
                        "browser.safebrowsing.malware.enabled": False,
                        "browser.safebrowsing.phishing.enabled": False,
                        
                        # Enhanced SSL/Certificate bypass
                        "security.ssl.require_safe_negotiation": False,
                        "security.ssl.treat_unsafe_negotiation_as_broken": False,
                        "security.ssl3.rsa_des_ede3_sha": True,
                        "security.tls.hello_downgrade_check": False,
                        "security.warn_entering_secure": False,
                        "security.warn_entering_weak": False,
                        "security.warn_leaving_secure": False,
                        "security.warn_submit_insecure": False,
                        "security.warn_viewing_mixed": False,
                        "dom.security.https_only_mode": False,
                        "security.mixed_content.block_active_content": False,
                        "security.mixed_content.block_display_content": False,
                        
                        # Certificate handling
                        "security.default_personal_cert": "Ask Every Time",
                        "security.ssl.errorReporting.enabled": False,
                        "security.ssl.errorReporting.automatic": False,
                        
                        # Additional network settings
                        "network.stricttransportsecurity.preloadlist": False,
                        "security.cert_pinning.enforcement_level": 0,
                    }
                )
                
                context = browser.new_context(ignore_https_errors=True)
                page = context.new_page()
                page.set_viewport_size({"width": 1280, "height": 720})
                
                # Try with longer timeout and different wait strategy
                page.goto(url, wait_until="commit", timeout=90000)
                page.wait_for_timeout(5000)
                
                screenshot_bytes = page.screenshot(full_page=True)
                context.close()
                browser.close()
                
                print("Fallback Firefox method succeeded.")
                return screenshot_bytes
                
        except Exception as fallback_error:
            print(f"Firefox fallback method also failed: {fallback_error}")
            
            # Try HTTP instead of HTTPS if URL was HTTPS
            if url.startswith('https://'):
                http_url = url.replace('https://', 'http://')
                print(f"Trying HTTP version: {http_url}")
                try:
                    with sync_playwright() as p:
                        browser = p.firefox.launch(
                            headless=True,
                            firefox_user_prefs={
                                "browser.safebrowsing.enabled": False,
                                "browser.safebrowsing.malware.enabled": False,
                                "browser.safebrowsing.phishing.enabled": False,
                                "dom.security.https_only_mode": False,
                            }
                        )
                        
                        page = browser.new_page()
                        page.set_viewport_size({"width": 1280, "height": 720})
                        page.goto(http_url, timeout=60000)
                        page.wait_for_timeout(3000)
                        
                        screenshot_bytes = page.screenshot(full_page=True)
                        browser.close()
                        
                        print("HTTP fallback method succeeded.")
                        return screenshot_bytes
                        
                except Exception as http_error:
                    print(f"HTTP fallback also failed: {http_error}")
            
            # Final fallback: Try Chromium with aggressive bypass
            print("Trying Chromium as final fallback...")
            try:
                with sync_playwright() as p:
                    browser = p.chromium.launch(
                        headless=True,
                        args=[
                            '--disable-web-security',
                            '--disable-features=VizDisplayCompositor',
                            '--disable-extensions',
                            '--no-sandbox',
                            '--disable-setuid-sandbox',
                            '--disable-dev-shm-usage',
                            '--disable-gpu',
                            '--ignore-certificate-errors',
                            '--ignore-ssl-errors',
                            '--ignore-certificate-errors-spki-list',
                            '--ignore-certificate-errors-spki-list',
                            '--allow-running-insecure-content',
                            '--disable-client-side-phishing-detection',
                            '--disable-component-update',
                            '--disable-default-apps',
                            '--disable-domain-reliability',
                            '--disable-features=AudioServiceOutOfProcess',
                            '--disable-hang-monitor',
                            '--disable-ipc-flooding-protection',
                            '--disable-popup-blocking',
                            '--disable-prompt-on-repost',
                            '--disable-renderer-backgrounding',
                            '--disable-sync',
                            '--force-color-profile=srgb',
                            '--metrics-recording-only',
                            '--no-crash-upload',
                            '--no-default-browser-check',
                            '--no-first-run',
                            '--no-pings',
                            '--password-store=basic',
                            '--use-mock-keychain',
                            '--disable-background-networking',
                            '--disable-background-timer-throttling',
                            '--disable-backgrounding-occluded-windows',
                            '--disable-breakpad',
                            '--disable-component-extensions-with-background-pages',
                            '--disable-features=TranslateUI',
                            '--disable-field-trial-config',
                            '--disable-back-forward-cache'
                        ]
                    )
                    
                    context = browser.new_context(
                        ignore_https_errors=True,
                        bypass_csp=True
                    )
                    
                    page = context.new_page()
                    page.set_viewport_size({"width": 1280, "height": 720})
                    page.goto(url, wait_until="commit", timeout=90000)
                    page.wait_for_timeout(3000)
                    
                    screenshot_bytes = page.screenshot(full_page=True)
                    context.close()
                    browser.close()
                    
                    print("Chromium fallback method succeeded.")
                    return screenshot_bytes
                    
            except Exception as chromium_error:
                print(f"Chromium fallback also failed: {chromium_error}")
                raise Exception(f"All methods failed. Firefox: {fallback_error}, Chromium: {chromium_error}")

# --- Main Execution ---
if __name__ == "__main__":
    # Example usage
    target_url = "https://googlno.com/"  # Your example URL
    
    # Comprehensive phishing detection prompt
    identification_prompt_base = """
    Analyze this webpage screenshot for any visual or textual indicators of a potential phishing or scam website.
    Specifically, consider the following:
    
    1. **Branding Consistency:** Are logos, color schemes, and fonts consistent with known legitimate brands visible on the page? Look for misspellings, low-quality graphics, or subtle inconsistencies.
    
    2. **Design Quality:** Does the overall design look professional, or does it appear hastily assembled with poor alignment, mixed fonts, or pixelated images?
    
    3. **Textual Content:** Are there any grammatical errors, unusual phrasing, or urgent/threatening language on the page commonly used in phishing attempts? Identify any requests for sensitive personal information (e.g., logins, credit cards, SSN).
    
    4. **Interactive Elements:** Describe any forms, buttons, or links visible on the page. What information do they solicit, and do they appear authentic?
    
    5. **Sense of Urgency/Threat/Unrealistic Offers:** Does the content on the page convey undue urgency, threats (e.g., account suspension), or offers that seem too good to be true?
    
    6. **Content Specificity:** Is the visible content generic, or is it highly specific to a legitimate service or transaction?
    
    7. **Security Indicators:** Based on the visual appearance, can you identify any obvious signs that this might be a fraudulent website attempting to mimic a legitimate service?
    
    Please provide a detailed analysis. 
    
    Conclude with a risk assessment (Low/Medium/High risk of being a phishing/scam site) and a one sentence explanation of the reasoning behind this assessment with the below format:
    RISK ASSESSMENT: [Low/Medium/High] - [Reasoning for assessment]
    """
    
    print("Starting Firefox-based phishing detection process...")
    print(f"Target URL: {target_url}")
    print("-" * 60)
    
    try:
        # Take screenshot using Firefox with enhanced bypass
        print("Step 1: Taking screenshot...")
        screenshot_data = take_screenshot_with_fallback(target_url)
        print(f"Screenshot captured successfully. Size: {len(screenshot_data)} bytes")
        
        # Send to Gemini for analysis
        print("\nStep 2: Analyzing with Gemini AI...")
        ai_identification = identify_image_with_gemini_from_bytes(
            screenshot_data,
            target_url,
            identification_prompt_base
        )
        
        print("\n" + "="*60)
        print("PHISHING DETECTION ANALYSIS RESULTS")
        print("="*60)
        print(f"URL: {target_url}")
        print("-" * 60)
        print(ai_identification)
        print("="*60)
        
        # Optional: Save screenshot for manual inspection
        # with open(f"screenshot_{int(time.time())}.png", "wb") as f:
        #     f.write(screenshot_data)
        # print(f"\nScreenshot saved as screenshot_{int(time.time())}.png")
        
    except Exception as e:
        print(f"\nProcess failed with error: {e}")
        print("\nTroubleshooting suggestions:")
        print("1. Ensure Firefox is installed and accessible to Playwright")
        print("2. Try running: playwright install firefox")
        print("3. Check if the URL is accessible from your network")
        print("4. Verify your Gemini API key is correctly set")
        print("5. Try with a different URL to test the setup")