# Phishing Detection Tool with AI

> Disclaimer: A mixture of Claude and Gemini helped optimised the code

A Python script that captures screenshots of potentially malicious websites and analyzes them using Google's Gemini AI to detect phishing attempts and scam indicators.

## Features

- **Multi-browser Support**: Primary Firefox implementation with Chromium fallback
- **Security Bypass**: Comprehensive Safe Browsing and SSL certificate bypass for research purposes
- **AI Analysis**: Uses Google Gemini 2.5 Flash to analyze screenshots for phishing indicators
- **Robust Fallback**: Multiple strategies including HTTP fallback and different browser configurations
- **Research-focused**: Designed specifically for cybersecurity research and phishing detection
- **In-Memory Processing**: All image handling is memory-based, ensuring no temporary files are saved.

## Prerequisites

```bash
pip install playwright requests
playwright install firefox
playwright install chromium 
```

## Setup

1. Install Python 3.8 or newer
2. Get a Google Gemini API key from [Google AI Studio](https://makersuite.google.com/app/apikey)
3. Replace `<api key>` in the script with your actual API key
4. Install required dependencies

## Usage

Obtain a key from Googel AI Studio or Vertex AI, and set it as an environment variable.

```bash
export GEMINI_APIKEY="YOUR_API_KEY"
```


```python
# Modify the target_url in the script
target_url = "https://suspicious-site.com"

# Run the script
python ai_image_phishing_detector.py
```

## How It Works

1. **Screenshot Capture**: Uses Firefox (with fallbacks) to capture full-page screenshots while bypassing security warnings
2. **AI Analysis**: Sends screenshot and URL to Gemini AI for comprehensive analysis
3. **Detection**: Analyzes for:
   - Brand impersonation and logo inconsistencies
   - Poor design quality and rushed layouts
   - Grammatical errors and suspicious language
   - Urgency tactics and unrealistic offers
   - Form fields requesting sensitive information
   - URL typo-squatting patterns

## Fallback Strategy

1. **Primary**: Firefox with comprehensive security bypass
2. **Secondary**: Firefox with minimal configuration
3. **Tertiary**: HTTP version (if HTTPS fails)
4. **Final**: Chromium with aggressive bypass arguments

## Output

The script provides:
- Detailed AI analysis of potential phishing indicators
- Risk assessment (Low/Medium/High)
- URL analysis for typo-squatting
- Visual content analysis

## Troubleshooting

- **SSL Errors**: Script includes comprehensive SSL bypass - try different networks if issues persist
- **Browser Issues**: Ensure Firefox is installed: `playwright install firefox`
- **API Errors**: Verify your Gemini API key is valid and has sufficient quota
- **Timeout Issues**: Check network connectivity and try with different URLs
- **Playwright Host Dependencies (Linux)**: Missing system libraries (e.g., `libgtk-4.so.1`) require installation via your OS package manager (e.g., sudo apt-get install <package>)
- **Installation Challenge**: If playwright install alone fails along with the dependencies, I had success running `npm init playwright@latest` first, then `playwright install`

## Roadmap utilising Playwright

- [X] Extract and De-obfuscate JavaScript Files
- [X] Network Request Interception (Catching the API endpoints!)
- [ ] Iframe and Cloaking Unwrapping
- [ ] Bypassing Cloudflare / Captcha walls

## License

This tool is provided for educational and research purposes. Use responsibly and in accordance with applicable laws and regulations.


> Example response:
```
Enter URL: http://ghpert8njt.dh056139.top/
Using smart hybrid dual browser analysis...
🔍 Starting smart hybrid dual-browser phishing analysis for: http://ghpert8njt.dh056139.top/
🔍 Debug mode enabled - will include technical browser details
--------------------------------------------------------------------------------
🔍 Starting dual-browser analysis for: http://ghpert8njt.dh056139.top/
Testing 4 user agents concurrently across shared engines
------------------------------------------------------------
Taking screenshot with firefox: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0...
Taking screenshot with chromium: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWeb...
Taking screenshot with chromium: Mozilla/5.0 (Linux; Android 14; SM-G998B) AppleWeb...
Taking screenshot with chromium: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Ap...
Extracting basic DOM information...
Basic DOM extraction successful: 6 links, 0 forms, 5 scripts
✅ chromium: '导航>>>...', 6 links, 0 forms, 5 scripts, 0 network reqs
Extracting basic DOM information...
Basic DOM extraction successful: 6 links, 0 forms, 5 scripts
✅ chromium: '导航>>>...', 6 links, 0 forms, 5 scripts, 0 network reqs
Extracting basic DOM information...
Basic DOM extraction successful: 6 links, 0 forms, 5 scripts
✅ chromium: '导航>>>...', 6 links, 0 forms, 5 scripts, 0 network reqs
Extracting basic DOM information...
Basic DOM extraction successful: 6 links, 0 forms, 5 scripts
✅ firefox: '导航>>>...', 6 links, 0 forms, 5 scripts, 0 network reqs
🔍 Using DUAL AI analysis - Reason: Different final URLs: https://dqsapaxcse.dh056139.top/demo/ vs https://ackspbfyzm.dh056139.top/demo/; Different browser engines: firefox vs chromium
📊 Dual analysis: firefox_windows vs chrome_windows
Sending dual analysis (2 screenshots + data) to Gemini API for 'http://ghpert8njt.dh056139.top/'

================================================================================
🔍 DETAILED CLI PHISHING ASSESSMENT
================================================================================
🚨 RISK LEVEL: HIGH

📝 SUMMARY:
The analyzed site is a highly suspicious portal that uses advanced evasion techniques, including script obfuscation and dynamic subdomain generation, to hide its content from security tools. The visual theme 'Money Tree' is commonly associated with fraudulent gambling or phishing schemes. The identical behavior across different browser sessions with varying subdomains confirms a sophisticated infrastructure designed for persistence and evasion.

--- 🕵️‍♂️ DETAILED ANALYSIS ---
1. Screenshot Comparison: The screenshots from both browsers are visually identical. They show a landing page for '摇钱树资料网' (Money Tree Information Network) with three 'Access Entrance' links and a recommendation to download Google Chrome.

2. Content Structure: The HTML structure and length (9426 characters) are identical across both browsers. Both pages contain 6 links, three of which are internal PHP routes (/zd/jmup1.php, etc.) and one external link to the official Google Chrome download page in China.

3. URL & Redirect Analysis: While the base domain 'dh056139.top' is consistent, the subdomains differ ('dqsapaxcse' for Firefox vs 'ackspbfyzm' for Chrome). This indicates the use of dynamically generated subdomains or a DGA (Domain Generation Algorithm) setup, which is a common evasion and tracking technique.

4. Browser Targeting: The content itself does not vary between the two tested browsers. However, the explicit recommendation to download Google Chrome suggests that the operators may have optimized their subsequent malicious payloads or scams for the Chrome browser.

5. Evasion Techniques: The site employs significant evasion techniques: 1) Heavy JavaScript obfuscation using string arrays and Base64 encoding to hide the page's actual text and link destinations from simple static analysis. 2) Dynamic subdomain generation. 3) Runtime content injection, where the main UI elements are rendered via script execution rather than being present in the initial HTML.

6. Threat Assessment: The risk is HIGH. The combination of heavy obfuscation, dynamic subdomains, and the nature of the content (gambling/lottery themed 'Money Tree' network) strongly suggests a malicious gateway or phishing portal designed to bypass security filters.

7. JavaScript Analysis: Five scripts are present. Three scripts use a similar obfuscation pattern (hex-indexed string arrays like `_0x5b67`) to decode and inject the 'Access Entrance' blocks into the DOM. Another script (`daohang`) decodes Base64 strings to display the site name and footer information. This is a classic 'cloaking' technique.

8. Network Analysis: No suspicious external network requests were captured during the initial load, as most actions are localized to the suspicious domain via relative paths.

🚩 KEY THREAT INDICATORS:
  - JavaScript obfuscation (hex arrays, Base64 decoding)
  - Runtime DOM manipulation to hide content
  - Dynamic subdomain generation (DGA-like behavior)
  - Suspicious theme (Gambling/Get-rich-quick)
  - Encouraging users to download specific software (Chrome)

============================================================
SMART DUAL BROWSER ANALYSIS SUMMARY
============================================================
🔍 DUAL ANALYSIS TRIGGERED - Significant differences detected:

🥇 Primary Result: firefox_windows (firefox)
   • Title: '导航>>>...'
   • Final URL: https://dqsapaxcse.dh056139.top/demo/
   • Content: 6 links, 0 forms

🥈 Secondary Result: chrome_windows (chromium)
   • Title: '导航>>>...'
   • Final URL: https://ackspbfyzm.dh056139.top/demo/
   • Content: 6 links, 0 forms

📋 All Browser Results:
✅ firefox_windows (firefox): '导航>>>...', 6 links, 0 forms
✅ chrome_windows (chromium): '导航>>>...', 6 links, 0 forms
✅ chrome_android (chromium): '导航>>>...', 6 links, 0 forms
✅ chrome_mac (chromium): '导航>>>...', 6 links, 0 forms

⚠️ Dual analysis used due to significant browser differences.
```

---

>OLD and Archived for reference
```bash
Starting Firefox-based phishing detection process...
Target URL: https://desk-app-now.com/lander/domain/ThaiBingo.exe
------------------------------------------------------------
Step 1: Taking screenshot...
Taking screenshot with Firefox (enhanced): https://desk-app-now.com/lander/domain/ThaiBingo.exe
Screenshot taken successfully with Firefox.
Screenshot captured successfully. Size: 56078 bytes

Step 2: Analyzing with Gemini...
Sending image (bytes) and URL 'https://desk-app-now.com/lander/domain/ThaiBingo.exe' to Gemini API

============================================================
PHISHING DETECTION ANALYSIS RESULTS
============================================================
URL: https://desk-app-now.com/lander/domain/ThaiBingo.exe
------------------------------------------------------------
## Detailed Analysis

1.  **Branding Consistency:** The page clearly displays the Cloudflare logo and references "Cloudflare Ray ID" at the bottom. The overall design and messaging are consistent with legitimate security warning pages issued by Cloudflare. There are no misspellings, low-quality graphics, or inconsistencies in Cloudflare's own branding on this warning page itself. The page is not attempting to impersonate another brand; rather, it's a legitimate security alert from Cloudflare.

2.  **Design Quality:** The design is professional, clean, and well-structured. The layout, typography, and spacing are consistent and indicate a legitimate and well-developed security warning page. The graphics, such as the warning icon and the Cloudflare logo, are of high quality.

3.  **Textual Content:** The text is grammatically correct and free of spelling errors. The messages "Warning" and "Suspected Phishing," along with the explanation ("Phishing is when a site attempts to steal sensitive information by falsely presenting as a safe source."), are clear, concise, and professional. There is no urgent, threatening, or overly emotional language typically used by scammers; instead, it's a direct and informative security alert. No sensitive information is requested on this page.

4.  **Interactive Elements:** The page features two distinct buttons: "Learn More" (likely linking to Cloudflare's documentation on phishing) and "Ignore & Proceed." These are standard choices for a security warning, allowing users to understand the risk or bypass the warning. The "Verifying..." spinner with the Cloudflare logo and associated "Privacy" and "Terms" links are consistent with Cloudflare's security challenge mechanisms. These elements appear authentic and do not solicit payment or login credentials.

5.  **Sense of Urgency/Threats/Unrealistic Offers:** The page conveys a sense of urgency because it's a security warning about a potential threat. However, this urgency stems from a legitimate security service (Cloudflare) trying to protect the user, not from a scammer attempting to coerce action. There are no unrealistic offers or manipulative pressure tactics.

6.  **Content Specificity:** The content is specific to a Cloudflare security warning, providing a "Cloudflare Ray ID" and mentioning "Your IP," which are technical details consistent with Cloudflare's services. The explanation of phishing is generic but accurate, indicating a general security function.

7.  **Security Indicators:** The entire page acts as a strong security indicator, as it is a legitimate warning generated by Cloudflare to alert the user about a website that has been reported for potential phishing. It serves as a protective measure to prevent access to a suspicious site.

8.  **URL Analysis (for `https://desk-app-now.com/lander/domain/ThaiBingo.exe`):**
    *   **Domain Name (`desk-app-now.com`):** The domain "desk-app-now.com" is generic and does not correspond to any established, legitimate software company or service. It does not appear to be a direct typo-squat of a major brand. However, its non-authoritative nature makes it suspicious for hosting executable files.
    *   **Subdomains/Path (`lander/domain/ThaiBingo.exe`):** The path `/lander/domain/` is unusual for legitimate software distribution. The most critical element is the file name `ThaiBingo.exe`. The `.exe` extension signifies an executable program, which can install malware (viruses, ransomware, spyware, etc.) if run. Distributing `.exe` files directly from generic domains via a direct download link is a common tactic used by malicious actors. "ThaiBingo" is likely a social engineering lure, suggesting a game or application to entice users to download and execute the file. This strongly indicates an attempt to masquerade as a legitimate software download to deliver malware.
    *   **TLD Abuse:** The use of `.com` is standard and does not, in itself, indicate TLD abuse.
    *   **Masquerading Attempt:** The URL is a clear attempt to masquerade as a legitimate source for a downloadable application, specifically to trick users into downloading and executing a potentially malicious program under the guise of "ThaiBingo."

## Risk Assessment Format
RISK ASSESSMENT: High - While the screenshot displays a legitimate Cloudflare security warning, the URL it is warning about (`https://desk-app-now.com/lander/domain/ThaiBingo.exe`) is highly suspicious due to its generic domain name and direct link to an executable file, strongly indicating a malware distribution attempt.
```