# Phishing Detection Tool with AI

> Disclaimer: A mixture of Claude 4.0 Sonnet and Gemini 2.5 Pro helped optimised the code

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

## License

This tool is provided for educational and research purposes. Use responsibly and in accordance with applicable laws and regulations.


> Example response:
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
