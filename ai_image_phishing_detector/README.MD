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