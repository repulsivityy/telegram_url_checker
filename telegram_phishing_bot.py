"""
Telegram Anti-Phishing Bot Checker

This bot extracts URLs and domains from Telegram messages and checks them against
VirusTotal/Google Threat Intel API and Google Web Risk API to identify potential malicious websites.

It provides a standardized response format for users, indicating whether the
links are safe, suspicious, or malicious. 

It leverages a combination of VT detection ratio, GTI assessment and Web Risk's threat scores to provide a risk assessment. 
It also includes an AI analysis component that can analyze screenshots of the URLs for phishing characteristics.

Disclaimer: Gemini 2.5 Pro and Claude Sonnet was used to optimise the code for performance and readability.

Usage: 
1. Set environment variables for TELEGRAM_TOKEN, VIRUSTOTAL_API_KEY, and WEBRISK_API_KEY.
2. install required packages: `pip install python-telegram-bot aiohttp`.
3. Update your variables under --- Constants --- section if needed.
4. Run the script: `python telegram_phishing_bot.py`.

# author: dominicchua@
# version: 2.2 - tweaked response and added more to debug filter
"""

import os
import re
import logging
import base64
import asyncio
import aiohttp
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional, List, Dict
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes

logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

#####################
# Environment Variables
#####################
TELEGRAM_TOKEN = os.environ.get("TELEGRAM_TOKEN", "YOUR_TELEGRAM_TOKEN")
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")
WEBRISK_API_KEY = os.environ.get("WEBRISK_API_KEY")
ADMIN_USER_ID = os.environ.get("ADMIN_USER_ID")  # Your Telegram user ID for admin commands

#####################
# Constants / Variables. Adjust these as needed.
#####################
MALICIOUS_THRESHOLD = 5
API_TIMEOUT = 10
TOTAL_TIMEOUT = 25
IDLE_SHUTDOWN_SECONDS = 600
MAX_CONCURRENT_CHECKS = 20
VT_POLLING_SCHEDULE = [90, 60, 60, 60, 30, 30, 30]  # Decreasing delays
VT_POLLING_DEFAULT_INTERVAL = 30  # Continue with 30s after schedule exhausted
TOTAL_POLLING_TIMEOUT = 360  # 6 minutes total timeout

DEBUG_MODE = False

@dataclass
class ScanResult:
    """A standardized object for all checker results."""
    is_malicious: bool
    summary: str
    source: str
    details: Dict = field(default_factory=dict)
    error: bool = False
    is_pending: bool = False
    risk_factors: Dict = field(default_factory=dict)

#####################
# Core Component to extract URLs and domains 
#####################
class URLExtractor:
    """Extracts and classifies URLs, Domains, and IP Addresses from text."""
    LINK_REGEX = re.compile(
        r'((?:https?://)?'
        r'((?:(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,24})|'
        r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))'
        r'(?::\d{1,5})?'
        r'(?:[/?#][^\s]*)?)',
        re.IGNORECASE
    )
    STANDALONE_IP_REGEX = re.compile(
        r'\b((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))\b'
    )

    @staticmethod
    def extract_urls_and_domains(text: str) -> List[Dict[str, str]]:
        candidates = URLExtractor.LINK_REGEX.findall(text)
        standalone_ips = set(URLExtractor.STANDALONE_IP_REGEX.findall(text))
        
        final_results = []
        seen = set()

        for candidate_tuple in candidates:
            candidate = candidate_tuple[0]
            
            if candidate in standalone_ips and "://" not in candidate and "/" not in candidate:
                final_results.append({'type': 'ip_address', 'value': candidate})
                seen.add(candidate)
                continue

            if "://" in candidate or "/" in candidate or (":" in candidate and "://" not in candidate):
                item_type = 'url'
                value = 'http://' + candidate if not candidate.startswith('http') else candidate
            else:
                item_type = 'domain'
                value = candidate
            
            item_tuple = (item_type, value)
            if item_tuple not in seen:
                final_results.append({'type': item_type, 'value': value})
                seen.add(item_tuple)
                
        for ip in standalone_ips:
            if ip not in seen:
                final_results.append({'type': 'ip_address', 'value': ip})
                seen.add(ip)

        return final_results

class BaseChecker(ABC):
    def __init__(self, session: aiohttp.ClientSession):
        self.session = session

    @abstractmethod
    async def check(self, value: str, item_type: str) -> ScanResult:
        pass

#####################
# Checks against VirusTotal / GTI
#####################
class VirusTotalChecker(BaseChecker):
    SOURCE_NAME = "VirusTotal"
    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str, session: aiohttp.ClientSession):
        super().__init__(session)
        self.api_key = api_key
        self.headers = {"x-apikey": self.api_key, "x-tool": "telegram-phishing-bot", "Accept": "application/json"}

    async def _make_request(self, endpoint, method='GET', **kwargs):
        return await self.session.request(method, endpoint, headers=self.headers, timeout=API_TIMEOUT, **kwargs)

    def _parse_results(self, vt_data: Dict) -> ScanResult:
        """Parse VirusTotal results with optional debugging"""
        # Only log when debug mode is enabled
        if DEBUG_MODE:
            logger.info(f"🔍 VT Response structure: {list(vt_data.keys())}")
            data_section = vt_data.get("data", {})
            logger.info(f"🔍 VT Data section keys: {list(data_section.keys())}")
            attributes = data_section.get("attributes", {})
            logger.info(f"🔍 VT Attributes keys: {list(attributes.keys())}")
        
        data_section = vt_data.get("data", {})
        attributes = data_section.get("attributes", {})
        
        # Check analysis status first
        analysis_status = attributes.get("status")
        if DEBUG_MODE:
            logger.info(f"🔍 VT Analysis status: {analysis_status}")
        
        is_pending = analysis_status in ["queued", "running"]
        
        # If still pending, return early
        if is_pending:
            analysis_id = data_section.get("id")
            if DEBUG_MODE:
                logger.info(f"🔍 Analysis still pending with ID: {analysis_id}")
            return ScanResult(
                False, 
                "⏳ Undergoing analysis...", 
                self.SOURCE_NAME, 
                details={"analysis_id": analysis_id, "status": analysis_status}, 
                is_pending=True
            )

        # Check what analysis data we have
        stats = attributes.get("last_analysis_stats", {})
        if DEBUG_MODE:
            logger.info(f"🔍 VT Analysis stats: {stats}")
        
        # Also check for other possible data locations
        if not stats:
            stats = attributes.get("stats", {})
            if DEBUG_MODE:
                logger.info(f"🔍 VT Alternative stats location: {stats}")
            
        if not stats:
            # Check if there's scan results in a different format
            if DEBUG_MODE:
                scan_results = attributes.get("scan_results", {})
                logger.info(f"🔍 VT Scan results: {list(scan_results.keys()) if scan_results else 'None'}")
                
            # Check for last_analysis_results
            last_analysis_results = attributes.get("last_analysis_results", {})
            if DEBUG_MODE:
                logger.info(f"🔍 VT Last analysis results: {list(last_analysis_results.keys()) if last_analysis_results else 'None'}")
            
            # If we have scan results, try to build stats from them
            if last_analysis_results:
                stats = self._build_stats_from_results(last_analysis_results)
                if DEBUG_MODE:
                    logger.info(f"🔍 VT Built stats from results: {stats}")

        if not stats:
            if DEBUG_MODE:
                logger.warning(f"🔍 No analysis stats found. Full attributes: {attributes}")
            return ScanResult(False, "No analysis data available", self.SOURCE_NAME, error=True)

        malicious_count = stats.get("malicious", 0) + stats.get("suspicious", 0)
        total_engines = sum(stats.values())
        summary = f"{malicious_count}/{total_engines} vendors flagged this"
        
        if DEBUG_MODE:
            logger.info(f"🔍 VT Final summary: {summary}")
        
        details = stats.copy()
        risk_factors = {
            "classic_score": malicious_count,
            "is_malicious_threshold": malicious_count >= MALICIOUS_THRESHOLD
        }

        # Check for GTI assessment
        gti_assessment = attributes.get("gti_assessment")
        if gti_assessment:
            if DEBUG_MODE:
                logger.info(f"🔍 VT GTI Assessment found: {gti_assessment}")
            gti_verdict = gti_assessment.get("verdict", {}).get("value")
            gti_score = gti_assessment.get("threat_score", {}).get("value")
            is_malicious = gti_verdict == "VERDICT_MALICIOUS"
            details.update(gti_assessment)
            risk_factors.update({
                "gti_verdict": gti_verdict,
                "gti_score": gti_score
            })
        else:
            if DEBUG_MODE:
                logger.info(f"🔍 VT No GTI assessment found")
            is_malicious = risk_factors["is_malicious_threshold"]
        
        return ScanResult(is_malicious, summary, self.SOURCE_NAME, details=details, risk_factors=risk_factors, is_pending=False)

    def _build_stats_from_results(self, last_analysis_results: Dict) -> Dict:
        """Build stats dictionary from individual engine results"""
        stats = {"malicious": 0, "suspicious": 0, "clean": 0, "harmless": 0, "undetected": 0, "timeout": 0}
        
        for engine, result in last_analysis_results.items():
            category = result.get("category", "undetected").lower()
            if category in stats:
                stats[category] += 1
            else:
                logger.warning(f"Unknown category from {engine}: {category}")
                stats["undetected"] += 1
        
        logger.info(f"Built stats from {len(last_analysis_results)} engines: {stats}")
        return stats

    async def check(self, value: str, item_type: str) -> ScanResult:
        try:
            endpoint_path = "urls" if item_type == "url" else "domains"
            identifier = base64.urlsafe_b64encode(value.encode()).decode().strip("=") if item_type == "url" else value
            endpoint = f"{self.BASE_URL}/{endpoint_path}/{identifier}"
            
            # CONDITIONAL DEBUG: Only log when debug mode is enabled
            if DEBUG_MODE:
                logger.info(f"🔍 VT Check: {item_type} = {value}")
                logger.info(f"🔍 VT Endpoint: {endpoint}")
                logger.info(f"🔍 VT Identifier: {identifier}")
            
            async with await self._make_request(endpoint) as response:
                if DEBUG_MODE:
                    logger.info(f"🔍 VT Response status: {response.status}")
                
                if response.status == 404:
                    if DEBUG_MODE:
                        logger.info(f"🔍 VT 404 - submitting URL for analysis")
                    return await self._submit_url(value) if item_type == 'url' else ScanResult(False, "Not found", self.SOURCE_NAME)
                
                response.raise_for_status()
                response_data = await response.json()
                
                # CONDITIONAL DEBUG: Log response size
                if DEBUG_MODE:
                    logger.info(f"🔍 VT Response size: {len(str(response_data))} chars")
                
                return self._parse_results(response_data)
                
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logger.error(f"{self.SOURCE_NAME} error for {value}: {e}")
            return ScanResult(False, "API Error", self.SOURCE_NAME, error=True)

    async def _submit_url(self, url: str) -> ScanResult:
        try:
            submit_endpoint = f"{self.BASE_URL}/urls"
            payload = aiohttp.FormData()
            payload.add_field('url', url)
            logger.info(f"URL not found. Submitting {url} for analysis.")
            async with await self._make_request(submit_endpoint, method='POST', data=payload) as response:
                if not response.ok: 
                    return ScanResult(False, "Failed to submit", self.SOURCE_NAME, error=True)
                analysis_id = (await response.json()).get("data", {}).get("id")
                if not analysis_id: 
                    return ScanResult(False, "Submission failed", self.SOURCE_NAME, error=True)
                return ScanResult(
                    False, 
                    "⏳ Submitted for analysis...", 
                    self.SOURCE_NAME, 
                    details={"analysis_id": analysis_id}, 
                    is_pending=True
                )
        except Exception as e:
            logger.error(f"Error during URL submission for {url}: {e}")
            return ScanResult(False, "API Error on submit", self.SOURCE_NAME, error=True)

    async def poll_for_result(self, analysis_id: str) -> ScanResult:
        """Uses VT status to make intelligent decisions"""
        analysis_endpoint = f"{self.BASE_URL}/analyses/{analysis_id}"
        start_time = asyncio.get_running_loop().time()
        schedule_iterator = iter(VT_POLLING_SCHEDULE)
        attempt = 0
        
        while asyncio.get_running_loop().time() - start_time < TOTAL_POLLING_TIMEOUT:
            attempt += 1
            try:
                delay = next(schedule_iterator)
            except StopIteration:
                delay = VT_POLLING_DEFAULT_INTERVAL
            
            logger.info(f"Polling VT analysis ID {analysis_id}. Waiting {delay}s... (Attempt {attempt})")
            await asyncio.sleep(delay)
            
            try:
                async with await self._make_request(analysis_endpoint) as response:
                    if response.ok:
                        analysis_data = await response.json()
                        status = analysis_data.get("data", {}).get("attributes", {}).get("status")
                        
                        if status == "completed":
                            logger.info(f"Analysis {analysis_id} complete after {attempt} attempts.")
                            return self._parse_results(analysis_data)
                        
                        elif status == "queued":
                            logger.info(f"Analysis {analysis_id} still queued (attempt {attempt}/7)")
                            # If still queued by 4th attempt, give up
                            if attempt >= 4:
                                logger.warning(f"Analysis {analysis_id} still queued after 4 attempts. Timing out.")
                                return ScanResult(
                                    False, 
                                    "⏱️ Analysis taking longer than expected", 
                                    self.SOURCE_NAME, 
                                    details={"timeout_reason": "still_queued", "attempts": attempt},
                                    error=True
                                )
                            continue  # Keep trying if under 4 attempts
                        
                        elif status in ["running", "in-progress"]:
                            logger.info(f"Analysis {analysis_id} in progress (attempt {attempt}/7)")
                            # LOGIC: Continue all 7 attempts for in-progress
                            continue
                        
                        else:
                            logger.warning(f"Unexpected status for analysis {analysis_id}: {status}")
                            return ScanResult(
                                False, 
                                f"⚠️ Unexpected analysis status: {status}", 
                                self.SOURCE_NAME, 
                                details={"unexpected_status": status},
                                error=True
                            )
                    else:
                        logger.error(f"HTTP {response.status} while polling analysis {analysis_id}")
                        # Don't break immediately on HTTP errors, might be temporary
                        if attempt >= 3:  # Give up after 3 HTTP errors
                            break
                        continue
                        
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                logger.error(f"Polling error for analysis ID {analysis_id}: {e}")
                # Continue trying unless we've had multiple failures
                if attempt >= 5:
                    break
                continue
        
        # If we reach here, we've exhausted all attempts or hit timeout
        logger.warning(f"Polling timed out for analysis ID {analysis_id} after {attempt} attempts.")
        return ScanResult(
            False, 
            "⏰ Analysis timeout - please try again later", 
            self.SOURCE_NAME, 
            details={"timeout_reason": "max_attempts", "attempts": attempt},
            error=True
        )

#####################
# Checks against Google Web Risk
#####################
class WebRiskChecker(BaseChecker):
    SOURCE_NAME = "Google Web Risk"
    BASE_URL = "https://webrisk.googleapis.com/v1eap1:evaluateUri"
    THREAT_TYPES = ["SOCIAL_ENGINEERING", "MALWARE", "UNWANTED_SOFTWARE"]
    THREAT_NAMES = {"MALWARE": "Malware", "SOCIAL_ENGINEERING": "Social Engineering", "UNWANTED_SOFTWARE": "Unwanted Software"}

    def __init__(self, api_key: str, session: aiohttp.ClientSession):
        super().__init__(session)
        self.api_key = api_key

    def _parse_results(self, wr_data: Dict) -> ScanResult:
        if not wr_data or "scores" not in wr_data: 
            return ScanResult(False, "No detections", self.SOURCE_NAME)
        is_malicious = any(score.get("confidenceLevel") != "SAFE" for score in wr_data.get("scores", []))
        threat_scores = {score.get("threatType"): score.get("confidenceLevel", "SAFE") for score in wr_data.get("scores", [])}
        summary = self._format_threat_summary(threat_scores)
        risk_factors = {"has_high_threat": any(c in ["HIGH", "EXTREMELY_HIGH"] for c in threat_scores.values()), "is_clean": not is_malicious}
        return ScanResult(is_malicious, summary, self.SOURCE_NAME, details=threat_scores, risk_factors=risk_factors)

    def _format_threat_summary(self, threat_scores: Dict) -> str:
        non_safe = [f"{self.THREAT_NAMES.get(t, t)}: {c}" for t, c in threat_scores.items() if c != "SAFE"]
        return ", ".join(non_safe) if non_safe else "SAFE"

    async def check(self, value: str, item_type: str) -> ScanResult:
        url_to_check = value if item_type == 'url' else f"http://{value}"
        try:
            payload = {"uri": url_to_check, "threatTypes": self.THREAT_TYPES}
            async with self.session.post(f"{self.BASE_URL}?key={self.api_key}", json=payload, timeout=API_TIMEOUT) as response:
                response.raise_for_status()
                return self._parse_results(await response.json())
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logger.error(f"{self.SOURCE_NAME} error for {value}: {e}")
            return ScanResult(False, "API Error", self.SOURCE_NAME, error=True)


#####################
# Checks screenshot against Gemini AI
#####################
from ai_phishing_detector.ai_phishing_detector import analyze_url_for_phishing

class AIImageChecker(BaseChecker):
    SOURCE_NAME = "AI Analysis"

    def __init__(self):
        """No session needed as it's a local sync function."""
        pass

    def _parse_results(self, analysis_text: str) -> ScanResult:
        """Parses the raw text output from the Gemini AI"""
        logger.info(f"AI Analysis response received: {len(analysis_text)} characters")
        
        if not analysis_text:
            return ScanResult(False, "No analysis data", self.SOURCE_NAME, error=True)

        # Store the full analysis text
        details = {"full_analysis": analysis_text}
        
        if DEBUG_MODE:
            logger.info(f"AI Analysis in debug mode - response length: {len(analysis_text)} characters")

        # Parse the risk assessment from the analysis
        match = re.search(r"RISK ASSESSMENT:\s*\**\[?(Low|Medium|High)\]?\**\s*-\s*(.*)", analysis_text, re.IGNORECASE | re.DOTALL)

        if match:
            risk_level = match.group(1).lower()
            reason = match.group(2).strip()
            is_malicious = risk_level == "high" 
            
            # Truncate long reasons for cleaner display in telegram
            if len(reason) > 200:
                reason = reason[:200] + "..."
            
            summary = f"Risk: {risk_level.capitalize()} - {reason}"
            risk_factors = {"ai_risk": risk_level}
            return ScanResult(is_malicious, summary, self.SOURCE_NAME, details=details, risk_factors=risk_factors)
    
        # Fallback if the specific line isn't found
        summary = "Could not determine risk level from AI response."
        return ScanResult(False, summary, self.SOURCE_NAME, details=details, error=True)

    async def check(self, value: str, item_type: str) -> ScanResult:
        """Runs the AI analysis with debug mode passed from global setting."""
        global DEBUG_MODE  # Access the global debug flag
        
        if item_type == 'domain':
            url_to_check = f"https://{value}"
        elif item_type == 'url':
            url_to_check = value
        else:
            return ScanResult(False, f"Skipped (not a URL or domain)", self.SOURCE_NAME)

        try:
            # Pass the current DEBUG_MODE to the AI analysis function
            analysis_result_string = await analyze_url_for_phishing(url_to_check, debug_mode=DEBUG_MODE)
            return self._parse_results(analysis_result_string)
        except Exception as e:
            logger.error(f"{self.SOURCE_NAME} error for {url_to_check}: {e}")
            return ScanResult(False, "Analysis failed", self.SOURCE_NAME, error=True)

#####################
# Formats the response for the user
#####################
class ResponseFormatter:
    RESPONSE_TEMPLATES = {
        "DANGER":  {"emoji": "🚨", "level": "DANGER: Malicious link detected!",  "rec": "🚫 DO NOT VISIT - This website poses a significant security risk."},
        "WARNING": {"emoji": "⚠️", "level": "WARNING: Potentially malicious link detected!", "rec": "⚠️ SUSPICIOUS - Proceed with caution and only if you trust the sender."},
        "SAFE":    {"emoji": "✅", "level": "Link seems safe",    "rec": "✅ SAFE - No threats detected, but always be cautious with unknown websites."},
        "ERROR":   {"emoji": "❓", "level": "ERROR",   "rec": "❓ INCONCLUSIVE - Exercise caution as threat assessment is unclear."}
    }

    def _get_risk_level(self, vt_result: Optional[ScanResult], wr_result: Optional[ScanResult], ai_result: Optional[ScanResult] = None) -> str:
        """Determines the final risk level based on checker results."""
        # --- Default setup for missing results ---
        vt_result = vt_result or ScanResult(False, "Not configured", "VirusTotal", error=True)
        wr_result = wr_result or ScanResult(False, "Not configured", "Google Web Risk", error=True)
        ai_result = ai_result or ScanResult(False, "Not run", "AI Analysis", error=True)

        if vt_result.error or wr_result.error:
            return "ERROR"
        
        vt_factors = vt_result.risk_factors
        wr_factors = wr_result.risk_factors
        ai_factors = ai_result.risk_factors

        # --- Consolidated DANGER Logic ---
        if (vt_factors.get("gti_verdict") == "VERDICT_MALICIOUS" or 
            (vt_factors.get("gti_score") is not None and vt_factors.get("gti_score") >= 60) or 
            wr_factors.get("has_high_threat") or 
            ai_factors.get("ai_risk") == "high"):
            return "DANGER"

        # --- SAFE Logic ---
        if (vt_factors.get("gti_verdict") == "VERDICT_HARMLESS" or 
            (vt_factors.get("classic_score") == 0 and wr_factors.get("is_clean"))):
            return "SAFE"
            
        # --- Default to WARNING ---
        return "WARNING"

    def format_combined_response(self, target: str, results_map: Dict[str, ScanResult], configured_checkers: set) -> str:
        """Format combined response. Debug details are now handled at the AI source."""
        global DEBUG_MODE  # Access global debug flag for status indicator
        
        vt_result = results_map.get("VirusTotal")
        wr_result = results_map.get("Google Web Risk")
        ai_result = results_map.get("AI Analysis")

        risk_level = self._get_risk_level(vt_result, wr_result, ai_result)
        template = self.RESPONSE_TEMPLATES[risk_level]

        header = f"{template['emoji']} {template['level']}"
        recommendation = f"<b>Recommendation:</b>\n {template['rec']}"
        defanged_target = target.replace('.', '[.]').replace(':', '[:]')

        details_lines = []

        # VirusTotal section
        if "VirusTotal" in configured_checkers:
            if vt_result:
                details_lines.append(f"VirusTotal: {vt_result.summary}")
                gti_verdict_raw = vt_result.details.get("verdict", {}).get("value")
                if gti_verdict_raw:
                    display_verdict = gti_verdict_raw.replace("VERDICT_", "").capitalize()
                    details_lines.append(f"Google TI Verdict: {display_verdict}")
            else:
                details_lines.append("VirusTotal: ⏳ Still analyzing...")

        # Google Web Risk section
        if "Google Web Risk" in configured_checkers:
            if wr_result:
                details_lines.append(f"Google Web Risk: {wr_result.summary}")
            else:
                details_lines.append("Google Web Risk: ⏳ Still analyzing...")

        # AI Analysis section
        if "AI Analysis" in configured_checkers:
            if ai_result:
                # In debug mode, the AI analysis already includes technical details
                if DEBUG_MODE and "full_analysis" in ai_result.details:
                    # Show the full analysis (which already includes debug info if enabled)
                    details_lines.append(f"AI Analysis: {ai_result.summary}")
                    details_lines.append("")  # Empty line for separation
                    details_lines.append("<b>🔍 DEBUG - Full AI Analysis:</b>")
                    details_lines.append(f"<pre>{ai_result.details['full_analysis']}</pre>")
                else:
                    # Normal mode - show only the summary
                    details_lines.append(f"AI Analysis: {ai_result.summary}")
                    if not ai_result.error and ai_result.risk_factors.get("ai_risk") in ["low", "medium"]:
                        details_lines.append("<i>(AI verdict is informational and did not influence the final risk level)</i>")
            else:
                details_lines.append("AI Analysis: ⏳ Still analyzing... It takes ~45 - 60s to complete...")

        details_section = "\n".join(filter(None, details_lines))

        response = (
            f"{header}\n"
            f"Link: <code>{defanged_target}</code>\n"
            f"----------------------------------\n"
            f"{details_section}\n\n"
            f"{recommendation}"
        )
        
        # Add debug indicator if in debug mode
        if DEBUG_MODE:
            response += f"\n\n<i>🔍 Debug mode active</i>"
            
        return response

#####################
# Telegram Bot Implementation
#####################
class TelegramBot:
    def __init__(self, token: str):
        self.application = Application.builder().token(token).build()
        self.url_extractor = URLExtractor()
        self.response_formatter = ResponseFormatter()
        self._add_handlers()
        self._session: Optional[aiohttp.ClientSession] = None
        self._session_lock = asyncio.Lock()
        self._session_close_task: Optional[asyncio.Task] = None

    def _add_handlers(self):
        self.application.add_handler(CommandHandler("start", self.start_command))
        self.application.add_handler(CommandHandler("help", self.help_command))
        self.application.add_handler(CommandHandler("debug", self.debug_command))  # ✅ NEW: Debug toggle
        self.application.add_handler(CommandHandler("status", self.status_command))  # ✅ NEW: Status check
        self.application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, self.handle_message))
        self.application.add_error_handler(self.error_handler)

    async def _get_session(self) -> aiohttp.ClientSession:
        async with self._session_lock:
            if self._session_close_task and not self._session_close_task.done(): 
                self._session_close_task.cancel()
            if self._session is None or self._session.closed:
                logger.info(f"Creating new aiohttp.ClientSession.")
                self._session = aiohttp.ClientSession()
            return self._session

    async def _schedule_session_shutdown(self):
        async with self._session_lock:
            self._session_close_task = asyncio.create_task(self._close_session_after_delay(IDLE_SHUTDOWN_SECONDS))

    async def _close_session_after_delay(self, delay: int):
        try:
            await asyncio.sleep(delay)
            async with self._session_lock:
                if self._session and not self._session.closed:
                    logger.info(f"Idle timeout reached. Closing ClientSession.")
                    await self._session.close()
        except asyncio.CancelledError:
            pass

    async def start_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        await update.message.reply_html("Hi! I'm an anti-phishing bot. Send me a message with any link to check it.")

    async def help_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        help_text = (
            "I check links against <b>VirusTotal</b>, <b>Google TI</b> and <b>Google Web Risk</b>.\n"
            "I use AI to analyse the website for any visual discrepencies, as well as to analyse the source code for signs of phishing.\n\n"
            "<b>Commands:</b>\n"
            "/start - Start the bot\n"
            "/help - Show this help\n"
            "/status - Show bot status"
        )
        
        # Add admin commands if user is admin
        if ADMIN_USER_ID and str(update.effective_user.id) == ADMIN_USER_ID:
            help_text += "\n\n<b>Admin Commands:</b>\n/debug - Toggle debug mode"
            
        await update.message.reply_html(help_text)

    def _is_admin(self, user_id: int) -> bool:
        """Check if user is admin"""
        return ADMIN_USER_ID and str(user_id) == ADMIN_USER_ID

    async def debug_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Toggle debug mode (admin only)"""
        if not self._is_admin(update.effective_user.id):
            await update.message.reply_text("❌ Admin access required.")
            return
        
        global DEBUG_MODE
        DEBUG_MODE = not DEBUG_MODE
        
        status = "🔍 ENABLED" if DEBUG_MODE else "🔇 DISABLED"
        await update.message.reply_html(f"<b>Debug Mode:</b> {status}")
        logger.info(f"Debug mode {status.lower()} by admin user {update.effective_user.id}")

    async def status_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Show bot status"""
        global DEBUG_MODE
        
        # Check API configurations
        vt_configured = "✅" if VIRUSTOTAL_API_KEY and not VIRUSTOTAL_API_KEY.startswith("YOUR_") else "❌"
        wr_configured = "✅" if WEBRISK_API_KEY and not WEBRISK_API_KEY.startswith("YOUR_") else "❌"
        debug_status = "🔍 ON" if DEBUG_MODE else "🔇 OFF"
        
        status_text = (
            f"<b>🤖 Bot Status</b>\n\n"
            f"<b>APIs:</b>\n"
            f"{vt_configured} VirusTotal\n"
            f"{wr_configured} Google Web Risk\n\n"
            f"<b>Settings:</b>\n"
            f"Debug Mode: {debug_status}\n"
            f"Malicious Threshold: {MALICIOUS_THRESHOLD}\n"
            f"Max Concurrent: {MAX_CONCURRENT_CHECKS}\n"
            f"Polling Timeout: {TOTAL_POLLING_TIMEOUT//60} minutes"
        )
        
        await update.message.reply_html(status_text)

    async def handle_message(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not update.message or not update.message.text: return
        items = self.url_extractor.extract_urls_and_domains(update.message.text)
        if not items:
            await update.message.reply_text("No URLs or domains were found in your message.")
            await self._schedule_session_shutdown()
            return

        session = await self._get_session()
        checkers = []
        if VIRUSTOTAL_API_KEY and not VIRUSTOTAL_API_KEY.startswith("YOUR_"):
            checkers.append(VirusTotalChecker(VIRUSTOTAL_API_KEY, session))
        if WEBRISK_API_KEY and not WEBRISK_API_KEY.startswith("YOUR_"):
            checkers.append(WebRiskChecker(WEBRISK_API_KEY, session))
        checkers.append(AIImageChecker())
        if not checkers:
            await update.message.reply_text("No security checkers are configured. Please set API keys.")
            return
            
        total_items = len(items)
        await update.message.reply_text(f"Found {total_items} item(s). Analyzing with {len(checkers)} configured service(s)...")
        
        scan_tasks = []
        for item in items:
            if item['type'] in ['url', 'domain']:
                scan_tasks.append(self._check_and_report_item(update, item, checkers))
            elif item['type'] == 'ip_address':
                ip_value = item['value']
                response_text = f"ℹ️ Found an IP address: <code>{ip_value.replace('.', '[.]')}</code>. Standalone IP addresses are not scanned."
                scan_tasks.append(update.message.reply_html(response_text))
        
        for i in range(0, len(scan_tasks), MAX_CONCURRENT_CHECKS):
            chunk = scan_tasks[i:i + MAX_CONCURRENT_CHECKS]
            if len(scan_tasks) > MAX_CONCURRENT_CHECKS:
                await update.message.reply_text(f"Processing a batch of {len(chunk)} items...")
            await asyncio.gather(*chunk)

        logger.info(f"Finished processing all {total_items} items.")
        await self._schedule_session_shutdown()

    #item_type, item_value = item['type'], item['value']

    async def _check_and_report_item(self, update: Update, item: Dict, all_checkers: List[BaseChecker]):
        item_type, item_value = item['type'], item['value']        
        proc_msg = await update.message.reply_html(f"🔍 Analyzing {item_type}: <code>{item_value.replace('.', '[.]')}</code>")
        
        try:
            configured_checker_names = {c.SOURCE_NAME for c in all_checkers}

            # 1. Launch all initial checkers concurrently
            initial_tasks = {asyncio.create_task(c.check(item_value, item_type), name=c.SOURCE_NAME) for c in all_checkers}
            pending_tasks = initial_tasks.copy()
            results_map = {}

            while pending_tasks:
                done, pending_tasks = await asyncio.wait(pending_tasks, return_when=asyncio.FIRST_COMPLETED)
            
                for task in done:
                    source_name = task.get_name()
                    try:
                        result = task.result()
                        results_map[source_name] = result
                        logger.info(f"Task '{source_name}' completed for {item_value}.")

                        # Handle VT polling if necessary
                        if isinstance(result, ScanResult) and result.source == VirusTotalChecker.SOURCE_NAME and result.is_pending:
                            vt_checker = next((c for c in all_checkers if isinstance(c, VirusTotalChecker)), None)
                            analysis_id = result.details.get("analysis_id")
                            if vt_checker and analysis_id:
                                polling_task = asyncio.create_task(vt_checker.poll_for_result(analysis_id), name="VirusTotal Polling")
                                pending_tasks.add(polling_task)

                    except Exception as e:
                        logger.error(f"Task '{source_name}' failed for {item_value}: {e}", exc_info=True)
                        results_map[source_name] = ScanResult(False, "Task failed", source_name, error=True)

                intermediate_response = self.response_formatter.format_combined_response(item_value, results_map, configured_checker_names)

                try:
                    await proc_msg.edit_text(intermediate_response, parse_mode='HTML')
                except Exception as edit_error:
                    logger.warning(f"Could not edit message for {item_value}, likely no change in content. Error: {edit_error}")

                # Check for Web Risk early exit condition AFTER updating the message
                wr_result = results_map.get(WebRiskChecker.SOURCE_NAME)
                if wr_result and wr_result.risk_factors.get("has_high_threat"):
                    logger.warning(f"High-confidence threat from Web Risk for {item_value}. Cancelling remaining tasks.")
                    for p_task in pending_tasks:
                        p_task.cancel()
                        source_name = p_task.get_name()
                        # Add a "Cancelled" status to the map
                        if source_name not in results_map:
                            results_map[source_name] = ScanResult(False, "❌ Cancelled due to confirmed threat", source_name)
                        # Perform the FINAL message edit with the updated map
                        final_response = self.response_formatter.format_combined_response(item_value, results_map, configured_checker_names)
                        await proc_msg.edit_text(final_response, parse_mode='HTML')
                    return # Exit early

        except Exception as e:
            logger.error(f"Error in _check_and_report_item for {item_value}: {e}", exc_info=True)
            await proc_msg.edit_text(f"❌ <b>Error</b> checking <code>{item_value.replace('.', '[.]')}</code>.", parse_mode='HTML')

    async def error_handler(self, update: object, context: ContextTypes.DEFAULT_TYPE):
        logger.error(f"Update {update} caused error: {context.error}", exc_info=context.error)

    async def shutdown(self):
        async with self._session_lock:
            if self._session_close_task and not self._session_close_task.done(): 
                self._session_close_task.cancel()
            if self._session and not self._session.closed: 
                await self._session.close()

    def run(self):
        try:
            self.application.run_polling()
        finally:
            loop = asyncio.get_event_loop()
            if loop.is_running(): 
                loop.create_task(self.shutdown())
            else: 
                loop.run_until_complete(self.shutdown())


def main():
    if not TELEGRAM_TOKEN or TELEGRAM_TOKEN.startswith("YOUR_"):
        logger.critical(f"TELEGRAM_TOKEN is not set. The bot cannot start.")
        return
        
    bot = TelegramBot(TELEGRAM_TOKEN)
    logger.info("Starting fully optimized bot...")
    bot.run()

if __name__ == "__main__":
    main()