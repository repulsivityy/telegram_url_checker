"""
Telegram Anti-Phishing Bot Checker

This bot extracts URLs and domains from Telegram messages and checks them against
VirusTotal/Google Threat Intel API and Google Web Risk API to identify potential malicious websites.

It provides a standardized response format for users, indicating whether the
links are safe, suspicious, or malicious. 

It leverages a combination of VT detection ratio, GTI assessment and Web Risk's threat scores to provide a risk assessment.

Disclaimer: Gemini 2.5 Pro and Claude Sonnet was used to optimise the code for performance and readability.

Usage: 
1. Set environment variables for TELEGRAM_TOKEN, VIRUSTOTAL_API_KEY, and WEBRISK_API_KEY.
2. install required packages: `pip install python-telegram-bot aiohttp`.
3. Update your variables under --- Constants --- section if needed.
4. Run the script: `python telegram_phishing_bot.py`.

# author: dominicchua@
# version: 1.5
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

#####################
# Constants / Variables. Adjust these as needed.
#####################
MALICIOUS_THRESHOLD = 3
API_TIMEOUT = 10
TOTAL_TIMEOUT = 25
IDLE_SHUTDOWN_SECONDS = 600
MAX_CONCURRENT_CHECKS = 20
VT_POLLING_SCHEDULE = [60, 45, 30] 
VT_POLLING_DEFAULT_INTERVAL = 30
TOTAL_POLLING_TIMEOUT = 240

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
    """Extracts URLs and domains based on clear classification rules."""
    DOMAIN_NAME_PATTERN = r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}"
    IPV4_PATTERN = r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
    HOST_PATTERN = f"(?:{DOMAIN_NAME_PATTERN}|{IPV4_PATTERN})"
    LINK_REGEX = re.compile(
        r'(?:https?://)?' + HOST_PATTERN + r'(?::\d+)?(?:[/?#][^\s]*)?',
        re.IGNORECASE
    )

    @staticmethod
    def extract_urls_and_domains(text: str) -> List[Dict[str, str]]:
        candidates = URLExtractor.LINK_REGEX.findall(text)
        final_results = []
        seen = set()
        for candidate in candidates:
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
        return final_results


class BaseChecker(ABC):
    """Abstract base class for security checkers."""
    def __init__(self, session: aiohttp.ClientSession):
        self.session = session

    @abstractmethod
    async def check(self, value: str, item_type: str) -> ScanResult:
        """Checks a value and returns a standardized ScanResult."""
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
        attributes = vt_data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        if not stats:
            return ScanResult(False, "No analysis data", self.SOURCE_NAME, error=True)
        malicious_count = stats.get("malicious", 0) + stats.get("suspicious", 0)
        total_engines = sum(stats.values())
        summary = f"{malicious_count}/{total_engines} vendors flagged this as malicious"
        details = stats.copy()
        risk_factors = {
            "classic_score": malicious_count,
            "is_malicious_threshold": malicious_count >= MALICIOUS_THRESHOLD
        }
        gti_assessment = attributes.get("gti_assessment")
        if gti_assessment:
            gti_verdict = gti_assessment.get("verdict", {}).get("value")
            gti_score = gti_assessment.get("threat_score", {}).get("value")
            is_malicious = gti_verdict == "VERDICT_MALICIOUS"
            details.update(gti_assessment)
            risk_factors.update({
                "gti_verdict": gti_verdict,
                "gti_score": gti_score
            })
        else:
            is_malicious = risk_factors["is_malicious_threshold"]
        return ScanResult(is_malicious, summary, self.SOURCE_NAME, details=details, risk_factors=risk_factors)

    async def check(self, value: str, item_type: str) -> ScanResult:
        try:
            endpoint_path = "urls" if item_type == "url" else "domains"
            identifier = base64.urlsafe_b64encode(value.encode()).decode().strip("=") if item_type == "url" else value
            endpoint = f"{self.BASE_URL}/{endpoint_path}/{identifier}"
            async with await self._make_request(endpoint) as response:
                if response.status == 404:
                    return await self._submit_url(value) if item_type == 'url' else ScanResult(False, "Not found", self.SOURCE_NAME)
                response.raise_for_status()
                return self._parse_results(await response.json())
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logger.error(f"{self.SOURCE_NAME} error for {value}: {e}")
            return ScanResult(False, "API Error", self.SOURCE_NAME, error=True)

    async def _submit_url(self, url: str) -> ScanResult:
        try:
            submit_endpoint = f"{self.BASE_URL}/urls"
            payload = aiohttp.FormData(); payload.add_field('url', url)
            logger.info(f"URL not found. Submitting {url} for analysis.")
            async with await self._make_request(submit_endpoint, method='POST', data=payload) as response:
                if not response.ok: return ScanResult(False, "Failed to submit", self.SOURCE_NAME, error=True)
                analysis_id = (await response.json()).get("data", {}).get("id")
                if not analysis_id: return ScanResult(False, "Submission failed", self.SOURCE_NAME, error=True)
                return ScanResult(False, "⏳ Undergoing analysis...", self.SOURCE_NAME, details={"analysis_id": analysis_id}, is_pending=True)
        except Exception as e:
            logger.error(f"Error during URL submission for {url}: {e}")
            return ScanResult(False, "API Error on submit", self.SOURCE_NAME, error=True)

    async def poll_for_result(self, analysis_id: str) -> ScanResult:
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
                        if analysis_data.get("data", {}).get("attributes", {}).get("status") == "completed":
                            logger.info(f"Analysis {analysis_id} complete.")
                            return self._parse_results(analysis_data)
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                logger.error(f"Polling error for analysis ID {analysis_id}: {e}")
        logger.warning(f"Polling finished or timed out for analysis ID {analysis_id}.")
        return ScanResult(False, "Analysis timed out", self.SOURCE_NAME, error=True)

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
        if not wr_data or "scores" not in wr_data: return ScanResult(False, "No detections", self.SOURCE_NAME)
        is_malicious = any(score.get("confidenceLevel") != "SAFE" for score in wr_data.get("scores", []))
        threat_scores = {score.get("threatType"): score.get("confidenceLevel", "SAFE") for score in wr_data.get("scores", [])}
        summary = self._format_threat_summary(threat_scores)
        risk_factors = {
            "has_high_threat": any(c in ["HIGH", "EXTREMELY_HIGH"] for c in threat_scores.values()),
            "is_clean": not is_malicious
        }
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
# Formats the response for the user
#####################
class ResponseFormatter:
    RESPONSE_TEMPLATES = {
        "DANGER":  {"emoji": "🚨", "level": "DANGER: Malicious link detected!",  "rec": "🚫 DO NOT VISIT - This website poses a significant security risk."},
        "WARNING": {"emoji": "⚠️", "level": "WARNING: Potentially malicious link detected!", "rec": "⚠️ SUSPICIOUS - Proceed with caution and only if you trust the sender."},
        "SAFE":    {"emoji": "✅", "level": "Link seems safe",    "rec": "✅ SAFE - No threats detected, but always be cautious with unknown websites."},
        "ERROR":   {"emoji": "❓", "level": "ERROR",   "rec": "❓ INCONCLUSIVE - Exercise caution as threat assessment is unclear."}
    }

    def _get_risk_level(self, vt_result: Optional[ScanResult], wr_result: Optional[ScanResult]) -> str:
        vt_result = vt_result or ScanResult(False, "Not configured", "VirusTotal", error=True)
        wr_result = wr_result or ScanResult(False, "Not configured", "Google Web Risk", error=True)
        if vt_result.error or wr_result.error: return "ERROR"
        vt_factors = vt_result.risk_factors
        wr_factors = wr_result.risk_factors
        if (vt_factors.get("gti_verdict") == "VERDICT_MALICIOUS" or
            (vt_factors.get("gti_score") is not None and vt_factors.get("gti_score") > 60) or
            wr_factors.get("has_high_threat") or
            vt_factors.get("is_malicious_threshold")):
            return "DANGER"
        if (vt_factors.get("gti_verdict") == "VERDICT_HARMLESS" or
            (vt_factors.get("classic_score") == 0 and wr_factors.get("is_clean"))):
            return "SAFE"
        return "WARNING"

    def format_combined_response(self, target: str, results_map: Dict[str, ScanResult], is_pending: bool = False) -> str:
        vt_result = results_map.get("VirusTotal")
        wr_result = results_map.get("Google Web Risk")
        risk_level = self._get_risk_level(vt_result, wr_result)
        template = self.RESPONSE_TEMPLATES[risk_level]
        header = f"{template['emoji']} {template['level']}"
        recommendation = f"<b>Recommendation:</b>\n {template['rec']}"
        defanged_target = target.replace('.', '[.]').replace(':', '[:]')
        
        details_lines = []
        if vt_result:
            details_lines.append(f"VirusTotal: {vt_result.summary}")
            gti_verdict_raw = vt_result.details.get("verdict", {}).get("value")
            if gti_verdict_raw:
                display_verdict = gti_verdict_raw.replace("VERDICT_", "").capitalize()
                details_lines.append(f"Google TI Verdict: {display_verdict}")
        
        if wr_result:
            details_lines.append(f"Google Web Risk: {wr_result.summary}")

        details_section = "\n".join(filter(None, details_lines))
        pending_text = "\n\n<i>⏳ Awaiting final analysis results from VirusTotal...</i>" if is_pending else ""
        return (f"{header}\n"f"Link: <code>{defanged_target}</code>\n""----------------------------------\n"f"{details_section}\n\n"f"{recommendation}{pending_text}")

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
        self.application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, self.handle_message))
        self.application.add_error_handler(self.error_handler)

    async def _get_session(self) -> aiohttp.ClientSession:
        async with self._session_lock:
            if self._session_close_task and not self._session_close_task.done(): self._session_close_task.cancel()
            if self._session is None or self._session.closed:
                logger.info("Creating new aiohttp.ClientSession.")
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
                    logger.info("Idle timeout reached. Closing ClientSession.")
                    await self._session.close()
        except asyncio.CancelledError:
            pass

    async def start_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        await update.message.reply_html("Hi! I'm an anti-phishing bot. Send me a message with any link to check it.")

    async def help_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        await update.message.reply_html("I check links against <b>VirusTotal</b> and <b>Google Web Risk</b>.")

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
        if not checkers:
            await update.message.reply_text("No security checkers are configured. Please set API keys.")
            return

        total_items = len(items)
        await update.message.reply_text(f"Found {total_items} item(s). Analyzing with {len(checkers)} configured service(s)...")
        
        for i in range(0, total_items, MAX_CONCURRENT_CHECKS):
            chunk = items[i:i + MAX_CONCURRENT_CHECKS]
            if total_items > MAX_CONCURRENT_CHECKS:
                await update.message.reply_text(f"Processing items {i+1} to {i+len(chunk)} of {total_items}...")
            tasks = [self._check_and_report_item(update, item, checkers) for item in chunk]
            await asyncio.gather(*tasks)
        logger.info(f"Finished processing all {total_items} items.")
        await self._schedule_session_shutdown()

    async def _check_and_report_item(self, update: Update, item: Dict, checkers: List[BaseChecker]):
        item_type, item_value = item['type'], item['value']
        proc_msg = await update.message.reply_html(f"🔍 Analyzing {item_type}: <code>{item_value.replace('.', '[.]')}</code>")
        
        # --- Block 1: Initial Fast Scan with short timeout ---
        try:
            tasks = [checker.check(item_value, item_type) for checker in checkers]
            results = await asyncio.wait_for(asyncio.gather(*tasks), timeout=TOTAL_TIMEOUT)
            
            results_map = {res.source: res for res in results}
            vt_result = results_map.get("VirusTotal")
            wr_result = results_map.get("Google Web Risk")

        except asyncio.TimeoutError:
            await proc_msg.edit_text(f"⏰ <b>Timeout</b> during initial scan for <code>{item_value.replace('.', '[.]')}</code>.", parse_mode='HTML')
            return
        except Exception as e:
            logger.error(f"Error during initial scan for {item_value}: {e}", exc_info=True)
            await proc_msg.edit_text(f"❌ <b>Error</b> during initial scan for <code>{item_value.replace('.', '[.]')}</code>.", parse_mode='HTML')
            return

        # --- Block 2: Decision and Polling Logic (outside the initial timeout) ---
        try:
            initial_risk_level = self.response_formatter._get_risk_level(vt_result, wr_result)
            should_poll = vt_result and vt_result.is_pending and initial_risk_level == "SAFE"

            initial_response = self.response_formatter.format_combined_response(item_value, results_map, is_pending=should_poll)
            await proc_msg.edit_text(initial_response, parse_mode='HTML')
            
            if should_poll:
                analysis_id = vt_result.details.get("analysis_id")
                vt_checker = next((c for c in checkers if isinstance(c, VirusTotalChecker)), None)
                if analysis_id and vt_checker:
                    final_vt_result = await vt_checker.poll_for_result(analysis_id)
                    results_map["VirusTotal"] = final_vt_result
                    final_response = self.response_formatter.format_combined_response(item_value, results_map)
                    await proc_msg.edit_text(final_response, parse_mode='HTML')

        except Exception as e:
            logger.error(f"Error during polling/final update for {item_value}: {e}", exc_info=True)
            await proc_msg.edit_text(f"❌ <b>Error</b> after initial scan for <code>{item_value.replace('.', '[.]')}</code>.", parse_mode='HTML')

    async def error_handler(self, update: object, context: ContextTypes.DEFAULT_TYPE):
        logger.error(f"Update {update} caused error: {context.error}", exc_info=context.error)

    async def shutdown(self):
        async with self._session_lock:
            if self._session_close_task and not self._session_close_task.done(): self._session_close_task.cancel()
            if self._session and not self._session.closed: await self._session.close()

    def run(self):
        try:
            self.application.run_polling()
        finally:
            loop = asyncio.get_event_loop()
            if loop.is_running(): loop.create_task(self.shutdown())
            else: loop.run_until_complete(self.shutdown())


def main():
    if not TELEGRAM_TOKEN or TELEGRAM_TOKEN.startswith("YOUR_"):
        logger.critical("TELEGRAM_TOKEN is not set. The bot cannot start.")
        return
        
    bot = TelegramBot(TELEGRAM_TOKEN)
    logger.info("Starting fully optimized bot...")
    bot.run()

if __name__ == "__main__":
    main()