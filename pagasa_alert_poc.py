#!/usr/bin/env python3
"""
PAGASA Weather Alert PoC - Cebu/Lapu-Lapu City Focus

Purpose:
    Crawl PAGASA weather pages and detect alerts relevant to Lapu-Lapu City/Cebu.
    Automatically downloads and parses PDF bulletins for accurate TCWS signal numbers.

Usage:
    python pagasa_alert_poc.py          # Human-readable output
    python pagasa_alert_poc.py --json   # JSON output for automation
    DEBUG=1 python pagasa_alert_poc.py  # Debug mode with PDF parsing details

Requirements:
    - Python 3.7+
    - PyPDF2 (for PDF bulletin parsing)
    - Standard library (urllib, html.parser, re, json, datetime)

Features:
    - HTML scraping for weather alerts (TCWS, Heavy Rainfall, Thunderstorms)
    - Automatic PDF download and parsing when exact signal numbers unavailable
    - Unified severity scale (1-5) across different alert types
    - JSON output mode for automation/integration

Expansion Points (for future bot integration):
    - Replace render_report() with send_telegram_message()
    - Add scheduler (e.g., APScheduler) in main loop
    - Add SQLite for alert history tracking
"""

import re
import sys
import time
from dataclasses import dataclass, asdict
from datetime import datetime
from html.parser import HTMLParser
from typing import List, Optional, Tuple
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

# Configuration
TIMEOUT_SECONDS = 15
MAX_RETRIES = 2
USER_AGENT = "Mozilla/5.0 (compatible; PAGASAAlertBot/1.0)"

# Target URLs (using bagong subdomain for better content availability)
URL_SEVERE_WEATHER_BULLETIN = "https://bagong.pagasa.dost.gov.ph/tropical-cyclone/severe-weather-bulletin"
URL_VISAYAS_FORECAST = "https://bagong.pagasa.dost.gov.ph/regional-forecast/visprsd"

# Alert severity levels
SEVERITY_OK = "OK"
SEVERITY_WATCH = "WATCH"
SEVERITY_WARNING = "WARNING"
SEVERITY_EMERGENCY = "EMERGENCY"


@dataclass
class AlertFinding:
    """Represents a single weather alert detection."""
    alert_type: str  # TYPHOON_WIND, HEAVY_RAIN, THUNDERSTORM, STRONG_WIND
    level: str  # Signal number, color code, or severity descriptor
    area_match: str  # "city_specific" (Lapu-Lapu), "province_wide" (Cebu), "none"
    source_url: str
    evidence_snippet: str  # Short excerpt showing the match
    issued_at: Optional[str] = None  # Issued time (if available)
    warning_no: Optional[str] = None  # Warning number (e.g., "8" for HRW#8)
    weather_system: Optional[str] = None  # Weather system name (e.g., "TS BASYANG")
    valid_from: Optional[str] = None  # Valid from time
    valid_until: Optional[str] = None  # Valid until time (expiration)
    next_update: Optional[str] = None  # Next bulletin/update time

    def get_coverage_description(self) -> str:
        """Get human-readable coverage description."""
        if self.area_match == "city_specific":
            return "Lapu-Lapu City"
        elif self.area_match == "province_wide":
            return "Cebu Province (includes Lapu-Lapu)"
        return "Unknown"

    def get_alert_name(self) -> str:
        """Get human-readable alert type name."""
        names = {
            "TYPHOON_WIND": "Typhoon Wind Signal",
            "HEAVY_RAIN": "Heavy Rainfall",
            "THUNDERSTORM": "Thunderstorm",
            "STRONG_WIND": "Strong Wind/Gale"
        }
        return names.get(self.alert_type, self.alert_type)

    def get_severity_level(self) -> int:
        """
        Get unified severity level (1-5) for comparison across alert types.
        5 = Most severe, 1 = Least severe

        Mapping:
        - TYPHOON_WIND Signal #5/4/3 → 5 (Catastrophic)
        - TYPHOON_WIND Signal #2 → 4 (Severe)
        - TYPHOON_WIND Signal #1 → 3 (Moderate)
        - TYPHOON_WIND ACTIVE → 3 (Moderate, unknown signal)
        - HEAVY_RAIN RED → 5 (Catastrophic)
        - HEAVY_RAIN ORANGE → 4 (Severe)
        - HEAVY_RAIN YELLOW → 3 (Moderate)
        - HEAVY_RAIN MODERATE-HEAVY → 2 (Minor)
        - STRONG_WIND ACTIVE → 3 (Moderate)
        - THUNDERSTORM WATCH/ADVISORY → 2 (Minor)
        - THUNDERSTORM ACTIVE/POSSIBLE → 1 (Minimal)
        """
        if self.alert_type == "TYPHOON_WIND":
            signal_match = re.search(r'(\d+)', self.level)
            if signal_match:
                signal_num = int(signal_match.group(1))
                if signal_num >= 3:
                    return 5  # Signal 3+ = Catastrophic
                elif signal_num == 2:
                    return 4  # Signal 2 = Severe
                elif signal_num == 1:
                    return 3  # Signal 1 = Moderate
            return 3  # ACTIVE (unknown signal) = Moderate

        elif self.alert_type == "HEAVY_RAIN":
            if self.level == "RED":
                return 5  # Catastrophic
            elif self.level == "ORANGE":
                return 4  # Severe
            elif self.level == "YELLOW":
                return 3  # Moderate
            elif self.level == "MODERATE-HEAVY":
                return 2  # Minor

        elif self.alert_type == "STRONG_WIND":
            return 3  # Moderate

        elif self.alert_type == "THUNDERSTORM":
            if self.level in ("WATCH", "ADVISORY"):
                return 2  # Minor
            elif self.level in ("ACTIVE", "POSSIBLE"):
                return 1  # Minimal

        return 1  # Default minimal

    def get_severity_label(self) -> str:
        """Get human-readable severity label."""
        severity_map = {
            5: "CATASTROPHIC",
            4: "SEVERE",
            3: "MODERATE",
            2: "MINOR",
            1: "MINIMAL"
        }
        return severity_map.get(self.get_severity_level(), "UNKNOWN")


class SimpleHTMLTextExtractor(HTMLParser):
    """Lightweight HTML parser to extract text content."""

    def __init__(self):
        super().__init__()
        self.text_parts = []

    def handle_data(self, data):
        self.text_parts.append(data)

    def get_text(self):
        return ' '.join(self.text_parts)


def normalize_text(text: str) -> str:
    """
    Normalize text for reliable location matching.
    - Lowercase
    - Remove hyphens, spaces, punctuation
    - Keep only alphanumeric
    """
    text = text.lower()
    text = re.sub(r'[^a-z0-9]', '', text)
    return text


def normalize_relative_dates(time_str: str) -> str:
    """
    Normalize relative dates like 'Today'/'Tomorrow' to absolute dates in PHST.

    Args:
        time_str: Time string that may contain 'Today' or 'Tomorrow'

    Returns:
        Time string with 'Today' replaced with full date (e.g., '06 February 2026')
        and 'Tomorrow' with next day's date
    """
    from datetime import datetime, timedelta, timezone

    if not time_str:
        return time_str

    # Get current date in PHST (UTC+8)
    phst = datetime.now(timezone.utc) + timedelta(hours=8)
    tomorrow = phst + timedelta(days=1)

    # Replace 'Today' with full date
    if re.search(r'\btoday\b', time_str, re.IGNORECASE):
        date_str = phst.strftime('%d %B %Y')
        time_str = re.sub(r'\btoday\b', date_str, time_str, flags=re.IGNORECASE)

    # Replace 'Tomorrow' with full date
    if re.search(r'\btomorrow\b', time_str, re.IGNORECASE):
        date_str = tomorrow.strftime('%d %B %Y')
        time_str = re.sub(r'\btomorrow\b', date_str, time_str, flags=re.IGNORECASE)

    return time_str


def check_area_match(text: str) -> str:
    """
    Check if text mentions Lapu-Lapu (city specific) or Cebu (province wide).
    Returns: "city_specific", "province_wide", or "none"
    """
    normalized = normalize_text(text)

    # City-specific match: Lapu-Lapu City explicitly mentioned
    if 'lapulapu' in normalized or 'lapulapucity' in normalized:
        return "city_specific"

    # Province-wide match: Cebu province (includes Lapu-Lapu)
    if 'cebu' in normalized:
        return "province_wide"

    return "none"


def fetch_with_retry(url: str, debug: bool = False) -> Tuple[Optional[str], Optional[str]]:
    """
    Fetch URL content with retry logic.
    Returns: (html_content, error_message)
    """
    for attempt in range(MAX_RETRIES):
        try:
            req = Request(url, headers={
                'User-Agent': USER_AGENT,
                'Accept-Encoding': 'identity',  # Avoid gzip/br compression issues
            })
            with urlopen(req, timeout=TIMEOUT_SECONDS) as response:
                html = response.read().decode('utf-8', errors='ignore')

                if debug:
                    print(f"  [DEBUG] HTML length: {len(html)} bytes")
                    print(f"  [DEBUG] First 500 chars: {html[:500]}")
                    text = extract_text_from_html(html)
                    print(f"  [DEBUG] Extracted text length: {len(text)} chars")
                    print(f"  [DEBUG] First 500 chars of text: {text[:500]}")

                return html, None
        except HTTPError as e:
            error = f"HTTP {e.code}: {e.reason}"
        except URLError as e:
            error = f"URL Error: {e.reason}"
        except Exception as e:
            error = f"Unexpected error: {str(e)}"

        if attempt < MAX_RETRIES - 1:
            time.sleep(2)

    return None, error


def extract_text_from_html(html: str) -> str:
    """Extract plain text from HTML, with fallback to raw HTML."""
    try:
        parser = SimpleHTMLTextExtractor()
        parser.feed(html)
        return parser.get_text()
    except Exception:
        # Fallback: use raw HTML for regex matching
        return html


def get_snippet(text: str, keyword: str, context_chars: int = 100) -> str:
    """Extract a short snippet around the keyword for evidence."""
    keyword_lower = keyword.lower()
    text_lower = text.lower()

    idx = text_lower.find(keyword_lower)
    if idx == -1:
        return keyword

    start = max(0, idx - context_chars)
    end = min(len(text), idx + len(keyword) + context_chars)
    snippet = text[start:end].strip()

    if start > 0:
        snippet = "..." + snippet
    if end < len(text):
        snippet = snippet + "..."

    return snippet


def extract_validity_times(text: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Extract validity time range from text.

    Looks for patterns like:
    - "Valid until HH:MM AM/PM DD Month YYYY"
    - "Valid for broadcast until HH:MM AM/PM DD Month YYYY"
    - "Issued at ... valid until ..."

    Returns: (valid_from, valid_until) tuple where both can be None
    """
    valid_from = None
    valid_until = None

    # Pattern 1: "Valid until ..."
    until_match = re.search(
        r'Valid\s+(?:for\s+broadcast\s+)?until[:\s]+([^.\n]{10,80})',
        text,
        re.IGNORECASE
    )
    if until_match:
        valid_until = until_match.group(1).strip()

    # Pattern 2: "Valid from ... to/until ..."
    from_to_match = re.search(
        r'Valid\s+from\s+([^.\n]{10,50}?)\s+(?:to|until)\s+([^.\n]{10,50})',
        text,
        re.IGNORECASE
    )
    if from_to_match:
        valid_from = from_to_match.group(1).strip()
        valid_until = from_to_match.group(2).strip()

    # Pattern 3: If we have "Issued at" but no valid_from, use issued time as valid_from
    if not valid_from:
        issued_match = re.search(r'Issued\s+at\s+([^\n]{10,50})', text, re.IGNORECASE)
        if issued_match:
            valid_from = issued_match.group(1).strip()

    # Normalize relative dates in both fields
    if valid_from:
        valid_from = normalize_relative_dates(valid_from)
    if valid_until:
        valid_until = normalize_relative_dates(valid_until)

    return valid_from, valid_until


def parse_tcws_bulletin(html: str, url: str) -> List[AlertFinding]:
    """
    Parse Severe Weather Bulletin for TCWS (Tropical Cyclone Wind Signal).

    Strategy:
    - Detect signal map images (signals_*.png) as indicator of active TCWS
    - If signal map exists, always check PDF for Cebu inclusion (prevents false negatives)
    - If HTML has TCWS section, parse it for explicit signal assignments
    - AVOID parsing explanatory text like "areas under Wind Signal No. 1 will experience..."
    """
    findings = []
    text = extract_text_from_html(html)

    # Extract validity times from the bulletin header (applies to all TCWS alerts)
    valid_from, valid_until = extract_validity_times(text)

    # Strategy 1: Look for TCWS signal map image (signals_*.png)
    # This indicates an active tropical cyclone with wind signals
    signal_map_pattern = r'signals_\w+\.(?:png|jpg|jpeg)'
    if re.search(signal_map_pattern, html, re.IGNORECASE):
        # Look for explicit TCWS section headings in HTML
        # Common patterns: "TROPICAL CYCLONE WIND SIGNALS", "AREAS UNDER WIND SIGNAL", "TCWS IN EFFECT"
        tcws_heading_pattern = r'(?:TROPICAL\s+CYCLONE\s+WIND\s+SIGNALS?|AREAS?\s+(?:UNDER|WITH)\s+(?:WIND\s+SIGNAL|TCWS)|TCWS\s+IN\s+EFFECT)'
        has_tcws_heading = re.search(tcws_heading_pattern, text, re.IGNORECASE)

        if not has_tcws_heading:
            # No TCWS text section found in HTML - rely on PDF parsing
            # Create ACTIVE placeholder (area_match will be determined from PDF)
            findings.append(AlertFinding(
                alert_type="TYPHOON_WIND",
                level="ACTIVE",
                area_match="unknown",  # Will be updated from PDF
                source_url=url,
                evidence_snippet="Typhoon wind signal map detected. PDF analysis required for exact signal assignment.",
                valid_from=valid_from,
                valid_until=valid_until
            ))
            return findings

        # Extract TCWS section from HTML
        tcws_section_pattern = r'(?:TROPICAL\s+CYCLONE\s+WIND\s+SIGNALS?|AREAS?\s+(?:UNDER|WITH)\s+(?:WIND\s+SIGNAL|TCWS))(.{0,5000}?)(?=(?:TRACK|HAZARDS\s+AFFECTING|Storm\s+Surge|Gale|$))'
        tcws_section_match = re.search(tcws_section_pattern, text, re.IGNORECASE | re.DOTALL)

        if not tcws_section_match:
            # Fallback: ACTIVE with PDF parsing needed (area_match from PDF)
            findings.append(AlertFinding(
                alert_type="TYPHOON_WIND",
                level="ACTIVE",
                area_match="unknown",  # Will be updated from PDF
                source_url=url,
                evidence_snippet="Typhoon wind signal in effect. Check PDF bulletin for exact signal level.",
                valid_from=valid_from,
                valid_until=valid_until
            ))
            return findings

        tcws_text = tcws_section_match.group(1)

        # Check if Cebu/Lapu-Lapu is mentioned in the TCWS section specifically
        tcws_area_match = check_area_match(tcws_text)

        if tcws_area_match == "none":
            # Cebu not in HTML TCWS section - but PDF might have it
            # Create ACTIVE placeholder for PDF to update
            findings.append(AlertFinding(
                alert_type="TYPHOON_WIND",
                level="ACTIVE",
                area_match="unknown",  # Will be updated from PDF
                source_url=url,
                evidence_snippet="Typhoon wind signal active. Cebu not found in HTML TCWS section - checking PDF.",
                valid_from=valid_from,
                valid_until=valid_until
            ))
            return findings

        # Look for explicit signal assignments in TCWS section only
        signal_area_pattern = r'(?:Signal|TCWS)\s*(?:#|No\.)?\s*([1-5])[:\s]*([^.]{0,500})'

        found_explicit = False
        for match in re.finditer(signal_area_pattern, tcws_text, re.IGNORECASE):
            signal_num = match.group(1)
            area_text = match.group(2)

            # Check if this is explanatory text (skip if it contains "will experience", "expected", etc.)
            if re.search(r'will\s+(?:experience|have)|expected|forecast', area_text, re.IGNORECASE):
                continue

            area_match = check_area_match(area_text)

            if area_match != "none":
                findings.append(AlertFinding(
                    alert_type="TYPHOON_WIND",
                    level=f"Signal #{signal_num}",
                    area_match=area_match,
                    source_url=url,
                    evidence_snippet=get_snippet(area_text, "Signal", 80),
                    valid_from=valid_from,
                    valid_until=valid_until
                ))
                found_explicit = True

        # If no explicit signal assignment found but Cebu is in TCWS section
        # Report as ACTIVE (exact signal will be determined from PDF)
        if not found_explicit and tcws_area_match != "none":
            findings.append(AlertFinding(
                alert_type="TYPHOON_WIND",
                level="ACTIVE",
                area_match=tcws_area_match,
                source_url=url,
                evidence_snippet="Typhoon wind signal in effect. Check official PAGASA map for exact signal level (1-5) for your specific location.",
                valid_from=valid_from,
                valid_until=valid_until
            ))

    return findings


def parse_visayas_forecast(html: str, url: str) -> List[AlertFinding]:
    """
    Parse Visayas Regional Forecast for:
    - Heavy Rainfall Warning (Yellow/Orange/Red) - block-based parsing
    - Thunderstorm Advisory/Watch
    - Gale/Strong Wind warnings
    - VISPRSD advisories (common format: #VISPRSD Issued at... #Cebu...)
    """
    findings = []
    text = extract_text_from_html(html)

    # Check if this is a Visayas regional advisory document
    overall_area_match = check_area_match(text)

    if overall_area_match == "none":
        return findings  # No Cebu/Lapu-Lapu mentioned

    # 1. Heavy Rainfall Warning - Block-based parsing
    # Look for "Heavy Rainfall Warning No. X" then parse Red/Orange/Yellow sections
    rainfall_warning_start = re.search(r'Heavy\s+Rainfall\s+Warning\s+(?:No\.|#)?\s*(\d+)', text, re.IGNORECASE)

    # Extract metadata (warning number, issued time, weather system, validity times)
    warning_no = None
    issued_at = None
    weather_system = None
    valid_from = None
    valid_until = None

    if rainfall_warning_start:
        warning_no = rainfall_warning_start.group(1)

        # Extract a large chunk after the warning header (up to 5000 chars to catch all warnings)
        block_start = rainfall_warning_start.start()
        block_end = min(len(text), block_start + 5000)
        warning_block = text[block_start:block_end]

        # Extract "Issued at" time
        issued_match = re.search(r'Issued\s+at\s+([^\n]{10,50})', warning_block, re.IGNORECASE)
        if issued_match:
            issued_at = issued_match.group(1).strip()

        # Extract weather system (e.g., "TS BASYANG", "Typhoon MARCE")
        system_match = re.search(r'Weather\s+System:\s*(.+?)(?:\n|$)', warning_block, re.IGNORECASE)
        if system_match:
            weather_system = system_match.group(1).strip()

        # Extract validity times - use "next warning" time for HRW
        # Pattern: "watch for the next warning to be issued at HH:MM AM/PM Today/Tomorrow"
        next_warning_match = re.search(
            r'next\s+warning\s+to\s+be\s+issued\s+at\s+([0-9:]+\s*(?:AM|PM)\s+\w+)',
            warning_block,
            re.IGNORECASE
        )
        next_update = None
        if next_warning_match:
            next_update = normalize_relative_dates(next_warning_match.group(1).strip())
            valid_from = issued_at  # Use issued time as valid_from
            valid_until = None  # Keep empty - next_update is not expiration
        else:
            # Fallback to generic validity time extraction
            valid_from, valid_until = extract_validity_times(warning_block)

        # Parse each color level separately
        # Match "Red Warning:" followed by content until next warning level or "Associated Hazard"
        color_patterns = [
            (r'Red\s+Warning:\s*(.+?)(?=(?:Orange\s+Warning:|Yellow\s+Warning:|Associated\s+Hazard:|Thunderstorm|Meanwhile|$))', "RED"),
            (r'Orange\s+Warning:\s*(.+?)(?=(?:Red\s+Warning:|Yellow\s+Warning:|Associated\s+Hazard:|Thunderstorm|Meanwhile|$))', "ORANGE"),
            (r'Yellow\s+Warning:\s*(.+?)(?=(?:Red\s+Warning:|Orange\s+Warning:|Associated\s+Hazard:|Thunderstorm|Meanwhile|$))', "YELLOW"),
        ]

        for pattern, color in color_patterns:
            match = re.search(pattern, warning_block, re.IGNORECASE | re.DOTALL)
            if match:
                color_section = match.group(1)

                # Check if Cebu or Lapu-Lapu is in this color section
                area_match = check_area_match(color_section)

                if area_match != "none":
                    # Create evidence with label included
                    evidence_with_label = f"{color} Warning: {color_section.strip()[:150]}"

                    findings.append(AlertFinding(
                        alert_type="HEAVY_RAIN",
                        level=color,
                        area_match=area_match,
                        source_url=url,
                        evidence_snippet=evidence_with_label,
                        issued_at=issued_at,
                        warning_no=warning_no,
                        weather_system=weather_system,
                        valid_from=valid_from,
                        valid_until=valid_until,
                        next_update=next_update
                    ))

    # Fallback: Try simple inline pattern if block parsing found nothing
    if not any(f.alert_type == "RAINFALL" for f in findings):
        rainfall_pattern = r'(?:Heavy\s+)?Rainfall\s+(?:Warning|Alert).*?(Yellow|Orange|Red)'
        for match in re.finditer(rainfall_pattern, text, re.IGNORECASE):
            color = match.group(1).upper()
            context_start = max(0, match.start() - 200)
            context_end = min(len(text), match.end() + 200)
            context = text[context_start:context_end]

            area_match = check_area_match(context)

            if area_match != "none":
                findings.append(AlertFinding(
                    alert_type="HEAVY_RAIN",
                    level=color,
                    area_match=area_match,
                    source_url=url,
                    evidence_snippet=get_snippet(context, color, 80)
                ))

    # 2. VISPRSD advisory with rain/thunderstorm mentions
    # Pattern: #VISPRSD ... Issued at ... mentions rain/thunderstorm and #Cebu
    # SKIP if we already have explicit RED/ORANGE/YELLOW warning (avoid redundancy)
    has_explicit_rainfall = any(f.alert_type == "HEAVY_RAIN" and f.level in ("RED", "ORANGE", "YELLOW") for f in findings)

    visprsd_pattern = r'#VISPRSD\b.*?(?:Issued\s+at|Valid\s+until)'
    if re.search(visprsd_pattern, text, re.IGNORECASE | re.DOTALL) and not has_explicit_rainfall:
        # Look for rainfall/thunderstorm keywords in document
        weather_keywords = [
            (r'(?:moderate\s+to\s+)?heavy\s+rain(?:showers|fall)?', "HEAVY_RAIN", "MODERATE-HEAVY"),
            (r'rainshowers?\s+with\s+lightning', "THUNDERSTORM", "ACTIVE"),
            (r'thunderstorms?', "THUNDERSTORM", "ACTIVE"),
            (r'lightning', "THUNDERSTORM", "POSSIBLE"),
        ]

        for pattern, alert_type, level in weather_keywords:
            matches = list(re.finditer(pattern, text, re.IGNORECASE))
            if matches:
                # Take the first match as representative
                match = matches[0]
                context_start = max(0, match.start() - 300)
                context_end = min(len(text), match.end() + 300)
                context = text[context_start:context_end]

                # Check if Cebu/Lapu-Lapu is in the context or overall document
                local_area = check_area_match(context)
                area_match = local_area if local_area != "none" else overall_area_match

                findings.append(AlertFinding(
                    alert_type=alert_type,
                    level=level,
                    area_match=area_match,
                    source_url=url,
                    evidence_snippet=get_snippet(context, match.group(0), 80)
                ))
                break  # Only add one weather finding per document

    # 3. Explicit Thunderstorm Advisory/Watch
    thunderstorm_patterns = [
        (r'Thunderstorm\s+Watch', "WATCH"),
        (r'Thunderstorm\s+Advisory', "ADVISORY"),
    ]

    for pattern, level in thunderstorm_patterns:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            context_start = max(0, match.start() - 200)
            context_end = min(len(text), match.end() + 400)
            context = text[context_start:context_end]

            area_match = check_area_match(context)

            if area_match != "none":
                # Extract issued time and validity times if present
                ts_issued = None
                issued_match = re.search(r'Issued\s+at\s+([^\n]{10,50})', context, re.IGNORECASE)
                if issued_match:
                    ts_issued = issued_match.group(1).strip()

                ts_valid_from, ts_valid_until = extract_validity_times(context)

                # Create evidence with label
                evidence_with_label = f"Thunderstorm {level}: {context[max(0, match.start()-context_start):min(len(context), match.end()-context_start+150)]}"

                findings.append(AlertFinding(
                    alert_type="THUNDERSTORM",
                    level=level,
                    area_match=area_match,
                    source_url=url,
                    evidence_snippet=evidence_with_label[:200],
                    issued_at=ts_issued,
                    valid_from=ts_valid_from,
                    valid_until=ts_valid_until
                ))
                break  # Only add one thunderstorm finding per type

    # 4. Gale/Strong Wind Warning
    wind_pattern = r'(?:Gale|Strong\s+Wind)\s+(?:Warning|Advisory)'
    for match in re.finditer(wind_pattern, text, re.IGNORECASE):
        context_start = max(0, match.start() - 200)
        context_end = min(len(text), match.end() + 200)
        context = text[context_start:context_end]

        area_match = check_area_match(context)

        if area_match != "none":
            findings.append(AlertFinding(
                alert_type="STRONG_WIND",
                level="ACTIVE",
                area_match=area_match,
                source_url=url,
                evidence_snippet=get_snippet(context, "Wind", 80)
            ))

    return findings


def classify_overall_severity(findings: List[AlertFinding]) -> str:
    """
    Determine overall severity based on detected alerts.
    Rules:
    - EMERGENCY: Typhoon Signal 3+, or Heavy Rain RED
    - WARNING: Typhoon Signal 1-2, or Heavy Rain ORANGE, or Strong Wind
    - WATCH: Thunderstorm Advisory, or Heavy Rain YELLOW
    - OK: No alerts
    """
    if not findings:
        return SEVERITY_OK

    for finding in findings:
        # EMERGENCY conditions
        if finding.alert_type == "TYPHOON_WIND":
            signal_match = re.search(r'(\d+)', finding.level)
            if signal_match and int(signal_match.group(1)) >= 3:
                return SEVERITY_EMERGENCY

        if finding.alert_type == "HEAVY_RAIN" and finding.level == "RED":
            return SEVERITY_EMERGENCY

    for finding in findings:
        # WARNING conditions
        if finding.alert_type == "TYPHOON_WIND":
            return SEVERITY_WARNING

        if finding.alert_type == "HEAVY_RAIN" and finding.level == "ORANGE":
            return SEVERITY_WARNING

        if finding.alert_type == "STRONG_WIND":
            return SEVERITY_WARNING

    for finding in findings:
        # WATCH conditions
        if finding.alert_type == "THUNDERSTORM" and finding.level in ("WATCH", "ADVISORY"):
            return SEVERITY_WATCH

        if finding.alert_type == "HEAVY_RAIN" and finding.level in ("YELLOW", "MODERATE-HEAVY"):
            return SEVERITY_WATCH

        if finding.alert_type == "THUNDERSTORM" and finding.level in ("ACTIVE", "POSSIBLE"):
            return SEVERITY_WATCH

    return SEVERITY_OK


def render_report(findings: List[AlertFinding], overall: str, timestamp: str, output_json: bool = False):
    """
    Print operator-friendly report of findings.

    EXPANSION POINT: Replace this with send_telegram_message() for bot integration.
    """
    from datetime import datetime, timezone, timedelta

    # Parse KST timestamp and convert to PHST
    dt_kst = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S KST")
    dt_kst = dt_kst.replace(tzinfo=timezone(timedelta(hours=9)))
    dt_phst = dt_kst.astimezone(timezone(timedelta(hours=8)))

    # If JSON output requested
    if output_json:
        import json
        output = {
            "timestamp_kst": timestamp,
            "timestamp_phst": dt_phst.strftime("%Y-%m-%d %H:%M:%S PHST"),
            "overall_status": overall,
            "target_area": "Cebu/Lapu-Lapu",
            "alerts": []
        }
        for f in findings:
            alert = {
                "alert_name": f.get_alert_name(),
                "alert_type": f.alert_type,
                "level": f.level,
                "severity": f.get_severity_level(),
                "severity_label": f.get_severity_label(),
                "coverage": f.area_match,
                "coverage_description": f.get_coverage_description(),
                "source": f.source_url
            }
            if f.issued_at:
                alert["issued_at"] = f.issued_at
            if f.warning_no:
                alert["warning_no"] = f.warning_no
            if f.weather_system:
                alert["weather_system"] = f.weather_system
            if f.valid_from:
                alert["valid_from"] = f.valid_from
            if f.valid_until:
                alert["valid_until"] = f.valid_until
            if f.next_update:
                alert["next_update"] = f.next_update
            output["alerts"].append(alert)
        print(json.dumps(output, indent=2, ensure_ascii=False))
        return

    # Human-readable format
    print("\n" + "=" * 70)
    print(f"PAGASA Cebu/Lapu-Lapu Alert — {overall}")
    print(f"{dt_kst.strftime('%H:%M KST')} / {dt_phst.strftime('%H:%M PHST')} — {dt_kst.strftime('%Y-%m-%d')}")
    print("=" * 70)

    if not findings:
        print("\n✓ No alerts detected for target area.")
        print(f"\nStatus: {overall}")
        print("=" * 70)
        return

    # Filter out redundant findings for cleaner display
    # Remove THUNDERSTORM ACTIVE/POSSIBLE if WATCH/ADVISORY exists
    has_ts_watch = any(f.alert_type == "THUNDERSTORM" and f.level in ("WATCH", "ADVISORY") for f in findings)
    display_findings = [
        f for f in findings
        if not (f.alert_type == "THUNDERSTORM" and f.level in ("ACTIVE", "POSSIBLE") and has_ts_watch)
    ]

    # Alert Summary
    print("\nActive Alerts:")
    for f in display_findings:
        # Build alert line with severity indicator
        severity_emoji = {
            5: "🔴",  # CATASTROPHIC
            4: "🟠",  # SEVERE
            3: "🟡",  # MODERATE
            2: "🔵",  # MINOR
            1: "⚪",  # MINIMAL
        }
        emoji = severity_emoji.get(f.get_severity_level(), "⚪")

        alert_line = f"{emoji} {f.get_alert_name()}: {f.level} ({f.get_severity_label()})"

        if f.warning_no:
            alert_line += f" [HRW#{f.warning_no}]"
        if f.issued_at:
            alert_line += f" — issued {f.issued_at}"

        print(alert_line)
        print(f"   Coverage: {f.get_coverage_description()}")

        # Show validity time range and next update if available
        if f.valid_from and f.valid_until:
            print(f"   Valid: {f.valid_from} → {f.valid_until}")
        elif f.valid_until:
            print(f"   Valid until: {f.valid_until}")
        elif f.valid_from:
            print(f"   Valid from: {f.valid_from}")

        # Show next update time separately (for HRW)
        if f.next_update:
            print(f"   Next update: {f.next_update}")

        # Show weather system if available (for first HEAVY_RAIN finding only)
        if f.weather_system and f.alert_type == "HEAVY_RAIN":
            print(f"   Weather System: {f.weather_system}")

    # Action guidance based on severity
    print(f"\n{'─' * 70}")
    print("Recommended Actions:")
    if overall == SEVERITY_EMERGENCY:
        print("⚠ EMERGENCY: Serious flooding/landslides expected.")
        print("  - Avoid low-lying and mountainous areas")
        print("  - Check flight/boat schedules - cancellations likely")
        print("  - Stay indoors, monitor updates every 3 hours")
    elif overall == SEVERITY_WARNING:
        print("⚠ WARNING: Flooding/strong winds threatening.")
        print("  - Avoid travel to affected areas if possible")
        print("  - Check transportation schedules")
        print("  - Monitor conditions before outdoor activities")
    elif overall == SEVERITY_WATCH:
        print("⚡ WATCH: Thunderstorms/moderate rain possible.")
        print("  - Carry umbrella, avoid outdoor swimming")
        print("  - Check weather before island tours")
    else:
        print("✓ No significant weather threats.")

    # Sources (compact)
    print(f"\n{'─' * 70}")
    print("Sources:")
    sources = set(f.source_url for f in findings)
    for s in sources:
        if "severe-weather-bulletin" in s:
            print("  - PAGASA Severe Weather Bulletin (TCWS)")
        elif "visprsd" in s:
            print("  - PAGASA Visayas Regional Forecast")

    print("=" * 70 + "\n")


def download_and_extract_pdf_text(pdf_url: str, debug: bool = False) -> Optional[str]:
    """
    Download PDF and extract text content.
    Returns: PDF text content or None on failure
    """
    try:
        # Try to import PyPDF2 (optional dependency)
        try:
            from PyPDF2 import PdfReader
        except ImportError:
            if debug:
                print("  [INFO] PyPDF2 not installed - skipping PDF analysis")
            return None

        # Download PDF
        req = Request(pdf_url, headers={
            'User-Agent': USER_AGENT,
            'Accept-Encoding': 'identity',
        })

        with urlopen(req, timeout=TIMEOUT_SECONDS) as response:
            pdf_data = response.read()

        if debug:
            print(f"  [DEBUG] Downloaded PDF: {len(pdf_data)} bytes")

        # Extract text from PDF
        from io import BytesIO
        pdf_file = BytesIO(pdf_data)
        reader = PdfReader(pdf_file)

        text = ""
        for page in reader.pages:
            text += page.extract_text() + "\n"

        if debug:
            print(f"  [DEBUG] Extracted PDF text: {len(text)} chars")
            print(f"  [DEBUG] First 500 chars: {text[:500]}")

        return text

    except ImportError:
        if debug:
            print("  [INFO] PyPDF2 not available - skipping PDF analysis")
        return None
    except Exception as e:
        if debug:
            print(f"  [WARNING] PDF download/parse failed: {e}")
        return None


def parse_tcws_from_pdf(pdf_text: str, debug: bool = False) -> Tuple[List[Tuple[int, str, str]], Optional[str], Optional[str]]:
    """
    Parse TCWS signal assignments from PDF bulletin text.

    Returns: (list of (signal_number, area_match, evidence) tuples, valid_from, valid_until)

    Strategy:
    1. Extract only the "TCWS IN EFFECT" section to avoid false positives
    2. Within that section, find signal blocks (1, 2, 3, 4, 5)
    3. Match Cebu/Lapu-Lapu within each signal's area list
    """
    results = []

    # Extract validity times from the entire PDF text (usually in header)
    valid_from, valid_until = extract_validity_times(pdf_text)

    # Extract TCWS section only (to avoid "Wind Signal No. 2" in hazard descriptions)
    tcws_section_match = re.search(
        r'TROPICAL\s+CYCLONE\s+WIND\s+SIGNALS?\s*\(TCWS\)\s+IN\s+EFFECT(.+?)(?=OTHER\s+HAZARDS|TRACK\s+AND\s+INTENSITY|$)',
        pdf_text,
        re.IGNORECASE | re.DOTALL
    )

    if not tcws_section_match:
        if debug:
            print("  [DEBUG] No TCWS section found in PDF")
        return results, valid_from, valid_until

    tcws_section = tcws_section_match.group(1)

    if debug:
        print(f"  [DEBUG] Extracted TCWS section ({len(tcws_section)} chars)")
        print(f"  [DEBUG] Section preview: {tcws_section[:500]}...")

    # Pattern 1: Signal number as standalone line (most common PAGASA format)
    # Matches: "\n1\n" followed by area list until next signal or section end
    standalone_signal_pattern = r'\n([1-5])\n(.+?)(?=\n[1-5]\n|$)'

    for match in re.finditer(standalone_signal_pattern, tcws_section, re.DOTALL):
        signal_num = int(match.group(1))
        block = match.group(2)

        if debug:
            print(f"  [DEBUG] Found Signal #{signal_num} block ({len(block)} chars)")
            print(f"  [DEBUG] Block preview: {block[:300]}...")

        # Check if Cebu or Lapu-Lapu is mentioned in this signal block
        area_match = check_area_match(block)

        if area_match != "none":
            evidence = get_snippet(block, "Cebu", 150)
            results.append((signal_num, area_match, evidence))
            if debug:
                print(f"  [DEBUG] ✓ Matched Cebu/Lapu-Lapu in Signal #{signal_num}")

    # Pattern 2: "TCWS No. X" or "Wind Signal No. X" format (fallback)
    if not results:
        tcws_block_pattern = r'(?:TCWS|Wind\s+Signal)\s+(?:No\.|Number|#)?\s*([1-5])[^\n]{0,100}\n(.{0,3000}?)(?=(?:TCWS|Wind\s+Signal)\s+(?:No\.|Number|#)?\s*[1-5]|$)'

        for match in re.finditer(tcws_block_pattern, tcws_section, re.IGNORECASE | re.DOTALL):
            signal_num = int(match.group(1))
            block = match.group(2)

            if debug:
                print(f"  [DEBUG] Found Signal #{signal_num} block (fallback) ({len(block)} chars)")

            area_match = check_area_match(block)

            if area_match != "none":
                evidence = get_snippet(block, "Cebu", 150)
                results.append((signal_num, area_match, evidence))
                if debug:
                    print(f"  [DEBUG] ✓ Matched Cebu/Lapu-Lapu in Signal #{signal_num}")

    if debug and not results:
        print("  [DEBUG] ✗ No TCWS assignments found for Cebu/Lapu-Lapu in TCWS section")

    return results, valid_from, valid_until


def find_pdf_link_in_html(html: str, debug: bool = False) -> Optional[str]:
    """
    Find PDF bulletin link in HTML.

    PAGASA uses patterns like:
    - https://pubfiles.pagasa.dost.gov.ph/tamss/weather/bulletin_basyang.pdf
    - https://pubfiles.pagasa.dost.gov.ph/tamss/weather/bulletin/TCB#17_basyang.pdf
    """
    # Look for PDF links in HTML
    pdf_patterns = [
        r'href=["\']([^"\']*pubfiles\.pagasa\.dost\.gov\.ph/tamss/weather/bulletin[^"\']*\.pdf)["\']',
        r'href=["\']([^"\']*\.pdf)["\']',
    ]

    for pattern in pdf_patterns:
        match = re.search(pattern, html, re.IGNORECASE)
        if match:
            pdf_url = match.group(1)
            # Make sure it's a full URL
            if not pdf_url.startswith('http'):
                pdf_url = 'https://bagong.pagasa.dost.gov.ph' + pdf_url

            if debug:
                print(f"  [DEBUG] Found PDF link: {pdf_url}")

            return pdf_url

    if debug:
        print("  [DEBUG] No PDF link found in HTML")

    return None


def fetch_pdf_if_needed(findings: List[AlertFinding], html: str, url: str, debug: bool = False) -> List[AlertFinding]:
    """
    Download and parse PDF bulletins to get exact TCWS signal numbers.

    This is called when we detect ACTIVE typhoon wind signals but don't have
    exact signal numbers from HTML parsing.

    Returns: Updated findings list with exact signal numbers from PDF
    """
    # Check if we have any ACTIVE typhoon wind findings (without exact signal number)
    has_active_tcws = any(
        f.alert_type == "TYPHOON_WIND" and f.level == "ACTIVE"
        for f in findings
    )

    if not has_active_tcws:
        return findings  # No need for PDF parsing

    if debug:
        print("\n[INFO] ACTIVE typhoon wind signal detected - attempting PDF analysis...")

    # Find PDF link in HTML
    pdf_url = find_pdf_link_in_html(html, debug=debug)

    if not pdf_url:
        if debug:
            print("  [WARNING] No PDF link found - keeping ACTIVE level")
        return findings

    # Download and extract PDF text
    pdf_text = download_and_extract_pdf_text(pdf_url, debug=debug)

    if not pdf_text:
        if debug:
            print("  [WARNING] PDF text extraction failed - keeping ACTIVE level")
        return findings

    # Parse TCWS assignments from PDF
    pdf_results, pdf_valid_from, pdf_valid_until = parse_tcws_from_pdf(pdf_text, debug=debug)

    if not pdf_results:
        # No Cebu found in PDF TCWS section
        if debug:
            print("  [INFO] No TCWS assignments found for Cebu in PDF")

        # Remove ACTIVE findings with area_match="unknown" (Cebu not in TCWS)
        updated_findings = [
            f for f in findings
            if not (f.alert_type == "TYPHOON_WIND" and f.level == "ACTIVE" and f.area_match == "unknown")
        ]

        if debug and len(updated_findings) < len(findings):
            print("  [INFO] Removed ACTIVE placeholder - Cebu not under TCWS")

        return updated_findings

    # Update findings: replace ACTIVE with exact signal numbers from PDF
    updated_findings = []
    active_replaced = False

    for finding in findings:
        if finding.alert_type == "TYPHOON_WIND" and finding.level == "ACTIVE" and not active_replaced:
            # Preserve validity times from original finding if PDF doesn't have them
            final_valid_from = pdf_valid_from or finding.valid_from
            final_valid_until = pdf_valid_until or finding.valid_until

            # Replace with PDF findings
            for signal_num, area_match, evidence in pdf_results:
                updated_findings.append(AlertFinding(
                    alert_type="TYPHOON_WIND",
                    level=f"Signal #{signal_num}",
                    area_match=area_match,
                    source_url=url,
                    evidence_snippet=f"[PDF] {evidence}",
                    valid_from=final_valid_from,
                    valid_until=final_valid_until
                ))
            active_replaced = True

            if debug:
                print(f"  [SUCCESS] Updated ACTIVE → {len(pdf_results)} signal assignment(s) from PDF")
        else:
            updated_findings.append(finding)

    return updated_findings


def run_self_test():
    """Simple self-test with sample HTML fragments."""
    print("Running self-test...")

    # Test 1: Typhoon wind signal detection with signal map
    sample_tcws = """
    <html><body>
    <img src="signals_basyang.png" alt="TCWS Map">
    <p>TROPICAL CYCLONE WIND SIGNALS</p>
    <p>Signal #2: Cebu including Lapu-Lapu City, Mandaue City</p>
    </body></html>
    """
    tcws_results = parse_tcws_bulletin(sample_tcws, "test_url")
    assert len(tcws_results) > 0, "Typhoon wind signal detection failed"
    # With explicit TCWS section and Cebu mentioned, should detect with proper area_match
    assert tcws_results[0].area_match in ("city_specific", "province_wide"), "Area detection failed"

    # Test 2: Rainfall warning
    sample_rainfall = """
    <html><body>
    <h2>Heavy Rainfall Warning - ORANGE</h2>
    <p>Areas affected: Cebu, Bohol, Leyte</p>
    </body></html>
    """
    rainfall_results = parse_visayas_forecast(sample_rainfall, "test_url")
    assert len(rainfall_results) > 0, "Rainfall detection failed"
    assert rainfall_results[0].level == "ORANGE", "Rainfall level parsing failed"

    # Test 3: Text normalization
    assert normalize_text("Lapu-Lapu City") == "lapulapucity"
    assert normalize_text("CEBU Province") == "cebuprovince"

    print("Self-test passed!\n")


def main():
    """Main execution flow."""
    import os

    # Parse command line arguments
    output_json = '--json' in sys.argv

    # Run self-test (skip if JSON output to keep output clean)
    if not output_json:
        run_self_test()

    # Check if debug mode is enabled via environment variable
    debug_mode = os.environ.get('DEBUG', '').lower() in ('1', 'true', 'yes')

    # Get current timestamp (Asia/Manila)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S KST")

    all_findings = []
    tcws_html = None  # Store HTML for PDF parsing later

    if not output_json:
        print(f"Fetching {URL_SEVERE_WEATHER_BULLETIN}...")

    # Fetch and parse Severe Weather Bulletin
    html, error = fetch_with_retry(URL_SEVERE_WEATHER_BULLETIN, debug=debug_mode)
    if html:
        tcws_html = html  # Store for PDF parsing
        findings = parse_tcws_bulletin(html, URL_SEVERE_WEATHER_BULLETIN)
        all_findings.extend(findings)
        if not output_json:
            print(f"  -> Found {len(findings)} alert(s)")
    else:
        if not output_json:
            print(f"  -> Error: {error}")

    if not output_json:
        print(f"Fetching {URL_VISAYAS_FORECAST}...")

    # Fetch and parse Visayas Regional Forecast
    html, error = fetch_with_retry(URL_VISAYAS_FORECAST, debug=debug_mode)
    if html:
        findings = parse_visayas_forecast(html, URL_VISAYAS_FORECAST)
        all_findings.extend(findings)
        if not output_json:
            print(f"  -> Found {len(findings)} alert(s)")
    else:
        if not output_json:
            print(f"  -> Error: {error}")

    # Try to get exact TCWS signal numbers from PDF if needed
    if tcws_html:
        all_findings = fetch_pdf_if_needed(all_findings, tcws_html, URL_SEVERE_WEATHER_BULLETIN, debug=debug_mode)

    # Classify overall severity
    overall = classify_overall_severity(all_findings)

    # Render report
    render_report(all_findings, overall, timestamp, output_json=output_json)

    # Exit code based on severity
    if overall == SEVERITY_EMERGENCY:
        sys.exit(2)
    elif overall == SEVERITY_WARNING:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
