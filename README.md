# PAGASA Weather Alert Bot for Cebu/Lapu-Lapu

Automated weather alert detection for Cebu and Lapu-Lapu City, Philippines, using PAGASA (Philippine Atmospheric, Geophysical and Astronomical Services Administration) data.

## Features

- **Real-time Alert Detection**
  - Heavy Rainfall Warnings (RED/ORANGE/YELLOW)
  - Tropical Cyclone Wind Signals (TCWS)
  - Thunderstorm Advisories/Watches
  - Gale/Strong Wind Warnings

- **Smart Location Matching**
  - Primary: Lapu-Lapu City (direct match)
  - Fallback: Cebu Province (when city-level data unavailable)
  - Resilient text-based parsing

- **Operator-Friendly Output**
  - Clear severity levels (OK/WATCH/WARNING/EMERGENCY)
  - Actionable recommendations
  - Timestamp in both KST and PHST
  - Warning numbers and issue times
  - Validity time ranges (when alerts are in effect)

- **Machine-Readable Output**
  - JSON format with `--json` flag
  - Structured data for automation
  - Ready for Telegram/API integration

## Installation

```bash
# Using pipenv (recommended)
pipenv install  # Installs PyPDF2 for PDF bulletin parsing
pipenv run python pagasa_alert_poc.py

# Or with standard Python
pip install pypdf2
python3 pagasa_alert_poc.py
```

**Note**: PyPDF2 is now a required dependency for accurate TCWS signal number detection from PDF bulletins.

## Usage

### Basic Usage

```bash
pipenv run python pagasa_alert_poc.py
```

**Example Output:**
```
======================================================================
PAGASA Cebu/Lapu-Lapu Alert — EMERGENCY
14:12 KST / 13:12 PHST — 2026-02-06
======================================================================

Active Alerts:
🟠 Typhoon Wind Signal: Signal #2 (SEVERE)
   Coverage: Cebu Province (includes Lapu-Lapu)
   Valid: 11:00 AM , 06 February 2026 → the next bulletin at 2:00 PM  today
🔴 Heavy Rainfall: RED (CATASTROPHIC) [HRW#8] — issued 11:00 AM 06 February 2026
   Coverage: Cebu Province (includes Lapu-Lapu)
   Valid: 11:00 AM 06 February 2026 → 05:00 AM, 7 February, 2026
   Weather System: Tropical Storm (TS) BASYANG
🔵 Thunderstorm: WATCH (MINOR) — issued 10:00 AM 06 February 2026
   Coverage: Cebu Province (includes Lapu-Lapu)
   Valid from: 10:00 AM 06 February 2026

──────────────────────────────────────────────────────────────────────
Recommended Actions:
⚠ EMERGENCY: Serious flooding/landslides expected.
  - Avoid low-lying and mountainous areas
  - Check flight/boat schedules - cancellations likely
  - Stay indoors, monitor updates every 3 hours
──────────────────────────────────────────────────────────────────────
```

### JSON Output (for automation)

```bash
pipenv run python pagasa_alert_poc.py --json
```

**Example Output:**
```json
{
  "timestamp_kst": "2026-02-06 14:12:10 KST",
  "timestamp_phst": "2026-02-06 13:12:10 PHST",
  "overall_status": "EMERGENCY",
  "target_area": "Cebu/Lapu-Lapu",
  "alerts": [
    {
      "alert_name": "Typhoon Wind Signal",
      "alert_type": "TYPHOON_WIND",
      "level": "Signal #2",
      "severity": 4,
      "severity_label": "SEVERE",
      "coverage": "province_wide",
      "coverage_description": "Cebu Province (includes Lapu-Lapu)",
      "source": "https://bagong.pagasa.dost.gov.ph/tropical-cyclone/severe-weather-bulletin",
      "valid_from": "11:00 AM , 06 February 2026",
      "valid_until": "the next bulletin at 2:00 PM  today"
    },
    {
      "alert_name": "Heavy Rainfall",
      "alert_type": "HEAVY_RAIN",
      "level": "RED",
      "severity": 5,
      "severity_label": "CATASTROPHIC",
      "coverage": "province_wide",
      "coverage_description": "Cebu Province (includes Lapu-Lapu)",
      "source": "https://bagong.pagasa.dost.gov.ph/regional-forecast/visprsd",
      "issued_at": "11:00 AM 06 February 2026",
      "warning_no": "8",
      "weather_system": "Tropical Storm (TS) BASYANG",
      "valid_from": "11:00 AM 06 February 2026",
      "valid_until": "05:00 AM, 7 February, 2026"
    },
    {
      "alert_name": "Thunderstorm",
      "alert_type": "THUNDERSTORM",
      "level": "WATCH",
      "severity": 2,
      "severity_label": "MINOR",
      "coverage": "province_wide",
      "coverage_description": "Cebu Province (includes Lapu-Lapu)",
      "source": "https://bagong.pagasa.dost.gov.ph/regional-forecast/visprsd",
      "issued_at": "10:00 AM 06 February 2026",
      "valid_from": "10:00 AM 06 February 2026"
    }
  ]
}
```

### Debug Mode

```bash
DEBUG=1 pipenv run python pagasa_alert_poc.py
```

Shows HTML fetch details and parsing diagnostics.

### Exit Codes

- `0` - OK (no alerts)
- `1` - WARNING or WATCH
- `2` - EMERGENCY

Useful for shell scripts:
```bash
pipenv run python pagasa_alert_poc.py
if [ $? -eq 2 ]; then
    echo "Emergency alert! Notify team."
fi
```

## Architecture

### Data Sources

1. **PAGASA Severe Weather Bulletin**
   - TCWS (Tropical Cyclone Wind Signals)
   - URL: `https://bagong.pagasa.dost.gov.ph/tropical-cyclone/severe-weather-bulletin`

2. **PAGASA Visayas Regional Forecast**
   - Heavy Rainfall Warnings
   - Thunderstorm Advisories
   - URL: `https://bagong.pagasa.dost.gov.ph/regional-forecast/visprsd`

### Alert Severity Classification

**Overall Status Levels:**

| Level | Conditions | Example |
|-------|-----------|---------|
| **EMERGENCY** | Typhoon Signal 3+, RED Rainfall | Serious flooding expected |
| **WARNING** | Typhoon Signal 1-2, ORANGE Rainfall, Strong Wind | Flooding threatening |
| **WATCH** | Thunderstorm Advisory, YELLOW Rainfall | Moderate weather activity |
| **OK** | No alerts detected | Normal conditions |

**Individual Alert Severity (1-5 scale):**

Each alert has a unified severity score for easy comparison:

| Severity | Label | Icon | Examples |
|----------|-------|------|----------|
| **5** | CATASTROPHIC | 🔴 | Typhoon Signal 3-5, Heavy Rain RED |
| **4** | SEVERE | 🟠 | Typhoon Signal 2, Heavy Rain ORANGE |
| **3** | MODERATE | 🟡 | Typhoon Signal 1/ACTIVE, Heavy Rain YELLOW, Strong Wind |
| **2** | MINOR | 🔵 | Thunderstorm WATCH/ADVISORY, Heavy Rain MODERATE |
| **1** | MINIMAL | ⚪ | Thunderstorm ACTIVE/POSSIBLE |

**Why Unified Severity?**

Different alert types use different scales:
- Typhoon: Signal #1-5
- Rainfall: RED/ORANGE/YELLOW
- Thunderstorm: WATCH/ADVISORY/ACTIVE

The unified severity (1-5) lets you compare across types at a glance. For automation, you can:
```python
# Filter only severe alerts
severe_alerts = [a for a in alerts if a["severity"] >= 4]

# Find most dangerous alert
max_severity = max(a["severity"] for a in alerts)
```

### Design Principles

- **Text-based parsing**: Resilient to HTML structure changes
- **Hybrid approach**: HTML parsing + PDF analysis for maximum accuracy
- **Automatic PDF fallback**: When HTML shows "ACTIVE" typhoon signal, automatically downloads and parses PDF bulletin for exact signal number
- **Conservative reporting**: Avoids false positives in TCWS detection
- **Deduplication**: Removes redundant findings (e.g., MODERATE-HEAVY when RED exists)

## Roadmap

### Phase 1: PoC ✅ COMPLETED
✅ Alert detection and console output
✅ Severity classification
✅ JSON output support
✅ **PDF bulletin parsing** - Automatic extraction of exact TCWS signal numbers

### Phase 2: Telegram Bot (Next)
- [ ] Telegram message formatting
- [ ] Bot token configuration
- [ ] State tracking (avoid duplicate notifications)
- [ ] Scheduler (APScheduler, 30-60 min intervals)

### Phase 3: Enhanced Intelligence
- [ ] SQLite alert history
- [ ] Trend analysis (improving/worsening)
- [ ] Multi-location support

## How PDF Parsing Works

When the script detects a typhoon signal map image but can't find explicit signal numbers in HTML (showing "ACTIVE"), it automatically:

1. **Finds PDF link** in the HTML page (e.g., `bulletin_basyang.pdf`)
2. **Downloads PDF** from PAGASA's public files server
3. **Extracts text** using PyPDF2
4. **Parses TCWS sections** looking for signal number assignments
5. **Updates findings** with exact signal number (e.g., ACTIVE → Signal #2)

Example debug output:
```
[INFO] ACTIVE typhoon wind signal detected - attempting PDF analysis...
  [DEBUG] Found PDF link: https://pubfiles.pagasa.dost.gov.ph/tamss/weather/bulletin_basyang.pdf
  [DEBUG] Downloaded PDF: 743177 bytes
  [DEBUG] Found Signal #2 block (1646 chars)
  [DEBUG] ✓ Matched Cebu/Lapu-Lapu in Signal #2
  [SUCCESS] Updated ACTIVE → 1 signal assignment(s) from PDF
```

**Fallback behavior**: If PDF download/parsing fails, the script keeps the "ACTIVE" level and continues normally.

## Expansion Points

### Telegram Integration

Replace `render_report()` for Telegram notifications:

```python
def send_telegram_message(bot_token: str, chat_id: str, findings: List[AlertFinding], overall: str):
    import requests
    message = format_telegram_message(findings, overall)
    requests.post(
        f"https://api.telegram.org/bot{bot_token}/sendMessage",
        json={"chat_id": chat_id, "text": message, "parse_mode": "Markdown"}
    )
```

### Scheduler Integration

```python
from apscheduler.schedulers.blocking import BlockingScheduler

scheduler = BlockingScheduler()
scheduler.add_job(main, 'interval', minutes=30)
scheduler.start()
```

## Configuration

Edit constants in [pagasa_alert_poc.py](pagasa_alert_poc.py):

```python
TIMEOUT_SECONDS = 15      # HTTP request timeout
MAX_RETRIES = 2           # Retry attempts on network failure
USER_AGENT = "..."        # User-Agent header
```

## Testing

Self-tests run automatically on each execution:

```python
def run_self_test():
    # Test 1: TCWS detection with signal map
    # Test 2: Rainfall warning parsing
    # Test 3: Text normalization
```

## Contributing

Current status: **Production-ready PoC**

Next priorities:
1. Telegram bot integration
2. State persistence (SQLite)
3. Multi-location configuration

## License

MIT License

## Credits

- Data source: [PAGASA](https://www.pagasa.dost.gov.ph/)
- Developed for Cebu-based tourism/operations teams
- Built with Claude Code

## Support

For issues or questions:
- Check debug output: `DEBUG=1 pipenv run python pagasa_alert_poc.py`
- Verify PAGASA URLs are accessible
- Ensure Python 3.7+ is installed
