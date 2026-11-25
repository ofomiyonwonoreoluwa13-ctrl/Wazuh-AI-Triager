"""
triager.py
----------
Watches Wazuh's alerts.json in real time. For every new alert at or above
MIN_LEVEL, asks a Groq-hosted LLM for a plain-English triage write-up and
emails it via the local Postfix → msmtp → Gmail pipeline.

Designed to run inside a Python venv on the Wazuh manager host.

Required environment variables:
    GROQ_API_KEY   — your Groq API key (starts with gsk_)
    EMAIL_TO       — the inbox the triaged alerts should land in

Usage:
    source .venv/bin/activate
    export GROQ_API_KEY="gsk_..."
    export EMAIL_TO="you@example.com"
    python3 triager.py

Author: Oreoluwa Ofomiyonwon
"""

import os
import json
import subprocess
import time
import sys
from groq import Groq

# ===== CONFIG =====
ALERTS_FILE   = os.environ.get("ALERTS_FILE", "/var/ossec/logs/alerts/alerts.json")
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "5"))
MIN_LEVEL     = int(os.environ.get("MIN_LEVEL", "5"))
MODEL         = os.environ.get("GROQ_MODEL", "openai/gpt-oss-120b")

# ===== STARTUP VALIDATION =====
try:
    GROQ_API_KEY = os.environ["GROQ_API_KEY"]
    EMAIL_TO     = os.environ["EMAIL_TO"]
except KeyError as missing:
    sys.exit(
        f"ERROR: environment variable {missing} is not set.\n"
        "       export GROQ_API_KEY and EMAIL_TO before running this script.\n"
        "       See .env.example for the full list."
    )

client = Groq(api_key=GROQ_API_KEY)


def triage_alert(alert_line):
    """Parse one JSON alert line, run it past the LLM, and email the result."""
    try:
        alert = json.loads(alert_line)
    except json.JSONDecodeError:
        # Partial write from Wazuh; skip, next poll will catch it.
        return

    level = alert.get("rule", {}).get("level", 0)
    if level < MIN_LEVEL:
        return

    timestamp   = alert.get("timestamp", "unknown")
    description = alert.get("rule", {}).get("description", "unknown")
    agent_name  = alert.get("agent", {}).get("name", "unknown")
    full_log    = alert.get("full_log", "(no raw log)")

    real_alert = f"""
Timestamp:   {timestamp}
Alert Level: {level}
Description: {description}
Host:        {agent_name}
Raw Log:     {full_log}
"""

    print(f"\n[{timestamp}] Alert level {level}: {description}")
    print("Asking AI for triage...")

    prompt = f"""
You are a SOC analyst assistant. A security alert just fired.
IMPORTANT: Respond in plain text only. Do NOT use any markdown
formatting — no asterisks, no hashes, no backticks, no bullet
characters. Write like a plain email to a colleague.

Explain:
1. What happened in plain English
2. How serious is it on a scale of 1 to 10
3. What the analyst should do next (as a numbered list using 1. 2. 3.)

Alert:
{real_alert}
"""

    response = client.chat.completions.create(
        model=MODEL,
        messages=[{"role": "user", "content": prompt}],
    )
    ai_output = response.choices[0].message.content

    email_subject = f"AI Triage: {description} (Level {level})"
    email_body = f"""Original Wazuh Alert:
{real_alert}

AI Triage Analysis:
{ai_output}

--
Sent by wazuh-ai-triager
"""

    result = subprocess.run(
        ["mail", "-s", email_subject, EMAIL_TO],
        input=email_body,
        text=True,
        capture_output=True,
    )

    if result.returncode == 0:
        print(f"Email sent -> {EMAIL_TO}")
    else:
        print(f"Email failed: {result.stderr}")


def watch_log():
    """Main loop: start at the current tail of the alerts file, then poll."""
    with open(ALERTS_FILE, "r") as f:
        seen_lines = len(f.readlines())

    print(f"Watching {ALERTS_FILE}")
    print(f"Starting at line {seen_lines} (ignoring older alerts)")
    print(f"Triaging alerts at level {MIN_LEVEL}+")
    print(f"Press Ctrl+C to stop\n")

    while True:
        try:
            with open(ALERTS_FILE, "r") as f:
                lines = f.readlines()
            if len(lines) > seen_lines:
                new_alerts = lines[seen_lines:]
                seen_lines = len(lines)
                for alert_line in new_alerts:
                    triage_alert(alert_line)
            time.sleep(POLL_INTERVAL)
        except KeyboardInterrupt:
            print("\nStopped watching.")
            break
        except Exception as e:
            print(f"Error: {e}")
            time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    watch_log()
