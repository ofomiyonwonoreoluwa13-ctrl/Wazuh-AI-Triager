# wazuh-ai-triager

An AI-powered alert triage layer for Wazuh. A Python watcher reads real Wazuh alerts from `alerts.json` in real time, hands each one to an LLM for plain-English analysis, and emails the triaged alert to a phone — subject, severity, what to do next.

Built as the second module of my Tier 1 SOC Analyst portfolio, on top of my [wazuh-siem-home-lab](https://github.com/ofomiyonwonoreoluwa13-ctrl/Wazuh-siem-home-lab) project. The SIEM lab proves I can detect; this proves I can triage.

---

## The Problem It Solves

A real SOC drowns in alerts. A Level 5 "failed password" looks identical to the next hundred Level 5 failed passwords — and buried in that noise is the one that matters. A Tier 1 analyst's first job is to pick up an alert, read the raw log, work out what actually happened, score the severity, and recommend a next action. That's exactly what this triager automates: it watches the Wazuh alerts file, and for every new alert at Level 5 or above, it produces the kind of short write-up a Tier 1 analyst would hand to a Tier 2.

End-to-end, from attack to triaged email on my phone, it runs in under 60 seconds.

---

## Architecture

```
┌──────────────────────────────┐          ┌──────────────────────────────────────┐
│  Windows 10 attacker box     │          │  Ubuntu — Wazuh-Soc (192.168.0.192)  │
│  192.168.0.211               │          │                                      │
│                              │  SSH     │  ┌────────────────────────────────┐  │
│  PowerShell:                 │ ─────►   │  │  sshd + Wazuh agent            │  │
│    ssh wrong@192.168.0.192   │ brute    │  │       │                        │  │
│    (x 10 with bad passwords) │ force    │  │       ▼                        │  │
└──────────────────────────────┘          │  │  wazuh-analysisd (rules 5710/  │  │
                                          │  │                   5712/5720)   │  │
                                          │  │       │                        │  │
                                          │  │       ▼                        │  │
                                          │  │  /var/ossec/logs/alerts/       │  │
                                          │  │  alerts.json                   │  │
                                          │  │       │                        │  │
                                          │  │       ▼                        │  │
                                          │  │  triager.py (polls every 5s)   │  │
                                          │  │       │                        │  │
                                          │  │       ▼                        │  │
                                          │  │  Groq API (openai/gpt-oss-120b)│  │
                                          │  │       │                        │  │
                                          │  │       ▼                        │  │
                                          │  │  mail → Postfix → msmtp        │  │
                                          │  │       │                        │  │
                                          │  └───────┼────────────────────────┘  │
                                          │          ▼                           │
                                          │    Gmail SMTP (TLS)                  │
                                          └──────────┼───────────────────────────┘
                                                     ▼
                                              📧 Phone inbox
                                           "AI Triage: SSHD authentication failed
                                            (Level 5)"
```

Same Wazuh manager and email pipeline as the base SIEM lab. The triager is an extra layer that reads what Wazuh has already detected and adds human-readable analysis on top.

---

## Stack

| Layer | Component |
|---|---|
| SIEM | Wazuh 4.14 (manager + indexer + dashboard) |
| Attacker host | Windows 10 PowerShell SSH client |
| Target host | Ubuntu LTS with OpenSSH server |
| Watcher runtime | Python 3.12 inside a `venv`, polling `alerts.json` every 5s |
| LLM backend | Groq API (`openai/gpt-oss-120b`) |
| Email relay | Postfix + msmtp + Gmail SMTP (TLS) |
| Transport from Python | `subprocess.run(["mail", "-s", ...])` into the same Postfix instance |

---

## What It Does

**Watches the Wazuh alerts file in real time.** `triager.py` opens `/var/ossec/logs/alerts/alerts.json`, records the current line count, and polls every 5 seconds for new lines. Each new line is one alert in JSON. The watcher is stateless beyond the line count — it doesn't need a database — and it recovers cleanly from `JSONDecodeError` on a mid-write line.

**Filters by severity.** Only Level 5 and above go to the LLM. Lower-level rules are preserved in the Wazuh dashboard but kept off the email path so the phone doesn't buzz on noise.

**Produces Tier 1 triage in plain English.** Each alert is sent to Groq with a prompt asking for:
1. What happened, in plain English
2. A severity score out of 10, with the model's own reasoning
3. A numbered list of next actions

The prompt explicitly forbids markdown — no asterisks, no backticks, no hashes — so the output lands in Gmail as clean readable text rather than raw `**bold**` syntax.

**Emails the whole thing.** Original Wazuh alert header + AI triage, piped through `mail` → Postfix → msmtp → Gmail → phone. Subject line is `AI Triage: <rule description> (Level <n>)` so the inbox is scannable at a glance.

---

## Simulated Attack — SSH Brute Force (Nov 19, 12:54)

The validation attack. Windows 10 box (`192.168.0.211`) spraying bad SSH passwords at the Ubuntu Wazuh manager (`192.168.0.192`) from an elevated PowerShell:

```powershell
# From the attacker Windows box
1..10 | ForEach-Object {
    ssh wronguser@192.168.0.192
    # (each prompt cancelled after three wrong attempts)
}
```

Within seconds, `alerts.json` filled with:
- Rule **5710** — "Attempt to login using a non-existent user" (Level 5)
- Rule **5712** — "sshd: brute force trying to get access to the system" (Level 10)
- Rule **5720** — "sshd: Multiple authentication failures" (Level 10)

Each one was picked up by the watcher, triaged by the LLM, and emailed. Five emails hit the phone in under a minute. The dashboard's Threat Hunting view showed the same events at the same time — so you can corroborate every email with a dashboard entry.

---

## Detection Evidence

Screenshots live in [`evidence/`](evidence/). The three key ones:

- `evidence/01-watcher-running.jpg` — Ubuntu terminal with the `triager.py` watcher processing five live SSH alerts back-to-back: each one `[timestamp] Alert level N: <description>` → `Asking AI for triage...` → `Email sent -> oreoluwabus105@gmail.com`.
- `evidence/02-ai-triage-ssh-failed-password.png` — Gmail on phone. Subject: `AI Triage: sshd: authentication failed. (Level 5)`. Body carries the original Wazuh alert header plus the AI's plain-English triage — what happened, severity 4/10, numbered next steps.
- `evidence/03-ai-triage-connection-reset.png` — Gmail on phone. Subject: `AI Triage: SSHD authentication failed. (Level 5)`. Different rule, same triage shape — proving the pipeline handles multiple alert types, not a one-off.

---

## The Code

The whole watcher is one file — [`triager.py`](triager.py). The important parts:

**Polling the alert file.** No inotify, no tail -F. Just Python counting lines on a 5-second timer. In a lab this is enough and it fails gracefully when Wazuh rotates the file.

```python
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
        break
    except Exception as e:
        print(f"Error: {e}")
        time.sleep(POLL_INTERVAL)
```

**The prompt.** Prescriptive, plain-text-only, with a numbered-list demand so the output is consistent across alerts:

```python
prompt = f"""
You are a SOC analyst assistant. A security alert just fired.
IMPORTANT: Respond in plain text only. Do NOT use any markdown
formatting — no asterisks, no hashes, no backticks, no bullet
characters. Write like a plain email to a colleague.

Explain:
1. What happened in plain English
2. How serious is it on a scale of 1 to 10
3. What the analyst should do next (as a numbered list using 1. 2. 3.)
"""
```

**Secrets handling.** The Groq API key is read from the `GROQ_API_KEY` environment variable — never hardcoded, never committed. The email recipient is read from `EMAIL_TO` (see `.env.example`).

---

## Lab Journey — The Fixes That Mattered

**The Gemini API key format trap.** Started on Google Gemini. Every API key I generated began with `AQ.` instead of the `AIza` prefix every tutorial expected, and every request came back `ACCESS_TOKEN_TYPE_UNSUPPORTED (401)`. The newer Google Cloud API-key flow issues a different token type than the older `AIza` keys most SDKs assume. Rather than fight the SDK, I pivoted the whole backend to Groq, whose keys (`gsk_...`) work with the official Python SDK out of the box. Lesson: when a vendor's SDK and its own portal disagree, switch vendors — the LLM output is interchangeable, the integration time isn't.

**Groq model deprecation, mid-build.** My first working version used `llama-3.3-70b-versatile`. One day later: `404, model not found`. Swapped to `llama-3.1-8b-instant`. 404 again. Groq had retired both in the window I was working. Wrote a three-line `list_models.py` that calls `client.models.list()` and prints every active model. Picked `openai/gpt-oss-120b` from the live list. Pinned it. Lesson: don't assume a model string from a blog post is still active — query the provider first.

**Permissions on `/var/ossec/logs/alerts/alerts.json`.** First run of the watcher: `PermissionError: [Errno 13]`. The alerts file is owned by `wazuh:wazuh` and the directory tree is restricted. Fixed with:

```bash
sudo chmod o+rx /var/ossec/
sudo chmod o+rx /var/ossec/logs/
sudo chmod o+rx /var/ossec/logs/alerts/
sudo chmod o+r  /var/ossec/logs/alerts/alerts.json
```

The directory `o+rx` matters as much as the file `o+r` — without `x` (execute / traverse) on each parent, you can't descend to the file even if the file itself is readable. The commands have to be re-run each time Wazuh rotates the file or restarts, which is called out in Known Limitations below.

**The "I can't see anything working" moment.** The first version of the triager just printed JSON to the terminal. That proved the pipeline worked but didn't feel real — I couldn't screenshot anything a hiring manager would understand. The pivot to email delivery was what made the project tangible. A Gmail notification on a phone is proof. A terminal line is a claim.

---

## Known Limitations

**File permissions need re-applying after Wazuh restarts.** Wazuh may rotate `alerts.json` or restart its own services, both of which reset the file ownership. On every lab boot I re-run the four `chmod` commands above before starting the watcher. In production the correct fix is to add the watcher's user to the `wazuh` group and set the file mode via `ossec.conf`, not world-readable shortcuts.

**Polling, not inotify.** The watcher polls every 5 seconds rather than hooking into kernel inotify events. That's a deliberate lab choice (simpler, more portable, easier to debug) and it caps end-to-end latency at `poll_interval + LLM_latency + mail_latency` — in practice under 15 seconds for high-severity events. For a production triager this would be swapped for `watchdog` or `inotifywait`.

**Minimum alert level is hardcoded at 5.** This was a conscious tuning choice — anything lower is noise for this lab. In a bigger environment the threshold would be per-rule or per-category.

**Sensitive data in the email body.** The triager emails the raw Wazuh alert payload alongside the AI analysis. In production, PII and credentials inside logs would need stripping before transit. In this lab, every alert is from my own test VMs.

**Single-threaded.** The watcher handles alerts serially. A real SOC burst would queue them. For a lab generating ~10 alerts a minute at peak, this hasn't been a bottleneck.

---

## Future Work

- Run the watcher as a `systemd` service so it auto-starts with the host and survives reboots cleanly
- Replace the polling loop with `watchdog` / `inotify` for sub-second latency
- Add a severity override layer: if the LLM scores an alert ≥ 8/10, flag it in the email subject (`[HIGH]`) and fire a second channel (Slack webhook / SMS)
- Fine-tune the prompt per rule category — SSH brute force needs a different triage shape than File Integrity Monitoring
- Add a rate limiter / de-duplicator so a sustained brute force doesn't produce 300 near-identical emails in a minute
- Extend to a lightweight Streamlit dashboard showing the last N triaged alerts, searchable, so a Tier 2 can review the queue

---

## Setup

Full step-by-step setup is in [`docs/setup.md`](docs/setup.md). The short version:

```bash
# On the Wazuh manager host
sudo apt install python3-venv python3-pip postfix msmtp bsd-mailx -y
# (configure postfix + msmtp with Gmail app password — see base SIEM lab repo)

git clone https://github.com/ofomiyonwonoreoluwa13-ctrl/wazuh-ai-triager.git
cd wazuh-ai-triager
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Grant the watcher read access to Wazuh's alert file
sudo chmod o+rx /var/ossec/ /var/ossec/logs/ /var/ossec/logs/alerts/
sudo chmod o+r  /var/ossec/logs/alerts/alerts.json

# Export your secrets (do NOT commit these)
export GROQ_API_KEY="gsk_your_key_here"
export EMAIL_TO="you@example.com"

python3 triager.py
```

---

## Repository Structure

```
wazuh-ai-triager/
├── README.md                          # This file
├── LICENSE                            # MIT
├── .gitignore
├── .env.example                       # Template for the two required env vars
├── requirements.txt                   # Python dependencies
├── triager.py                         # The watcher
├── docs/
│   └── setup.md                       # End-to-end setup walkthrough
├── scripts/
│   └── demo-ssh-brute-force.ps1       # The attacker PowerShell script
└── evidence/
    ├── 01-watcher-running.jpg         # Live terminal processing 5 alerts
    ├── 02-ai-triage-ssh-failed-password.png
    ├── 03-ai-triage-connection-reset.png
    └── README.md
```

---

## Author

**Oreoluwa Ofomiyonwon** — Tier 1 SOC Analyst

[LinkedIn](https://linkedin.com/in/oreoluwa-ofomiyonwon-100736306) · [GitHub](https://github.com/ofomiyonwonoreoluwa13-ctrl)
