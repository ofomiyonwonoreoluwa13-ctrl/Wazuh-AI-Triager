# Setup Walkthrough

End-to-end setup for the `wazuh-ai-triager` on a Wazuh manager host running Ubuntu LTS. Assumes the base `wazuh-siem-home-lab` is already working — the triager reads the alerts file that the SIEM is already writing, and uses the same Postfix + msmtp relay the SIEM already uses for its own emails.

---

## 0. Prerequisites

Before installing the triager you need:

- A working Wazuh 4.x manager that is writing to `/var/ossec/logs/alerts/alerts.json`
- The Postfix + msmtp + Gmail relay from the base SIEM lab (so `echo "test" | mail -s "test" you@example.com` already lands in your inbox from the Wazuh host)
- A Groq API key — free at <https://console.groq.com/keys>
- Shell access to the Wazuh manager host

Verify the email relay works before you do anything else:

```bash
echo "Triager pre-flight check" | mail -s "Pre-flight from Ubuntu" you@example.com
```

If that doesn't arrive in your inbox, fix the base SIEM lab first — the triager depends on it.

---

## 1. Install system packages

```bash
sudo apt update
sudo apt install python3-venv python3-pip -y
```

---

## 2. Clone the repo

```bash
cd ~
git clone https://github.com/ofomiyonwonoreoluwa13-ctrl/wazuh-ai-triager.git
cd wazuh-ai-triager
```

---

## 3. Create a Python virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

You should now see `(.venv)` in front of your prompt. All Python commands from here assume the venv is active.

---

## 4. Grant the watcher read access to Wazuh's alerts file

By default `/var/ossec/` and everything under it is locked to the `wazuh` user. The watcher needs permission to read `alerts.json` and to traverse its parent directories. The simplest lab-grade fix:

```bash
sudo chmod o+rx /var/ossec/
sudo chmod o+rx /var/ossec/logs/
sudo chmod o+rx /var/ossec/logs/alerts/
sudo chmod o+r  /var/ossec/logs/alerts/alerts.json
```

**You have to re-run these four lines every time Wazuh restarts or rotates the alerts file.** For a one-time lab demo that's fine. For anything longer-lived, add the watcher's user to the `wazuh` group and set the mode in `ossec.conf` instead of chmod-ing world-readable.

---

## 5. Set your secrets

Never put API keys in code.

```bash
export GROQ_API_KEY="gsk_your_actual_key_here"
export EMAIL_TO="you@example.com"
```

Verify they are set:

```bash
echo "$GROQ_API_KEY" | head -c 4   # should print: gsk_
echo "$EMAIL_TO"
```

If you want them to persist across logins, append the two `export` lines to `~/.bashrc` — but **never** commit a file that contains the real key.

---

## 6. Run the watcher

```bash
python3 triager.py
```

Expected output:

```
Watching /var/ossec/logs/alerts/alerts.json
Starting at line 10342 (ignoring older alerts)
Triaging alerts at level 5+
Press Ctrl+C to stop
```

It is now waiting. Any new alert Wazuh writes at Level 5+ will be picked up within 5 seconds.

---

## 7. Trigger a real alert — SSH brute force

From a second machine on the same LAN (the attacker box — Windows PowerShell or any Linux shell with the `ssh` client), hammer the Wazuh host:

```powershell
# Windows PowerShell on the attacker box
1..10 | ForEach-Object {
    ssh wronguser@192.168.0.192
    # cancel each prompt after a few wrong passwords
}
```

Or the equivalent on Linux:

```bash
for i in {1..10}; do ssh wronguser@192.168.0.192; done
```

Within a few seconds, the triager's terminal will start printing:

```
[2026-11-19T12:54:11+0000] Alert level 5: sshd: authentication failed.
Asking AI for triage...
Email sent -> you@example.com
```

Check your phone. A new Gmail notification should be sitting there with the subject `AI Triage: sshd: authentication failed. (Level 5)` and the AI's write-up in the body.

---

## 8. Cross-check on the Wazuh dashboard

Everything the triager emails is also being written to the Wazuh dashboard independently. Open the dashboard in a browser, go to **Threat Hunting**, and filter by:

```
rule.id:(5710 OR 5712 OR 5720)
```

You should see the same SSH authentication events the triager just emailed, with the same timestamps. The dashboard is Wazuh's native view; the triager is the "wakeup call" layer on top. Both running in parallel is exactly how a real SOC splits investigation (dashboard) from notification (pager).

---

## Stopping the watcher

`Ctrl+C` in the terminal running `triager.py`. It will print `Stopped watching.` and exit cleanly.

---

## Troubleshooting

**`ERROR: environment variable 'GROQ_API_KEY' is not set`** — you forgot step 5, or you're in a new shell that doesn't have the exports. Re-run them.

**`PermissionError: [Errno 13] alerts.json`** — Wazuh rotated the file and reset its permissions. Re-run step 4.

**`404 model not found`** — Groq retired the model named in `GROQ_MODEL`. List live models and pin a current one:

```bash
python3 -c "from groq import Groq; import os; print([m.id for m in Groq(api_key=os.environ['GROQ_API_KEY']).models.list().data])"
export GROQ_MODEL="openai/gpt-oss-120b"   # or whichever is live
```

**The watcher runs but no email arrives** — the relay is broken, not the triager. Run the pre-flight `mail` command from step 0 and work backwards: `mail.log` is at `/var/log/mail.log`.

**AI output comes back full of `**asterisks**`** — your Groq model is ignoring the plain-text instruction. Either swap to a better-behaved model (`openai/gpt-oss-120b` behaves) or add a regex pass in `triage_alert()` to strip markdown before emailing.
