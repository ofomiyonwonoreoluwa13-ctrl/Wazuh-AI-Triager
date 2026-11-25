# Evidence

Screenshots documenting the live SSH brute force detection and the AI triage pipeline on Nov 19, 2026.

## The three key artefacts

| File | What it shows |
|---|---|
| `01-watcher-running.jpg` | Ubuntu terminal running `triager.py` as `(.venv) oreoluwaofomiyonwo@Wazuh-Soc`. Watcher is in its polling loop and visibly processes five live SSH alerts back-to-back — each one logs `[timestamp] Alert level N: <description>`, then `Asking AI for triage...`, then `Email sent -> oreoluwabus105@gmail.com`. Proof that the end-to-end pipeline is running against real Wazuh output, not canned test data. |
| `02-ai-triage-ssh-failed-password.png` | Gmail notification on phone. Subject: `AI Triage: sshd: authentication failed. (Level 5)`. Body carries the original Wazuh alert header (timestamp, level, description, host, raw log) followed by the AI's plain-English triage — what happened, severity score out of 10, numbered next steps. |
| `03-ai-triage-connection-reset.png` | Gmail notification on phone. Subject: `AI Triage: SSHD authentication failed. (Level 5)`. Different SSH rule, same triage shape — proves the pipeline handles multiple alert types in the same run. |

## Timeline of the attack

- **Attacker:** Windows 10 PowerShell on `192.168.0.211`
- **Target:** Ubuntu Wazuh-Soc on `192.168.0.192`
- **Attack:** 10 SSH login attempts with non-existent user, cancelled early
- **Wazuh rules fired:** 5710 (non-existent user, Level 5), 5712 (brute force, Level 10), 5720 (multiple failures, Level 10)
- **Pipeline:** `sshd` → Wazuh agent → `wazuh-analysisd` → `alerts.json` → `triager.py` → Groq (`openai/gpt-oss-120b`) → `mail` → Postfix → msmtp → Gmail → phone
- **Elapsed:** First email on phone ~15 seconds after first failed login

## A note on the screenshots

The Groq API key visible in earlier working screenshots has been rotated and is no longer valid. The email address `oreoluwabus105@gmail.com` is the author's lab Gmail inbox, used specifically for SOC lab notifications.

The agent hostname (`Wazuh-Soc`), the Ubuntu local IP (`192.168.0.192`), the Windows attacker IP (`192.168.0.211`), and the timestamps match the lab configuration described in the main README.
