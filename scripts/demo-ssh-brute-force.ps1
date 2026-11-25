<#
    demo-ssh-brute-force.ps1
    ------------------------
    Validation attack for the wazuh-ai-triager project.

    Executed from the attacker Windows 10 box against the Ubuntu Wazuh
    manager. Fires repeated SSH login attempts with a non-existent user
    to trip Wazuh rules 5710 (non-existent user), 5712 (brute force),
    and 5720 (multiple auth failures).

    Expected outcome on the Wazuh host:
      - alerts.json receives Level 5 / Level 10 SSH events
      - triager.py picks each one up within POLL_INTERVAL seconds
      - Groq produces a plain-English triage
      - Postfix → msmtp → Gmail delivers it to the target phone
      - The same alerts also appear live in the Wazuh dashboard
        (Threat Hunting → filter rule.id:5710 OR 5712 OR 5720)

    WARNING: Only run this against a lab host you own. Deliberately
    failing SSH logins against a production host is a hostile act and
    will be logged as such.

    Author: Oreoluwa Ofomiyonwon
#>

# ===== CONFIG — edit these two lines =====
$Target     = '192.168.0.192'        # Wazuh manager IP on your LAN
$BadUser    = 'wronguser'            # Non-existent user to trigger rule 5710
$Attempts   = 10                     # How many ssh calls to make
$GapSeconds = 2                      # Pause between attempts

# ===== RUN =====
Write-Host "[*] wazuh-ai-triager demo attack" -ForegroundColor Cyan
Write-Host "[*] Target: $Target"
Write-Host "[*] Bad user: $BadUser"
Write-Host "[*] Attempts: $Attempts (gap $GapSeconds s)"
Write-Host ""
Write-Host "[*] On the Wazuh host, make sure the watcher is running:" -ForegroundColor Yellow
Write-Host "    source .venv/bin/activate && python3 triager.py"
Write-Host ""
Write-Host "[*] Press Enter to start the attack..."
Read-Host | Out-Null

for ($i = 1; $i -le $Attempts; $i++) {
    Write-Host "[Attempt $i/$Attempts] ssh $BadUser@$Target" -ForegroundColor Red
    # Cancel the password prompt almost immediately so we move on to the
    # next failed-login attempt. Each cancelled login still writes a
    # failed-auth event to the target's auth log, which Wazuh reads.
    Start-Process -FilePath 'ssh' `
                  -ArgumentList "-o StrictHostKeyChecking=no -o ConnectTimeout=5 $BadUser@$Target exit" `
                  -NoNewWindow -Wait
    Start-Sleep -Seconds $GapSeconds
}

Write-Host ""
Write-Host "[*] Attack complete. Check:" -ForegroundColor Cyan
Write-Host "    1. The triager terminal on the Wazuh host — new alerts should be processing"
Write-Host "    2. Your Gmail inbox — AI Triage emails should be arriving"
Write-Host "    3. Wazuh dashboard → Threat Hunting → filter rule.id:(5710 OR 5712 OR 5720)"
