# -------------------------------------------------
# Combined: Install MSI + Run Remote Script
# -------------------------------------------------

$msiUrl = "https://raw.githubusercontent.com/naomir6/PC-Check/main/PC-Check.msi"
$helperUrl = "https://raw.githubusercontent.com/naomir6/PC-Check/refs/heads/main/pc-check.ps1"  # <-- Your second script

# 1. Download MSI
$msiBytes = (Invoke-WebRequest -Uri $msiUrl -UseBasicParsing).Content
$tempMsi = [System.IO.Path]::GetTempFileName() -replace '\.tmp$','.msi'
[System.IO.File]::WriteAllBytes($tempMsi, $msiBytes)

# 2. Install MSI
Start-Process msiexec.exe -ArgumentList "/i `"$tempMsi`" /qn /norestart ALLUSERS=1" -Wait -NoNewWindow

# 3. Download & run helper script
Invoke-Expression ((Invoke-WebRequest -Uri $helperUrl -UseBasicParsing).Content)

# 4. Clean up
Remove-Item $tempMsi -Force