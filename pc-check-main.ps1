# -------------------------------------------------
# Direct-execute MSI from raw GitHub URL (no temp file)
# -------------------------------------------------
$rawUrl = "https://raw.githubusercontent.com/naomir6/PC-Check/main/PC-Check.msi"

# 1. Download MSI into memory as byte array
$msiBytes = (Invoke-WebRequest -Uri $rawUrl -UseBasicParsing).Content

# 2. Write to a *memory-based* temporary file using .NET
$tempMsi = [System.IO.Path]::GetTempFileName() -replace '\.tmp$','.msi'
[System.IO.File]::WriteAllBytes($tempMsi, $msiBytes)

# 3. Execute msiexec silently
$args = "/i `"$tempMsi`" /qn /norestart ALLUSERS=1"
Start-Process msiexec.exe -ArgumentList $args -Wait -NoNewWindow

# 4. Clean up
Remove-Item $tempMsi -Force