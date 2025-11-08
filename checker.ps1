# Comprehensive System Security & Device Scanner
# Fixed: IOMMU & Virtualization | No Section F | Downloads Save | No Duplicates

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "ERROR: This script must be run as Administrator" -ForegroundColor Red
    exit
}

$VendorID = "046D"
$DeviceID = "C53B"
$OutputFile = "$env:USERPROFILE\Downloads\SystemScan_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
$global:SecurityIssues = @()
$global:DetectionResults = @()
$global:FlaggedFileCount = 0
$global:XimDetected = $false
$global:SoftwareDetected = @()

# Create Downloads folder if missing
if (-not (Test-Path "$env:USERPROFILE\Downloads")) {
    try {
        New-Item -Path "$env:USERPROFILE\Downloads" -ItemType Directory -Force | Out-Null
    } catch {
        Write-Host "ERROR: Cannot create Downloads folder." -ForegroundColor Red
        exit
    }
}

# Create output file
try {
    $null = New-Item -Path $OutputFile -ItemType File -Force -ErrorAction Stop
} catch {
    Write-Host "FATAL ERROR: Cannot create output file." -ForegroundColor Red
    exit
}

function Write-Log {
    param($Message, [switch]$NoTimestamp, [string]$Color = "White")
    try {
        if ($NoTimestamp) {
            Write-Host $Message -ForegroundColor $Color
            Add-Content -Path $OutputFile -Value $Message -ErrorAction Stop
        } else {
            $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            $LogMessage = "[$Timestamp] $Message"
            Write-Host $LogMessage -ForegroundColor $Color
            Add-Content -Path $OutputFile -Value $LogMessage -ErrorAction Stop
        }
    } catch {
        Write-Host "LOG ERROR: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Add-Detection {
    param($Location, $Details)
    $global:DetectionResults += [PSCustomObject]@{ Location = $Location; Details = $Details }
}

function IsExtensionMismatch {
    param($FilePath)
    try {
        $bytes = [System.IO.File]::ReadAllBytes($FilePath) | Select-Object -First 4
        $sig = ($bytes | ForEach-Object { "{0:X2}" -f $_ }) -join ' '
        $ext = [System.IO.Path]::GetExtension($FilePath).ToLower()
        if ($ext -in @('.jpg', '.jpeg')) { if ($sig -notlike 'FF D8 FF*') { return $true } }
        elseif ($ext -eq '.png') { if ($sig -notlike '89 50 4E 47') { return $true } }
        elseif ($ext -in @('.txt', '.log', '.doc', '.docx')) { if ($sig -like '4D 5A*') { return $true } }
        return $false
    } catch { return $false }
}

function Is-FileSigned {
    param($FilePath)
    try {
        $sig = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction SilentlyContinue
        return ($sig.Status -eq 'Valid')
    } catch { return $false }
}

# ========================================================
# HEADER
# ========================================================
Write-Log "============================================================" -NoTimestamp -Color Cyan
Write-Log "Computer: $env:COMPUTERNAME | User: $env:USERNAME" -NoTimestamp
Write-Log "Scan Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -NoTimestamp
Write-Log "Report: $OutputFile" -NoTimestamp -Color Gray
Write-Log "============================================================" -NoTimestamp -Color Cyan
Write-Log "" -NoTimestamp

# ========================================================
# SECTION A: SYSTEM INFORMATION
# ========================================================
Write-Log "SECTION A: SYSTEM INFORMATION" -NoTimestamp -Color Yellow
Write-Log "============================================================" -NoTimestamp -Color Yellow
try {
    $OS = Get-CimInstance -ClassName Win32_OperatingSystem
    $InstallDate = $OS.InstallDate
    $DaysSinceInstall = (Get-Date) - $InstallDate
    $Days = [math]::Floor($DaysSinceInstall.TotalDays)
    $Hours = [math]::Floor($DaysSinceInstall.Hours)
    $Minutes = [math]::Floor($DaysSinceInstall.Minutes)
    $Seconds = [math]::Floor($DaysSinceInstall.Seconds)
    Write-Log " Install Date: $($InstallDate.ToString('yyyy-MM-dd HH:mm:ss'))" -Color Cyan
    Write-Log " Time Since Install: $Days days, $Hours hours, $Minutes minutes, $Seconds seconds" -Color Cyan
} catch { Write-Log " ERROR: Could not determine install date" -Color Red }
try {
    $Uptime = (Get-Date) - $OS.LastBootUpTime
    $UptimeDays = [math]::Floor($Uptime.TotalDays)
    $UptimeHours = [math]::Floor($Uptime.Hours)
    $UptimeMinutes = [math]::Floor($Uptime.Minutes)
    Write-Log " Last Boot: $($OS.LastBootUpTime.ToString('yyyy-MM-dd HH:mm:ss'))" -Color Cyan
    Write-Log " Uptime: $UptimeDays days, $UptimeHours hours, $UptimeMinutes minutes" -Color Cyan
} catch {}
try {
    $LogonEvent = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} -MaxEvents 1 -ErrorAction Stop
    $SessionStart = $LogonEvent.TimeCreated
    Write-Log " User Session Start: $($SessionStart.ToString('yyyy-MM-dd HH:mm:ss'))" -Color Cyan
} catch {
    $SessionStart = $OS.LastBootUpTime
    Write-Log " User Session Start: Using last boot time" -Color Yellow
}
Write-Log "" -NoTimestamp

# ========================================================
# SECTION B: SYSTEM SECURITY CONFIGURATION
# ========================================================
Write-Log "SECTION B: SYSTEM SECURITY CONFIGURATION" -NoTimestamp -Color Yellow
Write-Log "============================================================" -NoTimestamp -Color Yellow

Write-Log "Checking Secure Boot" -NoTimestamp
try {
    $SecureBoot = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
    if ($null -eq $SecureBoot) {
        Write-Log " Result: NOT SUPPORTED (Legacy BIOS)" -Color Yellow
    } elseif ($SecureBoot) {
        Write-Log " Result: ENABLED" -Color Green
    } else {
        Write-Log " Result: DISABLED" -Color Red
    }
} catch { Write-Log " Result: UNKNOWN" -Color Yellow }

Write-Log "Checking Core Isolation" -NoTimestamp
try {
    $CoreIsolation = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -ErrorAction SilentlyContinue
    if ($CoreIsolation.Enabled -eq 1) {
        Write-Log " Result: ENABLED" -Color Green
    } else {
        Write-Log " Result: DISABLED" -Color Red
    }
} catch { Write-Log " Result: DISABLED" -Color Red }

Write-Log "Checking Virtualization" -NoTimestamp
try {
    $CPU = Get-CimInstance -ClassName Win32_Processor
    $VirtualizationEnabled = $false
    foreach ($Processor in $CPU) {
        if ($Processor.VirtualizationFirmwareEnabled) { $VirtualizationEnabled = $true; break }
    }
    if ($VirtualizationEnabled) {
        Write-Log " Result: ENABLED" -Color Green
    } else {
        Write-Log " Result: DISABLED" -Color Red
    }
} catch { Write-Log " Result: UNKNOWN" -Color Yellow }

Write-Log "Checking IOMMU" -NoTimestamp
try {
    $VBS = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
    $DMAProtection = $false
    if ($VBS.AvailableSecurityProperties -contains 2) { $DMAProtection = $true }
    if ($DMAProtection) {
        Write-Log " Result: ENABLED (DMA Protection Active)" -Color Green
    } else {
        Write-Log " Result: DISABLED or NOT AVAILABLE" -Color Yellow
    }
} catch { Write-Log " Result: UNKNOWN" -Color Yellow }
Write-Log "" -NoTimestamp

# ========================================================
# SECTION C: Possible Spoofed USB's | Xim Matrix
# ========================================================
Write-Log "SECTION C: Possible Spoofed USB's | Xim Matrix" -NoTimestamp -Color Yellow
Write-Log "============================================================" -NoTimestamp -Color Yellow

Write-Log "[1/3] Enumerating all connected USB/HID devices..." -NoTimestamp
try {
    $AllUSBDevices = Get-PnpDevice | Where-Object { 
        $_.Class -in @("HIDClass", "USB", "Mouse", "Keyboard") -and $_.Status -eq "OK" 
    }

    # === DEDUPLICATE BY VID + PID ===
    $Seen = @{}
    $UniqueDevices = @()
    foreach ($Device in $AllUSBDevices) {
        $InstanceID = $Device.InstanceId
        if ($InstanceID -match 'VID_([0-9A-F]{4}).*PID_([0-9A-F]{4})') {
            $DeviceVID = $Matches[1]
            $DevicePID = $Matches[2]
            $key = "$DeviceVID`_$DevicePID"
            if (-not $Seen.ContainsKey($key)) {
                $Seen[$key] = $true
                $UniqueDevices += $Device
            }
        }
    }

    Write-Log " Found $($UniqueDevices.Count) unique USB/HID device(s):" -Color Cyan
    $DeviceCount = 0
    foreach ($Device in $UniqueDevices) {
        $DeviceCount++
        $InstanceID = $Device.InstanceId
        $DeviceVID = if ($InstanceID -match 'VID_([0-9A-F]{4})') { $Matches[1] } else { "Unknown" }
        $DevicePID = if ($InstanceID -match 'PID_([0-9A-F]{4})') { $Matches[1] } else { "Unknown" }
        Write-Log "  [$DeviceCount] $($Device.FriendlyName) - VEN_$DeviceVID & PID_$DevicePID" -Color Gray
    }
} catch {
    Write-Log " ERROR: Could not enumerate USB devices - $($_.Exception.Message)" -Color Red
}
Write-Log "" -NoTimestamp

Write-Log "[2/3] Scanning for XIM Matrix" -NoTimestamp
$XimLive = $false
try {
    $AllDevices = Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "OK" }
    foreach ($Device in $AllDevices) {
        $InstanceID = $Device.InstanceId
        if ($InstanceID -like "*VID_$VendorID*" -and $InstanceID -like "*PID_$DeviceID*") {
            $DeviceVID = if ($InstanceID -match 'VID_([0-9A-F]{4})') { $Matches[1] } else { "Unknown" }
            $DevicePID = if ($InstanceID -match 'PID_([0-9A-F]{4})') { $Matches[1] } else { "Unknown" }
            Write-Log " [DETECTED] XIM Matrix Device Found!" -Color Red
            Write-Log "     Device Name: $($Device.FriendlyName) - VEN_$DeviceVID & PID_$DevicePID" -Color Red
            Write-Log "     Status: $($Device.Status)" -Color Red
            Add-Detection "USB Device" "XIM Matrix detected: $($Device.FriendlyName) - $InstanceID"
            $XimLive = $true
        }
    }
    if (-not $XimLive) {
        Write-Log " Result: NO XIM MATRIX DEVICE CURRENTLY CONNECTED" -Color Green
    }
} catch { Write-Log " ERROR: $($_.Exception.Message)" -Color Red }
Write-Log "" -NoTimestamp

Write-Log "[3/3] Scanning USB registry for XIM Matrix traces" -NoTimestamp
$XimRegistry = $false
try {
    $USBEnumPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\USB"
    if (Test-Path $USBEnumPath) {
        $USBKeys = Get-ChildItem -Path $USBEnumPath -ErrorAction SilentlyContinue
        foreach ($Key in $USBKeys) {
            if ($Key.PSChildName -match "VID_$VendorID.*PID_$DeviceID") {
                Write-Log " [DETECTED] XIM Registry Entry Found!" -Color Red
                Write-Log "     Registry Path: $($Key.PSPath)" -Color Red
                Add-Detection "Registry" "XIM Matrix registry trace: $($Key.PSPath)"
                $XimRegistry = $true
            }
        }
    }
    if (-not $XimRegistry) {
        Write-Log " Result: NO XIM MATRIX REGISTRY TRACES FOUND" -Color Green
    }
} catch { Write-Log " ERROR: $($_.Exception.Message)" -Color Red }
Write-Log "" -NoTimestamp

# ========================================================
# SECTION D: SUSPICIOUS FILE DETECTION
# ========================================================
Write-Log "SECTION D: SUSPICIOUS FILE DETECTION" -NoTimestamp -Color Yellow
Write-Log "============================================================" -NoTimestamp -Color Yellow

$SuspiciousPatterns = @(
    "*xim*matrix*", "*ximmatrix*", "*xim_matrix*", "*xim-matrix*",
    "*cronusmax*", "*cronus*zen*", "*cronus_zen*", "*cronus-zen*",
    "*aimbot*.exe", "*triggerbot*.exe", "*wallhack*.exe", "*esp*hack*.exe",
    "*cheat*engine*.exe", "*cheat*.dll", "*cheat*.sys",
    "*norecoil*.exe", "*no*recoil*.exe", "*anti*recoil*.exe",
    "*injector*.exe", "*dll*inject*.exe", "*process*inject*.exe",
    "*hwid*spoof*.exe", "*spoofer*.exe", "*ban*bypass*.exe",
    "*kernel*driver*.sys", "*kdmapper*.exe", "*drvmap*.exe",
    "dapper.dll", "*dapper*.dll"
)

$ExcludePaths = @("*\WindowsApps\*", "*\Python\*\Scripts\*")

$ScanPaths = @(
    @{Path="$env:USERPROFILE\Downloads"; Name="Downloads"},
    @{Path="$env:USERPROFILE\Documents"; Name="Documents"},
    @{Path="$env:USERPROFILE\Desktop"; Name="Desktop"},
    @{Path="$env:TEMP"; Name="Temp"},
    @{Path="$env:LOCALAPPDATA"; Name="LocalAppData"},
    @{Path="$env:APPDATA"; Name="AppData"},
    @{Path="C:\Windows\System32"; Name="System32"},
    @{Path="C:\Windows\SysWOW64"; Name="SysWOW64"}
)

$SuspiciousFiles = @()

foreach ($Location in $ScanPaths) {
    if (-not (Test-Path $Location.Path)) { continue }
    foreach ($Pattern in $SuspiciousPatterns) {
        $Files = Get-ChildItem -Path $Location.Path -Filter $Pattern -Recurse -ErrorAction SilentlyContinue -Depth 4 |
                 Where-Object { $_.Extension -ne '.lnk' }
        foreach ($File in $Files) {
            $hash = (Get-FileHash $File.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
            $SuspiciousFiles += [PSCustomObject]@{
                Name = $File.Name; Path = $File.FullName; Size = [math]::Round($File.Length/1MB,2)
                Modified = $File.LastWriteTime; Hash = $hash; Label = "CHEAT_PATTERN"
            }
        }
    }
    $ExeFiles = Get-ChildItem -Path $Location.Path -Recurse -Filter "*.exe" -ErrorAction SilentlyContinue -Depth 4 |
                Where-Object { $_.Length -gt 0 -and $_.Extension -ne '.lnk' }
    foreach ($File in $ExeFiles) {
        $fullPath = $File.FullName
        if (-not ($ExcludePaths | Where-Object { $fullPath -like $_ })) {
            if (-not (Is-FileSigned $fullPath)) {
                $hash = (Get-FileHash $fullPath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                $SuspiciousFiles += [PSCustomObject]@{
                    Name = $File.Name; Path = $fullPath; Size = [math]::Round($File.Length/1MB,2)
                    Modified = $File.LastWriteTime; Hash = $hash; Label = "UNSIGNED"
                }
            }
        }
    }
    $Mismatch = Get-ChildItem -Path $Location.Path -Recurse -File -ErrorAction SilentlyContinue -Depth 4 |
                Where-Object { $_.Extension -in '.jpg','.jpeg','.png','.txt','.log','.doc','.docx' }
    foreach ($File in $Mismatch) {
        if (IsExtensionMismatch $File.FullName) {
            $hash = (Get-FileHash $File.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
            $SuspiciousFiles += [PSCustomObject]@{
                Name = $File.Name; Path = $File.FullName; Size = [math]::Round($File.Length/1MB,2)
                Modified = $File.LastWriteTime; Hash = $hash; Label = "EXTENSION_MISMATCH"
            }
        }
    }
}

$SuspiciousFiles = $SuspiciousFiles | Sort-Object Path -Unique
$global:FlaggedFileCount = $SuspiciousFiles.Count

if ($SuspiciousFiles.Count) {
    Write-Log " Result: FOUND $($SuspiciousFiles.Count) SUSPICIOUS FILE(S)" -Color Red
    foreach ($f in $SuspiciousFiles) {
        Write-Log " - [$($f.Label)] $($f.Name)" -Color Red
        Write-Log "   Path: $($f.Path)" -Color Red
        Write-Log "   Size: $($f.Size) MB | Hash: $($f.Hash)" -Color Red
    }
} else {
    Write-Log " Result: NO SUSPICIOUS FILES DETECTED" -Color Green
}
Write-Log "" -NoTimestamp

# ========================================================
# SECTION E: MONITOR INFORMATION
# ========================================================
Write-Log "SECTION E: MONITOR INFORMATION" -NoTimestamp -Color Yellow
Write-Log "============================================================" -NoTimestamp -Color Yellow

$MonitorCount = 0
try {
    $WmiMonitors = Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorID -ErrorAction SilentlyContinue
    foreach ($Mon in $WmiMonitors) {
        $MonitorCount++
        $Man = ($Mon.ManufacturerName | ForEach-Object { [char]$_ } | Where-Object { $_ -ge 32 }) -join ''
        $Model = ($Mon.ProductCodeID | ForEach-Object { [char]$_ } | Where-Object { $_ -ge 32 }) -join ''
        $Name = "$Man $Model".Trim()
        if (-not $Name -or $Name -eq " ") { $Name = "Unknown Monitor" }

        $IsActive = $Mon.Active -eq $true

        Write-Log "Monitor $MonitorCount" -Color White
        Write-Log "Name: $Name" -Color White
        Write-Log "Status: $(if($IsActive){'CONNECTED'}else{'DISCONNECTED'})" -Color $(if($IsActive){'Green'}else{'Gray'})
        Write-Log "" -NoTimestamp
    }
} catch { }

if ($MonitorCount -eq 0) {
    Write-Log " No monitors detected." -Color Yellow
}
Write-Log "" -NoTimestamp

# ========================================================
# SECTION G: POWERSHELL COMMAND HISTORY
# ========================================================
Write-Log "SECTION G: POWERSHELL COMMAND HISTORY" -NoTimestamp -Color Yellow
Write-Log "============================================================" -NoTimestamp -Color Yellow

$historyFile = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
if (Test-Path $historyFile) {
    $last50 = Get-Content $historyFile -Tail 50 -ErrorAction SilentlyContinue
    Write-Log " Last 50 PowerShell commands:" -Color Cyan
    $cmdCount = 0
    foreach ($cmd in $last50) {
        $cmdCount++
        Write-Log " [$cmdCount] $cmd" -Color Gray
    }
} else {
    Write-Log " No PowerShell history file found" -Color Yellow
}
Write-Log "" -NoTimestamp

# ========================================================
# SECTION H: WINDOWS DEFENDER CONFIGURATION
# ========================================================
Write-Log "SECTION H: WINDOWS DEFENDER CONFIGURATION" -NoTimestamp -Color Yellow
Write-Log "============================================================" -NoTimestamp -Color Yellow

Write-Log "Windows Defender Exclusions:" -NoTimestamp
try {
    $pref = Get-MpPreference -ErrorAction SilentlyContinue
    if ($pref.ExclusionPath) {
        Write-Log " Paths:" -Color Cyan
        foreach ($ex in $pref.ExclusionPath) { Write-Log " - $ex" -Color Gray }
    } else {
        Write-Log " No exclusions configured" -Color Green
    }
} catch { Write-Log " ERROR: Could not retrieve Defender preferences" -Color Red }

Write-Log "Windows Defender Detection History:" -NoTimestamp
try {
    $threats = Get-MpThreatDetection -ErrorAction SilentlyContinue | Sort-Object DetectionTime -Descending | Select-Object -First 50
    if ($threats) {
        foreach ($threat in $threats) {
            Write-Log " Detection Time: $($threat.DetectionTime)" -Color Gray
            Write-Log " Threat Name: $($threat.ThreatName)" -Color Gray
            Write-Log " Path: $($threat.InitialDetectionPath)" -Color Gray
            Write-Log " Action: $($threat.ActionStatus)" -Color Gray
            Write-Log "---" -NoTimestamp
        }
    } else {
        Write-Log " No recent threat detections" -Color Green
    }
} catch { Write-Log " ERROR: Could not retrieve Defender history" -Color Red }
Write-Log "" -NoTimestamp

# ========================================================
# SOFTWARE CHECK: Logitech G HUB / Razer Synapse
# ========================================================
if (Test-Path "$env:PROGRAMFILES\LGHUB\lghub.exe") { $global:SoftwareDetected += "Logitech G HUB" }
if (Test-Path "$env:PROGRAMFILES\Razer\Synapse3") {
    if (Get-ChildItem "$env:PROGRAMFILES\Razer\Synapse3" -Filter "RzDev_*.exe" -ErrorAction SilentlyContinue) {
        $global:SoftwareDetected += "Razer Synapse"
    }
}
elseif (Test-Path "$env:PROGRAMFILES\Razer\Synapse\RzSynapse.exe") {
    $global:SoftwareDetected += "Razer Synapse (Legacy)"
}

# ========================================================
# FINAL REPORT
# ========================================================
Write-Log "============================================================" -NoTimestamp -Color Cyan
Write-Log "SCAN SUMMARY" -NoTimestamp -Color Yellow
Write-Log "============================================================" -NoTimestamp -Color Cyan

$XimFound = $XimLive -or $XimRegistry -or ($global:DetectionResults.Details -match "XIM Matrix")
Write-Log "XIM Matrix Device: $(if($XimFound){'DETECTED'}else{'NOT DETECTED'})" -Color $(if($XimFound){'Red'}else{'Green'})
Write-Log "Unsigned Files: $($global:FlaggedFileCount)" -Color $(if($global:FlaggedFileCount -gt 0){'Red'}else{'Green'})
Write-Log "Possible Macro Software: $(if($global:SoftwareDetected.Count -gt 0){$global:SoftwareDetected -join ', '}else{'Not Found'})" -Color $(if($global:SoftwareDetected.Count -gt 0){'Yellow'}else{'Gray'})

Write-Log "" -NoTimestamp
Write-Log "Scan complete. Full report saved to: $OutputFile" -NoTimestamp -Color Cyan
Write-Log "============================================================" -NoTimestamp -Color Cyan