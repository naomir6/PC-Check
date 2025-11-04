# Comprehensive System Security & Device Scanner
# Checks for: XIM Matrix, suspicious files, security settings, monitors, forensics

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "ERROR: This script must be run as Administrator" -ForegroundColor Red
    exit
}

$VendorID = "046D"
$DeviceID = "C53B"
$OutputFile = "$env:USERPROFILE\Desktop\SystemScan_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
$global:SecurityIssues = @()
$global:DetectionResults = @()
$global:LuaScriptCount = 0
$global:FlaggedFileCount = 0

function Write-Log {
    param($Message, [switch]$NoTimestamp, [string]$Color = "White")
    if ($NoTimestamp) {
        Write-Host $Message -ForegroundColor $Color
        Add-Content -Path $OutputFile -Value $Message
    } else {
        $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $LogMessage = "[$Timestamp] $Message"
        Write-Host $LogMessage -ForegroundColor $Color
        Add-Content -Path $OutputFile -Value $LogMessage
    }
}
function Add-Detection {
    param($Location, $Details)
    $global:DetectionResults += [PSCustomObject]@{
        Location = $Location
        Details = $Details
    }
}
function Add-SecurityIssue {
    param($Category, $Issue, $Severity)
    $global:SecurityIssues += [PSCustomObject]@{
        Category = $Category
        Issue = $Issue
        Severity = $Severity
    }
}

# Registry last-write time
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class Registry {
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern int RegQueryInfoKey(
        IntPtr hKey,
        IntPtr lpClass,
        IntPtr lpcbClass,
        IntPtr lpReserved,
        IntPtr lpcSubKeys,
        IntPtr lpcMaxSubKeyLen,
        IntPtr lpcMaxClassLen,
        IntPtr lpcValues,
        IntPtr lpcMaxValueNameLen,
        IntPtr lpcMaxValueLen,
        IntPtr lpcbSecurityDescriptor,
        out long lpftLastWriteTime
    );
}
"@
function Get-RegistryKeyLastWriteTime {
    param($Path)
    try {
        $hiveMap = @{
            'HKLM' = [Microsoft.Win32.Registry]::LocalMachine
            'HKCU' = [Microsoft.Win32.Registry]::CurrentUser
            'HKCR' = [Microsoft.Win32.Registry]::ClassesRoot
        }
        $hiveKey = $Path -replace ':.*', ''
        $subKey = $Path -replace '.*:\\', ''
        $hive = $hiveMap[$hiveKey]
        if ($hive) {
            $key = $hive.OpenSubKey($subKey)
            if ($key) {
                $ft = 0
                $null = [Registry]::RegQueryInfoKey($key.Handle, $null, $null, $null, $null, $null, $null, $null, $null, $null, $null, [ref]$ft)
                $lastTime = [DateTime]::FromFileTime($ft)
                $key.Close()
                return $lastTime
            }
        }
    } catch {}
    return $null
}

# Extension mismatch
function IsExtensionMismatch {
    param($FilePath)
    try {
        $bytes = [System.IO.File]::ReadAllBytes($FilePath) | Select-Object -First 4
        $sig = ($bytes | ForEach-Object { "{0:X2}" -f $_ }) -join ' '
        $ext = [System.IO.Path]::GetExtension($FilePath).ToLower()
        if ($ext -in @('.jpg', '.jpeg')) {
            if ($sig -notlike 'FF D8 FF*') { return $true }
        } elseif ($ext -eq '.png') {
            if ($sig -notlike '89 50 4E 47') { return $true }
        } elseif ($ext -in @('.txt', '.log', '.doc', '.docx')) {
            if ($sig -like '4D 5A*') { return $true } # MZ = EXE
        }
        return $false
    } catch { return $false }
}

# File signed?
function Is-FileSigned {
    param($FilePath)
    try {
        $sig = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction SilentlyContinue
        return ($sig.Status -eq 'Valid')
    } catch { return $false }
}

# Header
Write-Log "============================================================" -NoTimestamp -Color Cyan
Write-Log "Computer: $env:COMPUTERNAME | User: $env:USERNAME" -NoTimestamp
Write-Log "Scan Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -NoTimestamp
Write-Log "============================================================" -NoTimestamp -Color Cyan
Write-Log "" -NoTimestamp

# ============================================================
# SECTION A: SYSTEM INFORMATION
# ============================================================
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
} catch {
    Write-Log " ERROR: Could not determine install date" -Color Red
}
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
    Write-Log " User Session Start: Using last boot time (could not get logon event)" -Color Yellow
}
Write-Log "" -NoTimestamp

# ============================================================
# SECTION B: SYSTEM SECURITY CONFIGURATION
# ============================================================
Write-Log "SECTION B: SYSTEM SECURITY CONFIGURATION" -NoTimestamp -Color Yellow
Write-Log "============================================================" -NoTimestamp -Color Yellow
# Secure Boot
Write-Log "Checking Secure Boot..." -NoTimestamp
try {
    $SecureBoot = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
    if ($null -eq $SecureBoot) {
        Write-Log " Result: NOT SUPPORTED (Legacy BIOS)" -Color Yellow
        Add-SecurityIssue "Secure Boot" "Not supported or disabled" "MEDIUM"
    } elseif ($SecureBoot) {
        Write-Log " Result: ENABLED" -Color Green
    } else {
        Write-Log " Result: DISABLED" -Color Red
        Add-SecurityIssue "Secure Boot" "Disabled" "HIGH"
    }
} catch {
    Write-Log " Result: UNKNOWN" -Color Yellow
}
# Core Isolation
Write-Log "Checking Core Isolation (Memory Integrity)..." -NoTimestamp
try {
    $CoreIsolation = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -ErrorAction SilentlyContinue
    if ($CoreIsolation.Enabled -eq 1) {
        Write-Log " Result: ENABLED" -Color Green
    } else {
        Write-Log " Result: DISABLED" -Color Red
        Add-SecurityIssue "Core Isolation" "Memory Integrity disabled" "HIGH"
    }
} catch {
    Write-Log " Result: DISABLED" -Color Red
    Add-SecurityIssue "Core Isolation" "Not configured" "HIGH"
}
# Virtualization
Write-Log "Checking Virtualization..." -NoTimestamp
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
        Add-SecurityIssue "Virtualization" "CPU virtualization disabled in BIOS" "MEDIUM"
    }
} catch {
    Write-Log " Result: UNKNOWN" -Color Yellow
}
# IOMMU
Write-Log "Checking IOMMU..." -NoTimestamp
try {
    $VBS = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
    $DMAProtection = $false
    if ($VBS.AvailableSecurityProperties -contains 2) { $DMAProtection = $true }
    if ($DMAProtection) {
        Write-Log " Result: ENABLED (DMA Protection Active)" -Color Green
    } else {
        Write-Log " Result: DISABLED or NOT AVAILABLE" -Color Yellow
        Add-SecurityIssue "IOMMU" "DMA protection not active" "LOW"
    }
} catch {
    Write-Log " Result: UNKNOWN" -Color Yellow
}
Write-Log "" -NoTimestamp

# ============================================================
# SECTION C: PREFETCH (unchanged)
# ============================================================
# [Unchanged – omitted for brevity]

# ============================================================
# SECTION D: RECYCLE BIN (unchanged)
# ============================================================
# [Unchanged – omitted for brevity]

# ============================================================
# SECTION F: SUSPICIOUS FILE SCAN – FULLY VERIFIED
# ============================================================
Write-Log "SECTION F: SUSPICIOUS FILE DETECTION" -NoTimestamp -Color Yellow
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
    "*dapper*.dll"
)

$ExcludePaths = @(
    "*\WindowsApps\*",
    "*\Python\*\Scripts\*"
)

$ScanPaths = @(
    @{Path="$env:USERPROFILE\Downloads"; Name="Downloads"},
    @{Path="$env:USERPROFILE\Documents"; Name="Documents"},
    @{Path="$env:USERPROFILE\Desktop"; Name="Desktop"},
    @{Path="$env:TEMP"; Name="Temp"},
    @{Path="$env:LOCALAPPDATA"; Name="LocalAppData"},
    @{Path="$env:APPDATA"; Name="AppData"}
)

$SuspiciousFiles = @()

foreach ($Location in $ScanPaths) {
    if (-not (Test-Path $Location.Path)) { continue }

    # 1. Pattern Matches
    foreach ($Pattern in $SuspiciousPatterns) {
        $Files = Get-ChildItem -Path $Location.Path -Filter $Pattern -Recurse -ErrorAction SilentlyContinue -Depth 4 |
                 Where-Object { $_.Extension -ne '.lnk' } | Select-Object -First 50
        foreach ($File in $Files) {
            $hash = (Get-FileHash $File.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
            $SuspiciousFiles += [pscustomobject]@{
                Name     = $File.Name
                Path     = $File.FullName
                Size     = [math]::Round($File.Length / 1MB, 2)
                Modified = $File.LastWriteTime
                Hash     = $hash
                Label    = "CHEAT_PATTERN"
            }
            Add-SecurityIssue "Suspicious Files" "Cheat pattern: $($File.Name)" "HIGH"
        }
    }

    # 2. Unsigned EXEs
    $ExeFiles = Get-ChildItem -Path $Location.Path -Recurse -Filter "*.exe" -ErrorAction SilentlyContinue -Depth 4 |
                Where-Object { $_.Length -gt 0 -and $_.Extension -ne '.lnk' } | Select-Object -First 50
    foreach ($File in $ExeFiles) {
        $fullPath = $File.FullName
        if (-not ($ExcludePaths | Where-Object { $fullPath -like $_ })) {
            if (-not (Is-FileSigned $fullPath)) {
                $hash = (Get-FileHash $fullPath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                $SuspiciousFiles += [pscustomobject]@{
                    Name     = $File.Name
                    Path     = $fullPath
                    Size     = [math]::Round($File.Length / 1MB, 2)
                    Modified = $File.LastWriteTime
                    Hash     = $hash
                    Label    = "UNSIGNED"
                }
                Add-SecurityIssue "Suspicious Files" "Unsigned EXE: $($File.Name)" "HIGH"
            }
        }
    }

    # 3. Extension Mismatch
    $PotentialMismatch = Get-ChildItem -Path $Location.Path -Recurse -File -ErrorAction SilentlyContinue -Depth 4 |
                         Where-Object { $_.Extension -in '.jpg','.jpeg','.png','.txt','.log','.doc','.docx' }
    foreach ($File in $PotentialMismatch) {
        if (IsExtensionMismatch $File.FullName) {
            $hash = (Get-FileHash $File.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
            $SuspiciousFiles += [pscustomobject]@{
                Name     = $File.Name
                Path     = $File.FullName
                Size     = [math]::Round($File.Length / 1MB, 2)
                Modified = $File.LastWriteTime
                Hash     = $hash
                Label    = "EXTENSION_MISMATCH"
            }
            Add-SecurityIssue "Suspicious Files" "Extension mismatch: $($File.Name)" "HIGH"
        }
    }
}

$SuspiciousFiles = $SuspiciousFiles | Sort-Object Path -Unique
$global:FlaggedFileCount = $SuspiciousFiles.Count

if ($SuspiciousFiles.Count) {
    Write-Log " Result: FOUND $($SuspiciousFiles.Count) SUSPICIOUS FILE(S)" -Color Red
    foreach ($File in $SuspiciousFiles) {
        Write-Log " - [$($File.Label)] $($File.Name)" -Color Red
        Write-Log "   Path: $($File.Path)" -Color Red
        Write-Log "   Size: $($File.Size) MB | Modified: $($File.Modified) | Hash: $($File.Hash)" -Color Red
    }
} else {
    Write-Log " Result: NO SUSPICIOUS FILES DETECTED" -Color Green
}
Write-Log "" -NoTimestamp

# ============================================================
# SECTION G: MONITOR ANALYSIS (unchanged)
# ============================================================
# [Unchanged – omitted for brevity]

# ============================================================
# SECTION J: LOGITECH G HUB LUA SCRIPTS – COUNT TRACKED
# ============================================================
Write-Log "SECTION J: LOGITECH G HUB LUA SCRIPTS" -NoTimestamp -Color Yellow
Write-Log "============================================================" -NoTimestamp -Color Yellow
$LGHUBPath = "$env:LOCALAPPDATA\LGHUB"
$LuaScripts = @()
if (Test-Path $LGHUBPath) {
    try {
        $LuaFiles = Get-ChildItem -Path $LGHUBPath -Filter "*.lua" -Recurse -ErrorAction SilentlyContinue
        foreach ($File in $LuaFiles) {
            $hash = (Get-FileHash $File.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
            $LuaScripts += [PSCustomObject]@{
                Name = $File.Name
                Path = $File.FullName
                Modified = $File.LastWriteTime
                Hash = $hash
            }
            Add-SecurityIssue "Scripts" "Lua script found: $($File.Name) Hash: $hash" "MEDIUM"
        }
        $global:LuaScriptCount = $LuaScripts.Count
        if ($LuaScripts.Count -gt 0) {
            Write-Log " Found $($LuaScripts.Count) LUA script(s)" -Color Red
            foreach ($Script in $LuaScripts) {
                Write-Log " - $($Script.Name) | Modified: $($Script.Modified) | Hash: $($Script.Hash)" -Color Red
                Write-Log " Path: $($Script.Path)" -Color Red
            }
        } else {
            Write-Log " No LUA scripts found" -Color Green
        }
    } catch {
        Write-Log " ERROR: $($_.Exception.Message)" -Color Red
    }
} else {
    Write-Log " LGHUB folder not found" -Color Yellow
}
Write-Log "" -NoTimestamp

# [Sections K–P unchanged]

# ============================================================
# FINAL SUMMARY – ONLY ONCE
# ============================================================
$XimStatus = if ($global:DetectionResults.Count -gt 0) { "DETECTED" } else { "NOT DETECTED" }
$XimColor = if ($XimStatus -eq "DETECTED") { "Red" } else { "Green" }
$FlaggedColor = if ($global:FlaggedFileCount -gt 0) { "Red" } else { "Green" }

$Summary = @"
============================================================
 SCAN SUMMARY
============================================================
XIM MATRIX: $XimStatus
LUA Scripts: $($global:LuaScriptCount)
Flagged Files: $($global:FlaggedFileCount) FOUND
============================================================
Full report saved to: $OutputFile
============================================================
"@

# Write to log file
Add-Content -Path $OutputFile -Value $Summary

# Print to console with colors
$Summary -split "`n" | ForEach-Object {
    $line = $_
    if ($line -match "XIM MATRIX") {
        Write-Host $line -ForegroundColor $XimColor
    } elseif ($line -match "Flagged Files") {
        Write-Host $line -ForegroundColor $FlaggedColor
    } elseif ($line -match "LUA Scripts") {
        Write-Host $line -ForegroundColor Cyan
    } else {
        Write-Host $line -ForegroundColor Cyan
    }
}