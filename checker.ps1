# ========================================================
# FULL SYSTEM SECURITY & MONITOR SCANNER
# FIXED: Add-Type error + Real names + CONNECTED status
# ========================================================

# === CHECK ADMIN ===
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "ERROR: Run as Administrator!" -ForegroundColor Red
    exit
}

# === CONFIG ===
$VendorID = "046D"
$DeviceID = "C53B"
$OutputFile = "$env:USERPROFILE\Desktop\SystemScan_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
$global:SecurityIssues = @()
$global:DetectionResults = @()
$global:FlaggedFileCount = 0

# === LOG FUNCTION ===
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

# === DETECTION HELPERS ===
function Add-Detection {
    param($Location, $Details)
    $global:DetectionResults += [PSCustomObject]@{ Location = $Location; Details = $Details }
}
function Add-SecurityIssue {
    param($Category, $Issue, $Severity)
    $global:SecurityIssues += [PSCustomObject]@{ Category = $Category; Issue = $Issue; Severity = $Severity }
}

# === FIXED: Add-Type only if not exists ===
if (-not ('Registry' -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class Registry {
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern int RegQueryInfoKey(
        IntPtr hKey, IntPtr lpClass, IntPtr lpcbClass, IntPtr lpReserved,
        IntPtr lpcSubKeys, IntPtr lpcMaxSubKeyLen, IntPtr lpcMaxClassLen,
        IntPtr lpcValues, IntPtr lpcMaxValueNameLen, IntPtr lpcMaxValueLen,
        IntPtr lpcbSecurityDescriptor, out long lpftLastWriteTime
    );
}
"@
}

# === Registry Last Write Time ===
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

# === File Checks ===
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

# ========================================================
# SECTION B: SYSTEM SECURITY CONFIGURATION
# ========================================================
Write-Log "SECTION B: SYSTEM SECURITY CONFIGURATION" -NoTimestamp -Color Yellow
Write-Log "============================================================" -NoTimestamp -Color Yellow
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

# ========================================================
# SECTION C: XIM MATRIX / SPOOFED USB
# ========================================================
Write-Log "SECTION C: Possible Spoofed USB's | Xim Matrix" -NoTimestamp -Color Yellow
Write-Log "============================================================" -NoTimestamp -Color Yellow

Write-Log "[1/3] Enumerating all connected USB/HID devices..." -NoTimestamp
try {
    $AllUSBDevices = Get-PnpDevice | Where-Object { 
        $_.Class -in @("HIDClass", "USB", "Mouse", "Keyboard") -and $_.Status -eq "OK" 
    }
    Write-Log " Found $($AllUSBDevices.Count) USB/HID device(s):" -Color Cyan
    $DeviceCount = 0
    foreach ($Device in $AllUSBDevices) {
        $DeviceCount++
        $InstanceID = $Device.InstanceId
        $vidMatch = $InstanceID -match 'VID_([0-9A-F]{4})'
        $pidMatch = $InstanceID -match 'PID_([0-9A-F]{4})'
        $ven = if ($vidMatch) { $Matches[1] } else { "Unknown" }
        $devPid = if ($pidMatch) { $Matches[1] } else { "Unknown" }
        Write-Log "  [$DeviceCount] $($Device.FriendlyName) - VEN_$ven & PID_$devPid" -Color Gray
    }
} catch {
    Write-Log " ERROR: Could not enumerate USB devices - $($_.Exception.Message)" -Color Red
}
Write-Log "" -NoTimestamp

Write-Log "[2/3] Scanning for XIM Matrix (VEN:$VendorID PID:$DeviceID)..." -NoTimestamp
try {
    $XimDetected = $false
    $AllDevices = Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "OK" }
    foreach ($Device in $AllDevices) {
        $InstanceID = $Device.InstanceId
        if ($InstanceID -like "*VID_$VendorID*" -and $InstanceID -like "*PID_$DeviceID*") {
            $vidMatch = $InstanceID -match 'VID_([0-9A-F]{4})'
            $pidMatch = $InstanceID -match 'PID_([0-9A-F]{4})'
            $ven = if ($vidMatch) { $Matches[1] } else { "Unknown" }
            $devPid = if ($pidMatch) { $Matches[1] } else { "Unknown" }
            Write-Log " [!!! DETECTED !!!] XIM Matrix Device Found!" -Color Red
            Write-Log "     Device Name: $($Device.FriendlyName) - VEN_$ven & PID_$devPid" -Color Red
            Write-Log "     Status: $($Device.Status)" -Color Red
            Add-Detection "USB Device" "XIM Matrix detected: $($Device.FriendlyName) - $InstanceID"
            Add-SecurityIssue "XIM Matrix" "XIM Matrix device currently connected" "CRITICAL"
            $XimDetected = $true
        }
    }
    if (-not $XimDetected) {
        Write-Log " Result: NO XIM MATRIX DEVICE CURRENTLY CONNECTED" -Color Green
    }
} catch {
    Write-Log " ERROR: $($_.Exception.Message)" -Color Red
}
Write-Log "" -NoTimestamp

Write-Log "[3/3] Scanning USB registry for XIM Matrix traces..." -NoTimestamp
try {
    $XimRegistryFound = $false
    $USBEnumPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\USB"
    if (Test-Path $USBEnumPath) {
        $USBKeys = Get-ChildItem -Path $USBEnumPath -ErrorAction SilentlyContinue
        foreach ($Key in $USBKeys) {
            if ($Key.PSChildName -match "VID_$VendorID.*PID_$DeviceID") {
                Write-Log " [!!! DETECTED !!!] XIM Registry Entry Found!" -Color Red
                Write-Log "     Registry Path: $($Key.PSPath)" -Color Red
                $LastWrite = Get-RegistryKeyLastWriteTime $Key.PSPath
                if ($LastWrite) {
                    $TimeSince = (Get-Date) - $LastWrite
                    Write-Log "     Last Modified: $($LastWrite.ToString('yyyy-MM-dd HH:mm:ss'))" -Color Red
                    Write-Log "     Time Since: $([math]::Floor($TimeSince.TotalDays)) days, $([math]::Floor($TimeSince.Hours)) hours ago" -Color Red
                }
                try {
                    $DeviceDesc = Get-ItemProperty -Path $Key.PSPath -Name "DeviceDesc" -ErrorAction SilentlyContinue
                    if ($DeviceDesc) {
                        Write-Log "     Device Description: $($DeviceDesc.DeviceDesc)" -Color Red
                    }
                } catch {}
                Add-Detection "Registry" "XIM Matrix registry trace: $($Key.PSPath)"
                Add-SecurityIssue "XIM Matrix" "XIM Matrix was previously connected (registry traces)" "HIGH"
                $XimRegistryFound = $true
            }
        }
        foreach ($Key in $USBKeys) {
            try {
                $SubKeys = Get-ChildItem -Path $Key.PSPath -ErrorAction SilentlyContinue
                foreach ($SubKey in $SubKeys) {
                    $FriendlyName = Get-ItemProperty -Path $SubKey.PSPath -Name "FriendlyName" -ErrorAction SilentlyContinue
                    if ($FriendlyName.FriendlyName -match "xim") {
                        Write-Log " [!!! DETECTED !!!] XIM-related device in registry!" -Color Red
                        Write-Log "     Device: $($FriendlyName.FriendlyName)" -Color Red
                        Write-Log "     Path: $($SubKey.PSPath)" -Color Red
                        $XimRegistryFound = $true
                    }
                }
            } catch {}
        }
    }
    if (-not $XimRegistryFound) {
        Write-Log " Result: NO XIM MATRIX REGISTRY TRACES FOUND" -Color Green
    }
} catch {
    Write-Log " ERROR: $($_.Exception.Message)" -Color Red
}
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
    @{Path="$env:APPDATA"; Name="AppData"},
    @{Path="C:\Windows\System32"; Name="System32"},
    @{Path="C:\Windows\SysWOW64"; Name="SysWOW64"}
)

$SuspiciousFiles = @()

foreach ($Location in $ScanPaths) {
    if (-not (Test-Path $Location.Path)) { continue }

    foreach ($Pattern in $SuspiciousPatterns) {
        $Files = Get-ChildItem -Path $Location.Path -Filter $Pattern -Recurse -ErrorAction SilentlyContinue -Depth 4 |
                 Where-Object { $_.Extension -ne '.lnk' } | Select-Object -First 50
        foreach ($File in $Files) {
            $hash = (Get-FileHash $File.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
            $label = if ($File.Name -like "*dapper*") { "DAPPER_DLL" } else { "CHEAT_PATTERN" }
            $SuspiciousFiles += [pscustomobject]@{
                Name     = $File.Name
                Path     = $File.FullName
                Size     = [math]::Round($File.Length / 1MB, 2)
                Modified = $File.LastWriteTime
                Hash     = $hash
                Label    = $label
            }
            Add-SecurityIssue "Suspicious Files" "$label : $($File.Name)" "HIGH"
        }
    }

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

# ========================================================
# SECTION E: MONITOR INFORMATION (REAL NAME + CONNECTED)
# ========================================================
Write-Log "SECTION E: MONITOR INFORMATION" -NoTimestamp -Color Yellow
Write-Log "============================================================" -NoTimestamp -Color Yellow

$MonitorCount = 0
$ConnectedMonitors = @()

# METHOD 1: WMI (Best)
try {
    $WmiMonitors = Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorID -ErrorAction SilentlyContinue
    $VideoControllers = Get-CimInstance -ClassName Win32_VideoController -ErrorAction SilentlyContinue

    foreach ($Mon in $WmiMonitors) {
        $MonitorCount++
        $Man = ($Mon.ManufacturerName | ForEach-Object { [char]$_ } | Where-Object { $_ -ge 32 }) -join ''
        $Model = ($Mon.ProductCodeID | ForEach-Object { [char]$_ } | Where-Object { $_ -ge 32 }) -join ''
        $Serial = ($Mon.SerialNumberID | ForEach-Object { [char]$_ } | Where-Object { $_ -ge 32 }) -join ''
        $Name = "$Man $Model".Trim()
        if (-not $Name -or $Name -eq " ") { $Name = "Unknown Monitor" }

        $ResText = "Unknown"
        foreach ($VC in $VideoControllers) {
            if ($VC.Name -like "*$Man*" -or $VC.Name -like "*$Model*") {
                $ResText = "$($VC.CurrentHorizontalResolution)x$($VC.CurrentVerticalResolution) @ $($VC.CurrentRefreshRate)Hz"
                break
            }
        }

        $IsActive = $Mon.Active -eq $true
        $StatusColor = if ($IsActive) { "Green" } else { "Gray" }

        Write-Log "Monitor $MonitorCount" -Color $StatusColor
        Write-Log "  Name: $Name" -Color White
        Write-Log "  Serial: $Serial" -Color Cyan
        Write-Log "  Resolution: $ResText" -Color Gray
        Write-Log "  Status: $(if($IsActive){'CONNECTED'}else{'DISCONNECTED'})" -Color $StatusColor
        Write-Log "" -NoTimestamp

        if ($IsActive) { $ConnectedMonitors += $Name }
    }
} catch {}

# METHOD 2: Registry + EDID Fallback
if ($MonitorCount -eq 0) {
    $RegPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\DISPLAY"
    if (Test-Path $RegPath) {
        $Keys = Get-ChildItem $RegPath -ErrorAction SilentlyContinue
        foreach ($VenKey in $Keys) {
            $ProdKeys = Get-ChildItem $VenKey.PSPath -ErrorAction SilentlyContinue
            foreach ($ProdKey in $ProdKeys) {
                $InstKeys = Get-ChildItem $ProdKey.PSPath -ErrorAction SilentlyContinue
                foreach ($Inst in $InstKeys) {
                    $MonitorCount++
                    $Path = $Inst.PSPath
                    $InstName = $Inst.PSChildName

                    $EDID = (Get-ItemProperty $Path -Name "UserModeDriverName" -ErrorAction SilentlyContinue).UserModeDriverName
                    $Name = "Unknown Monitor"
                    $Serial = "Unknown"
                    $manID = "UNK"
                    if ($EDID -and $EDID.Length -ge 128) {
                        try {
                            $bytes = $EDID[0..127]
                            $m1 = ($bytes[8] -shr 2) -band 0x1F
                            $m2 = (($bytes[8] -band 3) -shl 3) + ($bytes[9] -shr 5)
                            $m3 = $bytes[9] -band 0x1F
                            $manID = [char](64 + $m1) + [char](64 + $m2) + [char](64 + $m3)

                            $desc = $bytes[72..125]
                            if ($desc[0] -eq 0x00 -and $desc[1] -eq 0x00 -and $desc[2] -eq 0x00 -and $desc[3] -eq 0xFC) {
                                $text = ($desc[5..17] | Where-Object { $_ -ge 32 -and $_ -le 126 } | ForEach-Object { [char]$_ }) -join ''
                                $Name = $text.Trim()
                            }
                            if ($desc[18] -eq 0x00 -and $desc[19] -eq 0x00 -and $desc[20] -eq 0x00 -and $desc[21] -eq 0xFF) {
                                $text = ($desc[23..35] | Where-Object { $_ -ge 32 -and $_ -le 126 } | ForEach-Object { [char]$_ }) -join ''
                                $Serial = $text.Trim()
                            }
                        } catch {}
                    }

                    $Friendly = (Get-ItemProperty $Path -Name "FriendlyName" -ErrorAction SilentlyContinue).FriendlyName
                    if ($Friendly -and $Friendly -notlike "*Generic*") { $Name = $Friendly }

                    $IsConnected = $false
                    $ConfigKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Video\$InstName\0000"
                    if (Test-Path $ConfigKey) {
                        $CurrentConfig = Get-ItemProperty $ConfigKey -Name "HardwareInformation.CurrentConfig" -ErrorAction SilentlyContinue
                        if ($CurrentConfig -and $CurrentConfig.HardwareInformation.CurrentConfig -ne 0) {
                            $IsConnected = $true
                        }
                    }

                    $StatusColor = if ($IsConnected) { "Green" } else { "Gray" }

                    Write-Log "Monitor $MonitorCount" -Color $StatusColor
                    Write-Log "  Name: $Name" -Color White
                    Write-Log "  Vendor: $manID" -Color Gray
                    Write-Log "  Serial: $Serial" -Color Cyan
                    Write-Log "  Status: $(if($IsConnected){'CONNECTED'}else{'DISCONNECTED'})" -Color $StatusColor
                    Write-Log "" -NoTimestamp

                    if ($IsConnected) { $ConnectedMonitors += $Name }
                }
            }
        }
    }
}

if ($MonitorCount -eq 0) {
    Write-Log " No monitors detected." -Color Yellow
} else {
    Write-Log " Connected Monitors: $($ConnectedMonitors -join ', ')" -Color Green
}
Write-Log "" -NoTimestamp

# ========================================================
# SECTION F: RECENTLY EXECUTED FILES
# ========================================================
Write-Log "SECTION F: RECENTLY EXECUTED FILES" -NoTimestamp -Color Yellow
Write-Log "============================================================" -NoTimestamp -Color Yellow

$recentExecuted = @()
$recentThreshold = (Get-Date).AddDays(-30)

$prefetchPath = "C:\Windows\Prefetch"
if (Test-Path $prefetchPath) {
    $prefetchFiles = Get-ChildItem -Path $prefetchPath -Filter "*.pf" -ErrorAction SilentlyContinue | 
                     Where-Object { $_.LastWriteTime -gt $recentThreshold } | 
                     Sort-Object LastWriteTime -Descending | Select-Object -First 50
    foreach ($pf in $prefetchFiles) {
        $execName = $pf.Name -replace '-[A-F0-9]+\.pf$', ''
        $recentExecuted += [pscustomobject]@{
            Name     = $execName
            Path     = $pf.FullName
            Modified = $pf.LastWriteTime
            Label    = "PREFETCH"
        }
    }
}

$recentExecuted = $recentExecuted | Sort-Object Modified -Descending | Select-Object -Unique -First 50

if ($recentExecuted.Count) {
    Write-Log " Result: FOUND $($recentExecuted.Count) RECENTLY EXECUTED FILE(S)" -Color Cyan
    foreach ($File in $recentExecuted) {
        Write-Log " - [$($File.Label)] $($File.Name)" -Color Gray
        Write-Log "   Path: $($File.Path)" -Color Gray
        Write-Log "   Modified: $($File.Modified)" -Color Gray
    }
} else {
    Write-Log " Result: NO RECENTLY EXECUTED FILES DETECTED" -Color Green
}
Write-Log "" -NoTimestamp

# ========================================================
# SECTION G: POWERSHELL HISTORY
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
# SECTION H: DEFENDER CONFIG
# ========================================================
Write-Log "SECTION H: WINDOWS DEFENDER CONFIGURATION" -NoTimestamp -Color Yellow
Write-Log "============================================================" -NoTimestamp -Color Yellow

Write-Log "Windows Defender Exclusions:" -NoTimestamp
try {
    $pref = Get-MpPreference -ErrorAction SilentlyContinue
    if ($pref.ExclusionPath) {
        Write-Log " Paths:" -Color Cyan
        foreach ($ex in $pref.ExclusionPath) { Write-Log "  - $ex" -Color Gray }
    } else { Write-Log " No path exclusions" -Color Green }
    if ($pref.ExclusionProcess) {
        Write-Log " Processes:" -Color Cyan
        foreach ($ex in $pref.ExclusionProcess) { Write-Log "  - $ex" -Color Gray }
    } else { Write-Log " No process exclusions" -Color Green }
    if ($pref.ExclusionExtension) {
        Write-Log " Extensions:" -Color Cyan
        foreach ($ex in $pref.ExclusionExtension) { Write-Log "  - $ex" -Color Gray }
    } else { Write-Log " No extension exclusions" -Color Green }
    if ($pref.ExclusionIpAddress) {
        Write-Log " IP Addresses:" -Color Cyan
        foreach ($ex in $pref.ExclusionIpAddress) { Write-Log "  - $ex" -Color Gray }
    } else { Write-Log " No IP exclusions" -Color Green }
} catch {
    Write-Log " ERROR: Could not retrieve Defender preferences" -Color Red
}
Write-Log "" -NoTimestamp

Write-Log "Windows Defender Detection History (recent threats):" -NoTimestamp
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
} catch {
    Write-Log " ERROR: Could not retrieve Defender history" -Color Red
}
Write-Log "" -NoTimestamp

# ========================================================
# FINAL REPORT
# ========================================================
Write-Log "============================================================" -NoTimestamp -Color Cyan
Write-Log "Scan complete. Full report saved to: $OutputFile" -NoTimestamp -Color Cyan
Write-Log "============================================================" -NoTimestamp -Color Cyan