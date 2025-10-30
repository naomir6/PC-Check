# Comprehensive System Security & Device Scanner
# Checks for: XIM Matrix, suspicious files, security settings, monitors, forensics

$VendorID = "046D"
$DeviceID = "C53B"
$OutputFile = "$env:USERPROFILE\Desktop\SystemScan_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
$global:SecurityIssues = @()
$global:DetectionResults = @()

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

# Windows Installation Date
Write-Log "Windows Installation Date..." -NoTimestamp
try {
    $OS = Get-CimInstance -ClassName Win32_OperatingSystem
    $InstallDate = $OS.InstallDate
    $DaysSinceInstall = (Get-Date) - $InstallDate
    
    $Days = [math]::Floor($DaysSinceInstall.TotalDays)
    $Hours = [math]::Floor($DaysSinceInstall.Hours)
    $Minutes = [math]::Floor($DaysSinceInstall.Minutes)
    $Seconds = [math]::Floor($DaysSinceInstall.Seconds)
    
    Write-Log "  Install Date: $($InstallDate.ToString('yyyy-MM-dd HH:mm:ss'))" -Color Cyan
    Write-Log "  Time Since Install: $Days days, $Hours hours, $Minutes minutes, $Seconds seconds" -Color Cyan
} catch {
    Write-Log "  ERROR: Could not determine install date" -Color Red
}

# System Uptime
try {
    $Uptime = (Get-Date) - $OS.LastBootUpTime
    $UptimeDays = [math]::Floor($Uptime.TotalDays)
    $UptimeHours = [math]::Floor($Uptime.Hours)
    $UptimeMinutes = [math]::Floor($Uptime.Minutes)
    
    Write-Log "  Last Boot: $($OS.LastBootUpTime.ToString('yyyy-MM-dd HH:mm:ss'))" -Color Cyan
    Write-Log "  Uptime: $UptimeDays days, $UptimeHours hours, $UptimeMinutes minutes" -Color Cyan
} catch {}

Write-Log "" -NoTimestamp

# ============================================================
# SECTION B: SECURITY CONFIGURATION CHECKS
# ============================================================
Write-Log "SECTION B: SYSTEM SECURITY CONFIGURATION" -NoTimestamp -Color Yellow
Write-Log "============================================================" -NoTimestamp -Color Yellow

# B1: Secure Boot Status
Write-Log "Checking Secure Boot..." -NoTimestamp
try {
    $SecureBoot = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
    if ($null -eq $SecureBoot) {
        Write-Log "  Result: NOT SUPPORTED (Legacy BIOS)" -Color Yellow
        Add-SecurityIssue "Secure Boot" "Not supported or disabled" "MEDIUM"
    } elseif ($SecureBoot) {
        Write-Log "  Result: ENABLED" -Color Green
    } else {
        Write-Log "  Result: DISABLED" -Color Red
        Add-SecurityIssue "Secure Boot" "Disabled" "HIGH"
    }
} catch {
    Write-Log "  Result: UNKNOWN" -Color Yellow
}

# B2: Core Isolation / Memory Integrity
Write-Log "Checking Core Isolation (Memory Integrity)..." -NoTimestamp
try {
    $CoreIsolation = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -ErrorAction SilentlyContinue
    if ($CoreIsolation.Enabled -eq 1) {
        Write-Log "  Result: ENABLED" -Color Green
    } else {
        Write-Log "  Result: DISABLED" -Color Red
        Add-SecurityIssue "Core Isolation" "Memory Integrity disabled" "HIGH"
    }
} catch {
    Write-Log "  Result: DISABLED" -Color Red
    Add-SecurityIssue "Core Isolation" "Not configured" "HIGH"
}

# B3: Virtualization Status
Write-Log "Checking Virtualization..." -NoTimestamp
try {
    $CPU = Get-CimInstance -ClassName Win32_Processor -ErrorAction SilentlyContinue
    $VirtualizationEnabled = $false
    
    foreach ($Processor in $CPU) {
        if ($Processor.VirtualizationFirmwareEnabled) {
            $VirtualizationEnabled = $true
            break
        }
    }
    
    if ($VirtualizationEnabled) {
        Write-Log "  Result: ENABLED" -Color Green
    } else {
        Write-Log "  Result: DISABLED" -Color Red
        Add-SecurityIssue "Virtualization" "CPU virtualization disabled in BIOS" "MEDIUM"
    }
} catch {
    Write-Log "  Result: UNKNOWN" -Color Yellow
}

# B4: IOMMU (Input-Output Memory Management Unit)
Write-Log "Checking IOMMU..." -NoTimestamp
try {
    $VBS = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
    $DMAProtection = $false
    if ($VBS.SecurityServicesRunning -contains 2) {
        $DMAProtection = $true
    }
    
    if ($DMAProtection) {
        Write-Log "  Result: ENABLED (DMA Protection Active)" -Color Green
    } else {
        Write-Log "  Result: DISABLED or NOT AVAILABLE" -Color Yellow
        Add-SecurityIssue "IOMMU" "DMA protection not active" "LOW"
    }
} catch {
    Write-Log "  Result: UNKNOWN" -Color Yellow
}

Write-Log "" -NoTimestamp

# ============================================================
# SECTION C: RECENTLY EXECUTED FILES (PREFETCH)
# ============================================================
Write-Log "SECTION C: RECENTLY EXECUTED FILES (PREFETCH)" -NoTimestamp -Color Yellow
Write-Log "============================================================" -NoTimestamp -Color Yellow

$PrefetchPath = "$env:SystemRoot\Prefetch"
$SuspiciousPrefetch = @()
$RecentPrefetch = @()

if (Test-Path $PrefetchPath) {
    Write-Log "Analyzing Prefetch files..." -NoTimestamp
    try {
        $PrefetchFiles = Get-ChildItem -Path $PrefetchPath -Filter "*.pf" -ErrorAction SilentlyContinue | 
            Sort-Object LastWriteTime -Descending | 
            Select-Object -First 100
        
        $SuspiciousKeywords = @("xim", "cronus", "aimbot", "cheat", "hack", "injector", "spoof", "bypass", "macro", "trigger")
        
        foreach ($File in $PrefetchFiles) {
            $FileName = $File.Name -replace '\.pf$', '' -replace '-[A-F0-9]{8}$', ''
            
            # Check for suspicious names
            $IsSuspicious = $false
            foreach ($Keyword in $SuspiciousKeywords) {
                if ($FileName -like "*$Keyword*") {
                    $IsSuspicious = $true
                    $SuspiciousPrefetch += [PSCustomObject]@{
                        Name = $FileName
                        LastExecuted = $File.LastWriteTime
                        FullName = $File.Name
                    }
                    break
                }
            }
            
            # Collect recent executions (last 7 days)
            if ($File.LastWriteTime -gt (Get-Date).AddDays(-7)) {
                if (-not $IsSuspicious) {
                    $RecentPrefetch += [PSCustomObject]@{
                        Name = $FileName
                        LastExecuted = $File.LastWriteTime
                    }
                }
            }
        }
        
        # Display suspicious prefetch
        if ($SuspiciousPrefetch.Count -gt 0) {
            Write-Log "  SUSPICIOUS EXECUTED FILES: $($SuspiciousPrefetch.Count)" -Color Red
            foreach ($Item in $SuspiciousPrefetch) {
                Write-Log "    - $($Item.Name)" -Color Red
                Write-Log "      Last Executed: $($Item.LastExecuted)" -Color Red
                Add-SecurityIssue "Prefetch" "Suspicious execution: $($Item.Name)" "HIGH"
            }
        } else {
            Write-Log "  No suspicious executed files found" -Color Green
        }
        
        # Display recent executions
        Write-Log "  RECENT EXECUTIONS (Last 7 Days): $($RecentPrefetch.Count)" -Color Cyan
        $RecentPrefetch | Select-Object -First 20 | ForEach-Object {
            Write-Log "    - $($_.Name) ($(($_.LastExecuted).ToString('yyyy-MM-dd HH:mm')))" -Color Cyan
        }
        
    } catch {
        Write-Log "  ERROR: $($_.Exception.Message)" -Color Red
    }
} else {
    Write-Log "  Prefetch folder not accessible" -Color Yellow
}
Write-Log "" -NoTimestamp

# ============================================================
# SECTION D: RECENTLY DELETED FILES (RECYCLE BIN)
# ============================================================
Write-Log "SECTION D: RECENTLY DELETED FILES" -NoTimestamp -Color Yellow
Write-Log "============================================================" -NoTimestamp -Color Yellow

try {
    $Shell = New-Object -ComObject Shell.Application
    $RecycleBin = $Shell.NameSpace(0x0a)
    $DeletedFiles = @()
    
    if ($RecycleBin) {
        $Items = $RecycleBin.Items()
        foreach ($Item in $Items) {
            $DeletedFiles += [PSCustomObject]@{
                Name = $Item.Name
                DeleteDate = $RecycleBin.GetDetailsOf($Item, 2)
                OriginalLocation = $RecycleBin.GetDetailsOf($Item, 1)
                Size = $RecycleBin.GetDetailsOf($Item, 3)
            }
        }
        
        if ($DeletedFiles.Count -gt 0) {
            Write-Log "  Found $($DeletedFiles.Count) deleted file(s)" -Color Cyan
            $DeletedFiles | Sort-Object DeleteDate -Descending | Select-Object -First 25 | ForEach-Object {
                Write-Log "    $($_.Name) | $($_.DeleteDate) | $($_.Size)" -Color Cyan
                Write-Log "      Location: $($_.OriginalLocation)" -Color Cyan
            }
        } else {
            Write-Log "  Recycle Bin is empty" -Color Green
        }
    }
} catch {
    Write-Log "  ERROR: Could not access Recycle Bin" -Color Red
}
Write-Log "" -NoTimestamp

# ============================================================
# SECTION E: BROWSER HISTORY & DOWNLOADS
# ============================================================
Write-Log "SECTION E: BROWSER HISTORY AND DOWNLOADS" -NoTimestamp -Color Yellow
Write-Log "============================================================" -NoTimestamp -Color Yellow

$AllDownloads = @()
$SuspiciousURLs = @()
$SuspiciousURLKeywords = @("cheat", "hack", "aimbot", "xim", "cronus", "macro", "injector", "spoof", "bypass", "undetected")

# Chrome
Write-Log "Scanning Chrome..." -NoTimestamp
$ChromePaths = @(
    "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History",
    "$env:LOCALAPPDATA\Google\Chrome\User Data\Profile 1\History"
)

foreach ($ChromePath in $ChromePaths) {
    if (Test-Path $ChromePath) {
        try {
            $TempDB = "$env:TEMP\chrome_history_temp.db"
            Copy-Item -Path $ChromePath -Destination $TempDB -Force -ErrorAction SilentlyContinue
            
            $Connection = New-Object System.Data.SQLite.SQLiteConnection("Data Source=$TempDB;Version=3;")
            $Connection.Open()
            
            # Get downloads
            $DownloadQuery = "SELECT target_path, tab_url, start_time, total_bytes FROM downloads ORDER BY start_time DESC LIMIT 100"
            $Command = $Connection.CreateCommand()
            $Command.CommandText = $DownloadQuery
            $Reader = $Command.ExecuteReader()
            
            while ($Reader.Read()) {
                try {
                    $StartTime = [DateTime]::new(1601, 1, 1).AddMicroseconds($Reader["start_time"])
                    $AllDownloads += [PSCustomObject]@{
                        Browser = "Chrome"
                        File = Split-Path $Reader["target_path"] -Leaf
                        URL = $Reader["tab_url"]
                        Date = $StartTime
                        Size = [math]::Round($Reader["total_bytes"] / 1MB, 2)
                    }
                } catch {}
            }
            $Reader.Close()
            
            # Get suspicious URLs from history
            $URLQuery = "SELECT url, title, last_visit_time FROM urls WHERE last_visit_time > (SELECT (julianday('now') - 2440587.5) * 86400000000) ORDER BY last_visit_time DESC LIMIT 500"
            $Command.CommandText = $URLQuery
            $Reader = $Command.ExecuteReader()
            
            while ($Reader.Read()) {
                try {
                    $URL = $Reader["url"]
                    $Title = $Reader["title"]
                    foreach ($Keyword in $SuspiciousURLKeywords) {
                        if ($URL -like "*$Keyword*" -or $Title -like "*$Keyword*") {
                            $VisitTime = [DateTime]::new(1601, 1, 1).AddMicroseconds($Reader["last_visit_time"])
                            $SuspiciousURLs += [PSCustomObject]@{
                                Browser = "Chrome"
                                URL = $URL
                                Title = $Title
                                Visited = $VisitTime
                            }
                            break
                        }
                    }
                } catch {}
            }
            $Reader.Close()
            $Connection.Close()
            Remove-Item $TempDB -Force -ErrorAction SilentlyContinue
        } catch {}
    }
}

# Firefox
Write-Log "Scanning Firefox..." -NoTimestamp
$FirefoxProfilePath = "$env:APPDATA\Mozilla\Firefox\Profiles"
if (Test-Path $FirefoxProfilePath) {
    $Profiles = Get-ChildItem -Path $FirefoxProfilePath -Directory
    foreach ($Profile in $Profiles) {
        $PlacesDB = Join-Path $Profile.FullName "places.sqlite"
        if (Test-Path $PlacesDB) {
            try {
                $TempDB = "$env:TEMP\firefox_places_temp.db"
                Copy-Item -Path $PlacesDB -Destination $TempDB -Force -ErrorAction SilentlyContinue
                
                $Connection = New-Object System.Data.SQLite.SQLiteConnection("Data Source=$TempDB;Version=3;")
                $Connection.Open()
                
                # Get downloads and suspicious URLs
                $Query = "SELECT url, title, last_visit_date FROM moz_places WHERE last_visit_date IS NOT NULL ORDER BY last_visit_date DESC LIMIT 500"
                $Command = $Connection.CreateCommand()
                $Command.CommandText = $Query
                $Reader = $Command.ExecuteReader()
                
                while ($Reader.Read()) {
                    try {
                        $URL = $Reader["url"]
                        $Title = $Reader["title"]
                        foreach ($Keyword in $SuspiciousURLKeywords) {
                            if ($URL -like "*$Keyword*" -or $Title -like "*$Keyword*") {
                                $VisitTime = [DateTime]::new(1970, 1, 1).AddMicroseconds($Reader["last_visit_date"])
                                $SuspiciousURLs += [PSCustomObject]@{
                                    Browser = "Firefox"
                                    URL = $URL
                                    Title = $Title
                                    Visited = $VisitTime
                                }
                                break
                            }
                        }
                    } catch {}
                }
                $Reader.Close()
                $Connection.Close()
                Remove-Item $TempDB -Force -ErrorAction SilentlyContinue
            } catch {}
        }
    }
}

# Edge
Write-Log "Scanning Edge..." -NoTimestamp
$EdgePath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\History"
if (Test-Path $EdgePath) {
    try {
        $TempDB = "$env:TEMP\edge_history_temp.db"
        Copy-Item -Path $EdgePath -Destination $TempDB -Force -ErrorAction SilentlyContinue
        
        $Connection = New-Object System.Data.SQLite.SQLiteConnection("Data Source=$TempDB;Version=3;")
        $Connection.Open()
        
        # Get downloads
        $DownloadQuery = "SELECT target_path, tab_url, start_time, total_bytes FROM downloads ORDER BY start_time DESC LIMIT 100"
        $Command = $Connection.CreateCommand()
        $Command.CommandText = $DownloadQuery
        $Reader = $Command.ExecuteReader()
        
        while ($Reader.Read()) {
            try {
                $StartTime = [DateTime]::new(1601, 1, 1).AddMicroseconds($Reader["start_time"])
                $AllDownloads += [PSCustomObject]@{
                    Browser = "Edge"
                    File = Split-Path $Reader["target_path"] -Leaf
                    URL = $Reader["tab_url"]
                    Date = $StartTime
                    Size = [math]::Round($Reader["total_bytes"] / 1MB, 2)
                }
            } catch {}
        }
        $Reader.Close()
        
        # Get suspicious URLs
        $URLQuery = "SELECT url, title, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 500"
        $Command.CommandText = $URLQuery
        $Reader = $Command.ExecuteReader()
        
        while ($Reader.Read()) {
            try {
                $URL = $Reader["url"]
                $Title = $Reader["title"]
                foreach ($Keyword in $SuspiciousURLKeywords) {
                    if ($URL -like "*$Keyword*" -or $Title -like "*$Keyword*") {
                        $VisitTime = [DateTime]::new(1601, 1, 1).AddMicroseconds($Reader["last_visit_time"])
                        $SuspiciousURLs += [PSCustomObject]@{
                            Browser = "Edge"
                            URL = $URL
                            Title = $Title
                            Visited = $VisitTime
                        }
                        break
                    }
                }
            } catch {}
        }
        $Reader.Close()
        $Connection.Close()
        Remove-Item $TempDB -Force -ErrorAction SilentlyContinue
    } catch {}
}

# Display Downloads
if ($AllDownloads.Count -gt 0) {
    $UniqueDownloads = $AllDownloads | Sort-Object Date -Descending | Select-Object -First 50
    Write-Log "  RECENT DOWNLOADS: $($UniqueDownloads.Count)" -Color Cyan
    foreach ($Download in $UniqueDownloads) {
        Write-Log "    - $($Download.File)" -Color Cyan
        Write-Log "      Browser: $($Download.Browser) | Date: $($Download.Date.ToString('yyyy-MM-dd HH:mm'))" -Color Cyan
        Write-Log "      URL: $($Download.URL)" -Color Cyan
    }
} else {
    Write-Log "  No download history found" -Color Green
}

Write-Log "" -NoTimestamp

# Display Suspicious URLs
if ($SuspiciousURLs.Count -gt 0) {
    $UniqueSuspiciousURLs = $SuspiciousURLs | Sort-Object Visited -Descending | Select-Object URL, Browser, Title, Visited -Unique
    Write-Log "  SUSPICIOUS VISITED SITES: $($UniqueSuspiciousURLs.Count)" -Color Red
    foreach ($Site in $UniqueSuspiciousURLs) {
        Write-Log "    - $($Site.URL)" -Color Red
        Write-Log "      Title: $($Site.Title)" -Color Red
        Write-Log "      Browser: $($Site.Browser) | Visited: $($Site.Visited.ToString('yyyy-MM-dd HH:mm'))" -Color Red
        Add-SecurityIssue "Browser History" "Suspicious site visited: $($Site.URL)" "HIGH"
    }
} else {
    Write-Log "  No suspicious sites detected" -Color Green
}

Write-Log "" -NoTimestamp

# ============================================================
# SECTION F: SUSPICIOUS FILE SCAN
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
    "*kernel*driver*.sys", "*kdmapper*.exe", "*drvmap*.exe"
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
    if (Test-Path $Location.Path) {
        foreach ($Pattern in $SuspiciousPatterns) {
            try {
                $Files = Get-ChildItem -Path $Location.Path -Filter $Pattern -Recurse -ErrorAction SilentlyContinue -Depth 4 | Select-Object -First 50
                foreach ($File in $Files) {
                    $SuspiciousFiles += [PSCustomObject]@{
                        Name = $File.Name
                        Path = $File.FullName
                        Size = [math]::Round($File.Length / 1MB, 2)
                        Modified = $File.LastWriteTime
                    }
                    Add-SecurityIssue "Suspicious Files" "Detected: $($File.Name)" "HIGH"
                }
            } catch {}
        }
    }
}

# Remove duplicates
$SuspiciousFiles = $SuspiciousFiles | Sort-Object Path -Unique

if ($SuspiciousFiles.Count -gt 0) {
    Write-Log "  Result: FOUND $($SuspiciousFiles.Count) SUSPICIOUS FILE(S)" -Color Red
    foreach ($File in $SuspiciousFiles) {
        Write-Log "    - $($File.Name)" -Color Red
        Write-Log "      Path: $($File.Path)" -Color Red
        Write-Log "      Size: $($File.Size) MB | Modified: $($File.Modified)" -Color Red
    }
} else {
    Write-Log "  Result: NO SUSPICIOUS FILES DETECTED" -Color Green
}
Write-Log "" -NoTimestamp

# ============================================================
# SECTION G: MONITOR & DISPLAY DETECTION
# ============================================================
Write-Log "SECTION G: MONITOR AND DISPLAY ANALYSIS" -NoTimestamp -Color Yellow
Write-Log "============================================================" -NoTimestamp -Color Yellow

try {
    $Monitors = Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorID -ErrorAction SilentlyContinue
    
    if ($Monitors) {
        Write-Log "Found $($Monitors.Count) monitor(s):" -NoTimestamp -Color Cyan
        $MonitorIndex = 1
        foreach ($Monitor in $Monitors) {
            $Manufacturer = ($Monitor.ManufacturerName | Where-Object {$_ -ne 0} | ForEach-Object {[char]$_}) -join ""
            $ProductCode = ($Monitor.ProductCodeID | Where-Object {$_ -ne 0} | ForEach-Object {[char]$_}) -join ""
            $UserFriendlyName = ($Monitor.UserFriendlyName | Where-Object {$_ -ne 0} | ForEach-Object {[char]$_}) -join ""
            
            Write-Log "  Monitor $MonitorIndex" -Color Cyan
            Write-Log "    Name: $UserFriendlyName" -Color Cyan
            Write-Log "    Manufacturer: $Manufacturer" -Color Cyan
            Write-Log "    Product: $ProductCode" -Color Cyan
            
            $SuspiciousMonitorPatterns = @("xim", "cronus", "hdmi capture", "video capture", "game capture", "dummy", "elgato", "avermedia")
            $IsSuspicious = $false
            foreach ($Pattern in $SuspiciousMonitorPatterns) {
                if ($UserFriendlyName -like "*$Pattern*" -or $ProductCode -like "*$Pattern*" -or $Manufacturer -like "*$Pattern*") {
                    $IsSuspicious = $true
                    Write-Log "    Status: SUSPICIOUS (contains '$Pattern')" -Color Red
                    Add-SecurityIssue "Monitors" "Suspicious monitor: $UserFriendlyName" "HIGH"
                    break
                }
            }
            if (-not $IsSuspicious) {
                Write-Log "    Status: Normal" -Color Green
            }
            $MonitorIndex++
        }
    } else {
        Write-Log "  No monitors detected via WMI" -Color Yellow
    }
} catch {
    Write-Log "  ERROR: $($_.Exception.Message)" -Color Red
}
Write-Log "" -NoTimestamp

# ============================================================
# SECTION H: XIM MATRIX DEVICE DETECTION
# ============================================================
Write-Log "SECTION H: XIM MATRIX HARDWARE DETECTION" -NoTimestamp -Color Yellow
Write-Log "Target: VEN_$VendorID and DEV_$DeviceID" -NoTimestamp -Color Yellow
Write-Log "============================================================" -NoTimestamp -Color Yellow

# H1: PnP Devices
Write-Log "Scanning PnP Devices..." -NoTimestamp
try {
    $AllDevices = Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object {
        $_.InstanceId -match $VendorID -and $_.InstanceId -match $DeviceID
    }
    
    if ($AllDevices) {
        Write-Log "  Result: DETECTED $($AllDevices.Count) MATCHING DEVICE(S)" -Color Red
        foreach ($Device in $AllDevices) {
            Add-Detection "PnP Devices" "$($Device.FriendlyName) - $($Device.InstanceId)"
            Write-Log "    Device: $($Device.FriendlyName)" -Color Red
            Write-Log "    Instance: $($Device.InstanceId)" -Color Red
            Write-Log "    Status: $($Device.Status)" -Color Red
        }
    } else {
        Write-Log "  Result: NOT DETECTED" -Color Green
    }
} catch {
    Write-Log "  ERROR: $($_.Exception.Message)" -Color Red
}

# H2: Registry USB Enumeration
Write-Log "Scanning Registry..." -NoTimestamp
$RegPaths = @(
    "HKLM:\SYSTEM\CurrentControlSet\Enum\USB",
    "HKLM:\SYSTEM\CurrentControlSet\Enum\HID",
    "HKLM:\SYSTEM\ControlSet001\Enum\USB"
)

$RegistryDetections = 0
foreach ($RegPath in $RegPaths) {
    try {
        if (Test-Path $RegPath) {
            $Keys = Get-ChildItem -Path $RegPath -ErrorAction SilentlyContinue
            foreach ($Key in $Keys) {
                if ($Key.PSChildName -match $VendorID -and $Key.PSChildName -match $DeviceID) {
                    Add-Detection "Registry" "$($Key.PSChildName)"
                    Write-Log "  Result: DETECTED in Registry: $($Key.PSChildName)" -Color Red
                    $RegistryDetections++
                }
            }
        }
    } catch {}
}
if ($RegistryDetections -eq 0) {
    Write-Log "  Result: NOT DETECTED in Registry" -Color Green
}

# H3: SetupAPI Logs
Write-Log "Scanning SetupAPI Logs..." -NoTimestamp
$SetupLogs = @(
    "$env:windir\inf\setupapi.dev.log",
    "$env:windir\inf\setupapi.app.log"
)

$SetupAPIDetections = 0
foreach ($LogPath in $SetupLogs) {
    if (Test-Path $LogPath) {
        try {
            $LogContent = Get-Content -Path $LogPath -ErrorAction SilentlyContinue
            for ($i = 0; $i -lt $LogContent.Count; $i++) {
                if ($LogContent[$i] -match $VendorID) {
                    $StartIdx = [Math]::Max(0, $i - 5)
                    $EndIdx = [Math]::Min($LogContent.Count - 1, $i + 10)
                    $Context = $LogContent[$StartIdx..$EndIdx] -join "`n"
                    if ($Context -match $DeviceID) {
                        Add-Detection "SetupAPI Log" (Split-Path $LogPath -Leaf)
                        Write-Log "  Result: DETECTED in $(Split-Path $LogPath -Leaf)" -Color Red
                        $SetupAPIDetections++
                        break
                    }
                }
            }
        } catch {}
    }
}
if ($SetupAPIDetections -eq 0) {
    Write-Log "  Result: NOT DETECTED in SetupAPI Logs" -Color Green
}

# H4: Event Logs
Write-Log "Scanning Event Logs..." -NoTimestamp
try {
    $Events = Get-WinEvent -FilterHashtable @{LogName = 'System'; Id = 400,410,420} -MaxEvents 2000 -ErrorAction SilentlyContinue | Where-Object {
        $_.Message -match $VendorID -and $_.Message -match $DeviceID
    }
    
    if ($Events) {
        Add-Detection "Event Log" "$($Events.Count) events"
        Write-Log "  Result: DETECTED $($Events.Count) EVENT(S)" -Color Red
    } else {
        Write-Log "  Result: NOT DETECTED in Event Logs" -Color Green
    }
} catch {
    Write-Log "  Result: NOT DETECTED in Event Logs" -Color Green
}

# H5: WMI Devices
Write-Log "Scanning WMI..." -NoTimestamp
try {
    $WMIDevices = Get-WmiObject -Class Win32_PnPEntity -ErrorAction SilentlyContinue | Where-Object {
        $_.DeviceID -match $VendorID -and $_.DeviceID -match $DeviceID
    }
    
    if ($WMIDevices) {
        Add-Detection "WMI" "$($WMIDevices.Count) device(s)"
        Write-Log "  Result: DETECTED $($WMIDevices.Count) WMI DEVICE(S)" -Color Red
    } else {
        Write-Log "  Result: NOT DETECTED in WMI" -Color Green
    }
} catch {
    Write-Log "  Result: NOT DETECTED in WMI" -Color Green
}

Write-Log "" -NoTimestamp

# ============================================================
# FINAL SUMMARY
# ============================================================
Write-Log "============================================================" -NoTimestamp -Color Cyan
Write-Log "                    SCAN SUMMARY" -NoTimestamp -Color Cyan
Write-Log "============================================================" -NoTimestamp -Color Cyan
Write-Log "" -NoTimestamp

# XIM Detection Summary
if ($global:DetectionResults.Count -gt 0) {
    Write-Log "XIM MATRIX: DETECTED" -NoTimestamp -Color Red
    Write-Log "  Total Detections: $($global:DetectionResults.Count)" -NoTimestamp -Color Red
    $LocationGroups = $global:DetectionResults | Group-Object -Property Location
    foreach ($Group in $LocationGroups) {
        Write-Log "  $($Group.Name): $($Group.Count) detection(s)" -NoTimestamp -Color Yellow
    }
} else {
    Write-Log "XIM MATRIX: NOT DETECTED" -NoTimestamp -Color Green
}
Write-Log "" -NoTimestamp

# Security Issues Summary
if ($global:SecurityIssues.Count -gt 0) {
    Write-Log "SECURITY ISSUES: $($global:SecurityIssues.Count) FOUND" -NoTimestamp -Color Red
    
    $HighIssues = $global:SecurityIssues | Where-Object {$_.Severity -eq "HIGH"}
    if ($HighIssues) {
        Write-Log "  HIGH SEVERITY: $($HighIssues.Count)" -NoTimestamp -Color Red
        $HighIssues | Select-Object -First 20 | ForEach-Object {
            Write-Log "    - $($_.Category): $($_.Issue)" -NoTimestamp -Color Red
        }
        if ($HighIssues.Count -gt 20) {
            Write-Log "    ... and $($HighIssues.Count - 20) more" -NoTimestamp -Color Red
        }
    }
    
    $MediumIssues = $global:SecurityIssues | Where-Object {$_.Severity -eq "MEDIUM"}
    if ($MediumIssues) {
        Write-Log "  MEDIUM SEVERITY: $($MediumIssues.Count)" -NoTimestamp -Color Yellow
    }
    
    $LowIssues = $global:SecurityIssues | Where-Object {$_.Severity -eq "LOW"}
    if ($LowIssues) {
        Write-Log "  LOW SEVERITY: $($LowIssues.Count)" -NoTimestamp -Color Cyan
    }
} else {
    Write-Log "SECURITY ISSUES: NONE DETECTED" -NoTimestamp -Color Green
}

Write-Log "" -NoTimestamp
Write-Log "============================================================" -NoTimestamp -Color Cyan
Write-Log "Full report saved to: $OutputFile" -NoTimestamp -Color Cyan
Write-Log "============================================================" -NoTimestamp -Color Cyan

# Final Console Summary
Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "                    FINAL RESULTS" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
if ($global:DetectionResults.Count -gt 0) {
    Write-Host "XIM MATRIX: DETECTED ($($global:DetectionResults.Count) detections)" -ForegroundColor Red
} else {
    Write-Host "XIM MATRIX: NOT DETECTED" -ForegroundColor Green
}
Write-Host "------------------------------------------------------------" -ForegroundColor Cyan
if ($global:SecurityIssues.Count -gt 0) {
    $HighCount = ($global:SecurityIssues | Where-Object {$_.Severity -eq "HIGH"}).Count
    $MediumCount = ($global:SecurityIssues | Where-Object {$_.Severity -eq "MEDIUM"}).Count
    $LowCount = ($global:SecurityIssues | Where-Object {$_.Severity -eq "LOW"}).Count
    Write-Host "Security Issues: $($global:SecurityIssues.Count) total" -ForegroundColor Yellow
    if ($HighCount -gt 0) { Write-Host "  HIGH: $HighCount" -ForegroundColor Red }
    if ($MediumCount -gt 0) { Write-Host "  MEDIUM: $MediumCount" -ForegroundColor Yellow }
    if ($LowCount -gt 0) { Write-Host "  LOW: $LowCount" -ForegroundColor Cyan }
} else {
    Write-Host "Security Issues: None" -ForegroundColor Green
}
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Report: $OutputFile" -ForegroundColor Yellow
Write-Host "============================================================`n" -ForegroundColor Cyan