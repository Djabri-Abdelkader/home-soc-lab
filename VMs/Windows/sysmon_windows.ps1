# =============================================================================
# SOC HOME LAB — TASK 1: SYSMON INSTALLATION & CONFIGURATION (WINDOWS VM)
# =============================================================================
# Target Host : Windows 10 VM (monitored endpoint)
# Fleet Policy: Windows Agent Policy
# Goal        : Install Sysmon with SwiftOnSecurity config, ship events
#               to Elasticsearch via Elastic Agent
# Run as      : Administrator (PowerShell)
# =============================================================================


# =============================================================================
# THEORY BLOCK 1: WHAT IS SYSMON?
# =============================================================================
# Sysmon (System Monitor) is a free Microsoft Sysinternals tool that installs
# as a Windows service and kernel driver. It hooks into kernel callbacks to
# capture process, network, and file activity that native Windows logging
# either misses or logs poorly.
#
# It writes to its own dedicated Event Log channel:
#   Microsoft-Windows-Sysmon/Operational
#
# Without Sysmon, you cannot easily answer:
#   - Which process made this network connection?
#   - What is the SHA256 hash of this executable?
#   - Which parent process spawned cmd.exe?
# =============================================================================


# =============================================================================
# THEORY BLOCK 2: WINDOWS EVENT LOG CHANNELS
# =============================================================================
# Windows logging is NOT a single file. It is a hierarchy of named "channels"
# managed by the Windows Event Log service (WEvtSvc).
#
# Channel types:
#   Classic   : Security, System, Application  (pre-Vista legacy)
#   Operational: Microsoft-Windows-Sysmon/Operational  (modern, app-specific)
#
# Naming convention for modern channels:
#   Publisher-Name/ChannelType
#   e.g. Microsoft-Windows-Sysmon/Operational
#         ^publisher name          ^channel type
#
# IMPORTANT for detection engineering:
#   When configuring Elastic Agent or Winlogbeat, you specify the EXACT channel
#   name. A wrong name = silent failure (no logs, no error).
#
# List all channels on a Windows machine:
#   wevtutil el
# =============================================================================


# =============================================================================
# THEORY BLOCK 3: SYSMON EVENT IDs YOU MUST KNOW
# =============================================================================
#
# Event ID 1 — Process Create
#   What: Every new process spawn. Fields: CommandLine, ParentImage,
#         ParentCommandLine, User, Hashes (SHA256), ProcessGUID.
#   Why:  Native 4688 requires GPO to get command line. Sysmon gives you
#         full command line AND hashes out of the box.
#   Detection: winword.exe spawning cmd.exe = macro execution.
#              powershell.exe with encoded commands = LOLBin abuse.
#
# Event ID 3 — Network Connection
#   What: Every outbound TCP/UDP connection. Fields: Image (process path),
#         DestinationIp, DestinationPort, Protocol, SourceIp, SourcePort.
#   Why:  Links a network connection to the process that made it. Firewall
#         logs show the connection but not the process. Sysmon gives you both.
#   Detection: powershell.exe connecting to external IPs on port 443 = C2.
#              mshta.exe making any network connection = suspicious.
#
# Event ID 7 — Image Loaded (DLL Load)
#   What: Every DLL loaded into a process. Fields: ImageLoaded (DLL path),
#         Signed (bool), Signature, Hashes.
#   Why:  DLL hijacking and sideloading are common attack techniques.
#         Unsigned DLLs loaded by system processes = red flag.
#   Note: VERY high volume. SwiftOnSecurity config sets default to exclude
#         and only includes suspicious patterns. Be careful enabling broadly.
#   Detection: svchost.exe loading a DLL from C:\Users\Public\ = malicious.
#              Unsigned DLL loaded by lsass.exe = credential theft (Mimikatz).
#
# Event ID 11 — File Create
#   What: Every file creation or overwrite. Fields: TargetFilename,
#         CreationUtcTime, Image (process that created it).
#   Why:  Malware drops payloads. Web shells are written to disk. Ransomware
#         creates encrypted files.
#   Detection: Any process writing .exe or .ps1 to %TEMP% or %APPDATA%.
#              IIS worker process (w3wp.exe) writing an .aspx = web shell.
# =============================================================================


# =============================================================================
# STEP 1: CREATE DIRECTORY STRUCTURE
# =============================================================================

# Create a dedicated SOC lab directory for all tools
New-Item -ItemType Directory -Path "C:\SOCLab\Sysmon" -Force

# Navigate into it
Set-Location "C:\SOCLab\Sysmon"


# =============================================================================
# STEP 2: DOWNLOAD SYSMON AND SWIFTONSECURITY CONFIG
# =============================================================================

# Download Sysmon from Microsoft Sysinternals (official Microsoft source)
Invoke-WebRequest `
    -Uri "https://download.sysinternals.com/files/Sysmon.zip" `
    -OutFile "Sysmon.zip"

# Extract the archive — contains Sysmon.exe (32-bit) and Sysmon64.exe (64-bit)
# Use Sysmon64.exe on any modern Windows 10/11 system
Expand-Archive -Path "Sysmon.zip" -DestinationPath "C:\SOCLab\Sysmon" -Force

# Download SwiftOnSecurity Sysmon config
# This is the most widely used community baseline. It balances:
#   - High-fidelity detection (keeps important events)
#   - Low noise (excludes known-good system activity)
# Used in many SOC environments as a starting point before custom tuning.
Invoke-WebRequest `
    -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" `
    -OutFile "sysmonconfig.xml"


# =============================================================================
# THEORY BLOCK 4: HOW THE SWIFTONSECURITY CONFIG WORKS
# =============================================================================
# The config uses an include/exclude filter model per event type.
#
# Default behavior depends on the event type:
#   - Most events (Process Create, Network Connect, File Create):
#       onmatch="exclude" — log EVERYTHING unless a rule says to exclude it
#   - Image Load (Event ID 7):
#       onmatch="include" — log NOTHING unless a rule says to include it
#       (because DLL loads are extremely high volume)
#
# Example from the config XML:
#   <ProcessCreate onmatch="exclude">
#     <Image condition="is">C:\Windows\System32\wbem\WmiPrvSE.exe</Image>
#   </ProcessCreate>
#   ^ This means: log all process creations EXCEPT WmiPrvSE.exe
#
# You can add your own exclusions for lab noise (e.g., exclude your AV scanner)
# or your own inclusions for specific detections.
# =============================================================================

# Inspect the config before installing (optional but recommended)
# notepad C:\SOCLab\Sysmon\sysmonconfig.xml


# =============================================================================
# STEP 3: INSTALL SYSMON AS A WINDOWS SERVICE
# =============================================================================

# Install Sysmon with the SwiftOnSecurity config
# Flags:
#   -i              = install (first-time setup)
#   -accepteula     = silently accept the EULA (required for scripted installs)
#   sysmonconfig.xml = path to your filter config
C:\SOCLab\Sysmon\Sysmon64.exe -i C:\SOCLab\Sysmon\sysmonconfig.xml -accepteula

# What just happened:
#   1. A Windows Service called "Sysmon64" was installed (runs as SYSTEM)
#   2. A kernel driver called "SysmonDrv" was loaded
#   3. The Sysmon event log channel was registered:
#      Microsoft-Windows-Sysmon/Operational
#
# The kernel driver is what gives Sysmon its power — it registers callbacks
# at the kernel level for process creation, network connections, etc.
# This is below the API level, making it harder for user-mode malware to evade.


# =============================================================================
# STEP 4: VERIFY THE INSTALLATION
# =============================================================================

# Check that the Sysmon service is running
Get-Service Sysmon64
# Expected: Status=Running, StartType=Automatic

# Check that the kernel driver is loaded
sc.exe query SysmonDrv
# Expected: STATE : 4  RUNNING

# Verify the event log channel is registered and enabled
wevtutil gl "Microsoft-Windows-Sysmon/Operational"
# Look for: enabled: true
# Also shows: maxSize (default 64MB), retention policy

# List event log channels to confirm Sysmon is in the list
wevtutil el | Select-String -Pattern "Sysmon"
# Expected: Microsoft-Windows-Sysmon/Operational


# =============================================================================
# STEP 5: GENERATE TEST EVENTS TO VERIFY LOGGING
# =============================================================================

# --- Event ID 1: Process Create ---
# Spawn cmd.exe — this is a commonly detected pattern (any parent -> cmd.exe)
Start-Process -FilePath "cmd.exe" -ArgumentList "/c whoami" -Wait

# Spawn PowerShell with a command — classic LOLBin pattern to detect
Start-Process -FilePath "powershell.exe" `
    -ArgumentList "-NoProfile -Command Get-Process" -Wait

# --- Event ID 11: File Create ---
# Write a file to a suspicious path (%TEMP%) — malware commonly drops here
$tempPath = "$env:TEMP\sysmon_test_payload.txt"
New-Item -Path $tempPath -ItemType File -Force
Set-Content -Path $tempPath -Value "This is a Sysmon test file"

# Write a .ps1 script file — defenders watch for script drops
$scriptPath = "$env:TEMP\sysmon_test.ps1"
Set-Content -Path $scriptPath -Value "Write-Host 'sysmon test'"

# --- Event ID 3: Network Connection ---
# Make an outbound HTTP connection — will appear as powershell.exe -> 93.x.x.x
# Note: Sysmon may filter this if it matches an exclusion rule
Invoke-WebRequest -Uri "http://example.com" -UseBasicParsing -ErrorAction SilentlyContinue | Out-Null

# Query the Sysmon channel to confirm events are being generated
Write-Host "`n--- Last 10 Sysmon Events ---"
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10 |
    Format-Table TimeCreated, Id, Message -AutoSize -Wrap

# Filter for only Event ID 1 (Process Create)
Write-Host "`n--- Event ID 1 (Process Create) — Last 5 ---"
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
    Where-Object { $_.Id -eq 1 } |
    Select-Object -First 5 |
    ForEach-Object {
        $xml = [xml]$_.ToXml()
        [PSCustomObject]@{
            Time        = $_.TimeCreated
            EventID     = $_.Id
            Image       = ($xml.Event.EventData.Data | Where-Object Name -eq "Image")."#text"
            CommandLine = ($xml.Event.EventData.Data | Where-Object Name -eq "CommandLine")."#text"
            ParentImage = ($xml.Event.EventData.Data | Where-Object Name -eq "ParentImage")."#text"
            Hashes      = ($xml.Event.EventData.Data | Where-Object Name -eq "Hashes")."#text"
        }
    } | Format-List


# =============================================================================
# STEP 6: CONFIGURE ELASTIC AGENT TO COLLECT SYSMON LOGS
# =============================================================================

# ----------------------------------------------------------
# UI STEPS (Kibana Fleet) — document these as comments:
# ----------------------------------------------------------
#
# Option A: Add "Custom Windows Event Log" integration
# -------------------------------------------------------
# 1. Open Kibana in your browser
# 2. Go to: Fleet → Agent Policies → "Windows Agent Policy"
# 3. Click "Add integration"
# 4. In the search box, type: "Custom Windows Event Log"
# 5. Click on the result and then "Add Custom Windows Event Log"
# 6. Configure:
#      Channel Name : Microsoft-Windows-Sysmon/Operational
#      Dataset Name : windows.sysmon_operational
#      Event IDs    : (leave blank = collect all, or set: 1,3,7,11)
# 7. Click "Save and continue" → "Save and deploy changes"
# 8. Fleet will push the new policy to your Windows agent (30-60 seconds)
#
# Option B: Add the "Windows" integration (ships multiple channels at once)
# -------------------------------------------------------
# 1. Fleet → Agent Policies → "Windows Agent Policy" → Add integration
# 2. Search for: "Windows" → Select the Windows integration (by Elastic)
# 3. Scroll to the "Custom event log channel" section
# 4. Add channel: Microsoft-Windows-Sysmon/Operational
# 5. Save and deploy
#
# NOTE: Task 2 will configure Security, System, Application, and PowerShell
#       Operational channels — you can add them all in Task 2 instead of now.
# ----------------------------------------------------------


# =============================================================================
# STEP 7: VERIFY LOGS APPEAR IN KIBANA
# =============================================================================

# ----------------------------------------------------------
# UI STEPS (Kibana Discover):
# ----------------------------------------------------------
# 1. Kibana → Discover
# 2. Set time range: Last 15 minutes (or Last 1 hour)
# 3. Search query for Sysmon Process Create events:
#      event.code: "1" AND winlog.channel: "Microsoft-Windows-Sysmon/Operational"
#
# 4. Useful fields to add to your columns in Discover:
#      winlog.event_data.Image          (the process that was created)
#      winlog.event_data.CommandLine    (full command line)
#      winlog.event_data.ParentImage    (parent process)
#      winlog.event_data.Hashes         (SHA256 hash)
#      winlog.event_data.User           (user context)
#
# 5. For Network Connect (Event ID 3):
#      event.code: "3" AND winlog.channel: "Microsoft-Windows-Sysmon/Operational"
#      Useful fields:
#        destination.ip
#        destination.port
#        winlog.event_data.Image  (which process connected)
#
# 6. For File Create (Event ID 11):
#      event.code: "11" AND winlog.channel: "Microsoft-Windows-Sysmon/Operational"
#      Useful fields:
#        winlog.event_data.TargetFilename
#        winlog.event_data.Image
# ----------------------------------------------------------


# =============================================================================
# STEP 8: HOW TO UPDATE THE SYSMON CONFIG (NO REINSTALL NEEDED)
# =============================================================================

# If you tune the config (add exclusions, add rules), apply changes with -c:
# C:\SOCLab\Sysmon\Sysmon64.exe -c C:\SOCLab\Sysmon\sysmonconfig.xml

# Check current running config:
# C:\SOCLab\Sysmon\Sysmon64.exe -c
# (shows the schema version and confirms config is loaded)


# =============================================================================
# USEFUL QUERIES FOR KIBANA (KQL) — SAVE THESE
# =============================================================================
#
# All Sysmon events:
#   winlog.channel: "Microsoft-Windows-Sysmon/Operational"
#
# Process Create (ID 1) for any cmd.exe spawned:
#   event.code: "1" AND winlog.event_data.Image: "*cmd.exe"
#
# PowerShell spawning network connections (ID 3):
#   event.code: "3" AND winlog.event_data.Image: "*powershell.exe"
#
# Files written to TEMP (ID 11):
#   event.code: "11" AND winlog.event_data.TargetFilename: "*Temp*"
#
# Any process with encoded PowerShell command (ID 1):
#   event.code: "1" AND winlog.event_data.CommandLine: "*-enc*"
#
# Parent-child: Word spawning shell (ID 1):
#   event.code: "1" AND winlog.event_data.ParentImage: "*WINWORD.exe"
#     AND (winlog.event_data.Image: "*cmd.exe" OR winlog.event_data.Image: "*powershell.exe")


# =============================================================================
# INTERVIEW PREP — KEY CONCEPTS TO BE ABLE TO EXPLAIN
# =============================================================================
#
# Q: Why use Sysmon instead of native Windows logging?
# A: Native Windows Event ID 4688 requires GPO to enable command line logging
#    and provides no file hashes. Sysmon gives full command lines, SHA256
#    hashes, parent process info, and network-to-process mapping by default.
#    It also hooks at the kernel level via a driver, making it more complete.
#
# Q: What is a Windows Event Log channel?
# A: A named, structured log stream registered by a Windows service or app.
#    Each channel has a unique path (e.g. Microsoft-Windows-Sysmon/Operational).
#    The Event Log service routes events from providers to channels. Agents
#    like Elastic read specific channels by exact name.
#
# Q: What is the SwiftOnSecurity config doing?
# A: It provides XML filter rules that tell Sysmon which events to include or
#    exclude. For noisy event types (DLL loads), it flips to an include-only
#    model. For most events it uses exclusions to filter known-good system
#    noise, reducing EPS (events per second) while keeping high-fidelity data.
#
# Q: What Sysmon Event IDs matter most for detection?
# A: 1 (Process Create — process lineage + hashes), 3 (Network Connect —
#    process-to-IP mapping), 7 (Image Load — DLL hijacking detection),
#    11 (File Create — payload drops). Also: 8 (CreateRemoteThread — injection),
#    12/13 (Registry — persistence via Run keys), 22 (DNS query).
#
# Q: How does Sysmon differ from EDR?
# A: Sysmon is telemetry only — it logs and you query. EDR (CrowdStrike,
#    Defender for Endpoint) adds automated response, behavioral AI, and
#    real-time blocking. Sysmon is free and gives you EDR-like visibility
#    for detection engineering practice.


# =============================================================================
# CLEANUP SECTION (run only if needed)
# =============================================================================

# To uninstall Sysmon completely (DO NOT run during lab setup):
# C:\SOCLab\Sysmon\Sysmon64.exe -u

# To remove test files created in Step 5:
# Remove-Item "$env:TEMP\sysmon_test_payload.txt" -Force -ErrorAction SilentlyContinue
# Remove-Item "$env:TEMP\sysmon_test.ps1" -Force -ErrorAction SilentlyContinue

# =============================================================================
# END OF TASK 1
# Next: Task 2 — Windows Event Log channels (Security, System, Application,
#               PowerShell Operational) and Event IDs 4624, 4625, 4688,
#               4720, 4103, 4104
# =============================================================================