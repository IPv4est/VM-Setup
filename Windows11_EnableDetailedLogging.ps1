<# 
.SYNOPSIS
    Lab Provisioning - Final Master Script
    Binary: Sysmon64a.exe
    Coverage: 7 SACL Folders, 4104 PowerShell, 4688 CmdLine
#>

# --- ADMIN CHECK ---
$IsAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdmin) {
    Write-Host "CRITICAL: Run as Administrator!" -ForegroundColor Red
    pause
    exit
}

# --- GPEDIT + CMDLINE LOGGING ENABLEMENT ---
Write-Host "[-] Ensuring Group Policy + Command Line Logging..." -ForegroundColor Cyan

$GpeditPath = "$env:SystemRoot\System32\gpedit.msc"

if (-not (Test-Path $GpeditPath)) {
    Write-Host "  [*] gpedit.msc not found - installing via DISM..." -ForegroundColor Yellow

    $Packages = @(
        "Microsoft-Windows-GroupPolicy-ClientExtensions-Package",
        "Microsoft-Windows-GroupPolicy-ClientTools-Package"
    )

    foreach ($Pkg in $Packages) {
        $PkgPath = "$env:SystemRoot\servicing\Packages\$Pkg~*.mum"
        Get-ChildItem $PkgPath -ErrorAction SilentlyContinue | ForEach-Object {
            dism /online /norestart /add-package:"$($_.FullName)" | Out-Null
        }
    }

    Write-Host "  [+] gpedit components installed" -ForegroundColor Green
}
else {
    Write-Host "  [+] gpedit.msc already present" -ForegroundColor Green
}

$AuditPolicyPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit"

if (-not (Test-Path $AuditPolicyPath)) {
    New-Item -Path $AuditPolicyPath -Force | Out-Null
}

New-ItemProperty `
    -Path $AuditPolicyPath `
    -Name ProcessCreationIncludeCmdLine_Enabled `
    -Value 1 `
    -PropertyType DWord `
    -Force | Out-Null

Write-Host "  [+] Command Line Process Creation Logging ENABLED" -ForegroundColor Green

# --- REGISTRY POLICIES ---
Write-Host "[-] Configuring Registry Policies..." -ForegroundColor Cyan

$Paths = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit",
    "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
)

foreach ($Path in $Paths) {
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
}

New-ItemProperty `
    -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
    -Name ProcessCreationIncludeCmdLine_Output `
    -Value 1 `
    -PropertyType DWord `
    -Force | Out-Null

New-ItemProperty `
    -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
    -Name EnableScriptBlockLogging `
    -Value 1 `
    -PropertyType DWord `
    -Force | Out-Null

Set-ItemProperty `
    -Path "HKLM:\System\CurrentControlSet\Control\Lsa" `
    -Name SCENoApplyLegacyAuditPolicy `
    -Value 1 `
    -Type DWord `
    -Force

# --- NATIVE AUDIT POLICIES ---
Write-Host "[-] Setting Native Audit Policies..." -ForegroundColor Cyan
auditpol /set /subcategory:"Process Creation" /success:enable | Out-Null
auditpol /set /subcategory:"File System" /success:enable | Out-Null

# --- SYSMON INSTALLATION ---
Write-Host "[-] Installing Sysmon64a..." -ForegroundColor Cyan

$WorkDir = "$env:USERPROFILE\Downloads\Lab_Setup_Temp"

if (-not (Test-Path $WorkDir)) {
    New-Item -Path $WorkDir -ItemType Directory -Force | Out-Null
}

Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$WorkDir\Sysmon.zip"
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml" -OutFile "$WorkDir\sysmonconfig.xml"

Expand-Archive -Path "$WorkDir\Sysmon.zip" -DestinationPath $WorkDir -Force

$SysBin = "$WorkDir\Sysmon64a.exe"

if (Test-Path $SysBin) {
    Start-Process -FilePath $SysBin -ArgumentList "-i `"$WorkDir\sysmonconfig.xml`" -accepteula" -Wait
    Write-Host "[+] Sysmon64a Installed Successfully" -ForegroundColor Green
}
else {
    Write-Host "[!] Sysmon64a.exe NOT FOUND!" -ForegroundColor Red
}

# --- LOG CAPACITY & RETENTION CONTROL ---
Write-Host "[-] Configuring Event Log Size Limits (1GB, overwrite enabled)..." -ForegroundColor Cyan

$OneGB = 1073741824  # bytes

$EventLogs = @(
    "Security",
    "System",
    "Application",
    "Microsoft-Windows-Sysmon/Operational",
    "Microsoft-Windows-PowerShell/Operational",
    "Windows PowerShell"
)

foreach ($Log in $EventLogs) {
    try {
        wevtutil sl "$Log" /ms:$OneGB /rt:true /ab:false
        Write-Host "  [+] $Log set to 1GB (overwrite enabled)" -ForegroundColor Green
    } catch {
        Write-Host "  [!] Failed to configure $Log" -ForegroundColor DarkYellow
    }
}


# --- SACL CONFIGURATION ---
Write-Host "[-] Applying SACLs..." -ForegroundColor Cyan

$TargetFolders = @(
    "$env:USERPROFILE\Desktop",
    "$env:USERPROFILE\Documents",
    "$env:USERPROFILE\Downloads",
    "$env:USERPROFILE\Music",
    "$env:USERPROFILE\Pictures",
    "$env:USERPROFILE\Videos",
    "$env:USERPROFILE\AppData\Local\Temp"
)

$Rule = New-Object System.Security.AccessControl.FileSystemAuditRule(
    "Everyone",
    "CreateFiles, WriteData, Delete",
    "ContainerInherit, ObjectInherit",
    "None",
    "Success"
)

foreach ($F in $TargetFolders) {
    if (Test-Path $F) {
        $Acl = Get-Acl -Path $F -Audit
        $Acl.AddAuditRule($Rule)
        Set-Acl -Path $F -AclObject $Acl
        Write-Host "  [+] SACL Fixed: $F" -ForegroundColor Gray
    }
}

# --- FINALIZING ---
gpupdate /force | Out-Null

Write-Host ""
Write-Host "[***] MASTER PROVISIONING COMPLETE." -ForegroundColor Green
Write-Host "[!] REBOOT NOW TO SYNC KERNEL TELEMETRY." -ForegroundColor Yellow
