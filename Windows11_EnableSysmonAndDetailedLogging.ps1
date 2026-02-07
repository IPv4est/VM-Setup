.SYNOPSIS
    Lab Provisioning Script - Console Output Only.
    Cleans all logs and artifacts for a pristine snapshot.
#>

# --- 1. PRE-FLIGHT ---
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "CRITICAL: Run as Administrator!" -ForegroundColor Red; pause; exit
}

# --- 2. REGISTRY HARDENING ---
Write-Host "[-] Hardening Registry Policies..." -ForegroundColor Cyan
$Paths = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit",
    "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
)

foreach ($Path in $Paths) {
    if (!(Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
}

New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine" -Value 1 -PropertyType DWORD -Force | Out-Null
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1 -PropertyType DWord -Force | Out-Null

# --- 3. INSTALLATION ---
Write-Host "[-] Installing Sysmon..." -ForegroundColor Cyan
$WorkDir = "$env:USERPROFILE\Downloads\Lab_Setup_Temp"
New-Item -Path $WorkDir -ItemType Directory -Force | Out-Null

Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$WorkDir\Sysmon.zip"
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml" -OutFile "$WorkDir\sysmonconfig.xml"
Expand-Archive -Path "$WorkDir\Sysmon.zip" -DestinationPath $WorkDir -Force
Start-Process -FilePath "$WorkDir\Sysmon64a.exe" -ArgumentList "-i `"$WorkDir\sysmonconfig.xml`"", "-accepteula" -Wait

# Native Audit Policies
auditpol /set /subcategory:"Process Creation" /success:enable
auditpol /set /subcategory:"File System" /success:enable

# Apply SACLs to profile folders
$TargetFolders = @("$env:USERPROFILE\Music","$env:USERPROFILE\Downloads","$env:USERPROFILE\Desktop")
$Rule = New-Object System.Security.AccessControl.FileSystemAuditRule("Everyone", "CreateFiles, WriteData", "ContainerInherit, ObjectInherit", "None", "Success")
foreach ($F in $TargetFolders) {
    if (Test-Path $F) { $Acl = Get-Acl -Path $F -Audit; $Acl.AddAuditRule($Rule); Set-Acl -Path $F -AclObject $Acl }
}

Write-Host "[-] Waiting 10s for system to prime..." -ForegroundColor Gray
Start-Sleep -Seconds 10

# --- 4. VERIFICATION ---
Write-Host "`n--- STARTING VERIFICATION CUTOUT ---" -ForegroundColor Yellow

$MusicFile = "$env:USERPROFILE\Music\Master_Test_4663.txt"
$SysFile   = "$env:USERPROFILE\Downloads\Master_Test_Sys11.txt"
"Test" | Out-File $MusicFile
"Test" | Out-File $SysFile
powershell.exe -NoProfile -Command "Write-Output 'VERIFY-TELEMETRY-LOGGING-ACTIVE'"

$Found = @{"Native"=$false; "Sysmon"=$false; "Posh"=$false}
for ($i=0; $i -lt 15; $i++) {
    if (!$Found.Native) { $Evt = Get-WinEvent -LogName Security -MaxEvents 100 -ErrorAction SilentlyContinue | Where-Object {$_.Id -eq 4663 -and $_.Message -match "Master_Test_4663"}; if ($Evt) { $Found.Native = $true; Write-Host "[PASS] Security Log 4663 Detected" -ForegroundColor Green } }
    if (!$Found.Sysmon) { $Evt = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 100 -ErrorAction SilentlyContinue | Where-Object {$_.Id -eq 11 -and $_.Message -match "Master_Test_Sys11"}; if ($Evt) { $Found.Sysmon = $true; Write-Host "[PASS] Sysmon Event 11 Detected" -ForegroundColor Green } }
    if (!$Found.Posh) { $Evt = Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 200 -ErrorAction SilentlyContinue | Where-Object {$_.Id -eq 4104 -and $_.Message -match "VERIFY-TELEMETRY-LOGGING-ACTIVE"}; if ($Evt) { $Found.Posh = $true; Write-Host "[PASS] PowerShell 4104 Detected" -ForegroundColor Green } }
    if ($Found.Native -and $Found.Sysmon -and $Found.Posh) { break }
    Start-Sleep -Seconds 2
}

# --- 5. CLEANUP & SNAPSHOT PREP ---
Write-Host "`n[-] Cleaning artifacts and wiping all logs..." -ForegroundColor Cyan
Remove-Item $MusicFile, $SysFile, $WorkDir -Recurse -Force -ErrorAction SilentlyContinue
$Logs = @("Security", "Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-PowerShell/Operational", "System", "Application")
foreach ($L in $Logs) { wevtutil cl "$L" }

Write-Host "[***] PROVISIONING COMPLETE. READY FOR SNAPSHOT." -ForegroundColor Green
pause
