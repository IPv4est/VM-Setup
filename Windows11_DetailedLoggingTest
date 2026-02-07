Write-Host "--- STARTING FINAL TELEMETRY VERIFICATION ---" -ForegroundColor Yellow

# 1. TRIGGER EVENTS
$TestFile = "$env:USERPROFILE\Music\Master_Test_4663.txt"
$SysFile  = "$env:USERPROFILE\Downloads\Master_Test_Sys11.txt"

# Trigger File Creation (Native 4663 & Sysmon 11)
"Test" | Out-File $TestFile -Force
"Test" | Out-File $SysFile -Force

# Trigger Process Creation (Native 4688 & Sysmon 1)
cmd.exe /c "echo VERIFY_PROCESS_TELEMETRY"

# Trigger PowerShell (Posh 4104)
powershell.exe -NoProfile -Command "Write-Output 'VERIFY_PS_SCRIPT_LOGGING'"

Write-Host "[-] Waiting 8s for event buffers..." -ForegroundColor Gray
Start-Sleep -Seconds 8

# 2. RUN CHECKS
$Checks = @(
    @{Name="Native 4688 (Process+Cmd)"; Log="Security"; ID=4688; Filter="VERIFY_PROCESS_TELEMETRY"}
    @{Name="Native 4663 (File SACL)";   Log="Security"; ID=4663; Filter="Master_Test_4663"}
    @{Name="Sysmon 1 (Process)";       Log="Microsoft-Windows-Sysmon/Operational"; ID=1; Filter="VERIFY_PROCESS_TELEMETRY"}
    @{Name="Sysmon 11 (File Create)";  Log="Microsoft-Windows-Sysmon/Operational"; ID=11; Filter="Master_Test_Sys11"}
    @{Name="Posh 4104 (Script Block)"; Log="Microsoft-Windows-PowerShell/Operational"; ID=4104; Filter="VERIFY_PS_SCRIPT_LOGGING"}
)

foreach ($C in $Checks) {
    $Found = Get-WinEvent -LogName $C.Log -MaxEvents 200 -ErrorAction SilentlyContinue | 
             Where-Object { $_.Id -eq $C.ID -and $_.ToXml() -like "*$($C.Filter)*" }
    
    if ($Found) {
        Write-Host "[PASS] $($C.Name) Detected" -ForegroundColor Green
    } else {
        Write-Host "[FAIL] $($C.Name) Not Found" -ForegroundColor Red
    }
}

# 3. CLEANUP
Remove-Item $TestFile, $SysFile -ErrorAction SilentlyContinue
Write-Host "`n--- VERIFICATION COMPLETE ---" -ForegroundColor Yellow
