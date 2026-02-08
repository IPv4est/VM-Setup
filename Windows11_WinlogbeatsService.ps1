param (
    [Parameter(Mandatory=$true)]
    [ValidateSet("start", "stop", "status")]
    $Action
)

switch ($Action) {
    "start"  { Start-Service winlogbeat; Get-Service winlogbeat }
    "stop"   { Stop-Service winlogbeat; Get-Service winlogbeat }
    "status" { Get-Service winlogbeat }
}
