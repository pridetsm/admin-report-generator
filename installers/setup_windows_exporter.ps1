# windows_exporter Setup Script
# Derived from the verified install manual (HRE-HCIHOST-01).
# Run in an elevated PowerShell session. Tested and working sequence.
#
# BEFORE RUNNING: update the variables in Section 1 for this specific server.
# The script pauses at interactive steps (passwords, hash generation).
#
# AUTO-DEPLOY: if a workaround script exists in the same folder as this script,
# it will be deployed to C:\scripts\ and scheduled as MetricsWorkaround (3-min interval).
# Recognised names (in priority order):
#   collect_metrics_workaround_lite.ps1      (preferred - full native collector list)
#   collect_metrics_workaround.ps1           (full - service,textfile only servers)
#   collect_metrics_workaround_prefixed.ps1  (cross-machine variant)

# ==============================================================================
# SECTION 1 - Configure for this server (edit these before running)
# ==============================================================================
$InstallDir  = "C:\Program Files\windows_exporter"
$ConfDir     = "C:\Program Files\windows_exporter\conf"
$BindIP      = "10.200.246.2"           # e.g. 10.100.246.3
$PromIP      = "10.100.248.249"      # Prometheus server IP
$HostCN      = "byo-vdihost-01.corp.rbz.co.zw"           # FQDN e.g. byo-vdihost-01.corp.rbz.co.zw
$TextfileDir = "$ConfDir\textfile_inputs"

# Collector list - swap comments to use service,textfile only (safe) vs full list (confirmed clean servers)
# $Collectors = "service,textfile"
$Collectors  = "cpu,memory,logical_disk,physical_disk,net,os,service,system,tcp,textfile"

if ($BindIP -eq "CHANGE_ME" -or $HostCN -eq "CHANGE_ME") {
    Write-Error "Update SECTION 1 variables before running this script."
    exit 1
}

Write-Host "`n=== windows_exporter Setup ===" -ForegroundColor Cyan
Write-Host "Server:     $HostCN"
Write-Host "Bind IP:    $BindIP"
Write-Host "Collectors: $Collectors`n"

# ==============================================================================
# REINSTALL DETECTION
# ==============================================================================
$existingService = Get-Service -Name windows_exporter -ErrorAction SilentlyContinue
$existingBinary  = Test-Path "$InstallDir\windows_exporter.exe"
$existingConfig  = Test-Path "$ConfDir\web-config.yml"

if ($existingService -or $existingBinary -or $existingConfig) {
    Write-Host "WARNING: windows_exporter appears to already be installed on this server:" -ForegroundColor Yellow
    if ($existingService) { Write-Host "   Service status: $($existingService.Status)" }
    if ($existingBinary)  { Write-Host "   Binary exists : $InstallDir\windows_exporter.exe" }
    if ($existingConfig)  {
        Write-Host "   Config exists : $ConfDir\web-config.yml"
        $existingCert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -like "*$($env:computername)*" } | Select-Object -First 1
        if ($existingCert) { Write-Host "   Cert expires  : $($existingCert.NotAfter)  [$($existingCert.Subject)]" }
    }
    Write-Host ""
    $confirm = Read-Host "Proceed with reinstall? This will overwrite existing config, cert and service registration. (yes/no)"
    if ($confirm -ne "yes") {
        Write-Host "Aborted - no changes made." -ForegroundColor Cyan
        exit 0
    }
    Write-Host "`nProceeding with reinstall...`n" -ForegroundColor Yellow
    Stop-Service windows_exporter -ErrorAction SilentlyContinue
}

# ==============================================================================
# SECTION 2 - Python
# ==============================================================================
Write-Host "--- Checking Python ---" -ForegroundColor Yellow
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "Python not found - installing..."
    Invoke-WebRequest "https://www.python.org/ftp/python/3.12.7/python-3.12.7-amd64.exe" -OutFile "$env:TEMP\python-installer.exe"
    Start-Process -FilePath "$env:TEMP\python-installer.exe" -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1 Include_test=0" -Wait
    $pyPath = "C:\Program Files\Python312"
    [System.Environment]::SetEnvironmentVariable("Path", [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";$pyPath;$pyPath\Scripts", "Machine")
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
    Write-Host "Python installed."
} else {
    Write-Host "Python already available: $(python --version)"
}

# ==============================================================================
# SECTION 3 - Folders and binary
# ==============================================================================
Write-Host "`n--- Creating folders ---" -ForegroundColor Yellow
New-Item -ItemType Directory -Force -Path $InstallDir, $ConfDir, $TextfileDir | Out-Null
Write-Host "Folders created."

if (-not (Test-Path "$InstallDir\windows_exporter.exe")) {
    Write-Host "`n--- Downloading windows_exporter ---" -ForegroundColor Yellow
    $VER = (Invoke-RestMethod "https://api.github.com/repos/prometheus-community/windows_exporter/releases/latest").tag_name -replace '^v', ''
    Invoke-WebRequest "https://github.com/prometheus-community/windows_exporter/releases/download/v$VER/windows_exporter-$VER-amd64.exe" -OutFile "$InstallDir\windows_exporter.exe"
    Write-Host "Downloaded v$VER."
} else {
    Write-Host "windows_exporter.exe already present - skipping download."
}

# ==============================================================================
# SECTION 4 - bcrypt hash
# ==============================================================================
Write-Host "`n--- Generating bcrypt hash ---" -ForegroundColor Yellow
Write-Host "Enter the password Prometheus will use to authenticate (metrics_user):"
python -m pip install bcrypt -q
$bcryptHash = python -c "import bcrypt,getpass; print(bcrypt.hashpw(getpass.getpass().encode(), bcrypt.gensalt(12)).decode())"
Write-Host "Hash generated."

# ==============================================================================
# SECTION 5 - Certificate
# ==============================================================================
Write-Host "`n--- Creating self-signed certificate ---" -ForegroundColor Yellow
Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -eq "CN=$HostCN" } | Remove-Item -ErrorAction SilentlyContinue

$cert = New-SelfSignedCertificate -DnsName $HostCN -CertStoreLocation "cert:\LocalMachine\My" -NotAfter (Get-Date).AddDays(825)
Export-Certificate -Cert $cert -FilePath "$ConfDir\windows_exporter.crt" | Out-Null
$pfxPwd = Read-Host "Set PFX export password" -AsSecureString
Export-PfxCertificate -Cert $cert -FilePath "$ConfDir\windows_exporter.pfx" -Password $pfxPwd | Out-Null
Write-Host "Certificate created (expires $((Get-Date).AddDays(825).ToString('yyyy-MM-dd')))."

Write-Host "`n--- Converting PFX to PEM/KEY ---" -ForegroundColor Yellow
python -m pip install cryptography -q

$convertScript = @'
import getpass
from cryptography.hazmat.primitives.serialization import pkcs12, Encoding, PrivateFormat, NoEncryption

pwd = getpass.getpass("Re-enter the PFX password: ").encode()
with open(r"__CONFDIR__\windows_exporter.pfx", "rb") as f:
    pfx_data = f.read()

key, cert, _ = pkcs12.load_key_and_certificates(pfx_data, pwd)

with open(r"__CONFDIR__\windows_exporter.pem", "wb") as f:
    f.write(cert.public_bytes(Encoding.PEM))

with open(r"__CONFDIR__\windows_exporter.key", "wb") as f:
    f.write(key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))

print("PEM and KEY written.")
'@
$convertScript = $convertScript -replace '__CONFDIR__', $ConfDir
$convertScript | Set-Content "$env:TEMP\convert_pfx.py" -Encoding UTF8
python "$env:TEMP\convert_pfx.py"

if (-not (Test-Path "$ConfDir\windows_exporter.pem") -or -not (Test-Path "$ConfDir\windows_exporter.key")) {
    Write-Error "PEM/KEY conversion failed. Check PFX password and retry."
    exit 1
}
Write-Host "PEM and KEY confirmed."

# ==============================================================================
# SECTION 6 - web-config.yml
# ==============================================================================
Write-Host "`n--- Writing web-config.yml ---" -ForegroundColor Yellow

$webConfig = @"
tls_server_config:
  cert_file: $ConfDir\windows_exporter.pem
  key_file: $ConfDir\windows_exporter.key
basic_auth_users:
  metrics_user: $bcryptHash
"@
$webConfig | Set-Content "$ConfDir\web-config.yml" -Encoding UTF8

$configCheck = Get-Content "$ConfDir\web-config.yml" | Select-String "metrics_user"
if ($configCheck -notmatch '\$2b\$12\$') {
    Write-Error "bcrypt hash was corrupted in web-config.yml. Check and regenerate."
    exit 1
}
Write-Host "web-config.yml written and verified."

# ==============================================================================
# SECTION 7 - Service registration
# ==============================================================================
Write-Host "`n--- Registering service ---" -ForegroundColor Yellow
$binPath = "`"$InstallDir\windows_exporter.exe`" --web.listen-address=`"${BindIP}:9182`" --web.config.file=`"$ConfDir\web-config.yml`" --collectors.enabled=`"$Collectors`" --collector.textfile.directories=`"$TextfileDir`" --log.file=`"$ConfDir\service-debug.log`""

if (Get-Service -Name windows_exporter -ErrorAction SilentlyContinue) {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\windows_exporter" -Name ImagePath -Value $binPath
    Write-Host "Existing service updated."
} else {
    New-Service -Name windows_exporter -BinaryPathName $binPath -StartupType Automatic -DisplayName "windows_exporter"
    Write-Host "Service registered."
}

# ==============================================================================
# SECTION 8 - Service account
# ==============================================================================
Write-Host "`n--- Creating service account ---" -ForegroundColor Yellow
$svcPwd = Read-Host "New password for svc_windows_exporter" -AsSecureString

if (Get-LocalUser -Name "svc_windows_exporter" -ErrorAction SilentlyContinue) {
    Set-LocalUser -Name "svc_windows_exporter" -Password $svcPwd
    Write-Host "Account already exists - password reset."
} else {
    New-LocalUser -Name "svc_windows_exporter" -Password $svcPwd -PasswordNeverExpires -AccountNeverExpires
    Write-Host "Account created."
}

secedit /export /cfg "$env:TEMP\secpol.cfg" | Out-Null
$sid = (Get-LocalUser -Name "svc_windows_exporter").SID.Value
(Get-Content "$env:TEMP\secpol.cfg") -replace '(SeServiceLogonRight = .*)', "`$1,*$sid" | Set-Content "$env:TEMP\secpol.cfg"
secedit /configure /db "$env:TEMP\secedit.sdb" /cfg "$env:TEMP\secpol.cfg" /areas USER_RIGHTS | Out-Null
Write-Host "Log on as a service right granted."

icacls "$ConfDir" /grant "svc_windows_exporter:(OI)(CI)(M)" | Out-Null
Write-Host "Conf folder write access granted."

Add-LocalGroupMember -Group "Performance Monitor Users" -Member "svc_windows_exporter" -ErrorAction SilentlyContinue
Add-LocalGroupMember -Group "Performance Log Users" -Member "svc_windows_exporter" -ErrorAction SilentlyContinue
Write-Host "Added to Performance Monitor Users and Performance Log Users."

$svcPwdPlain = Read-Host "Re-enter the SAME svc_windows_exporter password (plain text)"
sc.exe config windows_exporter obj= ".\svc_windows_exporter" password= "$svcPwdPlain"

# ==============================================================================
# SECTION 9 - Firewall rule
# ==============================================================================
Write-Host "`n--- Adding firewall rule ---" -ForegroundColor Yellow
New-NetFirewallRule -DisplayName "windows_exporter (Prometheus only)" -Direction Inbound -Protocol TCP -LocalPort 9182 -RemoteAddress $PromIP -Action Allow -ErrorAction SilentlyContinue | Out-Null
Write-Host "Firewall rule added (allow $PromIP -> port 9182)."

# ==============================================================================
# SECTION 10 - Start and verify
# ==============================================================================
Write-Host "`n--- Starting service ---" -ForegroundColor Yellow
Stop-Service windows_exporter -ErrorAction SilentlyContinue
Start-Service windows_exporter
Start-Sleep -Seconds 4
$svc = Get-Service windows_exporter
Write-Host "Service status: $($svc.Status)"

if ($svc.Status -eq 'Running') {
    Write-Host "`nOK windows_exporter is RUNNING." -ForegroundColor Green
    Write-Host "Endpoint: https://${BindIP}:9182/metrics"
    Write-Host "Username: metrics_user"
} else {
    Write-Host "`nFAILED Service failed to start. Check log:" -ForegroundColor Red
    Get-Content "$ConfDir\service-debug.log" -Tail 15
    Write-Host "`nIf collectors failed with 'Unable to read the counter', revert to service,textfile:"
    Write-Host "  Set Collectors = service,textfile at the top of this script and re-run from Section 7."
}

Write-Host "`n--- Log tail ---" -ForegroundColor Yellow
Get-Content "$ConfDir\service-debug.log" -Tail 10

# ==============================================================================
# SECTION 11 - Auto-deploy workaround script if found alongside this script
# ==============================================================================
$scriptFolder = Split-Path -Parent $MyInvocation.MyCommand.Path

$workaroundCandidates = @(
    "collect_metrics_workaround_lite.ps1",
    "collect_metrics_workaround.ps1",
    "collect_metrics_workaround_prefixed.ps1"
)

$workaroundSrc = $null
foreach ($candidate in $workaroundCandidates) {
    $candidatePath = Join-Path $scriptFolder $candidate
    if (Test-Path $candidatePath) {
        $workaroundSrc = $candidatePath
        Write-Host "`n--- Workaround script found: $candidate ---" -ForegroundColor Yellow
        break
    }
}

if ($workaroundSrc) {
    New-Item -ItemType Directory -Force -Path "C:\scripts" | Out-Null
    Copy-Item -Path $workaroundSrc -Destination "C:\scripts\collect_metrics_workaround.ps1" -Force
    Write-Host "Script copied to C:\scripts\collect_metrics_workaround.ps1"

    Write-Host "Running script once to verify output..."
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\scripts\collect_metrics_workaround.ps1"
    $promFile = "$TextfileDir\wmi_workaround_metrics.prom"
    if (Test-Path $promFile) {
        $fileSize = (Get-Item $promFile).Length
        Write-Host "Output file created ($fileSize bytes) - script is working."
    } else {
        Write-Host "WARNING: Output file not found after manual run - check script for errors." -ForegroundColor Yellow
    }

    $taskName = "MetricsWorkaround"
    $action   = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"C:\scripts\collect_metrics_workaround.ps1`""
    $trigger  = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 3) -RepetitionDuration (New-TimeSpan -Days 3650)
    $settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Seconds 150)

    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
        Write-Host "Existing MetricsWorkaround task removed."
    }

    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -User "SYSTEM" -RunLevel Highest | Out-Null
    Write-Host "OK MetricsWorkaround scheduled task registered (every 3 minutes, SYSTEM)." -ForegroundColor Green
    Write-Host "`nConfirm task fires in ~3 minutes:"
    Write-Host "  Get-ScheduledTaskInfo -TaskName 'MetricsWorkaround' | Select-Object LastRunTime, LastTaskResult, NextRunTime"
} else {
    Write-Host "`n--- No workaround script found alongside setup script - skipping auto-deploy ---" -ForegroundColor Yellow
    Write-Host "Place one of the following in the same folder as this script and re-run:"
    Write-Host "  - collect_metrics_workaround_lite.ps1"
    Write-Host "  - collect_metrics_workaround.ps1"
    Write-Host "  - collect_metrics_workaround_prefixed.ps1"
}