# Adapted from https://tinyurl.com/redhatosvwin - thanks to Eran Ifrach.

# Create working directory
$BasePath = "C:\Windows\Temp\Install"
New-item $BasePath -itemtype directory

# Enable RDP
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

# Add Red Hat to Trusted Publisher. This requires that the Red Hat Guest Additions
# ISO is loaded as part of the bootstrap VM implementation.

$CertName = "balloon.cer"
$ExportCert = Join-Path $BasePath -ChildPath $CertName
$CertStorePath = "Cert:\LocalMachine\TrustedPublisher"
$CertStore = Get-Item $CertStorePath
$Cert = (Get-AuthenticodeSignature "e:\Balloon\2k19\amd64\balloon.sys").SignerCertificate
$ExportType = [System.Security.Cryptography.X509Certificates.X509ContentType]::Cert
[System.IO.File]::WriteAllBytes($ExportCert, $Cert.Export($ExportType))
$CertStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]"ReadWrite")
$CertStore.Add($Cert)
$CertStore.Close()

# install Guest Agent. This requires that the Red Hat Guest Additions
# ISO is loaded as part of the bootstrap VM implementation.

msiexec /i e:\virtio-win-gt-x64.msi /qn /passive

# install Qemu Tools (Drivers). This requires that the Red Hat Guest Additions
# ISO is loaded as part of the bootstrap VM implementation.

msiexec /i e:\guest-agent\qemu-ga-x86_64.msi /qn /passive

# Fix Guest Agent. This requires that the Red Hat Guest Additions
# ISO is loaded as part of the bootstrap VM implementation.

Start-Process  E:\vioserial\2k19\amd64\vioser.inf -Verb install

# Cleanup - remove temp installation directory
Remove-item $BasePath -Recurse

# Cleanup - remove AutoLogin
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_SZ /d 0 /f

# Run Sysprep and Shutdown
& C:\Windows\System32\Sysprep\sysprep.exe /generalize /oobe /shutdown
