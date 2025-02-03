# Fix Authorized Keys on first boot
New-Item -Force -ItemType Directory -Path $env:USERPROFILE\.ssh | Out-Null

Copy-Item -Path "c:\Windows\Temp\pkisetup.pub" -Destination "$env:USERPROFILE\.ssh\pkisetup.pub" | Out-Null
$authorizedKey = Get-Content -Path "$env:USERPROFILE\.ssh\pkisetup.pub"

Add-Content -Force -Path "$env:USERPROFILE\.ssh\authorized_keys" -Value $authorizedKey | Out-Null
Add-Content -Force -Path "C:\ProgramData\ssh\administrators_authorized_keys" -Value $authorizedKey | Out-Null