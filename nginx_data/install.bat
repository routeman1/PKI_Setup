:: This is part of the PKI-Setup series of scripts
:: This configures the VM template with SSH, PS7 and the required keys
::
:: Download the required files and save in the Windows Temp Directory
curl -k -o C:\Windows\Temp\template_config.ps1 https://host/template_config.ps1
curl -k -o C:\Windows\Temp\fix_authorized_keys.ps1 https://host/fix_authorized_keys.ps1
curl -k -o C:\Windows\Temp\pkisetup.pub https://host/pkisetup.pub
curl -k -o C:\Windows\Temp\unattend.xml https://host/unattend.xml
curl -Lo C:\Windows\Temp\OpenSSH-Win64-v9.8.1.0.msi https://github.com/PowerShell/Win32-OpenSSH/releases/download/v9.8.1.0p1-Preview/OpenSSH-Win64-v9.8.1.0.msi
curl -Lo C:\Windows\Temp\PowerShell-7.4.6-win-x64.msi https://github.com/PowerShell/PowerShell/releases/download/v7.4.6/PowerShell-7.4.6-win-x64.msi 
:: Execute the powershell script to install/configure 
powershell C:\Windows\Temp\template_config.ps1