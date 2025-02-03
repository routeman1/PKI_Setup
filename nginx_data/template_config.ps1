

## Update the following variables to match your environment
$unattend = "https://host/unattend.xml"
$sshkeyurl = "https://host/pkisetup.pub"
$sshkey = "pkisetup.pub"
$fixkeyscript = "https://host/fix_authorized_keys.ps1"

#---------------------[Functions]-----------------------------------
Function SSHconfig {

        Write-Host "Installing and configuring SSH service"
        
            Write-Host "Verifiying script is running as admin" 
            If (!(New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
            {
                Write-Host "Script is not running as admin" -ForegroundColor Red
                exit
            }

            # Begin SSH Configuration
            Write-Host "Checking if SSH is already installed"
            if ((Get-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0).State -eq 'Installed') {
                Write-Host "The Microsoft OpenSSH is Installed- Please remove this so that we can install the Github verison"
            }
            elseif (Get-Service -Name sshd -ErrorAction SilentlyContinue) {
                Write-Host "OpenSSH is Installed"
            } 
            else {
                Write-Host "Installing SSH"
                # Install the Windows OpenSSH Client & Server
                #Invoke-WebRequest -Uri "https://github.com/PowerShell/Win32-OpenSSH/releases/download/v9.8.1.0p1-Preview/OpenSSH-Win64-v9.8.1.0.msi" -OutFile "C:\Windows\Temp\OpenSSH-Win64-v9.8.1.0.msi"
                cmd /C "msiexec /i C:\Windows\Temp\OpenSSH-Win64-v9.8.1.0.msi" 

                ## Create sshd config file
                    Write-Host "Creating sshd config file" 

    #--------------------------
    # sshd_config file content 
    #--------------------------

    $sshdconf = @"
# This is the sshd server system-wide configuration file.  See
# sshd_config(5) for more information.

# The strategy used for options in the default sshd_config shipped with
# OpenSSH is to specify options with their default value where
# possible, but leave them commented.  Uncommented options override the
# default value.

#Port 22
#AddressFamily any
#ListenAddress 0.0.0.0
#ListenAddress ::

#HostKey __PROGRAMDATA__/ssh/ssh_host_rsa_key
#HostKey __PROGRAMDATA__/ssh/ssh_host_dsa_key
#HostKey __PROGRAMDATA__/ssh/ssh_host_ecdsa_key
#HostKey __PROGRAMDATA__/ssh/ssh_host_ed25519_key

# Ciphers and keying
#RekeyLimit default none

# Logging
#SyslogFacility AUTH
#LogLevel INFO

# Authentication:

#LoginGraceTime 2m
#PermitRootLogin prohibit-password
#StrictModes yes
#MaxAuthTries 6
#MaxSessions 10

PubkeyAuthentication yes

# The default is to check both .ssh/authorized_keys and .ssh/authorized_keys2
# but this is overridden so installations will only check .ssh/authorized_keys
AuthorizedKeysFile	.ssh/authorized_keys

#AuthorizedPrincipalsFile none

# For this to work you will also need host keys in %programData%/ssh/ssh_known_hosts
#HostbasedAuthentication no
# Change to yes if you don't trust ~/.ssh/known_hosts for
# HostbasedAuthentication
#IgnoreUserKnownHosts no
# Don't read the user's ~/.rhosts and ~/.shosts files
#IgnoreRhosts yes

# To disable tunneled clear text passwords, change to no here!
#PasswordAuthentication yes
#PermitEmptyPasswords no

# GSSAPI options
#GSSAPIAuthentication no

#AllowAgentForwarding yes
#AllowTcpForwarding yes
#GatewayPorts no
#PermitTTY yes
#PrintMotd yes
#PrintLastLog yes
#TCPKeepAlive yes
#UseLogin no
#PermitUserEnvironment no
#ClientAliveInterval 0
#ClientAliveCountMax 3
#UseDNS no
#PidFile /var/run/sshd.pid
#MaxStartups 10:30:100
#PermitTunnel no
#ChrootDirectory none
#VersionAddendum none

# no default banner path
#Banner none

# override default of no subsystems
Subsystem	sftp	sftp-server.exe
Subsystem	powershell c:/progra~1/powershell/7/pwsh.exe -sshs -nologo -noprofile

# Example of overriding settings on a per-user basis
#Match User anoncvs
#	AllowTcpForwarding no
#	PermitTTY no
#	ForceCommand cvs server

Match Group administrators
       AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys
"@

    $sshdconf | Out-File "C:\ProgramData\ssh\sshd_config" -Encoding utf8 -Force | Out-Null

            }

            # Confirm the Firewall rule is configured. If not create it
            Write-Host "Configuring Firewall rules"
            if (!(Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue | Select-Object Name, Enabled)) {
                Write-Output "Firewall Rule 'OpenSSH-Server-In-TCP' does not exist, creating it..."
                New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 | Out-Null
            } else {
                Write-Output "Firewall rule has been created and exists."
            }

        # Get the public key file from the website
            Write-Host "Adding the SSH Key to the authorized_keys file"
            New-Item -Force -ItemType Directory -Path $env:USERPROFILE\.ssh | Out-Null
            #Copy-Item -Path "C:\Windows\Temp\$sshkey" -Destination "$env:USERPROFILE\.ssh\$sshkey" | Out-Null
            #Invoke-WebRequest -Uri $sshkeyurl -OutFile $env:USERPROFILE\.ssh\$sshkey 
            $authorizedKey = Get-Content -Path C:\Windows\Temp\$sshkey
            Add-Content -Force -Path $env:USERPROFILE\.ssh\authorized_keys -Value $authorizedKey | Out-Null
            Add-Content -Force -Path "C:\ProgramData\ssh\administrators_authorized_keys" -Value $authorizedKey | Out-Null
            ##Copy-Item -Path "$env:USERPROFILE\.ssh\$sshkey" -Destination "C:\Windows\Temp\" | Out-Null

    Write-Host "SSH Configuration is complete" -ForegroundColor Green
        }

Function PSUpdate {

        Write-Host "Verifying the current PowerShell version"
        
            Write-Host "Verifiying script is running as admin" 
            If (!($PSVersionTable.PSVersion.Major -ge 7))
            {
                Write-Host "Upgrading PowerShell" 
                #Invoke-WebRequest -Uri "https://github.com/PowerShell/PowerShell/releases/download/v7.4.6/PowerShell-7.4.6-win-x64.msi" -OutFile "C:\Windows\Temp\PowerShell-7.4.6-win-x64.msi" 
                cmd /C "msiexec.exe /i C:\Windows\Temp\PowerShell-7.4.6-win-x64.msi /quiet ADD_EXPLORER_CONTEXT_MENU_OPENPOWERSHELL=1 ADD_FILE_CONTEXT_MENU_RUNPOWERSHELL=1 ENABLE_PSREMOTING=1 REGISTER_MANIFEST=1 USE_MU=1 ENABLE_MU=1 ADD_PATH=1"
            }
            else {
                Write-Host "PowerShell is up to date"
            }

            # Set default shell for OpenSSH to PS7
            Write-Host "Setting default shell for OpenSSH to PS7"
            New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "C:\Program Files\PowerShell\7\pwsh.exe" -PropertyType String -Force | Out-Null

    Write-Host "PowerShell Configuration is complete" -ForegroundColor Green
        }

Function Cleanup {

    Write-Host "Cleaning up temporary files"
    Remove-Item -Force -Path "C:\Windows\Temp\template_config.ps1" | Out-Null
    Remove-Item -Force -Path "C:\Windows\Temp\PowerShell-7.4.6-win-x64.msi" | Out-Null

    Write-Host "Configuring OpenSSH to generate new host keys on first boot"
    Remove-Item -Force -Path "C:\ProgramData\ssh\*.key" | Out-Null
    Remove-Item -Force -Path "C:\ProgramData\ssh\*.pub" | Out-Null

    #Write-Host "Staging Unattend.xml files"
    #Invoke-WebRequest -Uri "$unattend" -OutFile "C:\Windows\Temp\unattend.xml" 
    #Invoke-WebRequest -Uri "$fixkeyscript" -OutFile "C:\Windows\Temp\fix_authorized_keys.ps1" 
}

#---------------------------------------------------------[ Execution ]---------------------------------------------------

Write-Host "Setting Execution Policy for this Session"
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

Write-Host "Begining installation and configuration of SSH" -ForegroundColor Yellow
SSHconfig 

Write-Host "Updating PowerShell version and configuration to support SSH Connections" -ForegroundColor Yellow
PSUpdate 

Cleanup

Write-Host "Running Sysprep - The system will shutdown upon completion" -ForegroundColor Yellow
Write-Host "You can then convert this VM into a template" -ForegroundColor Yellow
Write-Host ""
Start-Sleep -Seconds 5
Start-Process -FilePath "C:\Windows\System32\Sysprep\Sysprep.exe" -ArgumentList "/generalize /oobe /shutdown /unattend:C:\Windows\Temp\unattend.xml"

