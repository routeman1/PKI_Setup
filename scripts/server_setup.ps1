#-------------------------[Initalization]-------------------------------

# NOTE: variables are read from the variables.csv file, and parsed from the menu script

#---------------------------[Server Prep]---------------------
# 
# Rename local Admin and Guest accounts (also change passwords), Disable guest, Rename computer
#
Function ServerPrep {
    param(
        [array]$HostList,
        [string]$UserName
    )
    
    $ComputerName = $HostList

    $secureDefWinLoginPass = ConvertTo-SecureString $DefWinLoginPass -AsPlainText -force 
    $secureNewAdminPass = ConvertTo-SecureString $NewAdminPass -AsPlainText -force
    $secureNewGuestPass = ConvertTo-SecureString $NewGuestPass -AsPlainText -force
    $secureRemoteAdminPass = ConvertTo-SecureString $RemoteAdminPass -AsPlainText -force
    $cred = (New-Object System.Management.Automation.PsCredential($DefWinAccount,$secureDefWinLoginPass))

    $AdminUserAccount = "Administrator"
    $GuestUserAccount = "Guest"  

        Write-Host "Running ServerPrep on: "$ComputerName[0]
        [String]$New_Host_Name = $ComputerName[0]
        $hostip = $ComputerName[1]

        # Here we take the contents of the function and pass it into the scriptblock as a string. 
        # Inside the scriptblock that’s running on the remote machine, we create a new scriptblock from that string and then run it. 
        Invoke-Command -HostName $hostip -UserName $DefWinAccount -KeyFilePath "$sshKeyFile" -ScriptBlock {

                # Set Timezone, Product Key, and activate windows
                Write-Host "[$using:New_Host_Name] Setting Timezone"
                Set-TimeZone -Name $using:Timezone
                Write-Host "[$using:New_Host_Name] Setting Product Key and Activating Windows"
                slmgr.vbs -ipk $using:WIN2022_LIC 
                slmgr.vbs -skms $using:VLM_IPAddress 
                slmgr.vbs -ato 

                # Rename Admin and Guest accounts   
                Write-Host "[$using:New_Host_Name] Renaming Admin and Guest accounts"
                Rename-LocalUser -Name "Administrator" -NewName $using:NewAdminAccount
                $AdminUserAccount = Get-LocalUser -Name $using:NewAdminAccount
                $AdminUserAccount | Set-LocalUser -Password $using:secureNewAdminPass
                Disable-LocalUser -Name $AdminUserAccount

                Rename-LocalUser "Guest" -NewName $using:NewGuestAccount
                $GuestUserAccount = Get-LocalUser -Name $using:NewGuestAccount
                $GuestUserAccount | Set-LocalUser -Password $using:secureNewGuestPass
                Disable-LocalUser -Name $GuestUserAccount

                Write-Host "[$using:New_Host_Name] Creating New Admin Account"
                New-LocalUser -Name $using:RemoteAdmin -Password $using:secureRemoteAdminPass | Out-Null
                Add-LocalGroupMember -Group "Administrators" -Member $using:RemoteAdmin
                Add-LocalGroupMember -Group "Remote Management Users" -Member $using:RemoteAdmin
        }

            # Need to re-connect with new admin account to rename computer
        Invoke-Command -HostName $hostip -UserName $RemoteAdmin -KeyFilePath "$sshKeyFile" -ScriptBlock {
                # Rename computer
                Write-Host "[$using:New_Host_Name] Renaming Computer"
                Rename-Computer -NewName $using:New_Host_Name -Force -Restart | Out-Null 

                Write-Host "[$using:New_Host_Name] Restarting to apply changes" 
        }
        
    
    Write-Host "Intial Server preperation is complete" -ForegroundColor Green
}

#---------------------------------------------------------[ Add Servers to the Domain ]---------------------------------------------------

Function AddServerstoDomain {
    param(
        [array]$HostList,
        [string]$UserName
    )

    # Join Server to the Domain
        [String]$Rem_Adm_Pw = $RemoteAdminPass
        [SecureString]$Securestring_Rem_Adm_Pw = $Rem_Adm_Pw | ConvertTo-SecureString -AsPlainText -Force
    
        $ComputerName = $HostList[0]
        $hostip = $HostList[1]

        $DNS1 = $DC1_Host_IPAddress
        $DNS2 = $DC2_Host_IPAddress
    
        $localCred = New-Object pscredential -ArgumentList ([pscustomobject]@{
            UserName = "$ComputerName\$RemoteAdmin"
            Password = $Securestring_Rem_Adm_Pw
            })
    
        $joinCred = New-Object pscredential -ArgumentList ([pscustomobject]@{
            UserName = "$AD_Domain\$RemoteAdmin"
            Password = $Securestring_Rem_Adm_Pw
            })
    
        $addComputerSplat = @{
            ComputerName = $ComputerName
            LocalCredential = $localCred
            DomainName = $AD_Domain
            Credential = $joinCred
            Restart = $true
            Force = $true
        }
    
    Write-Host "[$ComputerName] is preparing to join Domain: $AD_Domain"
    
    Invoke-Command -HostName $hostip -UserName $UserName -KeyFilePath "$sshKeyFile" -ScriptBlock {
            Write-Host "[$using:ComputerName] Changing the Servers NIC settings to point to Domain Controllers for DNS"
            Set-DnsClientServerAddress -InterfaceAlias "Ethernet0" -ServerAddresses $using:DNS1 #,$using:DNS2
    
            Write-Host "[$using:ComputerName] Joining Domain"
            Add-Computer @using:addComputerSplat
            }
    
    Start-Sleep -Seconds 20
    Write-Host "Server $ComputerName has joined the domain" -ForegroundColor Green
    }

 # ---------------------------------------------------[Add Second Domain Controller]---------------------------------------------------
Function AddDC {
    param(
        [array]$HostList,
        [string]$UserName
    )
    
    $secureSafeModePass = ConvertTo-SecureString $SafeModeAdministratorPassword -AsPlainText -force
    
    [String]$Rem_Adm_Pw = $RemoteAdminPass
    [SecureString]$Securestring_Rem_Adm_Pw = $Rem_Adm_Pw | ConvertTo-SecureString -AsPlainText -Force

    $ComputerName = $HostList[0]
    $hostip = $HostList[1]

    $DNS1 = $DC1_Host_IPAddress
    $DNS2 = $DC2_Host_IPAddress
    
    $joinCred = New-Object pscredential -ArgumentList ([pscustomobject]@{
        UserName = "$AD_Domain\$RemoteAdmin"
        Password = $Securestring_Rem_Adm_Pw
    })
    
    $addDCSplat = @{
        Credential = $joinCred
        DomainName = $AD_Domain
        SafeModeAdministratorPassword = $secureSafeModePass
        InstallDns = $true
        Force = $true
    }
    
    Invoke-Command -HostName $hostip -UserName $UserName -KeyFilePath "$sshKeyFile" -ScriptBlock {
    #Invoke-Command -ComputerName $ComputerName -Credential $joinCred -ScriptBlock {
        Write-Host "[$using:ComputerName] Installing AD Domain Services"
        # Set NIC settings to point to DC1
        Set-DnsClientServerAddress -InterfaceAlias "Ethernet0" -ServerAddresses $using:DNS1 #,$using:DNS2
        Install-WindowsFeature `
            -Name AD-Domain-Services `
            -IncludeManagementTools
    
        Write-Host "[$using:ComputerName] Installing AD Domain Controller and DNS"
        Install-ADDSDomainController @using:addDCSplat
    }
    
    Start-Sleep -Seconds 120
    
    Invoke-Command -HostName $DC2_Host_IPAddress -UserName $UserName -KeyFilePath "$sshKeyFile" -ScriptBlock {
        Write-Host "[$using:ComputerName] Fixing Server NIC DNS Settings"
        Set-DnsClientServerAddress -InterfaceAlias "Ethernet0" -ServerAddresses $using:DNS2,$using:DNS1
    }
    
    Write-Host "Secondary Domain Controller has been installed and configured" -ForegroundColor Green
    }
    