#-------------------------[Initalization]-------------------------------

# NOTE: variables are read from the variables.csv file, and parsed from the menu script

# To track script run time
$StartTime = Get-Date

#---------------------[Decleration]-----------------------------------

Function Show-variables {
    Write-Host ""
    Write-Host "****************************************************************************************" -ForegroundColor Red
    Write-Host " . This script will configure a Primary Domain Controller                               " -ForegroundColor Yellow
    Write-Host " . based on the variables in the variables.csv file                                       " -ForegroundColor Yellow
    Write-Host "****************************************************************************************" -ForegroundColor Red
    Write-Host ""
    Write-Host "Please verify the following information is correct before proceeding:" -ForegroundColor Yellow
    Write-Host ""

    # Print out the value of each variables
    Write-Host "Global Settings:" -ForegroundColor Green
    Write-Host "These values will be applied to all relevant systems" -ForegroundColor Green
    Write-Host " The Windows Local Admin Account will be changed to: $NewAdminAccount" -ForegroundColor Yellow
    Write-Host " The Windows Local Guest User Account will be changed to: $NewGuestAccount" -ForegroundColor Yellow
    Write-Host " This new Windows Local Admin Account will be created: $RemoteAdmin" -ForegroundColor Yellow
    Write-Host " The Timezone will be set to: $Timezone" -ForegroundColor Yellow
    Write-Host " "
    Write-Host "Windows Licensing Information" -ForegroundColor Green
    Write-Host " Windows License to be applied: $WIN2022_LIC" -ForegroundColor Yellow
    Write-Host " The Volume License Server is: $VLM_Hostname located at $VLM_IPAddress" -ForegroundColor Yellow
    Write-Host " "
    Write-Host "The following Servers will be configured:" -ForegroundColor Green
    Write-Host "Primary Domain Controller (PDC) Information:" -ForegroundColor Green
    Write-Host "  Server Name: "$DC1[0] -ForegroundColor Yellow
    Write-Host "  IP Address: "$DC1[1]"/"$CoreNet_prefix -ForegroundColor Yellow
}

#--------------------------[Setup ACTIVE DIRECTORY]-----------------------

Function ADInstallation {
     param(
    [string]$ComputerName,
    [System.Management.Automation.CredentialAttribute()]
    [System.Management.Automation.PSCredential] $Credential = [System.Management.Automation.PSCredential]::Empty
)
    $secureSafeModePass = ConvertTo-SecureString $SafeModeAdministratorPassword -AsPlainText -force

Write-Host "  Active Directory Domain Name: $AD_Domain"
Write-Host "  Domain Netbios Name: $Netbios_Name"
Write-Host "  Domain Mode: $ADDomainMode"
Write-Host "  Forest Mode: $ADForestMode"
Write-Host " "

Invoke-Command -HostName $ComputerName -UserName $RemoteAdmin -KeyFilePath "$sshKeyFile" -ScriptBlock {   
  
    # Start AD installation
    Write-Host "[$using:ComputerName] -Installing AD Domain Services"
    Install-WindowsFeature `
        -Name AD-Domain-Services `
        -IncludeManagementTools

    Import-Module ADDSDeployment

    Write-Host "[$using:ComputerName] Installing AD Forest"
    Install-ADDSForest `
        -CreateDnsDelegation:$false `
        -Databasepath "C:\Windows\NTDS" `
        -DomainMode $using:ADDomainMode `
        -DomainName $using:AD_Domain `
        -SafeModeAdministratorPassword $using:secureSafeModePass `
        -DomainNetbiosName $using:Netbios_Name `
        -ForestMode $using:ADForestMode `
        -InstallDns:$true `
        -LogPath "C:\Windows\NTDS" `
        -SysvolPath "C:\Windows\SYSVOL" `
        -Force:$true
    }

Write-Host ""
Write-Host "Active Directory is installed and configured" -ForegroundColor Green
Write-Host ""
}

#------------------------[Setup Users and groups]--------------------------

Function UserGroupSetup {
param(
    [string]$ComputerName,
    [string]$UserName
)

Invoke-Command -HostName $ComputerName -UserName $UserName -KeyFilePath "$sshKeyFile" -ScriptBlock {
    Write-Host "[$using:ComputerName] Adding $using:RemoteAdmin to appropriate groups"
    Add-ADGroupMember -Identity "Domain Admins" -Members $using:RemoteAdmin
    Add-ADGroupMember -Identity "Enterprise Admins" -Members $using:RemoteAdmin
    Add-ADGroupMember -Identity "Enterprise Key Admins" -Members $using:RemoteAdmin
    Add-ADGroupMember -Identity "Schema Admins" -Members $using:RemoteAdmin
    Add-ADGroupMember -Identity "Group Policy Creator Owners" -Members $using:RemoteAdmin
    
    Write-Host "[$using:ComputerName] Setting up Oganization Unit"
    $Server = (Get-ADDomainController -Discover -ForceDiscover).Hostname[0]
    $ConfigNC = $((Get-ADRootDSE -Server $Server).defaultNamingContext)
    $ADPATH = "OU=$using:AD_OU_Level1,$ConfigNC"
    New-ADOrganizationalUnit -Name $using:AD_OU_Level1 -Path $ConfigNC -ProtectedFromAccidentalDeletion $true
    New-ADOrganizationalUnit -Name "ACCOUNTS" -Path $ADPATH -ProtectedFromAccidentalDeletion $true
    New-ADOrganizationalUnit -Name "GROUPS" -Path "OU=ACCOUNTS,$ADPATH" -ProtectedFromAccidentalDeletion $true
    New-ADOrganizationalUnit -Name "USERS" -Path "OU=ACCOUNTS,$ADPATH" -ProtectedFromAccidentalDeletion $true
    New-ADOrganizationalUnit -Name "SERVICE_ACCTS" -Path "OU=ACCOUNTS,$ADPATH" -ProtectedFromAccidentalDeletion $true
    New-ADOrganizationalUnit -Name "WORKSTATIONS" -Path "$ADPATH" -ProtectedFromAccidentalDeletion $true

}

Write-Host "Active Directory OU, User, and group setup is complete" -ForegroundColor Green
}   

#----------------------------------------------------------------[DNS Configuration]------------------------------------------------------

Function DNSConfig {
param(
    [string]$ComputerName,
    [string]$UserName
)

Invoke-Command -HostName $ComputerName -UserName $UserName -KeyFilePath "$sshKeyFile" -ScriptBlock {
    Write-Host "[$using:ComputerName] Checking to see if DNS Server is running"
        $maxRetries = 5
        $retryCount = 0

        while ($retryCount -lt $maxRetries) {
            if (Get-Service -Name "DNS" -ErrorAction SilentlyContinue) {
                # DNS service is running
                Write-Host "DNS service is running."
                break
            } else {
                # DNS service is not running, try to start it
                Write-Host "DNS service is not running. Attempting to start..."
                Start-Service -Name "DNS" -ErrorAction SilentlyContinue

                if (Get-Service -Name "DNS" -ErrorAction SilentlyContinue) {
                    # DNS service started successfully
                    Write-Host "DNS service started successfully."
                    break
                } else {
                    # DNS service could not be started
                    Write-Host "DNS service could not be started."
                    $retryCount++
                    Start-Sleep 10 # Wait for 10 seconds before retrying
                }
            }
        }

        if ($retryCount -eq $maxRetries) {
            Write-Host "Failed to start DNS service after $maxRetries attempts."
        }   

    Write-Host "[$using:ComputerName] Adding DNS Records, Reverse Lookup Zones, and other settings"
    Add-DnsServerPrimaryZone -NetworkID "$using:CoreNet_Subnet/$using:CoreNet_prefix" -ReplicationScope "Domain" 

    # Create a PTR record for DC1 since it is not automatically created
	    $ipAddress = $using:DC1[1]
        # Get first Octect for the name of the PTR record
        $name = $ipAddress.Split('.')[-1]
        # Calculate the reverse lookup zone
        $ZoneName = "$($ipAddress.Split('.')[-2,-3,-4] -join ".").in-addr.arpa"
	# Create the PTR record
	Add-DnsServerResourceRecordPtr -Name $name -PtrDomainName "$using:DC1_Host_Name.$using:Domain" -ZoneName $ZoneName

    # Add DNS entries for the Volume License Manager
    Add-DnsServerResourceRecordA -Name $using:VLM_Hostname -ZoneName "$using:Domain" -IPv4Address "$using:VLM_IPAddress" -CreatePtr
    Add-DnsServerResourceRecord -Srv -Name "_VLMCS._tcp" -ZoneName "$using:Domain" -DomainName "$using:VLM_Hostname.$using:Domain" -Priority 0 -Weight 0 -Port 1688

    }
}

#---------------------------------------------------------[ Execution ]---------------------------------------------------

Show-variables
Write-Warning  "Are the values correct? Selecting Yes will start the auto setup. " -WarningAction Inquire

Write-Host "Begining pre-Installation Tests" -ForegroundColor Yellow
#Load the test script (for test functions)
. ./test.ps1 
# Test each host is up
ServerTestLoop -Username $DefWinAccount -HostList $DC1[1]
# Test that PSSession can be established via SSH
InstallationTests -Username $DefWinAccount -HostList $DC1[1]

Write-Host "Configuring Server Hostnames, and local security settings" -ForegroundColor Yellow
. ./server_setup.ps1
ServerPrep -HostList $DC1 -Username $DefWinAccount
 
Write-Host "Pausing to allow the systems to finish restarting." -ForegroundColor Magenta
Start-Sleep -Seconds 20

Write-Host "Verifying Severs are back up after the restart " -ForegroundColor Yellow
ServerTestLoop -Username $RemoteAdmin -HostList $DC1[1]

Write-Host "Starting Active Directory installation on the Primary Domain Controller" -ForegroundColor Yellow 
ADInstallation -ComputerName $DC1[1] 

Write-Host "Pausing to allow the PDC to finish restarting." -ForegroundColor Magenta
# Need to write test routine that looks for the DNS server to be up and running - That will replace the sleep command
Start-Sleep -Seconds 230 

Write-Host ""
Write-Host ""

Write-Host "Verifying the PDC is back up after the restart " -ForegroundColor Yellow
ServerTestLoop -UserName $RemoteAdmin -HostList $DC1[1] 

Write-Host "Setting up AD Users, Groups and Organizational Units" -ForegroundColor Yellow
UserGroupSetup -ComputerName $DC1[1] -UserName $RemoteAdmin

Write-Host "Configuring DNS Server Records" -ForegroundColor Yellow
DNSConfig -ComputerName $DC1[1] -UserName $RemoteAdmin

Write-Host ""
Write-Progress -Completed -Activity ""
Write-Host "Primary Domain Controller installataion and configuration complete" -ForegroundColor Green
Write-Host "Total execution time: $((get-date) - $StartTime)" -ForegroundColor Green
Write-Host ""


