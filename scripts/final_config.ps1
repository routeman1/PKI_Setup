#-------------------------[Initalization]-------------------------------

# Read the variables from the variables.csv comma delimited file. Ignore lines that start with #
Get-Content variables.csv | Where-Object {$_.length -gt 0} | Where-Object {!$_.StartsWith("#")} | ForEach-Object {

    $var = $_.Split(',',2).Trim()
    New-Variable -Scope Script -Name $var[0] -Value $var[1]

    }

# build host data arrays
$DC1 = @($DC1_Host_Name, $DC1_Host_IPAddress)
$DC2 = @($DC2_Host_Name, $DC2_Host_IPAddress)
$RCA = @($RCA_Host_Name, $RCA_Host_IPAddress)
$ICA = @($ICA_Host_Name, $ICA_Host_IPAddress)

# Define Secure Variables for Passwords
$secureRemoteAdminPass = ConvertTo-SecureString $RemoteAdminPass -AsPlainText -force

## To track script run time
$StartTime = Get-Date

#---------------------[Decleration]-----------------------------------
 
Function ShowBanner {
    Write-Host ""
    Write-Host "****************************************************************************************" -ForegroundColor Red
    Write-Host "*  This script will complete the configuration of the Enterprise PKI environment       *" -ForegroundColor Yellow
    Write-Host "*      MAKE SURE THE OTHER SCRIPTS HAVE BEEN RAN PRIOR TO RUNNING THIS SCRIPT          *" -ForegroundColor Yellow
    Write-Host "****************************************************************************************" -ForegroundColor Red
    Write-Host ""

}

# -------------------------

# Function PKIStat {
#         Write-Host "Certificate Authority Status" -ForegroundColor Yellow
#         Get-CA
#         Write-Host "Online Responder Status" -ForegroundColor Yellow
#         Connect-OnlineResponder
#         Write-Host "Enterprise PKI Status" -ForegroundColor Yellow
#         Get-CA | Get-EnterprisePKIHealthStatus -ErrorAction SilentlyContinue
        
#     }
Function PKITest {
    
    $pkihealth = Get-CA | Get-EnterprisePKIHealthStatus -ErrorAction SilentlyContinue
    $ocsp = Connect-OnlineResponder $ICA_Host_Name
    $ocsp = $ocsp | Get-OnlineResponderRevocationConfiguration
    $pkistat = $pkihealth.Status
    $ocspstat = $ocsp.Status

        if ($pkistat -eq "Ok" -and $null -eq $ocspstat ) 
        {
            Write-Host "PKI is fuctioning correctly" -ForegroundColor Green
        }
        else 
        {
            Write-Host "PKI is not fuctioning correctly" -ForegroundColor Red
        }
    }


Function SetupGPO {
    param(
        [array]$HostList,
        [string]$UserName
    )

    $ComputerName = $HostList[0]
    $ComputerIP = $HostList[1]   

    Invoke-Command -HostName $ComputerIP -UserName $RemoteAdmin -KeyFilePath "$sshKeyFile" -ScriptBlock { 
        Write-Host "[$using:ComputerName] Setting up Certificate GPOs"
        New-GPO -Name "PKIGPO" -Comment "Certificate and PKI Settings for the Domain" | Out-Null
        Get-GPO "PKIGPO" | New-GPLink -Target "$((Get-ADRootDSE).defaultNamingContext)" | Out-Null
        Set-GPRegistryValue -Name "PKIGPO" -Key "HKLM\Software\Policies\Microsoft\Cryptography\AutoEnrollment" -ValueName "AEPolicy" -Value 7 -Type Dword | Out-Null
    }
}
Function CreateNewAdmin {
    param(
        [array]$HostList,
        [string]$UserName
    )

    $ComputerName = $HostList[0]
    $ComputerIP = $HostList[1]   

    Invoke-Command -HostName $ComputerIP -UserName $RemoteAdmin -KeyFilePath "$sshKeyFile" -ScriptBlock {

        $ConfigNC = $((Get-ADRootDSE).defaultNamingContext)
        $ADPATH = "OU=$using:AD_OU_Level1,$ConfigNC"

        Write-Host ""
        Write-Host "We now need to create a new Domain Admin Account" -ForegroundColor Yellow
        Write-Host "The current Domain Admin Account that has been used for the installation, will be deleted for security purposes." -ForegroundColor Yellow
        Write-Host ""
        $NewAdmin = Read-Host "Enter the new Admin Account name for the $AD_Domain Domain" 

        $splat = @{
            Name = $NewAdmin
            AccountPassword = (Read-Host -AsSecureString 'Enter the new Admin account password')
            Path = "OU=USERS,OU=ACCOUNTS,$ADPATH"
            PasswordNeverExpires = $true
            Enabled = $true
            }

        New-ADUser @splat
        Write-Host "[$using:ComputerName] Adding $NewAdmin to appropriate groups"
        Add-ADGroupMember -Identity "Domain Admins" -Members $NewAdmin
        Add-ADGroupMember -Identity "Enterprise Admins" -Members $NewAdmin
        Add-ADGroupMember -Identity "Enterprise Key Admins" -Members $NewAdmin
        Add-ADGroupMember -Identity "Schema Admins" -Members $NewAdmin
        Add-ADGroupMember -Identity "Group Policy Creator Owners" -Members $NewAdmin
        }
    }

Function RemoveOldAdmin {
    param(
        [array]$HostList,
        [string]$UserName
    )
    
    Invoke-Command -HostName $DC1_Host_IPAddress -UserName $RemoteAdmin -KeyFilePath "$sshKeyFile" -ScriptBlock {
        Write-Host "[$using:DC1_Host_Name] Removing Domain Admin Account used to install"
        Remove-ADUser -Identity $using:RemoteAdmin | Out-Null
    }
}

Function Cleanup {
    param(
        [array]$HostList,
        [string]$UserName
    )

    $ComputerName = $HostList[0]
    $ComputerIP = $HostList[1]   

    Invoke-Command -HostName $ComputerIP -UserName $RemoteAdmin -KeyFilePath "$sshKeyFile" -ScriptBlock {
        Write-Host "[$using:ComputerName] Cleaning up from the installation"
        # Remove the Scripts folder (ICA)
        Remove-Item C:\scripts -Recurse #| Out-Null
        Remove-Item c:\*.req #| Out-Null
    }

}

Function RemoveOldLocalAdmin {
        param(
        [System.Management.Automation.CredentialAttribute()]
        [System.Management.Automation.PSCredential] $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $Computer = @($ICA, $RCA)

    Foreach ($Computer in $Computer) { 
        [String]$currentHost = $Computer[0]
        [String]$ComputerIP = $Computer[1]

        # Go through each computer and change the local admin account. 
        Write-Host "Cleaning up Install admin account on "$currentHost
        
        Invoke-Command -HostName $ComputerIP -UserName $RemoteAdmin -KeyFilePath "$sshKeyFile" -ScriptBlock {
            Write-Host "[$using:currentHost] Creating New Local Admin Account"
            New-LocalUser -Name $using:NewLocalAdmin -Password $using:NewLocalAdminPass | Out-Null
            Add-LocalGroupMember -Group "Administrators" -Member $using:NewLocalAdmin
            Add-LocalGroupMember -Group "Remote Management Users" -Member $using:NewLocalAdmin
        }

        Invoke-Command -HostName $ComputerIP -UserName $RemoteAdmin -KeyFilePath "$sshKeyFile" -ScriptBlock {
            Write-Host "[$using:currentHost] Removing Local Admin Account used for installation"
            Remove-LocalUser -Name $using:RemoteAdmin 

        }
    }
}

Function StopRCA {
    param(
    [string]$UserName
    )

    Invoke-Command -HostName $RCA_Host_IPAddress -UserName $UserName -KeyFilePath "$sshKeyFile" -ScriptBlock {
        # Shutdown Off-Line Root CA Server
        Write-Host "[$using:RCA_Host_Name] Shutting down the Offline Root Authority Server"
        Stop-Computer -Force
        }
    }

Function FixDC1DNS {       
    param(
    [string]$UserName
    )

    Invoke-Command -HostName $DC1_Host_IPAddress -UserName $UserName -KeyFilePath "$sshKeyFile" -ScriptBlock {
        Write-Host "[$using:DC1_Host_Name] Fixing Server NIC DNS Settings"
        Set-DnsClientServerAddress -InterfaceAlias "Ethernet0" -ServerAddresses $using:DC1_Host_IPAddress,$using:DC2_Host_IPAddress
    }
}
    
#---------------------------------------------------------[ Execution ]---------------------------------------------------


ShowBanner
Write-Warning  "Did the ICA_setup_PartII script complete successfully? Selecting Yes will start the script. " -WarningAction Inquire

$cred = (New-Object System.Management.Automation.PsCredential($RemoteAdmin,$secureRemoteAdminPass))

# Write-Host "Testing PKI & Certificate Server Status" -ForegroundColor Yellow
# PKITest

Write-Host "Configuring PKI GPO for the Domain" -ForegroundColor Yellow
SetupGPO -Username $RemoteAdmin -HostList $DC1

Write-Host "Begining Secondary DC installation" -ForegroundColor Yellow
    Write-Host "Begining pre-Installation Tests" -ForegroundColor Yellow
    #Load the test script (for test functions)
    . ./test.ps1 
        # Test each host is up
    ServerTestLoop -Username $DefWinAccount -HostList $DC2[1]
    # Test that PSSession can be established via SSH
    InstallationTests -Username $DefWinAccount -HostList $DC2[1]

    Write-Host "Configuring Server Hostname, and local security settings" -ForegroundColor Yellow
    . ./server_setup.ps1
    ServerPrep -HostList $DC2 -Username $DefWinAccount
 
    Write-Host "Pausing to allow the systems to finish restarting." -ForegroundColor Magenta
    Start-Sleep -Seconds 15

    Write-Host "Verifying Severs are back up after the restart " -ForegroundColor Yellow
    ServerTestLoop -Username $RemoteAdmin -HostList $DC2_Host_IPAddress

    Write-Host "Adding the Secondary Domain Controller to the Domain" -ForegroundColor Yellow
    AddDC -Username $RemoteAdmin -HostList $DC2
    Write-Host ""

Write-Host "Changing the Primary DC Server Interface DNS Settings" -ForegroundColor Yellow
FixDC1DNS -Username $RemoteAdmin 

Write-Host "Cleaning up from the installation" -ForegroundColor Yellow
Cleanup -Username $RemoteAdmin -HostList $ICA
Write-Host ""

Write-Host "Creating New Local Admin Account on the servers and removing the one used for installation" -ForegroundColor Yellow
    # Need these varible to be global so putting them here outside of the function
    $NewLocalAdmin = Read-Host "Enter the new LOCAL Admin Account name" 
    $NewLocalAdminPass = Read-Host -AsSecureString "Enter the new LOCAL Admin Account password"
    $newcred = (New-Object System.Management.Automation.PsCredential($NewLocalAdmin,$NewLocalAdminPass))
RemoveOldLocalAdmin -Credential $cred
Write-Host ""

Write-Host "Creating New Domain Admin Account" -ForegroundColor Yellow
CreateNewAdmin -Username $RemoteAdmin -HostList $DC1
Write-Host ""

Write-Host "Removing old Domain Admin Account used for installation" -ForegroundColor Yellow
Write-Host "Please re-enter the new Admin Account name and password for the $AD_Domain Domain in order to complete the installation"
$NewDomainAdmin = Read-Host "Enter the new Admin Account name for the $AD_Domain Domain" 
$NewDomainAdminPass = Read-Host -AsSecureString "Enter the new Admin account password"
#$secureNewAdminPass = ConvertTo-SecureString $NewAdminPass -AsPlainText -force
$newadmincred = (New-Object System.Management.Automation.PsCredential($NewDomainAdmin,$newDomainAdminPass))
RemoveOldAdmin -Credential $newadmincred
write-host ""

Write-Host "Shutting down the Offline Root Authority Server: $RCA_Host_Name"
StopRCA -Username $NewLocalAdmin 

Write-Host ""
Write-Host "Installation, Configuration and Cleanup is complete" -ForegroundColor Green
Write-Host "Total execution time: $((get-date) - $StartTime)" -ForegroundColor Green
Write-Host ""