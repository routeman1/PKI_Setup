#-------------------------[Initalization]-------------------------------

# NOTE: variables are read from the variables.csv file, and parsed from the menu script

# To track script run time
$StartTime = Get-Date

#----------------------------------------------------------------[DNS Configuration]------------------------------------------------------

Function DNSConfig {
    param(
        [array]$HostList,
        [string]$UserName
    )
    $ComputerName = $HostList[0]
    $ComputerIP = $HostList[1]

    $ICA_name = $ICA[0]
    $ICA_address = $ICA[1]
    $RCA_name = $RCA[0]
    $RCA_address = $RCA[1]
    
    Invoke-Command -HostName $ComputerIP -UserName $UserName -KeyFilePath "$sshKeyFile" -ScriptBlock {   
        Write-Host "[$using:ComputerName] Adding DNS Records, for the Certificate Services"
    
        # Create DNS etnries for certificate Servers
        Add-DnsServerResourceRecordA -Name $using:RCA_name -ZoneName "$using:Domain" -IPv4Address "$using:RCA_address" -CreatePtr
        Add-DnsServerResourceRecordA -Name $using:ICA_name -ZoneName "$using:Domain" -IPv4Address "$using:ICA_address" -CreatePtr
        Add-DnsServerResourceRecordCname -Name "pki" -ZoneName "$using:Domain" -HostNameAlias "$using:ICA_name.$using:Domain"
        Add-DnsServerResourceRecordCname -Name "ocsp" -ZoneName "$using:Domain" -HostNameAlias "$using:ICA_name.$using:Domain"
    }
    
    Write-Host "DNS Configuration is complete" -ForegroundColor Green
    }
    
#---------------------------------------------------------[Intermidiate CA Installation]---------------------------------------------------

Function IntermediateCAInstallation {
    param(
        [array]$HostList,
        [string]$UserName
    )
    $ComputerName = $HostList[0]
    $ComputerIP = $HostList[1]

[String]$Rem_Adm_Pw = $RemoteAdminPass
[SecureString]$Securestring_Rem_Adm_Pw = $Rem_Adm_Pw | ConvertTo-SecureString -AsPlainText -Force
$rcacred = New-Object pscredential -ArgumentList ([pscustomobject]@{
    UserName = $RemoteAdmin
    Password = $Securestring_Rem_Adm_Pw
})

$joinCred = New-Object pscredential -ArgumentList ([pscustomobject]@{
    UserName = "$AD_Domain\$RemoteAdmin"
    Password = $Securestring_Rem_Adm_Pw
})

$RCA_Host_Name = $RCA[0]
$DC1_Host_Name = $DC1[0]

$ICAparams = @{
    CAType = "EnterpriseSubordinateCa"
    CACommonName = $ICA_CAName
    KeyLength = "4096"
    HashAlgorithmName = "SHA256"
    CryptoProviderName = "RSA#Microsoft Software Key Storage Provider"
    Credential = $joinCred
    Force = $true
}

    # Begin Intermediate CA Setup
# Start Execution On Intermediate CA server
Invoke-Command -HostName $ComputerIP -UserName $UserName -KeyFilePath "$sshKeyFile" -ScriptBlock {  

    Write-Host "Begining Setup and Configuration of the Intermediate CA" -ForegroundColor Yellow
        
    Write-Host "[$using:ComputerName] Creating CAPolicy file" 

    #--------------------------
    # CAPolicy.INF file content 
    #--------------------------

    $CAPolicyInf = @"
[Version]
Signature="`$Windows NT$"

[PolicyStatementExtension]
Policies=AllIssuancePolicy,InternalPolicy
Critical=False

[AllIssuancePolicy]
OID=$using:Cert_AllIssuanceOID

[InternalPolicy]
OID=$using:Cert_InternalOID
Notice="$using:Cert_Notice"
URL=http://$using:PKI_URL/cps.html
        
[Certsrv_Server]
RenewalKeyLength=4096
RenewalValidityPeriod=Years
RenewalValidityPeriodUnits=5

AlternateSignatureAlgorithm=0

LoadDefaultTemplates=1
"@

    $CAPolicyInf | Out-File "C:\Windows\CAPolicy.inf" -Encoding utf8 -Force | Out-Null

    Write-Host "[$using:ComputerName] Installing required Windows Features" 
    Add-WindowsFeature -Name ADCS-Cert-Authority, ADCS-Web-Enrollment, Web-Mgmt-Service -IncludeManagementTools | Out-Null

    Write-Host "[$using:ComputerName] Install and configure AD Certificate Services" 

    Install-AdcsCertificationAuthority @using:ICAparams | Out-Null
    Install-AdcsWebEnrollment -Force | Out-Null

    Write-Host "[$using:ComputerName] Mapping X: to CertConfig share on Root CA"
    New-PSDrive -Name "X" -Root "\\$using:RCA_Host_Name\Share" -PSProvider "FileSystem" -Credential $using:rcacred | Out-Null

    # Copy request from Subordinate CA to Root CA
    Write-Host "[$using:ComputerName] Copy Certificate Request to Root CA for issuance" 
    Copy-Item C:\*.REQ -Destination "X:\Intermediate CA Files\Request" | Out-Null

    # Create Scripts directory for use later in this script
    New-Item -Path "C:\scripts" -ItemType "directory" | Out-Null
    }

###### Execution on Root CA Server #######
    Invoke-Command -HostName $RCA[1] -UserName $RemoteAdmin -KeyFilePath "$sshKeyFile" -ScriptBlock {
        $ComputerName = $using:RCA[0]
        # Initialize variables
        Write-Host "[$ComputerName] Processing Subordinate certificate request" 
        $RootCAName = (get-itemproperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration).Active
        $RootCAServer = hostname
        $SubordinateCAReq = Get-ChildItem "C:\Share\Intermediate CA Files\Request\*.req"
        
        # Submit CSR from Subordinate CA to the Root CA
        Write-Host "[$ComputerName] Submitting Subordinate certificate request to Root CA" 
        certreq -config $RootCAServer\$RootCAName -submit -attrib "CertificateTemplate:SubCA" $SubordinateCAReq.Fullname | Out-Null

        # Authorize Certificate Request
        Write-Host "[$ComputerName] Issuing Subordinate certificate" 
        certutil -resubmit 2 | Out-Null

        # Retrieve Subordinate CA certificate
        Write-Host "[$ComputerName] Retrieving/Exporting Subordinate certificate" 
        certreq -config $RootCAServer\$RootCAName -retrieve 2 "C:\CAConfig\SubordinateCA.crt" | Out-Null

        # Rename Root CA certificate (remove server name)
        Write-Host "[$ComputerName] Correcting RootCA filenames and cleanup" 
        $Source = "C:\CAConfig\$RootCAServer" + "_" + "$RootCAName.crt"
        $Target = "$RootCAName.crt"
        Rename-Item $Source $Target  | Out-Null
        Remove-Item C:\CAConfig\*.REQ | Out-Null

        # Copy files to Share folder
        Copy-Item "C:\CAConfig\$RootCAName.crt" -Destination "C:\Share\Root CA Files" | Out-Null
        Copy-Item "C:\CAConfig\SubordinateCA.crt" -Destination "C:\Share\Intermediate CA Files" | Out-Null

        Write-Host "[$ComputerName] Root CA Commands Completed" 
        Write-Host " "
    }
}
Function IntermediateCAConfig {
    param(
        [array]$HostList,
        [string]$UserName
    )
    $ComputerName = $HostList[0]
    $ComputerIP = $HostList[1]

    [String]$Rem_Adm_Pw = $RemoteAdminPass
    [SecureString]$Securestring_Rem_Adm_Pw = $Rem_Adm_Pw | ConvertTo-SecureString -AsPlainText -Force

    $joinCred = New-Object pscredential -ArgumentList ([pscustomobject]@{
        UserName = "$AD_Domain\$RemoteAdmin"
        Password = $Securestring_Rem_Adm_Pw
    })

    $RCA_Host_Name = $RCA[0]

    # Begin Intermediate CA Setup

    Invoke-Command -HostName $ComputerIP -UserName $UserName -KeyFilePath "$sshKeyFile" -ScriptBlock { 
        # Copy certificate/CRL from Root CA to Subordinate CA
        Write-Host "[$using:ComputerName]-Copy certificates and CRL from Root CA to Subordinate CA"  
        
        Write-Host "[$using:ComputerName]-Mapping X: to CertConfig share on Root CA"
        New-PSDrive -Name "X" -Root "\\$using:RCA_Host_Name\Share" -PSProvider "FileSystem" -Credential $using:joinCred | Out-Null

        Copy-Item "X:\Root CA Files\$using:RootCAName.crt" -Destination C:\Windows\system32\CertSrv\CertEnroll | Out-Null
        Copy-Item "X:\Root CA Files\$using:RootCAName.crl" -Destination C:\Windows\system32\CertSrv\CertEnroll | Out-Null
        Copy-Item "X:\Intermediate CA Files\SubordinateCA.crt" -Destination C:\Windows\system32\CertSrv\CertEnroll | Out-Null

        Write-Host "[$using:ComputerName]-Setting up CertData Web Virtual Directory"
        New-Item -Path "C:\CertData" -ItemType "directory" | Out-Null
        Copy-Item "X:\Root CA Files\*.*" -Destination C:\CertData | Out-Null
        Copy-Item "C:\Windows\system32\CertSrv\CertEnroll\*.crl" -Destination C:\CertData | Out-Null
        # Configure IIS for certificate support (ie: CRLs, etc)
        Import-Module WebAdministration
        New-WebVirtualDirectory -Site "Default Web Site" `
                    -Name "CertData" `
                    -PhysicalPath "C:\CertData" `
                    -Force | Out-Null
        Set-WebConfigurationProperty -Filter "/system.webServer/directoryBrowse" -PSPath "IIS:\Sites\Default Web Site\CertData" -Name "enabled" -Value "True" | Out-Null
        # Enable double escaping as per BPA
        "c:\windows\system31\inetsrv\appcmd set config /section:requestfiltering /allowdoubleescaping:true"
        iisreset.exe

        # Proceed with ICA certification process
        $RootCACert = Get-ChildItem "C:\Windows\system32\CertSrv\CertEnroll\$using:RootCAName.crt" 
        $RootCACRL = Get-ChildItem "C:\Windows\system32\CertSrv\CertEnroll\$using:RootCAName.crl"

        # Publish Root CA certificates to Subordinate server
        Write-Host "[$using:ComputerName]-Add Root CA certificate to Subordinate CA server" 
        certutil.exe -addstore -f root $RootCACert.FullName  | Out-Null  
        certutil.exe -addstore -f root $RootCACRL.FullName | Out-Null   

    }
}

Function Transfer_Templates {
    param(
        [string]$HostList,
        [string]$UserName
    )
        # Transfer cert template files upto the ICA server
        $session = New-PSSession -HostName $ICA[1] -UserName $UserName -KeyFilePath "$sshKeyFile" 
        Copy-Item -Path "./cert-templates" -Destination "C:\cert-templates\" -Recurse -ToSession $session
        Copy-Item -Path "./ica_setup_partII.ps1" -Destination "C:\scripts\ica_setup_partII.ps1" -ToSession $session
        Copy-Item -Path "./variables.csv" -Destination "C:\scripts\variables.csv" -ToSession $session
        Remove-PSSession $session 
    }
    

Function ICAReboot {
    param(
        [string]$UserName
    )
    Invoke-Command -HostName $ICA_Host_IPAddress -UserName $UserName -KeyFilePath "$sshKeyFile" -ScriptBlock { Restart-Computer }
    Invoke-Command -HostName $DC1_Host_IPAddress -UserName $UserName -KeyFilePath "$sshKeyFile" -ScriptBlock { Restart-Computer }
    Invoke-Command -HostName $RCA_Host_IPAddress -UserName $UserName -KeyFilePath "$sshKeyFile" -ScriptBlock { Restart-Computer }
}


#---------------------------------------------------------[ Execution ]---------------------------------------------------

Write-Host "Begining pre-Installation Tests" -ForegroundColor Yellow
#Load the test script (for test functions)
. ./test.ps1 
# Test each host is up
ServerTestLoop -Username $DefWinAccount -HostList $ICA[1]
ServerTestLoop -Username $RemoteAdmin -HostList $RCA[1]
ServerTestLoop -Username $RemoteAdmin -HostList $DC1[1]
# Test that PSSession can be established via SSH
ServerTestLoop -Username $DefWinAccount -HostList $ICA[1]
InstallationTests -Username $RemoteAdmin -HostList $RCA[1]
InstallationTests -Username $RemoteAdmin -HostList $DC1[1]

Write-Host "Configuring Server Hostname, and local security settings" -ForegroundColor Yellow
. ./server_setup.ps1
ServerPrep -HostList $ICA -Username $DefWinAccount
 
Write-Host "Pausing to allow the system to finish restarting." -ForegroundColor Magenta
Start-Sleep -Seconds 30

Write-Host "Verifying the sever is back up after the restart " -ForegroundColor Yellow
ServerTestLoop -Username $RemoteAdmin -HostList $ICA[1]

Write-Host "Configuring DNS Server Records" -ForegroundColor Yellow
DNSConfig -HostList $DC1 -Username "$RemoteAdmin@$AD_Domain"

Write-Host "Adding Intermediate CA Server to the Domain" -ForegroundColor Yellow
AddServerstoDomain -HostList $ICA -Username $RemoteAdmin

Write-Host "Waiting for the server to finish rebooting"
Start-Sleep -Seconds 30

Write-Host "Verifying the server is back up after the restart " -ForegroundColor Yellow
ServerTestLoop -Username $RemoteAdmin -HostList $ICA[1]

Write-Host "Begin Inital Set up of the Intermediate Certificate Authority" -ForegroundColor Yellow
IntermediateCAInstallation -HostList $ICA -Username "$RemoteAdmin@$AD_Domain"

Write-Host "Transfering Certificate Templates to the Intermediate CA Server" -ForegroundColor Yellow
Transfer_Templates -HostList $ICA -Username "$RemoteAdmin@$AD_Domain"

Write-Host "Configuring the Intermediate Certificate Authority" -ForegroundColor Yellow
IntermediateCAConfig -HostList $ICA -Username "$RemoteAdmin@$AD_Domain"

Write-Host "Rebooting the Intermediate Certificate Authority server" -ForegroundColor Yellow
ICAReboot -UserName $RemoteAdmin

# #######################################

Write-Host ""
Write-Host "                 *********** STOP ***********" -ForegroundColor Red
Write-Host ""
Write-Host "Due to Windows Security (double-hop) issues you will now need to open a seprate terminal " 
Write-Host "window and SSH into the Subordinate CA server. Useing the following SSH command: "
Write-Host "       ssh $RemoteAdmin@$AD_Domain@$ICA_Host_IPAddress" -ForegroundColor Yellow
Write-Host "This ensures that you are logged in with a Domain Admin account and not a local account"
Write-Host ""
Write-Host "After you have logged in; cd to 'c:\scripts\' and then run the following command:"
Write-Host "          ./ica_setup_partII.ps1        " -ForegroundColor Yellow
Write-Host "When that script finisishes executing, then logout of the Subordinate CA server ssh "
Write-Host "session and then select Menu Option 4 to complete the configuration process."
Write-Host ""
Write-Host "            ***************** STOP *****************" -ForegroundColor Red
Write-Host ""

# #######################################

Write-Host ""

Write-Host "The Initial Intermeditate Certificate Server and service configuration is complete." -ForegroundColor Green
Write-Host "Please allow the ICA server to finish rebooting before proceeding." -ForegroundColor Yellow
Write-Host ""
Write-Host "Total execution time: $((get-date) - $StartTime)" -ForegroundColor Green
