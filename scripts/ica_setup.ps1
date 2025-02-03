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
 
    # Publishing cert on DC1 to avoid permssion issues (publishing RootCA to AD on ICA server does not work) 
    Invoke-Command -HostName $DC1[1] -UserName $UserName -KeyFilePath "$sshKeyFile" -ScriptBlock {
        # Get Root CA cert from RCA server
        Write-Host "[$using:DC1_Host_Name] Preparing to publish Root CA certificate to AD"
        Write-Host "[$using:DC1_Host_Name] Copy Root CA certificate from RCA server"
        New-Item -Path "C:\temp" -ItemType "directory" | Out-Null
        New-PSDrive -Name "X" -Root "\\$using:RCA_Host_Name\Share" -PSProvider "FileSystem" -Credential $using:joinCred | Out-Null

        Copy-Item "X:\Root CA Files\$using:RootCAName.crt" -Destination C:\temp | Out-Null
        Copy-Item "X:\Root CA Files\$using:RootCAName.crl" -Destination C:\temp | Out-Null
        Copy-Item "X:\Intermediate CA Files\SubordinateCA.crt" -Destination C:\temp | Out-Null

        Write-Host "[$using:DC1_Host_Name] Publishing Root CA certificate to AD"
        # Publish Root CA certificate to AD
        certutil.exe -dsPublish -f c:\temp\$using:RootCAName.crt RootCA  | Out-Null  
        Write-Host "[$using:DC1_Host_Name] Root CA is now published to AD"
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


Function PublishCertificates {
    param(
        [string]$HostList,
        [string]$UserName
    )

    # [String]$Rem_Adm_Pw = $RemoteAdminPass
    # [SecureString]$Securestring_Rem_Adm_Pw = $Rem_Adm_Pw | ConvertTo-SecureString -AsPlainText -Force

    # $joinCred = New-Object pscredential -ArgumentList ([pscustomobject]@{
    #     UserName = "$AD_Domain\$RemoteAdmin"
    #     Password = $Securestring_Rem_Adm_Pw
    # })
    
    $DC1_Host_Name = $DC1[0]

    #### Connect to PDC and set up certificate directory #######
    Invoke-Command -HostName $DC1[1] -UserName $UserName -KeyFilePath "$sshKeyFile" -ScriptBlock { 
        Write-Host "[$using:DC1_Host_Name] Setting up Certificate Directory on PDC" -ForegroundColor Yellow
        New-Item -Path "C:\Certificates" -ItemType "directory" | Out-Null   
        Write-Host "[$using:DC1_Host_Name] Mapping X: to CertConfig share on Root CA"
        New-PSDrive -Name "X" -Root "\\$using:RCA_Host_Name\Share" -PSProvider "FileSystem" -Credential $using:rcacred | Out-Null  
        Copy-Item "X:\Intermediate CA Files\SubordinateCA.crt" -Destination C:\Certificates\$using:ICA_CAName.crt | Out-Null
        Copy-Item "X:\Root CA Files\$using:RootCAName.crt" -Destination C:\Certificates | Out-Null

        Write-Host "[$using:DC1_Host_Name] Publishing Intermediate CA certificate to AD"
        # Publish Root CA certificate to AD
        certutil.exe -dsPublish -f c:\Certificates\$using:ICA_CAName.crt SubCA  | Out-Null  
        Write-Host "[$using:DC1_Host_Name] Intermediate CA is now published to AD"  

        #Setup Globla variables for the rest of the script
        $global:ADDomain = $(Get-ADDomain)
        $global:ADName = $ADDomain.Name
        $global:PDC = $ADDomain.PDCEmulator
        $global:ConfigNC = $ADDomain.DistinguishedName

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
    
Function TemplateConfiguration {
    param(
        [array]$HostList,
        [string]$UserName
    )
    $ComputerName = $HostList[0]
    $ComputerIP = $HostList[1]

    # Have to set these variables via Invoke-Command to avoid a double hop issue in the scripts below.
    $PSSession = New-PSSession "$RemoteAdmin@$DC1_Host_IPAddress" -KeyFilePath $sshKeyFile
    $ADName = Invoke-Command -Session $PSSession -ScriptBlock {$(Get-ADDomain).Name}
    $PDC = Invoke-Command -Session $PSSession -ScriptBlock {$(Get-ADDomain).PDCEmulator}
    $ConfigNC = Invoke-Command -Session $PSSession -ScriptBlock {$(Get-ADDomain).DistinguishedName}
    
    Invoke-Command -HostName $DC1_Host_IPAddress -UserName $UserName -KeyFilePath "$sshKeyFile" -ScriptBlock {
        # create "ica-servers" group in AD with $ICA_Host_Name as the only member
        New-ADGroup -Name "ica-servers" -SamAccountName ica-servers -GroupCategory Security -GroupScope Global `
        -DisplayName "Intermediate Certificate Servers" -Path "CN=Computers,$using:ConfigNC" `
        -Description "DO NOT Delete or Modify - This is required for the PKI Certificate Templates to function correctly" 
        Add-ADGroupMember -Identity ica-servers -Members (Get-ADComputer $using:ICA_Host_Name) #-Server $PDC

            Read-Host -Prompt "Press any key to continue"
    }

    Invoke-Command -HostName $ComputerIP -UserName $UserName -KeyFilePath "$sshKeyFile" -ScriptBlock { 
        Write-Host "Domain:" $using:ADName
        Write-Host "PDC:" $using:PDC
        Write-Host "Config NC:" $using:ConfigNC
        
        Read-Host -Prompt "Press any key to continue" 

        Write-Host "[$using:ComputerName]-Installing Certificate Support Tools"
            #Need to add RSAT Powershell tools and Install the Module PSPKI to configure the OCSP Responder
            Install-WindowsFeature -Name RSAT-AD-PowerShell -IncludeAllSubFeature #| Out-Null
            ####Install-PackageProvider -Name NuGet -Force #| Out-Null
            Install-Module ADCSTemplate -Force #| Out-Null
            Install-Module -Name PSPKI -Force #| Out-Null
            Import-Module -Name PSPKI -Force #| Out-Null

        Write-Host "[$using:ComputerName]-Preparing to Import Certificate Templates"
        New-ADCSDrive | Out-Null

        # Customize Certificate Templates 
        Write-Host "[$using:ComputerName]-Importing Certificate Templates"
        New-ADCSTemplate -DisplayName "$ADName Key Archive" -JSON (Get-Content C:\cert-templates\KeyArchiveTemplate.json -Raw) -Server $PDC
        New-ADCSTemplate -DisplayName "$ADName Key Recovery Agent" -JSON (Get-Content C:\cert-templates\KeyRecoveryAgentTemplate.json -Raw) -Server $PDC
        New-ADCSTemplate -DisplayName "$ADName OCSP Response Signing" -JSON (Get-Content C:\cert-templates\OCSPResponseSigningTemplate.json -Raw) -Server $PDC 
        New-ADCSTemplate -DisplayName "$ADName User Certificate" -JSON (Get-Content C:\cert-templates\UserCertificateTemplate.json -Raw) -Server $PDC
        New-ADCSTemplate -DisplayName "$ADName Workstation Certificate" -JSON (Get-Content C:\cert-templates\WorkstationCertificateTemplate.json -Raw) -Server $PDC
        New-ADCSTemplate -DisplayName "$ADName Web Server Certificate" -JSON (Get-Content C:\cert-templates\WebServerCertificateTemplate.json -Raw) -Server $PDC

        # Setting Security on each template
        Set-ADCSTemplateACL -DisplayName "$ADName Key Recovery Agent" -Type Allow -Identity "Authenticated Users" -Enroll
        Set-ADCSTemplateACL -DisplayName "$ADName Key Recovery Agent" -Type Allow -Identity "$ADName\Domain Admins" -Enroll
        Set-ADCSTemplateACL -DisplayName "$ADName OCSP Response Signing" -Type Allow -Identity "$ADName\ica-servers" -Enroll
        Set-ADCSTemplateACL -DisplayName "$ADName OCSP Response Signing" -Type Allow -Identity "Authenticated Users" -Enroll
        Set-ADCSTemplateACL -DisplayName "$ADName User Certificate" -Type Allow -Identity "$ADName\ica-servers" -Enroll
        Set-ADCSTemplateACL -DisplayName "$ADName User Certificate" -Type Allow -Identity "Authenticated Users" 
        Set-ADCSTemplateACL -DisplayName "$ADName User Certificate" -Type Allow -Identity "$ADName\Domain Users" -Enroll -AutoEnroll
        Set-ADCSTemplateACL -DisplayName "$ADName Workstation Certificate" -Type Allow -Identity "$ADName\ica-servers" -Enroll
        Set-ADCSTemplateACL -DisplayName "$ADName Workstation Certificate" -Type Deny -Identity "$ADName\Domain Computers"
        Set-ADCSTemplateACL -DisplayName "$ADName Workstation Certificate" -Type Allow -Identity "$ADName\Domain Computers" -Enroll -AutoEnroll
        Set-ADCSTemplateACL -DisplayName "$ADName Web Server Certificate" -Type Allow -Identity "$ADName\ica-servers" -Enroll
        Set-ADCSTemplateACL -DisplayName "$ADName Web Server Certificate" -Type Allow -Identity "$ADName\Domain Admins" -Enroll -AutoEnroll

        # Publishing the templates 
        Write-Host "[$using:ComputerName]-Publishing the Certificate Templates"
        Get-CertificationAuthority | Get-CATemplate | Add-CATemplate -DisplayName "$ADName Key Archive", "$ADName Key Recovery Agent", "$ADName OCSP Response Signing",`
        "$ADName User Certificate", "$ADName Workstation Certificate", "$ADName Web Server Certificate"  | Set-CATemplate | Out-Null
    }
}
Function OCSPConfiguration {
    param(
        [array]$HostList,
        [string]$UserName
    )
    $ComputerName = $HostList[0]
    # $ComputerIP = $HostList[1]

    # Have to set these variables via Invoke-Command to avoid a double hop issue in the script below.
    $PSSession = New-PSSession -ConnectionURI "$UserName@$DC1_Host_IPAddress" -KeyFilePath $sshKeyFile
    $ADName = Invoke-Command -Session $PSSession -ScriptBlock {$(Get-ADDomain).Name}
    # $PDC = Invoke-Command -Session $PSSession -ScriptBlock {$(Get-ADDomain).PDCEmulator}
    $ConfigNC = Invoke-Command -Session $PSSession -ScriptBlock {$(Get-ADDomain).DistinguishedName}



    Invoke-Command -HostName $ComputeIP -UserName $UserName -KeyFilePath "$sshKeyFile" -ScriptBlock { 
        $CA = Get-CertificationAuthority "$usingICA_Host_Name.$using:Domain" -Enterprise
        $url = "ldap:///CN=$ICA_CAName,CN=$using:ICA_Host_Name,CN=CDP,CN=Public Key Services,CN=Services,CN=Configuration,$using:ConfigNC?certificateRevocationList?base?objectClass=cRLDistributionPoint"
        $encodedUrl = [System.Uri]::EscapeDataString($url)
    
        Write-Host "[$using:ComputerName]-Installing up OCSP Responder"
        Add-WindowsFeature ADCS-Online-Cert -IncludeManagementTools | Out-Null 
        Install-AdcsOnlineResponder -Force | Out-Null
        Write-Host "[$using:ComputerName]-Adding OSCP to AIA" 
        Add-CAAuthorityInformationAccess -Uri "http://ocsp.$using:Domain/ocsp" -AddToCertificateOcsp -Force | Out-Null

        Write-Host "[$using:ComputerName]-Configuring the Online Responder"

        Connect-OnlineResponder ($CA.ComputerName) | Add-OnlineResponderRevocationConfiguration -Name "$using:ADName OCSP Responder" -CA $CA | Out-Null
        Connect-OnlineResponder ($CA.ComputerName) | Get-OnlineResponderRevocationConfiguration -Name "$using:ADName OCSP Responder" | Set-OnlineResponderRevocationConfiguration `
            -SigningServer $CA `
            -SigningCertTemplate "$using:ADName`OCSPResponseSigning" `
            -SigningFlag "Silent, SigningCertAutoRenewal, ForceDelegatedCert, AutoDiscoverSigningCert, ResponderIdKeyHash, SigningCertAutoEnrollment" `
            -BaseCrlUrl $encodedUrl `
            -HashAlgorithm (New-Object SysadminsLV.PKI.Cryptography.Oid2 "sha256", $true) `
            -ErrorAction SilentlyContinue | Out-Null

        # Restart Certificate Service
        Restart-Service certsvc | Out-Null
    }
}

Function CertFix {
    param(
        [array]$HostList,
        [string]$UserName
    )
    $ComputerName = $HostList[0]
    $ComputerIP = $HostList[1]

    Invoke-Command -HostName $ComputerIP -UserName $UserName -KeyFilePath "$sshKeyFile" -ScriptBlock { 
        # Restart certsvc and test to see when it is back up
            Write-Host "[$using:ComputerName]-Restarting AD Certificate Services"
            Restart-Service certsvc | Out-Null
            Start-Sleep 3
            $serviceStatus = Get-Service -Name certsvc
            if ($serviceStatus.Status -eq "Running") {
                Write-Host "[$using:ComputerName]-Certificate Service started successfully"      
            }   
            else {
                Start-Service certsvc | Out-Null
                Start-Sleep 3
            }


        # Reissue CA-Exchange Certificate (if it exist) to fix OCSP error in PKI
        #Get-CA | Get-IssuedRequest -Filter "CertificateTemplate -eq CAExchange" | Revoke-Certificate -Reason "Superseded" | Out-Null
        certutil -cainfo xchg | Out-Null

        # Restart OCSP Responder Service to force cert generation
        Restart-Service OCSPSvc
        }
}

Function KeyRecovery {
    param(
        [array]$HostList,
        [string]$UserName
    )
    # $ComputerName = $HostList[0]
    $ComputerIP = $HostList[1]

    Invoke-Command -HostName $ComputerIP -UserName $UserName -KeyFilePath "$sshKeyFile" -ScriptBlock { 
        # Generate Key Recovery Agent Certificate from template
        Get-Certificate -Template "labKeyRecoveryAgent" -CertStoreLocation Cert:\CurrentUser\My 

        # Get KRA Cert
        $KRAcert = [System.Security.Cryptography.X509Certificates.X509Certificate2[]](Get-ChildItem  Cert:\CurrentUser\My | ?{$_.EnhancedKeyUsageList.FriendlyName -like 'Key Recovery Agent'})
        
        # Add the KRA cert to ICA Cert Authority 
        Get-CA | Get-CAKRACertificate | Add-CAKRACertificate -Certificate $KRAcert | Set-CAKRACertificate -RestartCA
    }
}

Function SecureIIS {
    param(
        [array]$HostList,
        [string]$UserName
    )
    # $ComputerName = $HostList[0]
    $ComputerIP = $HostList[1]

    Invoke-Command -HostName $ComputerIP -UserName $UserName -KeyFilePath "$sshKeyFile" -ScriptBlock { 

        # Generate and install a Web certificate
        $certlocation = "Cert:\LocalMachine\My"
        Get-Certificate -Template "labWebServerCertificate" -CertStoreLocation $certlocation -DnsName "pki.$using:Domain" -SubjectName "CN=pki.$using:Domain"
        # Configure IIS with the new certificate and enable SSL
        $cert = Get-ChildItem $certlocation | Where-Object {$_.Subject -like "*pki.$using:Domain*"} 
        $thumbprint = $cert.Thumbprint
        New-IISSiteBinding -Name "Default Web Site" -BindingInformation "*:443:" -Protocol https -CertificateThumbPrint $thumbprint -CertStoreLocation $certlocation

        # Require SSL for CertSrv Application Pool
        $cfgSection = Get-IISConfigSection -Location 'Default Web Site/CertSrv' -SectionPath "system.webServer/security/access"
        Set-IISConfigAttributeValue -ConfigElement $cfgSection -AttributeName "sslFlags" -AttributeValue "Ssl"
    }
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