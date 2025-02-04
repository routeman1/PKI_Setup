#-------------------------[Initalization]-------------------------------

# Read the variables from the variables.csv comma delimited file. Ignore lines that start with #
Get-Content variables.csv | Where-Object {$_.length -gt 0} | Where-Object {!$_.StartsWith("#")} | ForEach-Object {

    $var = $_.Split(',',2).Trim()
    New-Variable -Scope Script -Name $var[0] -Value $var[1]

    }

# To track script run time
$StartTime = Get-Date

#---------------------------------------------------------[Intermidiate CA Installation]---------------------------------------------------

Function ValidateLogin {
    $AD = ($AD_Domain -split '\.')
    $AD1 = $AD[0]
    If ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -match "$AD1\\$RemoteAdmin") {
        Write-Host "You are logged in with a Domain account - Continuing Setup"
    }
    Else {
        Write-Host "You are not logged in with a Domain account" -ForegroundColor Red
        Write-Host "Please log in with a Domain Admin account: (ie: ssh $RemoteAdmin@$AD_Domain@$ICA_Host_IPAddress)" -ForegroundColor Yellow
        Write-Host "The script will now exit"
        exit
    }
}
Function IntermediateCAConfigII {

    $ComputerName = (hostname)
    $ADName = $AD_OU_Level1

    # Continuing Intermediate CA Setup

        Write-Host "[$ComputerName]-Customizing AD Certificate Services" 
        Write-Host "[$ComputerName]-Setting up CRL distribution points" 

        Add-CACRLDistributionPoint -Uri "http://$PKI_URL/CertEnroll/<CaName><CRLNameSuffix><DeltaCRLAllowed>.crl" -AddToFreshestCrl -Force | Out-Null
        Add-CAAuthorityInformationAccess -Uri "http://$PKI_URL/CertEnroll/<ServerDNSName>_<CaName><CertificateName>.crt" -AddToCertificateAia -Force | Out-Null

        Write-Host "[$ComputerName]-Setting default values for issued certificates" 
        certutil.exe -setreg CA\CRLPeriodUnits 2  | Out-Null
        certutil.exe -setreg CA\CRLPeriod "Weeks"  | Out-Null
        certutil.exe -setreg CA\CRLDeltaPeriodUnits 1  | Out-Null
        certutil.exe -setreg CA\CRLDeltaPeriod "Days"  | Out-Null
        certutil.exe -setreg CA\CRLOverlapPeriodUnits 12  | Out-Null
        certutil.exe -setreg CA\CRLOverlapPeriod "Hours"  | Out-Null
        certutil.exe -setreg CA\ValidityPeriodUnits 1 | Out-Null
        certutil.exe -setreg CA\ValidityPeriod "Years"  | Out-Null
        certutil.exe -setreg CA\AuditFilter 127  | Out-Null
        
        # Start the Certification service 
        Write-Host "[$ComputerName]-Starting AD Certificate Services"
        Start-Service -Name certsvc | Out-Null
        Start-Sleep 3

            # Checking to see if the service is running
            $maxRetries = 5
            $retryInterval = 3 # in seconds

            for ($i = 0; $i -lt $maxRetries; $i++) {
                try { 
                    $serviceStatus = Get-Service -Name certsvc
                    if ($serviceStatus.Status -eq "Running") {
                        Write-Host "[$ComputerName]-Certificate Service started successfully"}
                        break
                    }   
                    catch {
                        Write-Warning "[$ComputerName] Failed to start certificate service (attempt $($i + 1)). Retrying in $retryInterval seconds..."
                        Start-Sleep -Seconds $retryInterval      
                    }
                    Write-Error "[$ComputerName] Failed to start certificate service after $maxRetries attempts."
                    exit
                }

        Write-Host "[$ComputerName]-Publishing CRL" 
        "certutil -crl" | Out-Null
        "certutil.exe -dsPublish 'C:\Windows\System32\CertSrv\CertEnroll\$ADName Enterprise CA.crl'" | Out-Null

        # Set audit Policy
        auditpol /set /category:"Object Access" /failure:enable /success:enable | Out-Null

        Write-Host "[$ComputerName]-Creating cps.html file" 
        #--------------------------
        # cps.html file content 
        #--------------------------
        $cps = @"
<html>
<head>
<title>$Domain CPS</title>
</head>
<body>
$Domain CPS
</body>
</html>
"@
        $cps | Out-File "C:\inetpub\wwwroot\cps.html"

        #Delete IIS files
        Remove-Item -Path "C:\inetpub\wwwroot\iisstart.htm" -Recurse -Force | Out-Null
        Remove-Item -Path "C:\inetpub\wwwroot\iisstart.png" -Recurse -Force | Out-Null

        # Create IIS Certificate Directory
        Write-Host "[$ComputerName]-Creating IIS Certificate Directory"
        New-Item -Path "C:\Certificates" -ItemType "directory" | Out-Null

        Write-Host "[$ComputerName]-Setting up IIS Certificates Virtual Directory"
        Import-Module WebAdministration
        New-WebVirtualDirectory -Site "Default Web Site" `
                    -Name "Certificates" `
                    -PhysicalPath "C:\Certificates" `
                    -Force | Out-Null    

        Write-Host "[$ComputerName]-Configuring Certificates Virtual Directory"
        Set-WebConfigurationProperty -Filter "/system.webServer/directoryBrowse" -PSPath "IIS:\Sites\Default Web Site\Certificates" -Name "enabled" -Value "True" | Out-Null
        Write-Host "[$ComputerName]-Copying certificates into Certificates directory"
        Copy-Item "C:\Windows\system32\CertSrv\CertEnroll\$RootCAName.crt" -Destination "C:\CertData" | Out-Null
        Copy-Item "C:\Windows\system32\CertSrv\CertEnroll\$RootCAName.crt" -Destination "C:\Certificates" | Out-Null
        Copy-Item "C:\Windows\system32\CertSrv\CertEnroll\SubordinateCA.crt" -Destination "C:\CertData\$ICA_CAName.crt" | Out-Null
        Copy-Item "C:\Windows\system32\CertSrv\CertEnroll\SubordinateCA.crt" -Destination "C:\Certificates\$ICA_CAName.crt" | Out-Null
        Copy-Item "C:\Windows\system32\CertSrv\CertEnroll\*.crl" -Destination "C:\CertData" | Out-Null

        Write-Host ""

    }

Function PublishCertificates {

    [String]$Rem_Adm_Pw = $RemoteAdminPass
    [SecureString]$Securestring_Rem_Adm_Pw = $Rem_Adm_Pw | ConvertTo-SecureString -AsPlainText -Force

    $Credential = New-Object pscredential -ArgumentList ([pscustomobject]@{
        UserName = "$AD_Domain\$RemoteAdmin"
        Password = $Securestring_Rem_Adm_Pw
    })

    $rcacred = New-Object pscredential -ArgumentList ([pscustomobject]@{
    UserName = $RemoteAdmin
    Password = $Securestring_Rem_Adm_Pw
    })
    


    #### Connect to PDC and set up certificate directory #######
    Invoke-Command -ComputerName $DC1_Host_Name -Credential $Credential -ScriptBlock {
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

    }
}
    
Function TemplateConfiguration {

    $ComputerName = (hostname)

        Write-Host "[$ComputerName] Installing Certificate Support Tools"
            #Need to add RSAT Powershell tools and Install the Module PSPKI to configure the OCSP Responder
            Install-WindowsFeature -Name RSAT-AD-PowerShell -IncludeAllSubFeature | Out-Null
            Install-Module ADCSTemplate -Force | Out-Null
            Install-Module -Name PSPKI -Force | Out-Null
            Import-Module -Name PSPKI -Force | Out-Null

    $ADName = $AD_OU_Level1
    $PDC = $DC1_Host_Name
    $ConfigNC = $((Get-ADRootDSE).defaultNamingContext)  
    
        # create "ica-servers" group in AD with $ICA_Host_Name as the only member
        New-ADGroup -Name "ica-servers" -SamAccountName ica-servers -GroupCategory Security -GroupScope Global `
        -DisplayName "Intermediate Certificate Servers" -Path "CN=Computers,$ConfigNC" `
        -Description "DO NOT Delete or Modify - This is required for the PKI Certificate Templates to function correctly" 
        Add-ADGroupMember -Identity ica-servers -Members (Get-ADComputer $ICA_Host_Name) 

        Write-Host "[$ComputerName] Preparing to Import Certificate Templates"
        New-ADCSDrive | Out-Null

        # Customize Certificate Templates 
        Write-Host "[$ComputerName] Importing Certificate Templates"
        New-ADCSTemplate -DisplayName "$ADName Key Archive" -JSON (Get-Content C:\cert-templates\KeyArchiveTemplate.json -Raw) 
        New-ADCSTemplate -DisplayName "$ADName Key Recovery Agent" -JSON (Get-Content C:\cert-templates\KeyRecoveryAgentTemplate.json -Raw) 
        New-ADCSTemplate -DisplayName "$ADName OCSP Response Signing" -JSON (Get-Content C:\cert-templates\OCSPResponseSigningTemplate.json -Raw) 
        New-ADCSTemplate -DisplayName "$ADName User Certificate" -JSON (Get-Content C:\cert-templates\UserCertificateTemplate.json -Raw) 
        New-ADCSTemplate -DisplayName "$ADName Workstation Certificate" -JSON (Get-Content C:\cert-templates\WorkstationCertificateTemplate.json -Raw) 
        New-ADCSTemplate -DisplayName "$ADName Web Server Certificate" -JSON (Get-Content C:\cert-templates\WebServerCertificateTemplate.json -Raw) 

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
        Write-Host "[$ComputerName] Publishing the Certificate Templates"
        Get-CertificationAuthority | Get-CATemplate | Add-CATemplate -DisplayName "$ADName Key Archive", "$ADName Key Recovery Agent", "$ADName OCSP Response Signing",`
        "$ADName User Certificate", "$ADName Workstation Certificate", "$ADName Web Server Certificate"  | Set-CATemplate | Out-Null
    }

Function OCSPConfiguration {

    $ComputerName = (hostname)

    # Have to set these variables via Invoke-Command to avoid a double hop issue in the script below.
    $ADName = $AD_OU_Level1
    $PDC = $DC1_Host_IPAddress
    $ConfigNC = $((Get-ADRootDSE -Server $PDC).defaultNamingContext)

        $CA = Get-CertificationAuthority "$ICA_Host_Name.$Domain" -Enterprise
        $url = "ldap:///CN=$ICA_CAName,CN=$ICA_Host_Name,CN=CDP,CN=Public Key Services,CN=Services,CN=Configuration,$ConfigNC?certificateRevocationList?base?objectClass=cRLDistributionPoint"
        $encodedUrl = [System.Uri]::EscapeDataString($url)
    
        Write-Host "[$ComputerName]-Installing up OCSP Responder"
        Add-WindowsFeature ADCS-Online-Cert -IncludeManagementTools | Out-Null 
        Install-AdcsOnlineResponder -Force | Out-Null
        Write-Host "[$ComputerName]-Adding OSCP to AIA" 
        Add-CAAuthorityInformationAccess -Uri "http://ocsp.$Domain/ocsp" -AddToCertificateOcsp -Force | Out-Null

        Write-Host "[$ComputerName]-Configuring the Online Responder"

        Connect-OnlineResponder ($CA.ComputerName) | Add-OnlineResponderRevocationConfiguration -Name "$ADName OCSP Responder" -CA $CA | Out-Null
        Connect-OnlineResponder ($CA.ComputerName) | Get-OnlineResponderRevocationConfiguration -Name "$ADName OCSP Responder" | Set-OnlineResponderRevocationConfiguration `
            -SigningServer $CA `
            -SigningCertTemplate $ADName"OCSPResponseSigning" `
            -SigningFlag "Silent, SigningCertAutoRenewal, ForceDelegatedCert, AutoDiscoverSigningCert, ResponderIdKeyHash, SigningCertAutoEnrollment" `
            -BaseCrlUrl $encodedUrl `
            -HashAlgorithm (New-Object SysadminsLV.PKI.Cryptography.Oid2 "sha256", $true) `
            -ErrorAction SilentlyContinue | Out-Null

        # Restart Certificate Service
        Restart-Service certsvc | Out-Null
    }
Function CertFix {

    $ComputerName = (hostname)

        # Restart certsvc and test to see when it is back up
            Write-Host "[$ComputerName]-Restarting AD Certificate Services"
            Restart-Service certsvc -ErrorAction SilentlyContinue | Out-Null
            Start-Sleep 3
            $serviceStatus = Get-Service -Name certsvc
            if ($serviceStatus.Status -eq "Running") {
                Write-Host "[$ComputerName]-Certificate Service started successfully"      
            }   
            else {
                Start-Service certsvc | Out-Null
                Start-Sleep 3
            }


        # Reissue CA-Exchange Certificate (if it exist) to fix OCSP error in PKI
        certutil -cainfo xchg | Out-Null

        # Restart OCSP Responder Service to force cert generation
        Restart-Service OCSPSvc
        }


Function KeyRecovery {

    $ADName = $AD_OU_Level1

        # Generate Key Recovery Agent Certificate from template
        Get-Certificate -Template $ADName"KeyRecoveryAgent" -CertStoreLocation Cert:\CurrentUser\My 

        # Get KRA Cert
        $KRAcert = [System.Security.Cryptography.X509Certificates.X509Certificate2[]](Get-ChildItem  Cert:\CurrentUser\My | ?{$_.EnhancedKeyUsageList.FriendlyName -like 'Key Recovery Agent'})
        
        # Add the KRA cert to ICA Cert Authority 
        Get-CA | Get-CAKRACertificate | Add-CAKRACertificate -Certificate $KRAcert | Set-CAKRACertificate -RestartCA
    }
Function SecureIIS {

        $ADName = $AD_OU_Level1
        Import-Module IISAdministration
        # Generate and install a Web certificate
        $certlocation = "Cert:\LocalMachine\My"
        Get-Certificate -Template $ADName"WebServerCertificate" -CertStoreLocation $certlocation -DnsName "pki.$Domain" -SubjectName "CN=pki.$Domain"
        # Configure IIS with the new certificate and enable SSL
        $cert = Get-ChildItem $certlocation | Where-Object {$_.Subject -like "*pki.$Domain*"} 
        $thumbprint = $cert.Thumbprint
        New-IISSiteBinding -Name "Default Web Site" -BindingInformation "*:443:" -Protocol https -CertificateThumbPrint $thumbprint -CertStoreLocation $certlocation
        
        # Require SSL for CertSrv Application Pool
        $cfgSection = Get-IISConfigSection -Location 'Default Web Site/CertSrv' -SectionPath "system.webServer/security/access"
        Set-IISConfigAttributeValue -ConfigElement $cfgSection -AttributeName "sslFlags" -AttributeValue "Ssl"
    }


#---------------------------------------------------------[ Execution ]---------------------------------------------------

Write-Host "Validating login user" -ForegroundColor Yellow
ValidateLogin

Write-Host "Installing the Intermediate Certificate " -ForegroundColor Yellow
certutil.exe -installcert C:\Windows\System32\CertSrv\CertEnroll\SubordinateCA.crt

Write-Host "Configuring the Intermediate Certificate Authority" -ForegroundColor Yellow
IntermediateCAConfigII 

Write-Host "Customizing the Certificate Templates" -ForegroundColor Yellow
TemplateConfiguration 

Write-Host "Setting up OCSP Responder" -ForegroundColor Yellow
OCSPConfiguration 

Write-Host "Publishing the Certs to the Domain" -ForegroundColor Yellow
PublishCertificates 

Write-Host "Setting up Key Recovery Agent" -ForegroundColor Yellow
KeyRecovery 

Write-Host "Reissuing and updating supporting Certificates" -ForegroundColor Yellow
CertFix 

Write-Host "Enabling SSL on IIS" -ForegroundColor Yellow
SecureIIS 

Write-Host ""

Write-Host "The Initial Certificate Servers and service configuration is complete." -ForegroundColor Green
Write-Host ""
Write-Host "Please Login into the ICA server and fix the permissons on the $Domain Certificate Templates" -ForegroundColor Yellow
Write-Host "before proceeding." -ForegroundColor Yellow
Write-Host ""
Write-Host "Total execution time: $((get-date) - $StartTime)" -ForegroundColor Green