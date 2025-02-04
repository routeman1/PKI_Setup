#-------------------------[Initalization]-------------------------------

# NOTE: variables are read from the variables.csv file, and parsed from the menu script

# To track script run time
$StartTime = Get-Date

# ----------------------------------------------------[Root CA Setup]--------------------------------------------------

Function RootCASetup {
    param(
        [string]$ComputerName,
        [string]$UserName
    )
    
    # Get the Distinguished Name of the Active Directory Domain  and store in variable
    $ADDN = (Invoke-Command -HostName $DC1[1] -UserName $UserName -KeyFilePath "$sshKeyFile" -ScriptBlock {
         Get-ADDomain | Select-Object -ExpandProperty DistinguishedName
    })
    
    # Begin Root CA Setup
    Invoke-Command -HostName $ComputerName -UserName $UserName -KeyFilePath "$sshKeyFile" -ScriptBlock {
        Write-Host "Begining Setup and Configuration of the Root CA" -ForegroundColor Yellow
        
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
RenewalValidityPeriodUnits=10
    
AlternateSignatureAlgorithm=0
    
CRLPeriod=Years
CRLPeriodUnits=10
    
CRLDeltaPeriod=Days
CRLDeltaPeriodUnits=0
    
"@
    
    $CAPolicyInf | Out-File "C:\Windows\CAPolicy.inf" -Encoding utf8 -Force | Out-Null
    
    Write-Host "[$using:ComputerName] Installing required Windows Features" 
    Add-WindowsFeature -Name ADCS-Cert-Authority -IncludeManagementTools | Out-Null
    
    Write-Host "[$using:ComputerName] Installing and configuring AD Certificate Services" 
    
    Install-AdcsCertificationAuthority -CAType StandaloneRootCA -CACommonName $using:RootCAName `
        -KeyLength "4096" -HashAlgorithm "SHA256" -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" `
        -ValidityPeriod "Years" -ValidityPeriodUnits "10" -Force | Out-Null
    
    # Set Validity period and other settings of certificates generated by this CA
    certutil.exe -setreg CA\DSConfigDN "CN=Configuration,$using:ADDN" | Out-Null
    certutil.exe -setreg CA\CRLPeriodUnits 52 | Out-Null
    certutil.exe -setreg CA\CRLPeriod "Weeks" | Out-Null
    certutil.exe -setreg CA\ValidityPeriodUnits 5 | Out-Null
    certutil.exe -setreg CA\ValidityPeriod "Years" | Out-Null
    certutil.exe -setreg CA\CRLOverlapPeriodUnits 12 | Out-Null
    certutil.exe -setreg CA\CRLOverlapPeriod "Hours" | Out-Null
    
    # Set Logging for the cerificates created by this CA in Local Security Policy Audit Object Access
    auditpol /set /category:"Object Access" /success:enable /failure:enable
    certutil.exe -setreg CA\AuditFilter 127 | Out-Null
    
    Write-Host "[$using:ComputerName] Restarting Certificate Services" 
    Restart-Service certsvc | Out-Null
    
    Write-Host "[$using:ComputerName] Customizing Certificate Services" 
    Add-CACRLDistributionPoint -Uri "http://$using:PKI_URL/CertData/<CaName><CRLNameSuffix><DeltaCRLAllowed>.crl" -AddToFreshestCrl -Force | Out-Null
    Remove-CACRLDistributionPoint -Uri "file://<ServerDNSName>/CertEnroll/<CAName><CRLNameSuffix><DeltaCRLAllowed>.crl" -AddToFreshestCrl -AddToCertificateCdp -Force | Out-Null
    Add-CAAuthorityInformationAccess -Uri "http://$using:PKI_URL/CertData/<ServerDNSName>_<CaName><CertificateName>.crt" -AddToCertificateAia -Force | Out-Null
    Remove-CAAuthorityInformationAccess -Uri "file://<ServerDNSName>/CertEnroll/<ServerDNSName>_<CAName><CertificateName>.crt" -Force | Out-Null
    
    Write-Host "[$using:ComputerName] Restarting Certificate Services" 
    Restart-Service certsvc | Out-Null
    Start-Sleep 5
        
    Write-Host "[$using:ComputerName] Publishing CRL" 
    certutil -crl | Out-Null
    
    # Create Shared Folder for Certificates
    Write-Host "[$using:ComputerName] Creating Shared Folder for Certificates"
    New-Item -Path "C:\Share" -ItemType "directory" | Out-Null
    New-Item -Path "C:\Share\Root CA Files" -ItemType "directory" | Out-Null
    New-Item -Path "C:\Share\Intermediate CA Files" -ItemType "directory" | Out-Null
    New-Item -Path "C:\Share\Intermediate CA Files\Request" -ItemType "directory" | Out-Null
    New-SmbShare -Name "Share" -Path "C:\Share" -FullAccess "Administrators" | Out-Null
    
    # Copy Root CA certificate and CRL to shared folder
    Copy-Item "C:\Windows\system32\CertSrv\CertEnroll\*.crt" -Destination "C:\Share\Root CA Files" | Out-Null
    Copy-Item "C:\Windows\system32\CertSrv\CertEnroll\*.crl" -Destination "C:\Share\Root CA Files" | Out-Null
    
    Write-Host "Root CA Build Completed!" -ForegroundColor Green
    
    }
}

#---------------------------------------------------------[ Execution ]---------------------------------------------------

Write-Host "Begining pre-Installation Tests" -ForegroundColor Yellow
#Load the test script (for test functions)
. ./test.ps1 
# Test each host is up
ServerTestLoop -Username $DefWinAccount -HostList $RCA[1]
ServerTestLoop -Username $RemoteAdmin -HostList $DC1[1]
# Test that PSSession can be established via SSH
InstallationTests -Username $DefWinAccount -HostList $RCA[1]
InstallationTests -Username $RemoteAdmin -HostList $DC1[1]

Write-Host "Configuring Server Hostname, and local security settings" -ForegroundColor Yellow
. ./server_setup.ps1
ServerPrep -HostList $RCA -Username $DefWinAccount
 
Write-Host "Pausing to allow the system to finish restarting." -ForegroundColor Magenta
Start-Sleep -Seconds 30

Write-Host "Verifying the sever is back up after the restart " -ForegroundColor Yellow
ServerTestLoop -Username $RemoteAdmin -HostList $RCA[1]

Write-Host "Starting Root CA Installation" -ForegroundColor Yellow 
RootCASetup -ComputerName $RCA[1] -Username $RemoteAdmin 

Write-Host ""
Write-Progress -Completed -Activity ""
Write-Host "Root Certificate Authority installataion and configuration complete" -ForegroundColor Green
Write-Host "Total execution time: $((get-date) - $StartTime)" -ForegroundColor Green
Write-Host ""