# Variables Readme

This is a guide to entering the values for the Variables CSV file. This file is used to customize your PKI installation and the associated virtual machines.  
**NOTE:** The variables file must be a text csv file. Be sure to remove any extra carriage returns at the end

## Variables and Definitions

**DefWinAccount** - This is the Default Windows (Local) Administrator Account name (usually Administrator) setup in the VM template  
**DefWinLoginPass** - This is the default Windows (Local) Administrator password that you entered when running the Out of Box Experience when setting up the VM template  
**NewAdminAccount** - This is what you want the Local Administrator account to be renamed to (for security reasons)  
**NewAdminPass** - This is will be the new Local Administrator password  
**NewGuestAccount** - This what the Windows Local Default Guest Account will be renamed to (Note: it will also be disabled)  
**NewGuestPass** - This will become the Windows Local Default Guest Account password (Note: the account will be disabled)  
**RemoteAdmin** - This is a Administrator account (both Local and Domain) created for the installation process (It will be removed at the end)  
**RemoteAdminPass** - This is the password for the RemoteAdmin account  
**CoreNet_Subnet** - This is the IP subnet that the VMs run on. Currently the script requires they are all on the same subnet. The entry must be the NETWORK (minus the subnet mask) i.e.: 10.1.2.0 - DO NOT ENTER A HOST IP  
**CoreNet_prefix** - This is the subnet mask bit length for the CoreNet_Subnet (i.e.: 24)  
**DC1_Host_Name** - Host name for the Primary Domain Controller (do not include the domain suffix)  
**DC1_Host_IPAddress** - Host IP for the Primary Domain Controller (IP only - no subnet mask)  
**DC2_Host_Name** - Host name for the Secondary Domain Controller (do not include the domain suffix)  
**DC2_Host_IPAddress** - Host IP for the Secondary Domain Controller (IP only - no subnet mask)  
**RCA_Host_Name** - Host name for the Root Certificate Authority (do not include the domain suffix)  
**RCA_Host_IPAddress** - Host IP for the Root Certificate Authority (IP only - no subnet mask)  
**ICA_Host_Name** - Host name for the Intermediate Certificate Authority (do not include the domain suffix)  
**ICA_Host_IPAddress** - Host IP for the Intermediate Certificate Authority (IP only - no subnet mask)  
**Timezone** - Sets the timezone that the VMs are operating in (i.e.: Mountain Standard Time)  
**VLM_Hostname** - Host name of your Microsoft Volume License Server (do not include the domain suffix)  
**VLM_IPAddress** - Host IP address of you Microsoft Volume License Server (IP only)  
**WIN2022_LIC** - Windows Product Key (should be a generic volume license key)  
**Domain** - DNS Domain (i.e.: demo.intra)  
**AD_Domain** - Active Directory domain name (i.e.:demo.intra)  
**ADDomainMode** - Active Directory Domain Mode - Usually Win2012R2  
**ADForestMode** - Active Directory Forest Mode - Usually Win2012R2  
**SafeModeAdministratorPassword** - Active Directory Safe Mode Administrator Password  
**Netbios_Name** - NetBIOS name  
**AD_OU_Level1** - Top Level AD OU that will be automatically configured  
**Cert_InternalOID** - You should leave this at 1.2.3.4.1455.67.89.5 unless you know what you are doing  
**Cert_AllIssuanceOID** - You should leave this at 2.5.29.32.0 unless you know what you are doing  
**Cert_Notice** - Comment(s) on all certificates that are issued.  
**PKI_URL** - The host.domain for the PKI URL (i.e.: pki.demo.intra)  
**OCSP_URL** - The host.domain for the OCSP URL (i.e.: ocsp.demo.intra)  
**RootCAName** - Full name for the CA Root Authority Certificate (i.e.: Demo Root Cert Authority)  
**ICA_CAName** - Full name for the Intermedicate Certificate (i.e.: Demo Intermediate CA)