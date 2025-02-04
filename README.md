# PKI Setup Overview

These scripts will set up a Primary and Secondary Domain Controller including a offline Root Certificate Authority (RCA) and a (Enterprise) Intermediate Certificate Authority (ICA). The Root will NOT be joined to the domain and the intermediate CA will be part of the domain. This is a full and working PKI implementation issuing certificates to the DC’s, workstations, users and other support services (ie: OCSP) as required. In addition, a certificate templates are created for Web services to be utilized when generating Web certs. 

Currently this has only been tested and verified to work with Windows Server 2022. Starting testing with Windows 2025 soon. 
 

## Running the Scripts

### Building the Docker Container:
- Clone the repository onto your Docker server
```
git clone https://github.com/routeman1/PKI_Setup.git
```
- Update the variables csv file with the appropriate configuration information. Modify the varibles.csv file with your own values and refer to the variables.md to help guide you. 
    - [Variables HTML](variables.html)
    - [Variables Markdown File](variables.md)
- You can optionally add your own web certificate and ssh key
    - To use your own web certificate, copy the cert and key (in Base64 format) to the Crypto directory. 
     **NOTE:** They must be named server.crt and server.key.
    - To use your own ssh keys copy the ssh private key (must be named pkisetup) and the public key (must be named pkisetup.pub) to the crypto directory.
    - If you do not place anything in the crypto directory, a self-signed cert will be generated along with a ssh key
- Run the "build-deploy.sh" script to build and deploy the container
    **NOTE:** Currently the container requires ports 80 and 443.  If you change this you will need to make updates to the files before building the container.
- These scripts require that the initial VMs have been built (Windows Server 2022 or higher - See VM Template Section)
- Static IPs have been assigned to each host (that matches the data in the variables file)

### VM Template:
Create your VM template(s) for the Domain Controller(s), Root CA, and Intermediate CA - They can all use the same template
- Load and configure Windows Server HW and OS (HD, RAM, NIC, etc.)
- Install VMware Tools (or relevant support application), and any required drivers
- Option: Patch the template OS with the most current patches
- Run the template configuration script to install ssh, update PowerShell and install/configure the ssh keys by running the following command from a command prompt:
```
curl -ko C:\Windows\Temp\install.bat https://*DOCKER_SERVER_IP*/install.bat & C:\Windows\Temp\install.bat
```
- Once completed, the system will automatically run sysprep and shutdown
- Convert the VM into a template and use this to deploy the related VMs (i.e.: dc1, dc2, rca, ica)

### Preparing for Install:
- Create four new VMs from the template: DC1, DC2, RCA, ICA
- Start each of the four VMs
- Complete the initial Out of Box Experience (OOBE) for each
    Note: if you are using a VLMS, you do not need to enter a license key
- Be sure to use the same password that was defined for the "DefLoginPass" variable in the csv file
- Assign the appropriate static IP to each host as reflected in the variables.csv file
- Logout of each VM when you are done and before you run the scripts - Otherwise the script will error out when it try’s to reboot the VMs

&nbsp;

### Running the Install Scripts 
On the docker host running the container type:
```
docker exec -it pki-setup pwsh 
```
- Then enter:
```
cd /scripts
```
- Launch the install menu
```
./install_menu.ps1
```
This will bring up a installation menu

#### Active Directory Setup
- Select 1 to begin the setup and configuration of a Domain controller with Active Directory
- Once the DC setup is complete, you can review the details of the installation to see if there are any errors.  Press any key to return to the main menu.

#### Root CA Setup
- Once the DC is up and Active Directory is configured, select option 2 to begin the Offline Root CA server setup and installation
- When it is finished you can review the details of the installation.  Press any key to return to the main menu.

#### ICA Setup
- Now select menu option 3 to begin the setup/configuration of the Intermediate CA
 **NOTE:** *When this script is done running, the ICA and PKI services are not yet fully configured - Pay close attention to the message that it displays on the screen

 #### ICA Setup Part 2
- You will need to log into the ICA server after it has completed rebooting.  (You can either SSH or login via the console) If logging in from the console, open a PowerShell windows (as Administrator). If you ssh into the server, you will already be in a PowerShell terminal. Change directory to C:\scripts and then run: ica_setup_partII.ps1
 **NOTE:** if you ssh into the server - be sure to use the ssh command displayed on the screen at the end of the ICA install.  This will ensure you login with a DOMAIN login (very important!)
- This will finish configuring the ICA and PKI services

#### Certificate Template Fixes
**Before proceeding you need to fix the Certificate Template permissions**
    - Log into the ICA server console if you are not already logged in that way
    - Launch the Certification Authority
    - Expand Certificate Templates then right click and select "Manage"
    - For each template the starts with *Domain* (you Domain defined in the csv) open the Properties, click on the Security tab and remove SYSTEM on each template - Also click on the Domain Admins and uncheck "Autoenroll" 
    Note: Leave autoenroll enabled for the Domain Admin on the "*Domain* Web Server Certificate" Template
- Be sure to log out of the ICA VM

#### Automating Steps 1-3
- Optionally you can select "A" from in the Installation menu and menu items 1-3 will run consecutavly 
  **NOTE:** You will still need to manually complete [ica_setup_partII](ICA Setup Part 2)

#### Final Configuration
Back on the deployment container Select Menu option 4 (Final Configuration)
- This will Setup the Secondary Domain Controller
- Clean up installation files
- Prompt you for new "local" Admin account name/password 
- Prompt you for a new "DOMAIN" admin username/password 
  **Note:** You will be prompted for this twice: Once to create the account the second time is because the script is now running as you to delete the installation account. 
- Remove the Installation Admin (enter Y when prompted to remove the account)
- It will then shutdown the RCA VM (since it is a off-line Root Authority)
   
- You can now exit the menu and shut the container down
 

## Misc. Notes and Tips

### Fequently Asked Questions (FAQ)
Answers to FAQ can be found here: 
    - [FAQ HTML](faq.html)
    - [FAQ Markdown File](faq.md)

### Generating a Web Certificate Request in Linux

To generate a web certificate request in Linux, ensure that OpenSSL is installed first.  Then run the following command to generate the certificate request:

```bash
openssl req -new -newkey rsa:4096 -nodes -keyout web_srv.key -out web_srv.csr \
-subj "/C=US/ST=CO/L=Denver/O=Support/OU=IT/CN=company.domain.intra" \
-addext 'subjectAltName=DNS:web.domain.intra,DNS:hostname.domain.intra,IP:172.18.10.24'
```

Open a web browser and log into the ICA server: (ie: https://ica.domain.intra/CertSrv)

- click request certificate
- click Advanced
- select “\____ Web Server Certificate”
- paste the csr data into the request box

At the certificate you requested has been issued to you screen:  
download the certificate in DER encoding

Rename the certnew.cer  files to the easily identify them (i.e.: web_srv.cer/web_srv.p7b).  Deploy the certificates on your web server following the instructions for that web server (or application).

*Note:* In Linux you will probably need to install the RCA and ICA certificates so that the web server will trust the new certificate.  To do this:

- Download the “*\*\*_* Certificate Authority.crt" and the "*\*\*_* Enterprise Certificate Authority.crt” files to your Linux host

```
cp {CA_FILE} /usr/local/share/ca-certificates/
cp {IA_FILE} /usr/local/share/ca-certificates/
update-ca-certificates
```

- \*Replace {CA_FILE} with the CA certificate name and {IA_FILE} with the Enterprise Certificate name.

&nbsp;
## Known Issues, To-do, Upcoming Features

### Known Issues:
- PowerShell may display an error at the end of the Domain setup that says:
`Unable to load shared library 'libmi' or one of its dependencies.`
    Currently not sure what is causing this, but everything is working
- The ICA part II script shows an error when Configuring the OCSP Responder "MethodInvocationException:" This can be ignored and should be fixed in a future update 

### To-do:
- Fix issues with certificate template ACLs
- Fix error with OCSP responder message 
- Resolve permission issue so that all script can be ran from the same location (ie: Not required to log into the ICA server)
- Optimize variables in scripts (including derived variables), better map out of global vs functional variables
- Optimize and streamline the code

### RoadMap of Future Features
- Interactive way to build the variables file (or edit existing variables) that builds the csv file automatically
&nbsp;

