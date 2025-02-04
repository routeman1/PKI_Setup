# Frequently Asked Questions

**Why did you build this?**
I found myself having to rebuild a PKI infrastructure multiple times for testing in a lab environment. Also, sadly I discovered most engineers could not deploy PKI properly.  I was fortunate enough to have somebody teach me and walk me through the process. There are other ways to deploy and configure PKI, but this is the typical configuration that I required so I (semi) automated the process to save me lots of time. 

**Why use a Docker Container?**
I choose to us a Docker container to simplify the deployment process and eliminate the need to setup and stage files on a separate web server. With a container it is very easy to control and ensure all the dependencies are of the correct version and configured a certain way. The other great benefit is the container is disposable, spin it up to build the environment and when you’re done, delete it as it is no longer required for operations.  

My other reason is that utilizing Microsoft WINRM, WSManCred capabilities are far too limiting.  You would need to build another windows server, update PowerShell, it must be on the same subnet otherwise you have to modify each of the other hosts (dc1&2, rca and ica), and you must do some registry modifications.  I initially went down this path and spent way too much time trying to work around the MS "security" features to install their own software with their own programing tools. PAINFUL! 

Utilizing a Docker container and SSH turned out to be much easier to prep the environment and had less impact on default registry settings and other security settings on the VMs. 

**Can I use my own Web Certificates?**
Absolutely! Just put your server cert and private key in the "crypto" directory before you run the "build-deploy" script.  Be sure to name the files server.crt and server.key.  Also make sure that they are in Base64 format

**What about using my own SSH keys?**
Yes - You would do the same as you did for the server certificates above.  Place you public and private ssh keys in the "crypto" directory.  Be sure to name them pkisetup and pkisetup.pub respectively. 

**Why is the Intermediate Certificate Authority install a 2-part process?**
This is because of Microsoft's convoluted security. I am not sure if this is a double-hop authentication issue (I don't believe so, regardless of what the internet forums say), or something else. I suspect that there needs to be some settings in the registry or AD (or both) for this to work successfully. It is on my to-do list to figure out and try to collapse the ICA setup into a single step.

**Why do you have to modify the Certificate Templates by hand?**
I am utilizing the PowerShell module ADCSTemplate that allows for the import/export of certificate templates in JSON format.  This simplifies the complexity of dealing with custom certificate templates greatly. Unfortantly it is not perfect and so currently you need to make a few modifications by hand. I am still resaerching and trying to find a way to automate this process. 

For more information on ADCSTemplate: https://github.com/GoateePFE/ADCSTemplate

**What other PowerShell Modules are utilized in the scripts?**
PSPKI is leveraged to assist in the certificate template, key recovery and OCSP responder configurations.  More details about that PowerShell module can be found here: https://www.pkisolutions.com/tools/pspki/

**Why do you delete the install accounts at the end?**
Security - Even though this script is for a lab environment, for the most part I still try to follow some basic security guidelines. 

**Why don't you remove the install SSH key?**
I didn't add a process to remove the installed ssh key as this leaves the system ready for you to run Ansible playbooks for further customization and automation. You can run Ansible playbook to update the SSH keys (I highly recommend this) or remove them by hand.

**Why does the script(s) have long pauses where nothing seems to be happening?**
The scripts need to wait for the VMs to complete their reboot processes.  Unfortunately, my home lab is a bit underpowered, so I needed to add much longer wait times.  If you are running on nice fast hardware and your VMs reboot very quickly, you can shorten the wait times by adjusting the "Start-Sleep" times in the various scripts.

**Can I use this to add PKI to an existing AD environment?**
*This script is intended for lab use only.*  It does not have all the code that would be needed to safely modify and existing AD environment. It should go without saying: *Use this at your own risk.* I take no responsibility for you destroying your environment. 

**Will this work on Mac Docker Desktop?**
Sadly, not right now - It is on my to-do list if I get time to work on it. Currently the location of the support files to build container are different on a Mac then what the scripts are currently pointing to.  In addition, the ARM architecture creates a few interesting challenges building the container. 

**I found an issue, or have a suggestion**
If you find this useful, feel free to contribute. This was my first PowerShell project so there is lots of room for improvement. 

