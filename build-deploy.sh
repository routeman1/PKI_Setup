#!/usr/bin/bash

## This script will build the docker image and then 
## deploy it to with the correct configuration

echo "This script will build the docker image and then deploy it to with the correct configuration"
echo "Make sure you are running this script on the docker server that the container will be deployed to"
echo "as this script will update the nessecary files with the ip address of this host"
echo ""
prompt="Press enter to continue"
read -p "$prompt"

## Get ip address of the current host
export HOST_IP=$(ip route get 1 | sed -n 's/^.*src \([0-9.]*\) .*$/\1/p')

## update the template_config.ps1 file
sed -i "s,https://host/unattend.xml,https://$HOST_IP/unattend.xml,g" ./nginx_data/template_config.ps1
sed -i "s,https://host/pkisetup.pub,https://$HOST_IP/pkisetup.pub,g" ./nginx_data/template_config.ps1
sed -i "s,https://host/fix_authorized_keys.ps1,https://$HOST_IP/fix_authorized_keys.ps1,g" ./nginx_data/template_config.ps1
sed -i "s,https://host,https://$HOST_IP,g" ./nginx_data/install.bat

# Check to see if there are files in the Crypto directory
if [ -z `find ./crypto -type d -empty` ]; then
    # If there are - Modify the dockerfile to Copy the crypto files
    sed -i "s,#COPY ./crypto,COPY ./crypto,g" ./dockerfile
fi 

#build the container
docker build -f dockerfile -t pki-setup .

## Deploy the container
docker run -d -p 443:443 -p 80:80 --name pki-setup pki-setup
