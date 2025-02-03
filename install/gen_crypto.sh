#!/usr/bin/sh

# Check to see if there are SSL certs for the web server
if [ -f "/install/crypto/server.crt" ]; then
  cp /install/crypto/server.crt /etc/ssl/server.crt
  cp /install/crypto/server.key /etc/ssl/server.key
else
  # command to run if file does not exist
  echo "No server.crt file exists, generating web server certificate..."
  openssl req -x509 -newkey rsa:4096 -keyout /etc/ssl/server.key -out /etc/ssl/server.crt -sha256 -days 365 -nodes -subj "/CN=pki-setup"
fi

# Check to see if there are SSH keys 
if [ -f "/install/crypto/pkisetup" ]; then
  cp /install/crypto/pkisetup /root/.ssh/pkisetup
  chmod 600 /root/.ssh/pkisetup
  cp /install/crypto/pkisetup.pub /opt/nginx_data/pkisetup.pub
else
  # command to run if file does not exist
  echo "No authorized_keys file exists, generating SSH public/private key pair..."
  mkdir -p /root/.ssh
  chmod 700 /root/.ssh
  ssh-keygen -t ecdsa -b 521 -f /root/.ssh/pkisetup #-P ""
  cp /root/.ssh/pkisetup.pub /opt/nginx_data/pkisetup.pub
fi
