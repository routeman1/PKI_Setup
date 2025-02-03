# Crypto Readme

- You can optionally add your own web certificate and ssh key
    - To use your own web certificate, copy the cert and key (in Base64 format) to the Crypto directory. 
     **NOTE:** They must be named server.crt and server.key.
- To use your own ssh keys copy the ssh private key (must be named pkisetup) and the public key (must be named pkisetup.pub) to the crypto directory.
- If you do not place anything in the crypto directory, a self-signed cert will be generated along with a ssh key

**NOTE: DO NOT DELETE THIS FILE** or the Docker build process will fail.