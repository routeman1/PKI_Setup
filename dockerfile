# Use the latest ubuntu-focal image as the base
#### Build Stage ####
ARG BASE_IMAGE="ubuntu/nginx"
FROM $BASE_IMAGE AS base_layer

USER root

# Copy install files
COPY ./install /install/
RUN mkdir /install/crypto
## NOTE: Do not modify the next line this is used by the build-deploy.sh script
#COPY ./crypto /install/crypto

# Configure NGINX
ADD /install/nginx/nginx.conf /etc/nginx/
ADD /install/nginx/default /etc/nginx/sites-available/default
COPY ./nginx_data /opt/nginx_data/

### Install supporting packages
RUN apt-get update && apt-get install openssh-client ca-certificates inetutils-ping pandoc -y

## Setup landing page and FAQ
COPY ./*.md /opt/nginx_data/
RUN pandoc -s /opt/nginx_data/README.md -o /opt/nginx_data/index.html
RUN pandoc -s /opt/nginx_data/faq.md -o /opt/nginx_data/faq.html
RUN pandoc -s /opt/nginx_data/variables.md -o /opt/nginx_data/variables.html

### Copy/Create SSL certs and SSH keys
RUN mkdir /root/.ssh 
RUN /install/gen_crypto.sh

### Install PowerShell
RUN /install/powershell.sh
  ## Copy PS scripts and templates
COPY ./scripts /scripts/
COPY ./cert-templates /scripts/cert-templates/
COPY ./variables.csv /scripts/variables.csv

## Run Apt Cleanup 
RUN apt-get autoremove --purge -y && apt-get clean 

### Labels
LABEL "org.opencontainers.image.authors"="Jon Kelly'"
LABEL "org.label-schema.name"="PKI Setup"
LABEL "org.label-schema.description"="Container for PKI Setup in a Windows Enviornment."
LABEL "org.label-schema.url"="https://github.com/routeman1/pki_setup" 
