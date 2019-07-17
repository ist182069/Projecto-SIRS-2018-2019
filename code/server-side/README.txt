##########################
### Required Platform  ###
##########################

# Linux setup:
# Linux 4.9.0-kali3-amd64 x86_64 (name: Kali GNU/Linux, version: 2017.1)

##########################
### SETUP INSTRUCTIONS ###
##########################

# FIRST TIME DEPLOYMENT:

# These 2 steps were only for us in the beginning:
./CA_SERVER_CERTS_KEYPAIRS.sh
# Copy the trusted ca cert to the client

# Relevant steps:
# our app is stable using OpenSSL version "OpenSSL 1.1.1a  20 Nov 2018" and Python version "Python 2.7.15+ (default, Aug 31 2018, 11:56:52)"
# if update is needed run:
apt-get update
apt-get install python
apt-get install python-pip
apt-get install build-essential libssl-dev libffi-dev python-dev
apt-get install openssl 		# if needed, follow this installer to install it manually: https://websiteforstudents.com/manually-install-the-latest-openssl-toolkit-on-ubuntu-16-04-18-04-lts/ ; just remember to download it from "https://www.openssl.org/source/openssl-1.1.1a.tar.gz", so you can download the used version "1.1.1a", and substitute 1.1.1 for 1.1.1a in all steps
chmod +x server.py
chmod +x *.sh
pip install -r requirements.txt

# run it
python server.py
