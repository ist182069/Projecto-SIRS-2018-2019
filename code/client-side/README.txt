##########################
### Required Platform  ###
##########################

# Linux setup:
# Linux 4.9.0-kali3-amd64 x86_64 (name: Kali GNU/Linux, version: 2017.1)

##########################
### SETUP INSTRUCTIONS ###
##########################

# FIRST TIME DEPLOYMENT:

# Relevant steps:
# our app is stable using OpenSSL version "OpenSSL 1.1.1a  20 Nov 2018" and Python version "Python 2.7.15+ (default, Aug 31 2018, 11:56:52)"
# if update is needed run:
apt-get update
apt-get install python
apt-get install python-pip
apt-get install build-essential libssl-dev libffi-dev python-dev
apt-get install openssl 		# if needed, follow this installer to install it manually: https://websiteforstudents.com/manually-install-the-latest-openssl-toolkit-on-ubuntu-16-04-18-04-lts/ ; just remember to download it from "https://www.openssl.org/source/openssl-1.1.1a.tar.gz", so you can download the used version "1.1.1a", and substitute 1.1.1 for 1.1.1a in all steps
chmod +x client.py
chmod +x utils/*.sh
pip install -r requirements.txt
# extra step for activating argcomplete module and, hence, being able to autocomplete the args for facilitated usage
# run:
activate-global-python-argcomplete
# and close the shell afterwards.

# Read client options
python client.py -h
python client.py

# Play with client
python client.py --login davidmatos --list-files
python client.py --login davidmatos --synchronize myfiles/apresentacao.txt
python client.py --login davidmatos --synchronize myfiles/sirs/
python client.py --login davidmatos --synchronize-all-individual        # same as doing "--synchronize myfiles/"
python client.py --login davidmatos --fetch myfiles/apresentacao.txt
python client.py --login davidmatos --fetch myfiles/sirs/
python client.py --login davidmatos --fetch-all-individual        # same as doing "--fetch myfiles/"
python client.py --login davidmatos --list-all-users
python client.py --login davidmatos --share ~/Documents/shared_document.docx 	# one time share for a group of users, use synchronize-shared and fetch-shared after sharing
python client.py --login davidmatos --share ~/Documents/mypersonaldocuments/ 	# one time share for a group of users, use synchronize-shared and fetch-shared after sharing
python client.py --login davidmatos --fetch-shared ~/Documents/shared_document.docx
python client.py --login davidmatos --fetch-shared ~/Documents/mypersonaldocuments/
python client.py --login davidmatos --synchronize-shared ~/Documents/shared_document.docx
python client.py --login davidmatos --synchronize-shared ~/Documents/mypersonaldocuments/

# In case you want to work on another version of a file or if you suffer a ransomware attack, we have stored backups in the server.
python client.py --login davidmatos --list-backups
python client.py --login davidmatos --revert-individual
python client.py --login davidmatos --revert-shared
