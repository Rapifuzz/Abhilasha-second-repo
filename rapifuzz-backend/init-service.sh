#!/bin/bash
# Do not change
# Author: Vaishno Chaitanya

if (( $EUID != 0 )); then
    echo "Please run as root/ sudo"
    exit
fi
printf "[Service]\nType=simple\nWorkingDirectory=~\nEnvironmentFile=/etc/environment\nExecStart=/opt/app/be/start.sh\nUser=$USER\nGroup=$USER\n\n[Install]\nWantedBy=multi-user.target" > /etc/systemd/system/be.service
chmod +x /opt/app/be/start.sh
systemctl daemon-reload
sudo systemctl enable be
echo
echo "Finished!"
