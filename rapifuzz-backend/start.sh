#!/bin/bash
# DO NOT CHANGE
# Author: Vaishno Chaitanya

if [ -z "${HOST_IP:-}" ]; then
    # check if the system is an AWS EC2 instance
    if curl -sSf http://169.254.169.254/latest/meta-data/instance-id >/dev/null 2>&1; then
        # get the public IP address of the EC2 instance
        public_ip=$(curl -sS http://169.254.169.254/latest/meta-data/public-ipv4)
    fi

    # check if the system is a GCE instance
    if [[ -f "/etc/lsb-release" ]]; then
        if grep -q "Google" "/etc/lsb-release"; then
            # get the public IP address of the GCE instance
            public_ip=$(curl -sS "http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip" -H "Metadata-Flavor: Google")
        fi
    fi

    if [ -z "${public_ip:-}" ]; then
        HOST_IP=$(hostname -I)
        read -ra HOST_IP -d '' <<<"$HOST_IP"
        HOST_IP=${HOST_IP[0]}
    else
        HOST_IP=$public_ip
    fi
fi

export HOST_IP=${HOST_IP//[[:blank:]]/}

cd /opt/app/be/ && source venv/bin/activate && gunicorn --bind 0.0.0.0:8000 --workers=4 --threads=4 --timeout 300 rapifuzz.wsgi
