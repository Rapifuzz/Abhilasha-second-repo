#!/bin/bash
echo "####################starting backend script#####################" 
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install apt-utils -y
 
apt-get install python3-django -y
apt-get install build-essential -y
 
apt install apt-transport-https curl gnupg-agent ca-certificates software-properties-common -y
cd /usr/lib/python3/dist-packages/ && ln -s apt_pkg.cpython-36m-x86_64-linux-gnu.so apt_pkg.so
apt-get install mariadb-server -y
apt install mysql-server -y
 
apt-get install xfonts-75dpi -y
apt-get install --reinstall python3-pip python3-venv python3-dev net-tools libffi-dev libssl-dev default-libmysqlclient-dev psmisc  dialog whiptail -y
 
apt-get install libffi-dev libssl-dev default-libmysqlclient-dev -y
 
echo "###############################shell script complete###############################"
 