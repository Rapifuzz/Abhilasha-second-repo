# API Fuzzer

API Fuzzer Project

# Docker Deployment [Soon]
# VM Deployment Commands
Ubuntu should have one sudoer user "peach".

#### System Dependencies
```sh
sudo apt-get update
sudo apt-get upgrade
sudo apt-get install git
sudo apt-get install net-tools
```

#### Project Dependencies
```sh
sudo apt-get install python3
sudo apt-get install python3-pip
sudo apt-get install python3-venv
sudo apt-get install python3-dev libffi-dev libssl-dev
sudo apt-get install libmysqlclient-dev
sudo pip3 install mitmproxy
sudo apt-get install mysql-server
```

#### Setup user and database
```sh
sudo mysql
    > SELECT user,authentication_string,plugin,host FROM mysql.user;
    > CREATE USER 'peachuser'@'localhost' IDENTIFIED BY 'peach@db';
    > GRANT ALL PRIVILEGES ON *.* TO 'peachuser'@'localhost' WITH GRANT OPTION;
    > FLUSH PRIVILEGES;
    > CREATE DATABASE security_testing_db;
    > exit;
```

## MySQL database credentials
> username: peachuser

> password: peach@db

> dbname: security_testing_db

## Commands to start peach project manually
```sh
sudo service peachapi start/stop/status/restart                     # For Peach API Fuzzer
sudo service peachfuzzer start/stop/status/restart                  # For Peach Fuzzer
sudo service peachfuzzerview start/stop/status/restart              # For Peach Fuzzer Landing page
```

## For debugging
```sh
sudo journalctl -u peachapi -f                                      # For Peach API Fuzzer
sudo journalctl -u peachfuzzer -f                                   # For Peach Fuzzer
sudo journalctl -u peachfuzzerview -f                               # For Peach Fuzzer Landing page
```

## Full database Reset
```sh
DROP database security_testing_db;                                  # Remove the database
CREATE DATABASE security_testing_db;                                # Create the database
```
## Switching to GUI
```sh
sudo systemctl set-default graphical
sudo systemctl start gdm3
```