#!/bin/bash
# Installation of Paraponera

KVER=`uname -a`
ARCH=`uname -m`
DISTRO=''
echo -e "\x1B[01;34m[*]\x1B[0m Installing Paraponera dependencies"

if [[ "$KVER" =~ Debian ]]; then
	
	if [[ "$(cat /etc/debian_version )" =~ Kali  ]]; then
		apt-get install python-nmap -y > /tmp/parapondera_install.log
		DISTRO='Kali'
	fi
	
	if [[ "$(cat /etc/debian_version )" =~ 7.0  ]]; then
		echo deb http://ftp.us.debian.org/debian unstable main contrib >> /etc/apt/sources.list
		apt-get update > /tmp/parapondera_install.log
		apt-get install python-nmap python-glade2 python-webkit python-pexpect ettercap-text-only sslstrip dsniff driftnet nmap -y >> /tmp/parapondera_install.log
		head -n -1 /etc/apt/sources.list > sources.list; mv sources.list /etc/apt/sources.list
		DISTRO='Debian'
	fi	

elif [[ "$KVER" =~ fc18 ]]; then
	yum install pywebkitgtk sslstrip dsniff driftnet python-nmap ettercap python-pexpect wget -y > /tmp/parapondera_install.log
	
	if [ ! -f /usr/sbin/ettercap ]; then
		ln -sf /usr/bin/ettercap /usr/sbin/ettercap
	fi
	DISTRO='Fedora'

elif [[ "$KVER" =~ buntu ]]; then
	sudo apt-get install python-nmap python-glade2 python-webkit ettercap-text-only sslstrip dsniff driftnet nmap --force-yes -y > /tmp/paraponera_install.log
	DISTRO='Ubuntu'
fi

if [[ ! $DISTRO ]]; then
    echo -e "\x1B[01;31m[*]\x1B[0m Sorry your system is not supported."
    exit 1
fi


echo -e "\x1B[01;34m[*]\x1B[0m Checking if Metasploit Framework is installed"
updatedb
MSFC=`locate -n1 msfconsole`

if [ ! -f "${MSFC}" ]; then

	echo -e "\x1B[01;34m[*]\x1B[0m Downloading Metasploit Framework"
	if [ "${ARCH}" == 'x86_64' ]; then
		wget -c http://downloads.metasploit.com/data/releases/metasploit-latest-linux-x64-installer.run -q
		chmod +x metasploit-latest-linux-x64-installer.run
	        echo -e "\x1B[01;34m[*]\x1B[0m Installing Metasploit Framework"

		./metasploit-latest-linux-x64-installer.run --mode unattended
	else
		wget -c http://downloads.metasploit.com/data/releases/metasploit-latest-linux-installer.run -q
		chmod +x metasploit-latest-linux-installer.run
	        echo -e "\x1B[01;34m[*]\x1B[0m Installing Metasploit Framework"
		./metasploit-latest-linux-installer.run --mode unattended
	fi
else
	echo -e "\x1B[01;34m[*]\x1B[0m Metasploit Framework is installed"
fi


updatedb
MSFC=`locate -n1 msfconsole`

if [ ! -f "${MSFC}" ]; then
    echo -e "\x1B[01;31m[*]\x1B[0m Something went wrong with Metasploit Framework..."
    exit 1
fi	

echo -e "\x1B[01;34m[*]\x1B[0m Creating symlinks"
if [ ! -f /usr/bin/msfconsole ]; then
	ln -sf ${MSFC} /usr/bin/msfconsole
fi

echo -e "\x1B[01;34m[*]\x1B[0m Cleaning up installation"
rm -Rf downloads.metasploit.com

if [ "${ARCH}" == 'x86_64' ]; then
	rm metasploit-latest-linux-x64-installer.run
else
	rm metasploit-latest-linux-installer.run
fi	

echo -e "\x1B[01;32m[*]\x1B[0m Installation Complete. Enjoy"

