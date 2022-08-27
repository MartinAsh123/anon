#!/bin/bash

#Author: Martin
#Date: 11/07/2022

#Description
#This program is checking if you are root - if you are , it will install and turn on "Nipe".
#It also checks if you are anonymus (different country code than your regular), and connects to the desired server ip with SSH service and executes commands within the script.

#Usage: anon.sh
#anon function
IP=$(curl -s ifconfig.me) #checking my public ip
bcountry=$(whois $IP 2>/dev/null | grep country | awk '{print $2}' | uniq) # 'b' stants for 'before' using nipe
function APT
{
	git clone https://github.com/htrgouvea/nipe
cd nipe
sudo cpan install Try::Tiny Config::Simple JSON
sudo perl nipe.pl install
sudo perl nipe.pl start

}

function anon
{
	IP=$(curl -s ifconfig.me) #checking my public ip again
	acountry=$(whois $IP 2>/dev/null | grep country | awk '{print $2}' | uniq) #getting the country code - 'a' stands for 'after' using nipe
	if [ "$acountry" == "$bcountry" ] #if the country var = IL country code then you are not anonymous else you are
	then
	echo " You are not anonymous"
	echo " exitting..."
	else
	echo " You are anonymous"
	#Conn3ct function call
	Conn3ct
	fi 	
}
function Conn3ct
{
read -p "Please insert the server IP you would like to access: " DIP #IP to connect
	echo "[>>] Connecting to $DIP...." 
	read -p "Please enter the username: " USR #enter a username
	read -p "Please enter the password: " PASS #enter a password
    sshpass -p "$PASS" ssh -t -o StrictHostKeyChecking=no "$USR"@"$DIP"   "nmap $(ip a | grep eth0 | grep inet | awk '{print $2}')" #nmap
    sshpass -p "$PASS" ssh -t -o StrictHostKeyChecking=no "$USR"@"$DIP"  'whois $(curl -s ifconfig.co) ' #whois	
	
}
#Checking if the user is root - if yes then continue and launch anon function , if not then exit	
if [ $(whoami) == "root" ]
then
APT
echo "Checking your anonymity..."
#anon function call
anon
else 
echo "You are not root..."
echo "exitting..."
fi
