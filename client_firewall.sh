# This is a firewall for clients of your OpenVZ/OpenVPN server. It is made to intergrate easily
# with the Debian/Ubuntu UFW. After running this, you can use UFW to open/close ports at will. 
# Credit to Cyberbiz for the original template. Modified by Darkerego for the reasons above.
# Do whatever, just give us credit. 

#!/bin/bash
# Need root!
if [[ $EUID -ne 0 ]]; then
	echo "Got root..?"
	exit 1
fi

# Constants
	IPT="/sbin/iptables"
	BlOCKLIST="blockedip"
	BLOCKMSG="BLOCKED IP DROP"
# Log Messages
	logDNSC='invalid dnscrypt'
	logTMS='invalid transmission'
	logTUN='invalid vpn sever!'
# Variables
	vpnPRT=65432
	vpnSSH=33567
	vpnSVR=1.2.3.4
	vpnCLI=10.9.0.1
	tunSVR=10.9.0.1
	DNS_1=208.67.222.222
	DNS_2=208.67.220.220
	transPRT=51431
	domain=53
	http=80
	service1="" # some other ports
	service2="" 
	localSN='192.168.1.1/24'
#vpnSVR2=94.156.77.219
#And interface (usually tun0 or tap0)
	vpnITF=tun+
#Flush our current chains:
#
	$IPT -F
	$IPT -t nat -F
	$IPT -t mangle -F
	$IPT -X
	
# Make sure UFW doesn't break anything
	ufw reset
#Now for our UFW defaults:
	ufw default deny incoming
	ufw default deny outgoing

	echo "Defaults set..."

## DNS Queries should pass to initiate the connection
##ufw allow out 53 to 192.168.101.1
##ufw allow out to 176.56.237.171 port 443 proto udp
##ufw allow out to 77.66.84.233 port 443 proto udp
##Only allow out to server on vpn port

if [ -f '/root/scripts/blocked.ips' ];
then
## create a new iptables list
	$IPT -N $BLOCKLIST

for ipblock in $BADIPS
do
	$IPT -A $BLOCKLIST -s $ipblock -j LOG --log-prefix "$BLOCKMSG"
	$IPT -A $BLOCKLIST -s $ipblock -j DROP
done

	$IPT -I INPUT -j $BLOCKLIST
	$IPT -I OUTPUT -j $BLOCKLIST
	$IPT -I FORWARD -j $BLOCKLIST
fi



# Transmission Peer Port
tPP_EN=false
##
if [[ $tPP_EN == "true" ]]; then

	echo Warning: Transmission peer port open...
	####
	$IPT -A INPUT -i tun+ -p tcp --dport $transPRT -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT
	$IPT -A INPUT -i tun+ -p udp --dport $transPRT -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT
else
	echo Not openening transmission peer port...
fi
	echo Setting vpn rules...
####Allow VPN
	$IPT -A OUTPUT -o tun+ -j ACCEPT
	$IPT -A OUTPUT -o eth0 -p tcp -d $vpnSVR --dport $vpnPRT -j ACCEPT
	$IPT -A OUTPUT -o eth0 -p udp -d $vpnSVR --dport $vpnPRT -j ACCEPT
	$IPT -A OUTPUT -o wlan0 -p tcp -d $vpnSVR --dport $vpnPRT -j ACCEPT
	$IPT -A OUTPUT -o wlan0 -p udp -d $vpnSVR --dport $vpnPRT -j ACCEPT
	$IPT -A OUTPUT -o eth0 -p tcp -d $vpnSVR --dport $vpnSSH -j ACCEPT
	$IPT -A OUTPUT -o wlan0 -p tcp -d $vpnSVR --dport $vpnSSH -j ACCEPT

	echo Preventing transmission leaks...

## Prevent Transmission Leaks

	$IPT -A OUTPUT -o tun+ -p tcp --dport $transPRT -j ACCEPT
	$IPT -A OUTPUT -o tun+ -p udp --dport $transPRT -j ACCEPT
	$IPT -A OUTPUT -o eth0 -p tcp --dport $transPRT -j REJECT
	$IPT -A OUTPUT -o eth0 -p udp --dport $transPRT -j REJECT
	$IPT -A OUTPUT -o wlan+ -p tcp --dport $transPRT -j REJECT
	$IPT -A OUTPUT -o wlan+ -p udp --dport $transPRT -j REJECT

	echo Setting dnscrypt rules...

# Dnscrypt-proxy rules
	$IPT -A OUTPUT -p udp -m owner --uid-owner dnscrypt -d $DNS_1 --sport 1024:65535 --dport 443 -j ACCEPT
	$IPT -A OUTPUT -p udp -m owner --uid-owner dnscrypt -d $DNS_2 --sport 1024:65535 --dport 443 -j ACCEPT
	$IPT -A OUTPUT -m owner --uid-owner dnscrypt -j LOG --log-prefix '$logDNSC'
	$IPT -A OUTPUT -m owner --uid-owner dnscrypt -j REJECT

	echo Setting vpn-reachable services....

# VPN Services we need to reach
	$IPT -A OUTPUT -o tun+ -s $vpnCLI -d $tunSVR -p udp --dport $domain -j ACCEPT
	$IPT -A OUTPUT -o tun+ -s $vpnCLI -d $tunSVR -p tcp --dport $http -j ACCEPT
	$IPT -A OUTPUT -o tun+ -s $vpnCLI -d $tunSVR -p tcp --dport $service -j ACCEPT
	$IPT -A OUTPUT -o tun+ -s $vpnCLI -d $tunSVR -p tcp --dport $service2 -j ACCEPT
	$IPT -A OUTPUT -o tun+ -s $vpnCLI -d $tunSVR -p tcp --dport $vpnSSH -j ACCEPT
	$IPT -A OUTPUT -o tun+ -d $tunSVR -j LOG --log-prefix='$logTUN'
	$IPT -A OUTPUT -o tun+ -d $tunSVR -j REJECT

	echo Setting private network settings...

##Allow access to all private networks.

	$IPT -A OUTPUT -o tun+ -d $localSN -j REJECT
	$IPT -A OUTPUT -o tun+ -d $localSN -j REJECT
	$IPT -A OUTPUT -o wlan+ -d $localSN -j ACCEPT
	$IPT -A OUTPUT -o eth0 -d $localSN -j ACCEPT

	echo Will now enable the fw...
## Or let UFW handle it if you're less paranoid
 
	#ufw allow out to 192.168.0.0/16
	#ufw allow out to 172.16.0.0/12
	#ufw allow out to 10.0.0.0/8

# Allow ipv4 muticast (If you need it)
	#ufw allow out to 224.0.0.0/24
	#ufw allow out to 239.0.0.0/8
# Allow local ipv6
	#ufw allow out to ff01::/16

#Finally, turn it on...
	ufw enable

	echo Enabled...

	ufw reload

	echo "Done!"
