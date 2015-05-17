#!/bin/bash
# A linux iptables script for openvpn servers running inside openvz containers with restricted kernels.
# Inside openvz we cannot referance interfaces like a physical server (ie: '-i eth1')
# so intead we use -i venet0 -d your.ip.addrs.here, we also use source routing
# instead of masquerading for the vpn.
# -------------------------------------------------------------------------
# Copyright (c) 2004 nixCraft project <http://cyberciti.biz/fb/>
# This script is licensed under GNU GPL version 2.0 or above
# -------------------------------------------------------------------------
# Modified by Darkerego for OpenVPN servers inside OpenVZ containers
# Firewall script for OpenVZ containers running
# openvpn, dnscrypt, and some vpn reachable services
# Cyberbiz, modified by darkerego for Openvz OpenVPN 
# boxes with two IP address's
#### Constants #####################################
IPT="/sbin/iptables"
SPAMLIST="blockedip"
SPAMDROPMSG="BLOCKED IP DROP"

####--Set Variables Here--#####
EXTIF="venet0" # venet0 is the interface on openvz
EXTIP="1.2.3.4"	# your main ip addrs
OUTIP="1.2.3.5" # your secondary/outgoing ip addrs
VPN_IF="tun+" # for openvpn
VPN_SN="10.9.0.0/24" # opevpn subnet
VPNSRVR="10.9.0.1" # openvpn server's ip
sshPRT="22222" # choose a random high ssh port
vpnPRT="1194" # openvpn port
####---END-VARIABLES--#####

#### RESET IPTABLES ###############################
echo "Starting IPv4 Wall..."
$IPT -F
$IPT -X
$IPT -t nat -F
$IPT -t nat -X
$IPT -t mangle -F
$IPT -t mangle -X
####
[ -f /root/scripts/blocked.ips.txt ] && BADIPS=$(egrep -v -E "^#|^$" /spamlist)
# Allow Loopback
$IPT -A INPUT -i lo -j ACCEPT
$IPT -A OUTPUT -o lo -j ACCEPT
#### DROP all incomming traffic ####
$IPT -P INPUT DROP
$IPT -P OUTPUT DROP
$IPT -P FORWARD DROP
##### SPAM LIST (not necessary) #####
if [ -f /spamlist ];
then
$IPT -N $SPAMLIST
for ipblock in $BADIPS
do
$IPT -A $SPAMLIST -s $ipblock -j LOG --log-prefix "$SPAMDROPMSG"
$IPT -A $SPAMLIST -s $ipblock -j DROP
done
$IPT -I INPUT -j $SPAMLIST
$IPT -I OUTPUT -j $SPAMLIST
$IPT -I FORWARD -j $SPAMLIST
fi
######## Source Spoof Protection ####
#### (we should never be incoming from our own IP)####
iptables -A INPUT -i venet0 -s $EXTIP -d $EXTIP -j DROP
iptables -A OUTPUT -o venet0 -d $EXTIP -j DROP
iptables -A INPUT -i venet0 -s $OUTIP -d $OUTIP -j DROP
iptables -A OUTPUT -o venet0 -d $OUTIP -j DROP
#### Block sync ####
$IPT -A INPUT -p tcp ! --syn -m state --state NEW -m limit --limit 5/m --limit-burst 7 -j LOG --log-level 4 --log-prefix "Drop Sync"
$IPT -A INPUT -p tcp ! --syn -m state --state NEW -j DROP
#### Block Fragments ####
$IPT -A INPUT -f -m limit --limit 5/m --limit-burst 7 -j LOG --log-level 4 --log-prefix "Fragments Packets"
$IPT -A INPUT -f -j DROP
#### Block bad stuff #### 
####(tcp flags that should never happen) ####
$IPT -A INPUT -p tcp --tcp-flags ALL FIN,URG,PSH -j DROP
$IPT -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
$IPT -A INPUT -p tcp --tcp-flags ALL NONE -m limit --limit 5/m --limit-burst 7 -j LOG --log-level 4 --log-prefix "NULL "
$IPT -A INPUT -p tcp --tcp-flags ALL NONE -j DROP # NULL packets
$IPT -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
$IPT -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -m limit --limit 5/m --limit-burst 7 -j LOG --log-level 4 --log-prefix "XMAS "
$IPT -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP #XMAS
$IPT -A INPUT -p tcp --tcp-flags FIN,ACK FIN -m limit --limit 5/m --limit-burst 7 -j LOG --log-level 4 --log-prefix "FIN "
$IPT -A INPUT -p tcp --tcp-flags FIN,ACK FIN -j DROP # FIN packet scan
$IPT -A INPUT -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP

#### ALLOW ESTABLISHED (DON'T delete this!) #### 
$IPT -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPT -A OUTPUT -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
#### SSH  ####
$IPT -A INPUT -i venet0 -d $EXTIP -p tcp -m tcp --source-port 513:65535 --dport $sshPRT -j ACCEPT
#
######## INCOMING SERVICES -- Left these commented out as examples ########
#$IPT -A INPUT -i venet0 -d $OUTIP -p udp -m udp --source-port 1024:65535 --dport 50000 -j ACCEPT
#$IPT -A INPUT -i venet0 -d $OUTIP -p tcp -m tcp --source-port 1024:65535 --dport 80 -j ACCEPT
#### Drop incoming on outgoing IP unless established/related ####
$IPT -A INPUT -i venet0 -d $OUTIP -m state --state ESTABLISHED,RELATED -j ACCEPT
#### ACCEPT VPN ####
#$IPT -A INPUT -i venet0 -d $EXTIP -p udp -m udp --source-port 1024:65535 --dport $vpnPRT $EXTIP -j ACCEPT
#### VPN TUNNEL ####
#$IPT -A INPUT -i tun+ -j ACCEPT
#$IPT -A FORWARD -i tun+ -j ACCEPT
#$IPT -A FORWARD -i venet0 -d $VPN_SN -o tun+ -m state --state RELATED,ESTABLISHED -j ACCEPT
#$IPT -A FORWARD -i tun+ -s $VPN_SN -o venet0 -m state --state RELATED,ESTABLISHED -j ACCEPT
#$IPT -A FORWARD -i tun+ -m state --state NEW -o venet0 -j ACCEPT
#$IPT -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
#$IPT -A FORWARD -j LOG --log-level 4 --log-prefix "Reject Foward "
#$IPT -A FORWARD -j REJECT
#$IPT -t nat -A POSTROUTING  -s $VPN_SN -o venet0 -j SNAT --to-source $EXT_IP


######## VPN REACHABLE SERVICES ########
#$IPT -A INPUT -i tun+ -s $VPN_SN -p tcp -m tcp --source-port 1024:65535 --dport $sshPRT -j ACCEPT

#### HTTP (from inside vpn) ####
#$IPT -A INPUT -i tun+ -s $VPN_SN -p tcp -m tcp --source-port 1024:65535 --dport 80 -j ACCEPT
#### Privoxy/Tor ####
#$IPT -A INPUT -i tun+ -s $VPN_SN -d $VPNSRVR -p tcp -m tcp --source-port 1024:65535 --destination-port 9001 -j ACCEPT
#$IPT -A INPUT -i tun+ -s $VPN_SN2 -p tcp -m tcp --source-port 1024:65535 --destination-port 8118 -j ACCEPT
#### Transmission Web ####
#$IPT -A INPUT -i tun+ -s $VPN_SN -p tcp -m tcp --source-port 1024:65535 --dport 9100 -j ACCEPT
#### DNSCrypt/Unbound VPN ####
#$IPT -A INPUT -i tun+ -s $VPN_SN -d $VPNSRVR -p udp -m udp --dport 53 -m state --state NEW -j ACCEPT
#$IPT -A INPUT -i tun+ -s $VPN_SN -d $VPNSRVR -p tcp -m tcp --destination-port 53 -m state --state NEW -j ACCEPT



#### DNSCrypt Outgoing Rules ####
#$IPT -A OUTPUT -m owner --uid-owner dnscrypt -p udp -m udp --source-port 1024:65535 --dport 443 -j ACCEPT
#$IPT -A OUTPUT -m owner --uid-owner dnscrypt -p tcp -m tcp --source-port 1024:65535 --dport 443 -j ACCEPT
#$IPT -A OUTPUT -m owner --uid-owner dnscrypt -j DROP
#### ICMP Ping stuff ####
$IPT -A INPUT -p icmp --icmp-type 8 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
$IPT -A OUTPUT -p icmp --icmp-type 0 -m state --state ESTABLISHED,RELATED -j ACCEPT
#### I drop incoming on my 2ndary ip ####
$IPT -A INPUT -i venet0 -d $OUTIP -m state --state RELATED,ESTABLISHED -j ACCEPT
$IPT -A INPUT -i venet0 -d $OUTIP -j LOG --log-level 4 --log-prefix "DROP OUTIP "
$IPT -A INPUT -i venet0 -d $OUTIP -j DROP
#### Drop Source Spoofing ####
## These are private ranges, should never come from internet##
iptables -A INPUT -i venet0 -s 127.0.0.0/8 -j DROP
iptables -A INPUT -i venet0 -s 10.0.0.0/8 --j DROP
iptables -A INPUT -i venet0 -s 172.16.0.0/12 -j DROP
iptables -A INPUT -i venet0 -s 192.168.0.0/16 -j DROP
iptables -A INPUT -i venet0 -s 224.0.0.0/3 -j DROP
#### Drop Windows BS ####
$IPT -A INPUT -p tcp --dport 137:139 -j REJECT
$IPT -A INPUT -p udp --dport 137:139 -j REJECT
$IPT -A INPUT -p udp --dport 445 -j REJECT
#### LOG&DROP ####

$IPT -A INPUT -p udp --dport 1900 -j LOG --log-prefix "LOG UPNP "
$IPT -A INPUT -j LOG --log-prefix "DROP IN "
$IPT -A FORWARD -j LOG --log-prefix "DROP FWD "
$IPT -A INPUT -j DROP

exit 0
